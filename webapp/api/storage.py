from __future__ import annotations

import base64
import binascii
import functools
import json
import logging
import os
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Seconds a connection waits on another connection's lock (the records and
# anomalies connections share one file) before raising "database is locked".
# Callers do not retry: the ingest loop retries on its next poll (duplicates
# are ignored by the UNIQUE keys) and HTTP requests return a logged 500.
SQLITE_BUSY_TIMEOUT_SECS = 30

# Full-text index layout. The external-content index keeps only the index and
# reads message / raw_line from the records table (content='records'). Older
# versions created a standalone table that stored a second copy of both.
_FTS_EXTERNAL_SQL = (
    "CREATE VIRTUAL TABLE IF NOT EXISTS {name} "
    "USING fts5(message, raw_line, content='records', content_rowid='id')"
)
_FTS_MIGRATION_TABLE = "records_fts_ext"
# Rows copied into the new index per locked step; the lock is released between
# steps so ingest and HTTP queries keep running during a migration.
FTS_MIGRATION_BATCH = 2000

# Per-object ingest retries: the first retry happens on the next poll, later
# ones back off exponentially up to this cap, so a permanently broken object
# costs at most one GET per cap interval and never blocks other objects.
OBJECT_RETRY_BASE_SECS = 60
OBJECT_RETRY_MAX_SECS = 3600

# Records deleted per locked step when pruning, so a large first prune does
# not hold the shared connection (and readiness) for minutes.
PRUNE_BATCH = 5000

# Largest integer SQLite stores; ids beyond it are a client error, not a 500.
MAX_SQLITE_INT = 2**63 - 1

# Facet values returned per field (most frequent first). A cluster with
# churning pod names would otherwise send every name ever seen.
FACET_VALUES_MAX = 1000
DASHBOARD_LIST_MAX = 100

# Log context (entries around one record of the same pod/container): at most
# this many per side, searched within this distance of the record's time.
CONTEXT_LINES_MAX = 50
CONTEXT_WINDOW_SECS = 6 * 3600

# Per-prefix S3 listing errors kept from the last poll (for the status page).
_PREFIX_ERRORS_MAX = 50
_PREFIX_ERROR_CHARS = 300

_RECORD_COLUMNS = (
    "id, timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line, "
    "source_key, source_etag, line_number, is_falco"
)

# Below this much free space on the database volume, /api/status reports
# the disk as low (SQLite needs room for its WAL, temp files and growth).
DISK_LOW_FREE_BYTES = 256 * 1024 * 1024
DISK_LOW_FREE_FRACTION = 0.05


def open_connection(db_path: Path) -> sqlite3.Connection:
    """A connection to the app database with the shared busy timeout. Used for
    connections owned by a single thread (e.g. the insights detector)."""
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
    conn.row_factory = sqlite3.Row
    return conn


_JOURNAL_MODES = frozenset({"wal", "delete", "truncate", "persist"})


def _journal_mode_name(value: str) -> str:
    # PRAGMA values cannot be bound as parameters; only known names reach SQL.
    if value not in _JOURNAL_MODES:
        raise ValueError(f"Unsupported SQLite journal mode {value!r}; use one of {sorted(_JOURNAL_MODES)}")
    return value


def utc_stamp(offset_secs: float = 0) -> str:
    """Fixed-width UTC timestamp (always with microseconds) so values compare
    correctly as strings. Used for the retry schedule."""
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_secs)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _rollback_quietly(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        try:
            conn.rollback()
        except sqlite3.Error:
            logger.exception("Rolling back a failed write also failed")


def _locked(method):
    """Serialize use of the shared connection. The HTTP worker threads, the
    ingest loop and the insights job all use it, and concurrent use of one
    sqlite3 connection fails intermittently (InterfaceError / IndexError).

    A method that fails part-way through a write rolls it back. Otherwise the
    open transaction would be committed by the next unrelated commit, e.g.
    records saved without their full-text rows (disk full in the middle of a
    batch), which corrupts an external-content index on a later delete."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            try:
                return method(self, *args, **kwargs)
            except BaseException:
                _rollback_quietly(self._conn)
                raise

    return wrapper


def _iso_ms(value: datetime) -> str:
    """UTC ISO-8601 with milliseconds, the format browsers send."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _encode_cursor(ts: str, record_id: int) -> str:
    payload = json.dumps({"ts": ts, "id": record_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[str, int] | None:
    """Decode a paging cursor. Anything that is not a cursor this server issued
    raises ValueError, which the HTTP layer reports as a 400."""
    if not cursor:
        return None
    try:
        pad = "=" * (-len(cursor) % 4)
        payload = base64.urlsafe_b64decode((cursor + pad).encode("ascii"))
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error):
        raise ValueError("Invalid cursor") from None
    if not isinstance(data, dict):
        raise ValueError("Invalid cursor")
    ts, record_id = data.get("ts"), data.get("id")
    if not isinstance(ts, str) or not ts or isinstance(record_id, bool) or not isinstance(record_id, int):
        raise ValueError("Invalid cursor")
    if not 0 <= record_id <= MAX_SQLITE_INT or len(ts) > 64:
        raise ValueError("Invalid cursor")
    return ts, record_id


class LogStorage:
    def __init__(self, db_path: Path, *, journal_mode: str = "wal"):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.fts_enabled = False
        # "external" | "migrating" (a legacy index from an older version still
        # serves search while the external one is backfilled) | "" when FTS5
        # is unavailable.
        self.fts_layout = ""
        self._legacy_fts = False  # a standalone index from an older version still exists
        self.fts_migration_error: str | None = None  # set by the server's migration loop
        self.journal_mode = ""
        with self._lock:
            self._configure(journal_mode)
            self._init_schema()

    def _configure(self, journal_mode: str) -> None:
        is_new = self._conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] == 0
        if is_new:
            # Only takes effect before the first table exists. Lets pruning hand
            # freed pages back to the filesystem (see _release_free_pages).
            self._conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        requested = (journal_mode or "wal").strip().lower()
        # WAL lets the insights reader and the anomaly writer run alongside the
        # ingest writer. It needs a local filesystem (shared-memory index);
        # set LOGSCOPE_SQLITE_JOURNAL_MODE=delete for network filesystems.
        actual = str(self._conn.execute(f"PRAGMA journal_mode = {_journal_mode_name(requested)}").fetchone()[0]).lower()
        if actual != requested:
            logger.warning("SQLite journal_mode %s requested but the database uses %s", requested, actual)
        self.journal_mode = actual

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity_bucket TEXT NOT NULL,
                scope TEXT NOT NULL,
                namespace TEXT NOT NULL,
                pod TEXT NOT NULL,
                container TEXT NOT NULL,
                message TEXT NOT NULL,
                raw_line TEXT NOT NULL,
                source_key TEXT NOT NULL,
                source_etag TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                is_falco INTEGER NOT NULL DEFAULT 0,
                ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(source_key, source_etag, line_number)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ingested_objects (
                bucket TEXT NOT NULL,
                key TEXT NOT NULL,
                etag TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                status TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                PRIMARY KEY (bucket, key, etag)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS prefix_state (
                prefix TEXT PRIMARY KEY,
                last_key TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS app_state (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS object_failures (
                bucket TEXT NOT NULL,
                key TEXT NOT NULL,
                etag TEXT NOT NULL,
                prefix TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                first_failed_at TEXT NOT NULL,
                next_attempt_at TEXT NOT NULL,
                PRIMARY KEY (bucket, key, etag)
            )
            """
        )
        self._init_fts(cur)
        self._conn.commit()

    def _table_sql(self, name: str) -> str | None:
        row = self._conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
        return str(row[0]) if row and row[0] else None

    def _init_fts(self, cur: sqlite3.Cursor) -> None:
        """Pick the full-text layout. A database with an external-content index
        uses it. An empty database gets one directly. Anything else (a legacy
        standalone index from an older version, or records with no index at
        all) is backfilled into records_fts_ext by migrate_fts_step and swapped
        in when complete; until then search uses the legacy index if there is
        one, or substring matching if there is not."""
        existing = self._table_sql("records_fts")
        try:
            if existing is not None and "content=" in existing.replace(" ", "").lower():
                self.fts_layout = "external"
                self._legacy_fts = False
                if self._table_sql(_FTS_MIGRATION_TABLE) is not None:  # leftover from an older run
                    self._run_ddl([f"DROP TABLE {_FTS_MIGRATION_TABLE}"])
                    self._clear_migration_state()
            elif existing is None and cur.execute("SELECT 1 FROM records LIMIT 1").fetchone() is None:
                cur.execute(_FTS_EXTERNAL_SQL.format(name="records_fts"))
                self.fts_layout = "external"
                self._legacy_fts = False
            else:
                self._legacy_fts = existing is not None
                cur.execute(_FTS_EXTERNAL_SQL.format(name=_FTS_MIGRATION_TABLE))
                if self._get_state("fts_migration_upper") is None or not self._migration_consistent():
                    self._restart_migration()
                self.fts_layout = "migrating"
            self.fts_enabled = True
        except sqlite3.OperationalError:
            self.fts_enabled = False
            self.fts_layout = ""

    @property
    def fts_search(self) -> bool:
        """Whether searches can use an FTS index right now."""
        return self.fts_enabled and (self.fts_layout == "external" or self._legacy_fts)

    def _run_ddl(self, statements: list[str]) -> None:
        """Python's sqlite3 runs DDL outside an implicit transaction (each
        statement commits on its own), so a multi-statement schema change needs
        an explicit one to be all-or-nothing."""
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in statements:
                self._conn.execute(statement)
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise

    def _clear_migration_state(self) -> None:
        self._conn.execute("DELETE FROM app_state WHERE name IN ('fts_migration_done', 'fts_migration_upper')")
        self._conn.commit()

    def _restart_migration(self) -> None:
        upper = int(self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM records").fetchone()[0])
        self._run_ddl([f"DROP TABLE IF EXISTS {_FTS_MIGRATION_TABLE}", _FTS_EXTERNAL_SQL.format(name=_FTS_MIGRATION_TABLE)])
        self._set_state("fts_migration_upper", str(upper))
        self._set_state("fts_migration_done", "0")
        self._conn.commit()

    def _migration_consistent(self) -> bool:
        """The half-built index must hold exactly the rows the migration put
        there: every record at or below `done`, and every record above
        `upper` (written by dual-write). An older version running in between
        (a downgrade) writes and prunes without updating it."""
        done, upper = self._fts_migration_bounds()
        docsize = f"{_FTS_MIGRATION_TABLE}_docsize"
        for where, args in (("id <= ?", (done,)), ("id > ?", (upper,))):
            records = self._conn.execute(f"SELECT COUNT(*) FROM records WHERE {where}", args).fetchone()[0]
            indexed = self._conn.execute(f"SELECT COUNT(*) FROM {docsize} WHERE {where}", args).fetchone()[0]
            if records != indexed:
                logger.warning(
                    "Full-text migration index does not match the records (%d vs %d rows); restarting the backfill",
                    indexed, records,
                )
                return False
        return True

    def _fts_migration_bounds(self) -> tuple[int, int]:
        """(done, upper): rows with done < id <= upper are not yet in the new
        index; rows above upper were written to both indexes on insert."""
        return int(self._get_state("fts_migration_done") or 0), int(self._get_state("fts_migration_upper") or 0)

    @_locked
    def migrate_fts_step(self, batch: int = FTS_MIGRATION_BATCH) -> bool:
        """Copy one batch of pre-existing rows into the external-content index,
        or swap it in once every row is indexed. Returns True when no migration
        is pending. Each step commits, so a restart resumes where it stopped."""
        if self.fts_layout != "migrating":
            return True
        done, upper = self._fts_migration_bounds()
        last = self._conn.execute(
            "SELECT MAX(id) FROM (SELECT id FROM records WHERE id > ? AND id <= ? ORDER BY id LIMIT ?)",
            (done, upper, batch),
        ).fetchone()[0]
        if last is not None:
            self._conn.execute(
                f"INSERT INTO {_FTS_MIGRATION_TABLE}(rowid, message, raw_line) "
                "SELECT id, message, raw_line FROM records WHERE id > ? AND id <= ?",
                (done, int(last)),
            )
            self._set_state("fts_migration_done", str(int(last)))
            self._conn.commit()
            return False
        # Every row is indexed: swap in one transaction, so a crash leaves
        # either the old layout (and the migration resumes) or the new one.
        statements = ["DROP TABLE records_fts"] if self._legacy_fts else []
        statements += [
            f"ALTER TABLE {_FTS_MIGRATION_TABLE} RENAME TO records_fts",
            "DELETE FROM app_state WHERE name IN ('fts_migration_done', 'fts_migration_upper')",
        ]
        self._run_ddl(statements)
        self.fts_layout = "external"
        self._legacy_fts = False
        logger.info("Full-text index migrated to external content; the legacy copy was dropped")
        self._release_free_pages()
        return True

    def _fts_index_row(self, cur: sqlite3.Cursor, record_id: int, message: str, raw_line: str) -> None:
        if self.fts_layout == "external" or self._legacy_fts:
            cur.execute("INSERT INTO records_fts(rowid, message, raw_line) VALUES (?, ?, ?)", (record_id, message, raw_line))
        if self.fts_layout == "migrating":
            _, upper = self._fts_migration_bounds()
            if record_id > upper:  # rows at or below upper are copied by migrate_fts_step
                cur.execute(
                    f"INSERT INTO {_FTS_MIGRATION_TABLE}(rowid, message, raw_line) VALUES (?, ?, ?)",
                    (record_id, message, raw_line),
                )

    def _fts_delete_ids(self, ids_json: str) -> None:
        """Remove index entries for records about to be deleted (ids as a
        JSON array). External-content deletes must quote the stored values
        (records are never updated in place, so they match what was indexed)
        and must only name indexed rows."""
        in_ids = "id IN (SELECT value FROM json_each(?))"
        if self.fts_layout == "external":
            self._conn.execute(
                "INSERT INTO records_fts(records_fts, rowid, message, raw_line) "
                f"SELECT 'delete', id, message, raw_line FROM records WHERE {in_ids}",
                (ids_json,),
            )
            return
        if self._legacy_fts:
            self._conn.execute("DELETE FROM records_fts WHERE rowid IN (SELECT value FROM json_each(?))", (ids_json,))
        if self.fts_layout == "migrating":
            done, upper = self._fts_migration_bounds()
            self._conn.execute(
                f"INSERT INTO {_FTS_MIGRATION_TABLE}({_FTS_MIGRATION_TABLE}, rowid, message, raw_line) "
                f"SELECT 'delete', id, message, raw_line FROM records WHERE {in_ids} AND (id <= ? OR id > ?)",
                (ids_json, done, upper),
            )

    def _release_free_pages(self) -> None:
        """Return free pages to the filesystem when the database was created
        with incremental auto-vacuum and enough of it is free to matter.
        Databases created before that setting reuse free pages instead; see
        `python -m webapp.api.dbtool compact`."""
        if int(self._conn.execute("PRAGMA auto_vacuum").fetchone()[0]) != 2:
            return
        free = int(self._conn.execute("PRAGMA freelist_count").fetchone()[0])
        total = int(self._conn.execute("PRAGMA page_count").fetchone()[0])
        if total and free * 10 >= total:  # at least 10% free
            # Each step of this pragma frees one page; fetchall() runs it to the end.
            self._conn.execute("PRAGMA incremental_vacuum").fetchall()
            self._conn.commit()

    def _set_state(self, name: str, value: str) -> None:
        self._conn.execute(
            """
            INSERT INTO app_state(name, value) VALUES (?, ?)
            ON CONFLICT(name) DO UPDATE SET value = excluded.value
            """,
            (name, value),
        )

    def _get_state(self, name: str) -> str | None:
        row = self._conn.execute("SELECT value FROM app_state WHERE name = ?", (name,)).fetchone()
        return str(row[0]) if row else None

    @_locked
    def get_prefix_cursor(self, prefix: str) -> str | None:
        row = self._conn.execute("SELECT last_key FROM prefix_state WHERE prefix = ?", (prefix,)).fetchone()
        return str(row[0]) if row else None

    @_locked
    def set_prefix_cursor(self, prefix: str, last_key: str) -> None:
        self._conn.execute(
            """
            INSERT INTO prefix_state(prefix, last_key, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(prefix) DO UPDATE SET last_key = excluded.last_key, updated_at = excluded.updated_at
            """,
            (prefix, last_key, _utc_now()),
        )
        # Commit now: an open write transaction would otherwise stay open across
        # the next S3 request and block the anomaly writer (separate connection).
        self._conn.commit()

    @_locked
    def object_seen(self, bucket: str, key: str, etag: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM ingested_objects WHERE bucket = ? AND key = ? AND etag = ?",
            (bucket, key, etag),
        ).fetchone()
        return row is not None

    @_locked
    def mark_object(self, bucket: str, key: str, etag: str, last_modified: str, status: str, record_count: int) -> None:
        self._conn.execute(
            """
            INSERT INTO ingested_objects(bucket, key, etag, last_modified, ingested_at, status, record_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bucket, key, etag) DO UPDATE SET
                last_modified = excluded.last_modified,
                ingested_at = excluded.ingested_at,
                status = excluded.status,
                record_count = excluded.record_count
            """,
            (bucket, key, etag, last_modified, _utc_now(), status, record_count),
        )
        self._conn.commit()

    @_locked
    def get_object_failure(self, bucket: str, key: str, etag: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM object_failures WHERE bucket = ? AND key = ? AND etag = ?", (bucket, key, etag)
        ).fetchone()
        return dict(row) if row else None

    @_locked
    def record_object_failure(
        self, bucket: str, key: str, etag: str, *, prefix: str, last_modified: str, error: str
    ) -> int:
        """Count a failed read of one object and schedule its next attempt.
        Returns the number of consecutive failures."""
        row = self._conn.execute(
            "SELECT attempts FROM object_failures WHERE bucket = ? AND key = ? AND etag = ?", (bucket, key, etag)
        ).fetchone()
        attempts = (int(row[0]) if row else 0) + 1
        delay = 0 if attempts == 1 else min(OBJECT_RETRY_BASE_SECS * 2 ** (attempts - 2), OBJECT_RETRY_MAX_SECS)
        self._conn.execute(
            """
            INSERT INTO object_failures(bucket, key, etag, prefix, last_modified, attempts, last_error,
                                        first_failed_at, next_attempt_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bucket, key, etag) DO UPDATE SET
                attempts = excluded.attempts,
                last_error = excluded.last_error,
                next_attempt_at = excluded.next_attempt_at
            """,
            (bucket, key, etag, prefix, last_modified, attempts, error[:500], utc_stamp(), utc_stamp(delay)),
        )
        self._conn.commit()
        return attempts

    @_locked
    def clear_object_failure(self, bucket: str, key: str, etag: str) -> None:
        self._conn.execute(
            "DELETE FROM object_failures WHERE bucket = ? AND key = ? AND etag = ?", (bucket, key, etag)
        )
        self._conn.commit()

    @_locked
    def due_object_failures(self, bucket: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM object_failures WHERE bucket = ? AND next_attempt_at <= ? "
            "ORDER BY next_attempt_at LIMIT ?",
            (bucket, utc_stamp(), limit),
        ).fetchall()
        return [dict(row) for row in rows]

    @_locked
    def object_failure_summary(self) -> dict[str, Any]:
        count = int(self._conn.execute("SELECT COUNT(*) FROM object_failures").fetchone()[0])
        latest = self._conn.execute(
            "SELECT key, attempts, last_error, next_attempt_at FROM object_failures "
            "ORDER BY first_failed_at DESC LIMIT 1"
        ).fetchone()
        # One row per configured prefix at most (severity buckets x scopes).
        by_prefix = self._conn.execute(
            "SELECT prefix, COUNT(*) AS count, MAX(attempts) AS max_attempts, MIN(next_attempt_at) AS next_attempt_at "
            "FROM object_failures GROUP BY prefix ORDER BY count DESC, prefix LIMIT ?",
            (_PREFIX_ERRORS_MAX,),
        ).fetchall()
        return {
            "failing_objects": count,
            "latest_failure": dict(latest) if latest else None,
            "failures_by_prefix": [dict(row) for row in by_prefix],
        }

    @_locked
    def insert_records(self, records: list[dict[str, Any]]) -> int:
        if not records:
            return 0
        cur = self._conn.cursor()
        inserted = 0
        for record in records:
            cur.execute(
                """
                INSERT OR IGNORE INTO records(
                    timestamp, severity_bucket, scope, namespace, pod, container,
                    message, raw_line, source_key, source_etag, line_number, is_falco, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["timestamp"],
                    record["severity_bucket"],
                    record["scope"],
                    record["namespace"],
                    record["pod"],
                    record["container"],
                    record["message"],
                    record["raw_line"],
                    record["source_key"],
                    record["source_etag"],
                    int(record["line_number"]),
                    int(record["is_falco"]),
                    _utc_now(),
                ),
            )
            if cur.rowcount:
                inserted += 1
                if self.fts_enabled:
                    self._fts_index_row(cur, int(cur.lastrowid), record["message"], record["raw_line"])
        self._conn.commit()
        return inserted

    @_locked
    def ingest_state(
        self,
        *,
        last_poll_at: str,
        last_successful_ingest_at: str | None,
        last_object_last_modified: str | None,
        last_error: str | None = None,
        prefix_errors: dict[str, str] | None = None,
    ) -> None:
        self._set_state("last_polled_at", last_poll_at)
        if prefix_errors is not None:
            # Listing failures of the last poll, per prefix ({} clears them).
            # Error texts come from S3/botocore and SQLite, never log content.
            kept = [
                {"prefix": prefix[:500], "error": str(error)[:_PREFIX_ERROR_CHARS]}
                for prefix, error in sorted(prefix_errors.items())[:_PREFIX_ERRORS_MAX]
            ]
            self._set_state("last_prefix_errors", json.dumps(kept, separators=(",", ":")))
        if last_successful_ingest_at is not None:
            self._set_state("last_successful_ingest_at", last_successful_ingest_at)
        if last_object_last_modified is not None:
            self._set_state("last_object_last_modified", last_object_last_modified)
        if last_error is not None:
            self._set_state("last_error", last_error)
        else:
            # A successful poll clears the previous failure.
            self._conn.execute("DELETE FROM app_state WHERE name = 'last_error'")
        self._conn.commit()

    def _check_fts_query(self, q: str) -> None:
        """Reject malformed FTS5 query syntax as a client error, so real
        database failures are not mistaken for bad input."""
        try:
            self._conn.execute("SELECT 1 FROM records_fts WHERE records_fts MATCH ? LIMIT 1", (q,)).fetchall()
        except sqlite3.OperationalError as exc:
            raise ValueError(f"Invalid search query: {exc}") from None

    def _build_filters(self, params: dict[str, Any]) -> tuple[str, list[Any]]:
        clauses = ["1 = 1"]
        args: list[Any] = []
        for field in ("scope", "namespace", "pod", "container", "severity_bucket"):
            value = params.get(field)
            if value:
                clauses.append(f"{field} = ?")
                args.append(value)
        start = params.get("start")
        end = params.get("end")
        before = params.get("before")
        if start:
            clauses.append("timestamp >= ?")
            args.append(start)
        if end:  # inclusive end (API compatibility)
            clauses.append("timestamp <= ?")
            args.append(end)
        if before:  # exclusive end: the UI's [start, before) convention
            clauses.append("timestamp < ?")
            args.append(before)
        q = params.get("q")
        if q:
            if self.fts_search:
                self._check_fts_query(q)
                clauses.append("id IN (SELECT rowid FROM records_fts WHERE records_fts MATCH ?)")
                args.append(q)
            else:
                clauses.append("(LOWER(message) LIKE ? OR LOWER(raw_line) LIKE ?)")
                needle = f"%{str(q).lower()}%"
                args.extend([needle, needle])
        return " AND ".join(clauses), args

    @_locked
    def query_logs(self, params: dict[str, Any], *, limit: int, cursor: tuple[str, int] | None = None, direction: str = "desc") -> dict[str, Any]:
        where_sql, args = self._build_filters(params)
        if cursor:
            ts, record_id = cursor
            if direction == "desc":
                where_sql += " AND (timestamp < ? OR (timestamp = ? AND id < ?))"
            else:
                where_sql += " AND (timestamp > ? OR (timestamp = ? AND id > ?))"
            args.extend([ts, ts, record_id])
        order = "DESC" if direction == "desc" else "ASC"
        rows = self._conn.execute(
            f"""
            SELECT id, timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,
                   source_key, source_etag, line_number, is_falco
            FROM records
            WHERE {where_sql}
            ORDER BY timestamp {order}, id {order}
            LIMIT ?
            """,
            (*args, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [dict(row) for row in rows]
        next_cursor = _encode_cursor(items[-1]["timestamp"], int(items[-1]["id"])) if items else None
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more, "max_id": self._max_id()}

    def _max_id(self) -> int:
        return int(self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM records").fetchone()[0])

    @_locked
    def query_tail(self, params: dict[str, Any], *, after_id: int | None, limit: int) -> dict[str, Any]:
        """Records ingested after `after_id` (row ids grow in ingest order), so
        objects that land late with older event timestamps still reach a live
        view. Returns the newest `limit` matches, newest first, and `last_id`
        to pass as the next `after_id`. Without `after_id` it only returns the
        current position, so a client can start tailing from "now"."""
        upper = self._max_id()
        if after_id is None:
            return {"items": [], "last_id": upper, "truncated": False}
        if after_id > upper:
            # Ids never go backwards in one database, so the database was
            # restored or replaced: restart the client from the current end
            # instead of waiting for ids to catch up with its old position.
            return {"items": [], "last_id": upper, "truncated": False, "reset": True}
        where_sql, args = self._build_filters(params)
        rows = self._conn.execute(
            f"""
            SELECT id, timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,
                   source_key, source_etag, line_number, is_falco
            FROM records
            WHERE {where_sql} AND id > ? AND id <= ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (*args, after_id, upper, limit + 1),
        ).fetchall()
        truncated = len(rows) > limit
        return {
            "items": [dict(row) for row in rows[:limit]],
            "last_id": upper,
            "truncated": truncated,
        }

    @_locked
    def query_facets(self, params: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        where_sql, args = self._build_filters(params)
        fields = ["scope", "namespace", "pod", "container", "severity_bucket"]
        out: dict[str, list[dict[str, Any]]] = {}
        for field in fields:
            rows = self._conn.execute(
                f"""
                SELECT {field} AS value, COUNT(*) AS count
                FROM records
                WHERE {where_sql}
                GROUP BY {field}
                ORDER BY count DESC, value ASC
                LIMIT ?
                """,
                (*args, FACET_VALUES_MAX),
            ).fetchall()
            out[field] = [{"value": row[0], "count": int(row[1])} for row in rows]
        return out

    @_locked
    def query_dashboard(self, params: dict[str, Any]) -> dict[str, Any]:
        where_sql, args = self._build_filters(params)
        error_where_sql, error_args = self._build_filters({**params, "severity_bucket": "error"})

        summary_row = self._conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_logs,
                SUM(CASE WHEN severity_bucket = 'error' THEN 1 ELSE 0 END) AS error_count,
                SUM(CASE WHEN severity_bucket = 'warning' THEN 1 ELSE 0 END) AS warning_count,
                SUM(CASE WHEN severity_bucket = 'info' THEN 1 ELSE 0 END) AS info_count,
                SUM(CASE WHEN severity_bucket = 'debug' THEN 1 ELSE 0 END) AS debug_count,
                SUM(CASE WHEN severity_bucket = 'metrics' THEN 1 ELSE 0 END) AS metrics_count,
                SUM(CASE WHEN scope = 'security' THEN 1 ELSE 0 END) AS security_count,
                COUNT(DISTINCT namespace) AS unique_namespaces,
                COUNT(DISTINCT pod) AS unique_pods
            FROM records
            WHERE {where_sql}
            """,
            args,
        ).fetchone()

        severity_rows = self._conn.execute(
            f"""
            SELECT severity_bucket AS value, COUNT(*) AS count
            FROM records
            WHERE {where_sql}
            GROUP BY severity_bucket
            ORDER BY count DESC, value ASC
            """,
            args,
        ).fetchall()

        namespace_rows = self._conn.execute(
            f"""
            SELECT namespace AS value, COUNT(*) AS count
            FROM records
            WHERE {where_sql}
            GROUP BY namespace
            ORDER BY count DESC, value ASC
            LIMIT ?
            """,
            (*args, DASHBOARD_LIST_MAX),
        ).fetchall()

        error_namespace_rows = self._conn.execute(
            f"""
            SELECT namespace AS value, COUNT(*) AS count
            FROM records
            WHERE {error_where_sql}
            GROUP BY namespace
            ORDER BY count DESC, value ASC
            LIMIT ?
            """,
            (*error_args, DASHBOARD_LIST_MAX),
        ).fetchall()

        error_pod_rows = self._conn.execute(
            f"""
            SELECT pod AS value, COUNT(*) AS count
            FROM records
            WHERE {error_where_sql}
            GROUP BY pod
            ORDER BY count DESC, value ASC
            LIMIT ?
            """,
            (*error_args, DASHBOARD_LIST_MAX),
        ).fetchall()

        top_error_rows = self._conn.execute(
            f"""
            SELECT message AS value, COUNT(*) AS count
            FROM records
            WHERE {error_where_sql}
            GROUP BY message
            ORDER BY count DESC, value ASC
            LIMIT 10
            """,
            error_args,
        ).fetchall()

        timeline_total_rows = self._conn.execute(
            f"""
            SELECT substr(timestamp, 1, 13) || ':00:00Z' AS bucket,
                   COUNT(*) AS total_count
            FROM records
            WHERE {where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            args,
        ).fetchall()

        timeline_error_rows = self._conn.execute(
            f"""
            SELECT substr(timestamp, 1, 13) || ':00:00Z' AS bucket,
                   COUNT(*) AS error_count
            FROM records
            WHERE {error_where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            error_args,
        ).fetchall()

        timeline_map: dict[str, dict[str, Any]] = {}
        for row in timeline_total_rows:
            bucket = str(row[0])
            timeline_map[bucket] = {"timestamp": bucket, "total_logs": int(row[1] or 0), "error_logs": 0}
        for row in timeline_error_rows:
            bucket = str(row[0])
            entry = timeline_map.setdefault(bucket, {"timestamp": bucket, "total_logs": 0, "error_logs": 0})
            entry["error_logs"] = int(row[1] or 0)

        return {
            "summary": {
                "total_logs": int(summary_row[0] or 0),
                "error_count": int(summary_row[1] or 0),
                "warning_count": int(summary_row[2] or 0),
                "info_count": int(summary_row[3] or 0),
                "debug_count": int(summary_row[4] or 0),
                "metrics_count": int(summary_row[5] or 0),
                "security_count": int(summary_row[6] or 0),
                "unique_namespaces": int(summary_row[7] or 0),
                "unique_pods": int(summary_row[8] or 0),
            },
            "severity": [{"value": row[0], "count": int(row[1] or 0)} for row in severity_rows],
            "namespaces": [{"value": row[0], "count": int(row[1] or 0)} for row in namespace_rows],
            "error_namespaces": [{"value": row[0], "count": int(row[1] or 0)} for row in error_namespace_rows],
            "error_pods": [{"value": row[0], "count": int(row[1] or 0)} for row in error_pod_rows],
            "top_errors": [{"value": row[0], "count": int(row[1] or 0)} for row in top_error_rows],
            "timeline": [timeline_map[key] for key in sorted(timeline_map)],
        }

    def prune_records_before(self, cutoff: str, *, batch: int = PRUNE_BATCH) -> int:
        """Delete cached records (and their FTS rows) older than cutoff, in
        batches that each commit and release the lock. The S3 source objects
        past retention are expired by the bucket lifecycle rule, so their
        ingest bookkeeping is dropped too. Returns records removed."""
        removed = 0
        while True:
            count = self._prune_batch(cutoff, batch)
            removed += count
            if count < batch:
                break
        self._prune_bookkeeping(cutoff, release=bool(removed))
        return removed

    @_locked
    def _prune_batch(self, cutoff: str, batch: int) -> int:
        ids = [int(row[0]) for row in self._conn.execute(
            "SELECT id FROM records WHERE timestamp < ? LIMIT ?", (cutoff, batch)
        )]
        if not ids:
            return 0
        ids_json = json.dumps(ids)
        if self.fts_enabled:
            self._fts_delete_ids(ids_json)
        self._conn.execute("DELETE FROM records WHERE id IN (SELECT value FROM json_each(?))", (ids_json,))
        self._conn.commit()
        return len(ids)

    @_locked
    def _prune_bookkeeping(self, cutoff: str, *, release: bool) -> None:
        self._conn.execute("DELETE FROM ingested_objects WHERE last_modified < ?", (cutoff,))
        # Objects past retention are expired from the bucket; stop retrying them.
        self._conn.execute("DELETE FROM object_failures WHERE last_modified < ?", (cutoff,))
        self._conn.commit()
        if release:
            self._release_free_pages()

    @_locked
    def query_context(
        self,
        record_id: int,
        *,
        lines_before: int = 10,
        lines_after: int = 10,
        start: str | None = None,
        before: str | None = None,
        window_secs: int = CONTEXT_WINDOW_SECS,
    ) -> dict[str, Any] | None:
        """Entries just before and after one record from the same namespace,
        pod and container, in event-time order (ties broken by row id, i.e.
        ingest order, so the order is deterministic). Each side is limited to
        `lines_*` rows (at most CONTEXT_LINES_MAX), to `window_secs` around
        the record's time, and to the optional [start, before) range.
        Severity and search filters are deliberately not applied: context
        shows what the workload logged around the selected entry.
        Returns None when the record does not exist."""
        anchor_row = self._conn.execute(
            f"SELECT {_RECORD_COLUMNS} FROM records WHERE id = ?", (record_id,)
        ).fetchone()
        if anchor_row is None:
            return None
        anchor = dict(anchor_row)
        lines_before = max(0, min(int(lines_before), CONTEXT_LINES_MAX))
        lines_after = max(0, min(int(lines_after), CONTEXT_LINES_MAX))
        ts = str(anchor["timestamp"])
        group = (anchor["namespace"], anchor["pod"], anchor["container"])

        # Lower / upper time bounds: the search window around the record,
        # narrowed by the caller's range. Bounds are ISO strings compared the
        # same way as every other timestamp filter.
        lower: str | None = None
        upper: str | None = None
        limited_by_window = False
        try:
            moment = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            lower = _iso_ms(moment - timedelta(seconds=window_secs))
            upper = _iso_ms(moment + timedelta(seconds=window_secs))
            limited_by_window = True
        except ValueError:
            pass  # unparseable timestamp: only the row limits apply
        lower_from_range = bool(start and (lower is None or start > lower))
        upper_from_range = bool(before and (upper is None or before < upper))
        if lower_from_range:
            lower = start
        if upper_from_range:
            upper = before

        group_sql = "namespace = ? AND pod = ? AND container = ?"
        earlier_sql = f"SELECT {_RECORD_COLUMNS} FROM records WHERE {group_sql} " \
            "AND (timestamp < ? OR (timestamp = ? AND id < ?))"
        earlier_args: list[Any] = [*group, ts, ts, record_id]
        if lower is not None:
            earlier_sql += " AND timestamp >= ?"
            earlier_args.append(lower)
        earlier = self._conn.execute(
            earlier_sql + " ORDER BY timestamp DESC, id DESC LIMIT ?", (*earlier_args, lines_before + 1)
        ).fetchall() if lines_before else []

        later_sql = f"SELECT {_RECORD_COLUMNS} FROM records WHERE {group_sql} " \
            "AND (timestamp > ? OR (timestamp = ? AND id > ?))"
        later_args: list[Any] = [*group, ts, ts, record_id]
        if upper is not None:
            later_sql += " AND timestamp < ?"
            later_args.append(upper)
        later = self._conn.execute(
            later_sql + " ORDER BY timestamp ASC, id ASC LIMIT ?", (*later_args, lines_after + 1)
        ).fetchall() if lines_after else []

        return {
            "anchor": anchor,
            "group": {"namespace": group[0], "pod": group[1], "container": group[2]},
            # Chronological order on both sides.
            "before": [dict(row) for row in reversed(earlier[:lines_before])],
            "after": [dict(row) for row in later[:lines_after]],
            # True when more entries exist within the bounds than were returned.
            "more_before": len(earlier) > lines_before,
            "more_after": len(later) > lines_after,
            # Where the search stopped when a side came back short: entries
            # beyond these bounds were not searched.
            "bounds": {
                "from": lower,
                "to": upper,
                "from_is_range": lower_from_range,
                "to_is_range": upper_from_range,
                "window_secs": window_secs if limited_by_window else None,
            },
            "lines_before": lines_before,
            "lines_after": lines_after,
        }

    @_locked
    def get_record_by_id(self, record_id: int) -> dict[str, Any] | None:
        """Fetch a single record by its row id, for per-line explain.
        Re-derives from storage rather than trusting client-supplied text."""
        row = self._conn.execute(
            """
            SELECT id, timestamp, severity_bucket, scope, namespace, pod, container,
                   message, raw_line, source_key, source_etag, line_number, is_falco
            FROM records
            WHERE id = ?
            """,
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    @property
    def conn(self) -> sqlite3.Connection:
        """Read access to the shared records connection (used by InsightsJob).
        Hold `lock` while using it from another thread."""
        return self._conn

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def ping(self, timeout: float = 2.0) -> bool:
        """True when the connection answers. False when another thread holds
        it for longer than `timeout` (busy, not necessarily broken); the
        caller decides how long busy is acceptable. Errors propagate."""
        if not self._lock.acquire(timeout=timeout):
            return False
        try:
            self._conn.execute("SELECT 1").fetchone()
            return True
        finally:
            self._lock.release()

    @_locked
    def get_state(self, name: str) -> str | None:
        """One app_state value without get_status()'s full-table counts."""
        return self._get_state(name)

    @_locked
    def get_status(self) -> dict[str, Any]:
        last_polled_at = self._get_state("last_polled_at")
        last_successful_ingest_at = self._get_state("last_successful_ingest_at")
        last_object_last_modified = self._get_state("last_object_last_modified")
        last_error = self._get_state("last_error")
        total_records = int(self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        total_objects = int(self._conn.execute("SELECT COUNT(*) FROM ingested_objects").fetchone()[0])
        latest_record_timestamp = self._conn.execute("SELECT MAX(timestamp) FROM records").fetchone()[0]
        return {
            "last_polled_at": last_polled_at,
            "last_successful_ingest_at": last_successful_ingest_at,
            "last_object_last_modified": last_object_last_modified,
            "last_error": last_error,
            "total_records": total_records,
            "total_objects": total_objects,
            "latest_record_timestamp": latest_record_timestamp,
            "prefix_errors": self._prefix_errors(),
            "storage": self._storage_status(),
        }

    def _prefix_errors(self) -> list[dict[str, str]]:
        raw = self._get_state("last_prefix_errors")
        if not raw:
            return []
        try:
            value = json.loads(raw)
        except ValueError:
            return []
        return value if isinstance(value, list) else []

    def _storage_status(self) -> dict[str, Any]:
        """Database size, free disk space and index-migration progress. Paths
        and sizes only; never row contents."""
        page_size = int(self._conn.execute("PRAGMA page_size").fetchone()[0])
        pages = int(self._conn.execute("PRAGMA page_count").fetchone()[0])
        free_pages = int(self._conn.execute("PRAGMA freelist_count").fetchone()[0])
        try:
            wal_bytes = os.path.getsize(f"{self.db_path}-wal")
        except OSError:
            wal_bytes = 0
        out: dict[str, Any] = {
            "journal_mode": self.journal_mode,
            "fts_layout": self.fts_layout,
            "db_bytes": pages * page_size,
            "free_page_bytes": free_pages * page_size,
            "wal_bytes": wal_bytes,
        }
        try:
            usage = shutil.disk_usage(self.db_path.parent)
        except OSError:
            usage = None
        if usage is not None:
            out["disk_free_bytes"] = usage.free
            out["disk_total_bytes"] = usage.total
            out["disk_low"] = usage.free < min(DISK_LOW_FREE_BYTES, usage.total * 0.5) or (
                usage.free < usage.total * DISK_LOW_FREE_FRACTION
            )
        if self.fts_layout == "migrating":
            done, upper = self._fts_migration_bounds()
            remaining = int(self._conn.execute(
                "SELECT COUNT(*) FROM records WHERE id > ? AND id <= ?", (done, upper)
            ).fetchone()[0])
            out["fts_migration"] = {"rows_remaining": remaining, "last_error": self.fts_migration_error}
        return out