from __future__ import annotations

import base64
import binascii
import functools
import json
import logging
import math
import os
import queue
import re
import shutil
import sqlite3
import threading
import time
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

# Secondary indexes on records for filtered queries (field filter + time
# range or time ordering). The UNIQUE key only serves ingest dedupe. Every
# time filter and ordering uses ts_epoch (UTC seconds), never the text.
_RECORD_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_records_epoch ON records(ts_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_records_ns_epoch ON records(namespace, ts_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_records_sev_epoch ON records(severity_bucket, ts_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_records_scope_epoch ON records(scope, ts_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_records_pod_epoch ON records(pod, ts_epoch)",
)
# Text-timestamp indexes of older versions; dropped at start.
_LEGACY_RECORD_INDEXES = (
    "idx_records_ts_ns", "idx_records_ns_ts", "idx_records_sev_ts", "idx_records_scope_ts", "idx_records_pod_ts",
)
# Rows given a ts_epoch per locked step when backfilling a database written
# by an older version (see backfill_ts_step).
TS_BACKFILL_BATCH = 5000

# Hourly rollup: entries per (UTC hour, scope, namespace, pod, container,
# severity), kept in the same transaction as every insert, prune and ts_epoch
# backfill. Count-only queries without a text search read whole hours from it
# and only the partial hours at a range's edges from records.
ROLLUP_SECS = 3600
_ROLLUP_SQL = (
    "CREATE TABLE IF NOT EXISTS counts_hourly ("
    "hour_epoch INTEGER NOT NULL, scope TEXT NOT NULL, namespace TEXT NOT NULL, pod TEXT NOT NULL, "
    "container TEXT NOT NULL, severity TEXT NOT NULL, n INTEGER NOT NULL, "
    "PRIMARY KEY (hour_epoch, scope, namespace, pod, container, severity)) WITHOUT ROWID"
)
# Planner statistics: a full ANALYZE (about 0.7 s per million rows, writer
# lock only; the read pool keeps serving), rerun after this many new rows.
# Sampled statistics (analysis_limit) were measured to mislead the planner
# into skip-scans over the pod index that are several times slower.
ANALYZE_AFTER_ROWS = 500_000
# FTS5 automerge level (default 4): merge segments sooner, so the index
# stays near-optimized without a full 'optimize' pass.
FTS_AUTOMERGE = 8
# Pages merged per locked step of the off-peak FTS merge (see fts_merge_step).
FTS_MERGE_PAGES = 500
# Record ids aggregated per locked step of the one-time rebuild of a
# database written before the rollup existed (see rebuild_rollup_step).
ROLLUP_REBUILD_BATCH = 50_000
# records columns -> counts_hourly columns, for the filter fields.
_ROLLUP_COLUMN = {"scope": "scope", "namespace": "namespace", "pod": "pod", "container": "container",
                  "severity_bucket": "severity"}
_HOUR_SQL = f"CAST(ts_epoch / {ROLLUP_SECS} AS INTEGER) * {ROLLUP_SECS}"
_UPSERT_ROLLUP = (
    "INSERT INTO counts_hourly (hour_epoch, scope, namespace, pod, container, severity, n) "
    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (hour_epoch, scope, namespace, pod, container, severity) "
    "DO UPDATE SET n = n + excluded.n"
)


def hour_of(epoch: float) -> int:
    """The UTC hour an event time falls in (as epoch seconds); the same
    value _HOUR_SQL computes in SQL."""
    return int(epoch / ROLLUP_SECS) * ROLLUP_SECS

# Filter fields: (record column, exclusion parameter). An exclusion parameter
# holds values to leave out, e.g. xns=kube-system.
FILTER_FIELDS = (
    ("scope", "xscope"),
    ("namespace", "xns"),
    ("pod", "xpod"),
    ("container", "xctr"),
    ("severity_bucket", "xsev"),
)

# /api/fields: values returned per field, and the time budget of each
# field's query (checked every _PROGRESS_OPS SQLite VM instructions).
FIELD_TOP_VALUES = 10
FIELD_QUERY_TIMEOUT_SECS = 2.0
_PROGRESS_OPS = 1000

# /api/histogram: bucket sizes (seconds) to choose from, the bucket count
# aimed for, and the most buckets returned (older ones are dropped).
HISTOGRAM_BUCKET_SECS = (60, 300, 900, 3600, 21600)
HISTOGRAM_TARGET_BUCKETS = 60
HISTOGRAM_MAX_BUCKETS = 1000
_HISTOGRAM_SEVERITIES = ("error", "warning", "info", "debug")

_RECORD_COLUMNS = (
    "id, timestamp, ts_epoch, severity_bucket, scope, namespace, pod, container, message, raw_line, "
    "source_key, source_etag, line_number, is_falco"
)

# Below this much free space on the database volume, /api/status reports
# the disk as low (SQLite needs room for its WAL, temp files and growth).
DISK_LOW_FREE_BYTES = 256 * 1024 * 1024
DISK_LOW_FREE_FRACTION = 0.05


CACHE_DB_ENV = "LOGSCOPE_WEBAPP_DB_PATH"


def default_cache_db_path() -> Path:
    """$XDG_CACHE_HOME/logscope/cache.sqlite, else ~/.cache/logscope/. A
    relative XDG_CACHE_HOME is ignored, as the XDG spec requires. Never /tmp:
    the cache survives reboots (and is not world-readable). Overridden by
    webapp.backend.db_path and $LOGSCOPE_WEBAPP_DB_PATH."""
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".cache"
    return base / "logscope" / "cache.sqlite"


def count_objects_under(conn: sqlite3.Connection, prefix: str) -> tuple[int, int]:
    """(ingested objects whose key starts with prefix, all other objects); a
    key range, so the primary key index is used."""
    total = int(conn.execute("SELECT COUNT(*) FROM ingested_objects").fetchone()[0])
    under = int(conn.execute(
        "SELECT COUNT(*) FROM ingested_objects WHERE key >= ? AND key < ?", (prefix, prefix + "\uffff")
    ).fetchone()[0])
    return under, total - under


# Per-connection tuning, applied to every connection: page cache (KiB when
# negative), memory-mapped reads (2 GiB, about SQLite's usual build limit),
# and temp tables (sorts, GROUP BY) in temp files, i.e. the OS page cache.
# temp_store = MEMORY was measured to stop concurrent readers from scaling
# (4 threads: 33 vs 117 queries/s, most CPU in the kernel), so it is FILE.
SQLITE_CACHE_KIB = 65536
SQLITE_MMAP_BYTES = 2_147_418_112
SQLITE_TEMP_STORE = "FILE"
# Read-only connections serving GET requests (LOGSCOPE_SQLITE_READERS; 0 =
# every query on the one shared connection, under its lock).
READERS_ENV = "LOGSCOPE_SQLITE_READERS"
DEFAULT_READERS = 4


def tune_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.execute(f"PRAGMA cache_size = -{SQLITE_CACHE_KIB}")
    conn.execute(f"PRAGMA mmap_size = {SQLITE_MMAP_BYTES}")
    conn.execute(f"PRAGMA temp_store = {SQLITE_TEMP_STORE}")
    return conn


def open_connection(db_path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    """A connection to the app database with the shared busy timeout and
    tuning. Used for connections owned by a single thread (e.g. the insights
    detector) and for the read pool (read_only: the file opened mode=ro)."""
    target, uri = (f"file:{Path(db_path).resolve()}?mode=ro", True) if read_only else (db_path, False)
    conn = sqlite3.connect(target, uri=uri, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
    conn.row_factory = sqlite3.Row
    return tune_connection(conn)


def _reader_count() -> int:
    raw = os.environ.get(READERS_ENV, "").strip()
    try:
        return max(0, int(raw)) if raw else DEFAULT_READERS
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r; using %d", READERS_ENV, raw, DEFAULT_READERS)
        return DEFAULT_READERS


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


def _reading(method):
    """Run a read-only method on a pooled read connection, inside one read
    transaction (a single snapshot for all its statements), without the
    writer's lock: with WAL, reads neither wait for nor block ingest. Without
    a pool (LOGSCOPE_SQLITE_READERS=0 or a non-WAL journal) it runs on the
    shared connection under the lock, as before. Nested calls reuse the
    caller's connection."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if getattr(self._local, "conn", None) is not None:
            return method(self, *args, **kwargs)
        if self._pool is None:
            with self._lock:
                return method(self, *args, **kwargs)
        generation, conn = self._pool.get()
        self._local.conn = conn
        try:
            conn.execute("BEGIN")
            return method(self, *args, **kwargs)
        finally:
            self._local.conn = None
            try:
                conn.rollback()  # read-only: ends the snapshot
            except sqlite3.Error:
                logger.exception("Ending a read transaction failed")
            if generation != self._pool_generation:  # opened before new planner statistics
                conn.close()
                generation, conn = self._pool_generation, open_connection(self.db_path, read_only=True)
            self._pool.put((generation, conn))

    return wrapper


def _iso_ms(value: datetime) -> str:
    """UTC ISO-8601 with milliseconds, the format browsers send."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _fts_phrase(token: str) -> str:
    return '"' + token.replace('"', '""') + '"'


def _like_pattern(text: str) -> str:
    """A LIKE substring pattern (ESCAPE '\\') matching text literally."""
    escaped = text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def split_search_terms(q: str) -> tuple[list[str], list[str]]:
    """Whitespace-separated search words as (wanted, excluded); a leading '-'
    excludes a word. FTS operators (AND, OR, NOT, NEAR, *, :) typed by the
    user are plain words here."""
    wanted: list[str] = []
    excluded: list[str] = []
    for token in q.split():
        if len(token) > 1 and token.startswith("-"):
            excluded.append(token[1:])
        else:
            wanted.append(token)
    return wanted, excluded


def _has_word_chars(token: str) -> bool:
    # The FTS tokenizer drops punctuation; a phrase of punctuation only is
    # empty and matches nothing, so such words are matched as substrings.
    return any(ch.isalnum() for ch in token)


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
# ISO-8601 / RFC 3339 event times as log pipelines write them: "T" or a space
# between date and time, optional seconds, any number of fraction digits
# (Vector writes nanoseconds), and Z, UTC, +HH:MM, +HHMM, +HH or no zone.
_EVENT_TIME_RE = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})"
    r"(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?"
    r"\s*(Z|z|UTC|[+-]\d{2}(?::?\d{2})?)?\s*$"
)


def to_epoch(value: Any) -> float | None:
    """UTC epoch seconds of an event time, or None when it does not parse.
    A time without a zone is UTC. Fractions beyond microseconds are dropped.
    One conversion path for record times and request bounds, so the same
    instant always yields the same float."""
    match = _EVENT_TIME_RE.match(str(value or ""))
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    try:
        moment = datetime(int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0),
                          int((fraction or "0")[:6].ljust(6, "0")), tzinfo=timezone.utc)
    except ValueError:  # e.g. month 13 or a leap second
        return None
    if zone and zone not in ("Z", "z", "UTC"):
        digits = zone[1:].replace(":", "")
        hours, minutes = int(digits[:2]), int(digits[2:4] or 0)
        if hours > 14 or minutes > 59:
            return None
        offset = timedelta(hours=hours, minutes=minutes)
        moment = moment - offset if zone[0] == "+" else moment + offset
    return (moment - _EPOCH).total_seconds()


def iso_from_epoch(epoch: float) -> str:
    return _iso_ms(datetime.fromtimestamp(epoch, timezone.utc))


def _param_epoch(value: Any) -> float | None:
    """A time bound from a request as epoch seconds; ValueError (a 400) when
    it is not a time."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    epoch = to_epoch(value)
    if epoch is None:
        raise ValueError(f"Invalid time {str(value)[:40]!r}")
    return epoch


def _encode_cursor(epoch: float, record_id: int) -> str:
    payload = json.dumps({"e": epoch, "id": record_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[float, int] | None:
    """Decode a paging cursor into (ts_epoch, id). A cursor from an older
    version carries the text timestamp ("ts"), which is converted. Anything
    that is not a cursor this server issued raises ValueError, which the HTTP
    layer reports as a 400."""
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
    record_id = data.get("id")
    if isinstance(record_id, bool) or not isinstance(record_id, int) or not 0 <= record_id <= MAX_SQLITE_INT:
        raise ValueError("Invalid cursor")
    epoch = data.get("e")
    if "e" not in data:
        ts = data.get("ts")
        epoch = to_epoch(ts) if isinstance(ts, str) and len(ts) <= 64 else None
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)) or not math.isfinite(epoch):
        raise ValueError("Invalid cursor")
    return float(epoch), record_id


class LogStorage:
    def __init__(self, db_path: Path, *, journal_mode: str = "wal"):
        if not db_path.parent.exists():
            os.makedirs(db_path.parent, mode=0o700, exist_ok=True)  # cached log lines: owner only
        self.db_path = db_path
        self._conn = open_connection(db_path)
        self._lock = threading.RLock()
        self._local = threading.local()  # the read connection a _reading call runs on
        self._pool: queue.LifoQueue | None = None
        self.fts_enabled = False
        # "external" | "migrating" (a legacy index from an older version still
        # serves search while the external one is backfilled) | "" when FTS5
        # is unavailable.
        self.fts_layout = ""
        self._legacy_fts = False  # a standalone index from an older version still exists
        self.fts_migration_error: str | None = None  # set by the server's migration loop
        # Rows from an older version still without ts_epoch (see backfill_ts_step).
        self.ts_backfill_pending = False
        self.ts_backfill_error: str | None = None  # set by the server's backfill loop
        # counts_hourly is complete (no rebuild pending); see rebuild_rollup_step.
        self.rollup_ready = False
        self.rollup_error: str | None = None  # set by the server's rebuild loop
        self.use_rollup = True  # False forces the raw-row path (tests compare both)
        self._rows_since_analyze = 0
        self._has_stats = False
        self.journal_mode = ""
        with self._lock:
            self._configure(journal_mode)
            self._init_schema()
        readers = _reader_count()
        self._pool_generation = 0
        if readers and self.journal_mode == "wal":
            self._pool = queue.LifoQueue()
            for _ in range(readers):
                self._pool.put((0, open_connection(db_path, read_only=True)))

    def _c(self) -> sqlite3.Connection:
        """The connection for the running method: its pooled read connection
        inside a _reading call, else the shared (writer) connection."""
        return getattr(self._local, "conn", None) or self._conn

    def close(self) -> None:
        """Close the read pool and the shared connection."""
        while self._pool is not None and not self._pool.empty():
            self._pool.get_nowait()[1].close()
        self._conn.close()

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
        if actual == "wal":
            # No fsync per commit (WAL stays consistent; a power loss can only
            # drop the last commits). Objects are marked ingested after their
            # rows commit, so anything lost is read from S3 again. Measured
            # +25-30% ingest throughput.
            self._conn.execute("PRAGMA synchronous = NORMAL")

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ts_epoch REAL,
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
                http_meta TEXT,
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
        columns = {str(row[1]) for row in cur.execute("PRAGMA table_info(records)")}
        if "ts_epoch" not in columns:
            # Older database: existing rows are filled in by backfill_ts_step.
            cur.execute("ALTER TABLE records ADD COLUMN ts_epoch REAL")
        if "http_meta" not in columns:
            # Access-log fields (method/path/status/client_ip/...) for rows that
            # are HTTP access logs; NULL otherwise. Older rows stay NULL.
            cur.execute("ALTER TABLE records ADD COLUMN http_meta TEXT")
        for name in _LEGACY_RECORD_INDEXES:
            cur.execute(f"DROP INDEX IF EXISTS {name}")
        for statement in _RECORD_INDEXES:
            cur.execute(statement)
        self.ts_backfill_pending = cur.execute(
            "SELECT 1 FROM records WHERE ts_epoch IS NULL LIMIT 1").fetchone() is not None
        if self._table_sql("counts_hourly") is None:
            cur.execute(_ROLLUP_SQL)
            self._restart_rollup()
        else:
            self.rollup_ready = self._get_state("rollup_upper") is None
            if not self._rollup_consistent():
                self._restart_rollup()
        self.rollup_ready = self._get_state("rollup_upper") is None
        self._init_fts(cur)
        if self.fts_layout == "external":
            cur.execute("INSERT INTO records_fts(records_fts, rank) VALUES ('automerge', ?)", (FTS_AUTOMERGE,))
        self._has_stats = self._table_sql("sqlite_stat1") is not None
        self._conn.commit()

    # -- hourly rollup ------------------------------------------------------------

    def _rollup_bounds(self) -> tuple[int, int]:
        """(done, upper) of a pending rebuild: rows with done < id <= upper are
        not in the rollup yet. Rows above upper were added at insert."""
        return int(self._get_state("rollup_done") or 0), int(self._get_state("rollup_upper") or 0)

    def _restart_rollup(self) -> None:
        """Empty the rollup and schedule a rebuild of every existing row."""
        self._conn.execute("DELETE FROM counts_hourly")
        self._conn.execute("DELETE FROM app_state WHERE name = 'rollup_max_id'")
        self._conn.execute("DELETE FROM app_state WHERE name IN ('rollup_done', 'rollup_upper')")
        upper = int(self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM records").fetchone()[0])
        if upper:  # rows written before the rollup: added in the background
            self._set_state("rollup_upper", str(upper))
            self._set_state("rollup_done", "0")
        self.rollup_ready = not upper

    def _rollup_consistent(self) -> bool:
        """The rollup must count exactly the rows it claims to. A version
        without it (a downgrade) inserts and prunes without updating it."""
        counted, args = self._rollup_counted_sql()
        rows = int(self._conn.execute(
            f"SELECT COUNT(*) FROM records WHERE ts_epoch IS NOT NULL AND {counted}", args).fetchone()[0])
        total = int(self._conn.execute("SELECT COALESCE(SUM(n), 0) FROM counts_hourly").fetchone()[0])
        if rows != total:
            logger.warning("Hourly rollup does not match the records (%d vs %d); rebuilding it", total, rows)
        return rows == total

    def _rollup_counted_sql(self) -> tuple[str, list[Any]]:
        """A condition on records.id: the row's count is in the rollup."""
        if self.rollup_ready:
            return "1", []
        done, upper = self._rollup_bounds()
        return "(id <= ? OR id > ?)", [done, upper]

    def _rollup_apply(self, deltas: dict[tuple, int]) -> None:
        """Add (or, negative, remove) counts; rows that reach zero are deleted,
        so the rollup holds exactly the groups that have records."""
        if not deltas:
            return
        self._conn.executemany(_UPSERT_ROLLUP, [(*key, n) for key, n in deltas.items() if n])
        gone = [key for key, n in deltas.items() if n < 0]
        if gone:
            self._conn.executemany(
                "DELETE FROM counts_hourly WHERE hour_epoch = ? AND scope = ? AND namespace = ? AND pod = ? "
                "AND container = ? AND severity = ? AND n <= 0", gone)

    def _rollup_deltas(self, where: str, args: list[Any], sign: int) -> dict[tuple, int]:
        """Counts of the matching records with a ts_epoch whose count is (or
        is about to be) in the rollup, grouped by rollup key."""
        counted, counted_args = self._rollup_counted_sql()
        rows = self._conn.execute(
            f"SELECT {_HOUR_SQL}, scope, namespace, pod, container, severity_bucket, COUNT(*) FROM records "
            f"WHERE {where} AND ts_epoch IS NOT NULL AND {counted} GROUP BY 1, 2, 3, 4, 5, 6",
            (*args, *counted_args)).fetchall()
        return {tuple(row[:6]): sign * int(row[6]) for row in rows}

    # -- maintenance ------------------------------------------------------------------

    @_locked
    def optimize(self, *, analyze: bool = False) -> None:
        """PRAGMA optimize (cheap; re-analyzes only what the planner needs),
        or a full ANALYZE (no statistics yet, or after large ingests)."""
        self._conn.execute("ANALYZE" if analyze else "PRAGMA optimize")
        self._conn.commit()
        if analyze:
            self._rows_since_analyze = 0
            self._has_stats = True
            # Open connections keep the statistics they loaded; the read
            # pool replaces each connection as it comes back.
            self._pool_generation += 1

    @property
    def analyze_due(self) -> bool:
        return self._rows_since_analyze >= ANALYZE_AFTER_ROWS or not self._has_stats

    @_locked
    def fts_merge_step(self, pages: int = FTS_MERGE_PAGES) -> bool:
        """One incremental FTS5 merge step; True when it found work. Repeated
        until False it amounts to 'optimize' without holding the lock long."""
        if not self.fts_enabled or self.fts_layout != "external":
            return False
        before = self._conn.total_changes
        self._conn.execute("INSERT INTO records_fts(records_fts, rank) VALUES ('merge', ?)", (pages,))
        self._conn.commit()
        return self._conn.total_changes - before >= 2

    @_locked
    def rebuild_rollup_step(self, batch: int = ROLLUP_REBUILD_BATCH) -> bool:
        """Add one id range of rows written before the rollup existed (or
        before it was dropped). Returns True when the rollup is complete.
        Each step commits, so a restart resumes; ingest, pruning and the
        ts_epoch backfill keep it exact meanwhile (see _rollup_counted_sql)."""
        if self.rollup_ready:
            return True
        done, upper = self._rollup_bounds()
        hi = min(done + batch, upper)
        rows = self._conn.execute(
            f"SELECT {_HOUR_SQL}, scope, namespace, pod, container, severity_bucket, COUNT(*) FROM records "
            "WHERE id > ? AND id <= ? AND ts_epoch IS NOT NULL GROUP BY 1, 2, 3, 4, 5, 6", (done, hi)).fetchall()
        self._rollup_apply({tuple(row[:6]): int(row[6]) for row in rows})
        if hi >= upper:
            self._conn.execute("DELETE FROM app_state WHERE name IN ('rollup_done', 'rollup_upper')")
            self._set_state("rollup_max_id", str(self._max_id()))
            self.rollup_ready = True
        else:
            self._set_state("rollup_done", str(hi))
        self._conn.commit()
        if self.rollup_ready:
            logger.info("Hourly rollup rebuilt")
        return self.rollup_ready

    def rollup_usable(self, params: dict[str, Any]) -> bool:
        """Whether a count over these filters can come from the rollup: it is
        complete, every row has its ts_epoch, and there is no text search."""
        return (self.use_rollup and self.rollup_ready and not self.ts_backfill_pending
                and not params.get("q"))

    @_locked
    def backfill_ts_step(self, batch: int = TS_BACKFILL_BATCH) -> int:
        """Give one batch of rows written by an older version their ts_epoch.
        Returns the rows updated (0 when none are left). Each step commits and
        releases the lock, and finds its rows by ts_epoch IS NULL, so a
        restart resumes where it stopped. A timestamp that does not parse
        gets its S3 object's time (else the row's ingest time) and is
        counted like one at ingest."""
        rows = self._conn.execute(
            "SELECT id, timestamp, source_key, source_etag, ingested_at, scope, namespace, pod, container, "
            "severity_bucket FROM records WHERE ts_epoch IS NULL ORDER BY id LIMIT ?", (batch,)
        ).fetchall()
        if not rows:
            self.ts_backfill_pending = False
            return 0
        updates: list[tuple[float, int]] = []
        object_times: dict[tuple[str, str], float | None] = {}
        fallbacks = 0
        for row in rows:
            epoch = to_epoch(row["timestamp"])
            if epoch is None:
                ident = (str(row["source_key"]), str(row["source_etag"]))
                if ident not in object_times:
                    found = self._conn.execute(
                        "SELECT last_modified FROM ingested_objects WHERE key = ? AND etag = ? LIMIT 1", ident
                    ).fetchone()
                    object_times[ident] = to_epoch(found[0]) if found else None
                epoch = object_times[ident]
                if epoch is None:
                    epoch = to_epoch(row["ingested_at"]) or time.time()
                fallbacks += 1
            updates.append((epoch, int(row["id"])))
        self._conn.executemany("UPDATE records SET ts_epoch = ? WHERE id = ?", updates)
        if fallbacks:
            self._add_ts_fallbacks(fallbacks)
        # Rows the rollup rebuild has already passed (it skipped them while
        # they had no time) are counted now; later ones are counted by it.
        done, upper = self._rollup_bounds()
        by_id = {int(row["id"]): row for row in rows}
        deltas: dict[tuple, int] = {}
        for epoch, record_id in updates:
            if self.rollup_ready or record_id <= done or record_id > upper:
                row = by_id[record_id]
                key = (hour_of(epoch), row["scope"], row["namespace"], row["pod"], row["container"],
                       row["severity_bucket"])
                deltas[key] = deltas.get(key, 0) + 1
        self._rollup_apply(deltas)
        self._conn.commit()
        return len(updates)

    def _add_ts_fallbacks(self, count: int) -> None:
        current = int(self._get_state("ts_fallback_count") or 0)
        self._set_state("ts_fallback_count", str(current + count))

    def ts_backfill_remaining(self) -> int:
        return int(self._c().execute("SELECT COUNT(*) FROM records WHERE ts_epoch IS NULL").fetchone()[0])

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
        row = self._c().execute("SELECT value FROM app_state WHERE name = ?", (name,)).fetchone()
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

    @_reading
    def object_failure_summary(self) -> dict[str, Any]:
        count = int(self._c().execute("SELECT COUNT(*) FROM object_failures").fetchone()[0])
        latest = self._c().execute(
            "SELECT key, attempts, last_error, next_attempt_at FROM object_failures "
            "ORDER BY first_failed_at DESC LIMIT 1"
        ).fetchone()
        # One row per configured prefix at most (severity buckets x scopes).
        by_prefix = self._c().execute(
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
        fallbacks = 0
        rollup: dict[tuple, int] = {}
        for record in records:
            # make_record fills ts_epoch (the S3 object's time when the line's
            # timestamp does not parse, flagged ts_fallback); callers that
            # leave it out get the timestamp parsed here, else the time now.
            epoch = record.get("ts_epoch")
            fallback = bool(record.get("ts_fallback"))
            if epoch is None:
                epoch = to_epoch(record["timestamp"])
                if epoch is None:
                    epoch, fallback = time.time(), True
            cur.execute(
                """
                INSERT OR IGNORE INTO records(
                    timestamp, ts_epoch, severity_bucket, scope, namespace, pod, container,
                    message, raw_line, source_key, source_etag, line_number, is_falco, ingested_at, http_meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["timestamp"],
                    float(epoch),
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
                    record.get("http_meta"),
                ),
            )
            if cur.rowcount:
                inserted += 1
                fallbacks += fallback
                key = (hour_of(float(epoch)), record["scope"], record["namespace"], record["pod"],
                       record["container"], record["severity_bucket"])
                rollup[key] = rollup.get(key, 0) + 1
                if self.fts_enabled:
                    self._fts_index_row(cur, int(cur.lastrowid), record["message"], record["raw_line"])
        if fallbacks:
            self._add_ts_fallbacks(fallbacks)
        self._rollup_apply(rollup)  # new ids are always above a pending rebuild's range
        if inserted:
            # The newest id the rollup has counted: readers on other
            # connections (Insights) check that no writer went around it.
            self._set_state("rollup_max_id", str(int(cur.lastrowid)))
        self._conn.commit()
        self._rows_since_analyze += inserted
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
            self._c().execute("SELECT 1 FROM records_fts WHERE records_fts MATCH ? LIMIT 1", (q,)).fetchall()
        except sqlite3.OperationalError as exc:
            raise ValueError(f"Invalid search query: {exc}") from None

    def _build_filters(self, params: dict[str, Any], *, skip_field: str | None = None) -> tuple[str, list[Any]]:
        """WHERE clause for the API filters. skip_field leaves out the equality
        filter on that one field (its exclusions still apply)."""
        clauses = ["1 = 1"]
        args: list[Any] = []
        for field, exclude_key in FILTER_FIELDS:
            value = params.get(field)
            if value and field != skip_field:
                clauses.append(f"{field} = ?")
                args.append(value)
            excluded = params.get(exclude_key)
            if excluded:
                clauses.append(f"{field} NOT IN (SELECT value FROM json_each(?))")
                args.append(json.dumps(list(excluded)))
        start = _param_epoch(params.get("start"))
        end = _param_epoch(params.get("end"))
        before = _param_epoch(params.get("before"))
        if start is not None:
            clauses.append("ts_epoch >= ?")
            args.append(start)
        if end is not None:  # inclusive end (API compatibility)
            clauses.append("ts_epoch <= ?")
            args.append(end)
        if before is not None:  # exclusive end: the UI's [start, before) convention
            clauses.append("ts_epoch < ?")
            args.append(before)
        q = params.get("q")
        if q:
            if params.get("qmode") == "raw":
                self._raw_search_clause(str(q), clauses, args)
            else:
                self._phrase_search_clauses(str(q), clauses, args)
        return " AND ".join(clauses), args

    # -- counts from the rollup ------------------------------------------------------

    @staticmethod
    def _rollup_filters(params: dict[str, Any], *, skip_field: str | None = None) -> tuple[str, list[Any]]:
        """_build_filters' field filters on counts_hourly columns (no time, no search)."""
        clauses = ["1 = 1"]
        args: list[Any] = []
        for field, exclude_key in FILTER_FIELDS:
            column = _ROLLUP_COLUMN[field]
            value = params.get(field)
            if value and field != skip_field:
                clauses.append(f"{column} = ?")
                args.append(value)
            excluded = params.get(exclude_key)
            if excluded:
                clauses.append(f"{column} NOT IN (SELECT value FROM json_each(?))")
                args.append(json.dumps(list(excluded)))
        return " AND ".join(clauses), args

    @staticmethod
    def _split_hours(params: dict[str, Any]) -> tuple[int | None, int | None, list[dict[str, Any]]] | None:
        """A filter's time range as whole hours [h1, h2) (None: unbounded)
        plus the partial hours at its edges as params for raw queries. None
        when the range holds no whole hour."""
        start = _param_epoch(params.get("start"))
        end = _param_epoch(params.get("end"))        # inclusive
        before = _param_epoch(params.get("before"))  # exclusive
        uppers = [u for u in (end, before) if u is not None]
        h1 = None if start is None else math.ceil(start / ROLLUP_SECS) * ROLLUP_SECS
        h2 = None if not uppers else math.floor(min(uppers) / ROLLUP_SECS) * ROLLUP_SECS
        if h1 is not None and h2 is not None and h1 >= h2:
            return None
        edges = []
        base = {k: v for k, v in params.items() if k not in ("start", "end", "before")}
        if start is not None and start < h1:
            edges.append({**base, "start": start, "before": h1})
        if h2 is not None and (before is None or h2 < before) and (end is None or h2 <= end):
            edges.append({**base, "start": h2, **({"end": end} if end is not None else {}),
                          **({"before": before} if before is not None else {})})
        return h1, h2, edges

    def _grouped_counts(self, params: dict[str, Any], keys: list[str], *, skip_field: str | None = None,
                        bucket: tuple[int, int] | None = None) -> list[tuple] | None:
        """Rows (bucket?, *keys, entry count) equal to grouping the filtered
        records by those keys (and by bucket = (origin, size): the time
        bucket index), with whole hours read from counts_hourly. None when
        the rollup cannot serve these params (the caller runs its raw query).
        Keys are filter field names; size must be a multiple of an hour."""
        if not self.rollup_usable(params) or (bucket and bucket[1] % ROLLUP_SECS):
            return None
        split = self._split_hours(params)
        if split is None:
            return None
        h1, h2, edges = split
        names = [f"k{i}" for i in range(len(keys) + (1 if bucket else 0))]
        parts: list[str] = []
        args: list[Any] = []
        bucket_args = list(bucket) if bucket else []
        roll_cols = (["CAST((hour_epoch - ?) / ? AS INTEGER)"] if bucket else []) + [_ROLLUP_COLUMN[k] for k in keys]
        where, where_args = self._rollup_filters(params, skip_field=skip_field)
        if h1 is not None:
            where += " AND hour_epoch >= ?"
            where_args.append(h1)
        if h2 is not None:
            where += " AND hour_epoch < ?"
            where_args.append(h2)
        select = ", ".join(f"{c} AS {n}" for c, n in zip(roll_cols, names, strict=True))
        parts.append(f"SELECT {select}, SUM(n) AS c FROM counts_hourly WHERE {where} GROUP BY {', '.join(names)}"
                     if names else f"SELECT SUM(n) AS c FROM counts_hourly WHERE {where}")
        args += bucket_args + where_args
        raw_cols = (["CAST((ts_epoch - ?) / ? AS INTEGER)"] if bucket else []) + list(keys)
        for edge in edges:
            edge_where, edge_args = self._build_filters(edge, skip_field=skip_field)
            select = ", ".join(f"{c} AS {n}" for c, n in zip(raw_cols, names, strict=True))
            parts.append(f"SELECT {select}, COUNT(*) AS c FROM records WHERE {edge_where} GROUP BY {', '.join(names)}"
                         if names else f"SELECT COUNT(*) AS c FROM records WHERE {edge_where}")
            args += bucket_args + edge_args
        union = " UNION ALL ".join(parts)
        if not names:
            return [(int(self._c().execute(f"SELECT COALESCE(SUM(c), 0) FROM ({union})", args).fetchone()[0]),)]
        cols = ", ".join(names)
        return [tuple(row) for row in self._c().execute(
            f"SELECT {cols}, SUM(c) FROM ({union}) GROUP BY {cols} HAVING SUM(c) > 0", args)]

    _LIKE_SQL = "(LOWER(message) LIKE ? ESCAPE '\\' OR LOWER(raw_line) LIKE ? ESCAPE '\\')"
    _MATCH_SQL = "id {op} (SELECT rowid FROM records_fts WHERE records_fts MATCH ?)"

    def _raw_search_clause(self, q: str, clauses: list[str], args: list[Any]) -> None:
        """qmode=raw: q is FTS5 query syntax (or one substring without FTS)."""
        if self.fts_search:
            self._check_fts_query(q)
            clauses.append(self._MATCH_SQL.format(op="IN"))
            args.append(q)
        else:
            clauses.append(self._LIKE_SQL)
            needle = _like_pattern(q)
            args.extend([needle, needle])

    def _phrase_search_clauses(self, q: str, clauses: list[str], args: list[Any]) -> None:
        """Default search: every word must appear (each word is matched as an
        FTS phrase, so kube-system or 10.0.3.4 match as written), and a word
        with a leading '-' must not."""
        wanted, excluded = split_search_terms(q)
        # Without FTS every word is a substring match; with it, only words
        # the FTS tokenizer cannot index are.
        fts_wanted = [t for t in wanted if self.fts_search and _has_word_chars(t)]
        fts_excluded = [t for t in excluded if self.fts_search and _has_word_chars(t)]
        if fts_wanted:
            clauses.append(self._MATCH_SQL.format(op="IN"))
            args.append(" AND ".join(_fts_phrase(t) for t in fts_wanted))
        if fts_excluded:
            # FTS5 NOT is binary ("a NOT b"), so exclusions are a separate
            # NOT IN; that also covers a query of exclusions only.
            clauses.append(self._MATCH_SQL.format(op="NOT IN"))
            args.append(" OR ".join(_fts_phrase(t) for t in fts_excluded))
        for tokens, fts_tokens, negate in ((wanted, fts_wanted, ""), (excluded, fts_excluded, "NOT ")):
            for token in tokens:
                if token not in fts_tokens:
                    clauses.append(negate + self._LIKE_SQL)
                    args.extend([_like_pattern(token)] * 2)

    @_reading
    def query_logs(self, params: dict[str, Any], *, limit: int, cursor: tuple[float, int] | None = None,
                   direction: str = "desc") -> dict[str, Any]:
        where_sql, args = self._build_filters(params)
        if cursor:
            epoch, record_id = cursor
            if direction == "desc":
                where_sql += " AND (ts_epoch < ? OR (ts_epoch = ? AND id < ?))"
            else:
                where_sql += " AND (ts_epoch > ? OR (ts_epoch = ? AND id > ?))"
            args.extend([epoch, epoch, record_id])
        order = "DESC" if direction == "desc" else "ASC"
        rows = self._c().execute(
            f"""
            SELECT {_RECORD_COLUMNS}
            FROM records
            WHERE {where_sql}
            ORDER BY ts_epoch {order}, id {order}
            LIMIT ?
            """,
            (*args, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [dict(row) for row in rows]
        next_cursor = None
        if items and items[-1]["ts_epoch"] is not None:
            next_cursor = _encode_cursor(float(items[-1]["ts_epoch"]), int(items[-1]["id"]))
        elif items:
            has_more = False  # rows still waiting for the ts_epoch backfill sort last and cannot be paged past
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more, "max_id": self._max_id()}

    def _max_id(self) -> int:
        return int(self._c().execute("SELECT COALESCE(MAX(id), 0) FROM records").fetchone()[0])

    @_reading
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
        rows = self._c().execute(
            f"""
            SELECT {_RECORD_COLUMNS}
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

    # -- alerts ---------------------------------------------------------------------

    _ALERT_METRICS = {
        "count": "COUNT(*)",
        "error_count": "COALESCE(SUM(severity_bucket = 'error'), 0)",
        "distinct_pods": "COUNT(DISTINCT pod)",
    }
    _ALERT_GROUPS = {"none": "''", "namespace": "namespace", "pod": "pod"}

    @_reading
    def alert_metric(self, params: dict[str, Any], *, metric: str, group_by: str = "none", max_groups: int = 20,
                     lowest_first: bool = False, timeout_secs: float = FIELD_QUERY_TIMEOUT_SECS) -> dict[str, Any]:
        """One alert evaluation: the metric over the filtered entries (params
        carry the window as start/end), per group. At most max_groups groups,
        the most extreme first (highest, or lowest with lowest_first);
        `overflow` counts the rest. TimeoutError past timeout_secs."""
        expr = self._ALERT_METRICS[metric]
        group = self._ALERT_GROUPS[group_by]
        where_sql, args = self._build_filters(params)
        order = "ASC" if lowest_first else "DESC"
        try:
            with self._time_limit(timeout_secs):
                rows = self._alert_metric_rollup(params, metric, group_by, max_groups, lowest_first)
                if rows is None:
                    rows = self._c().execute(
                        f"""
                        SELECT g, value, COUNT(*) OVER () FROM (
                            SELECT {group} AS g, {expr} AS value FROM records WHERE {where_sql} GROUP BY g
                        ) ORDER BY value {order}, g LIMIT ?
                        """,
                        (*args, max(1, int(max_groups))),
                    ).fetchall()
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc):
                raise TimeoutError("alert query timed out") from None
            raise
        total = int(rows[0][2]) if rows else 0
        groups = {str(row[0] or ""): float(row[1] or 0) for row in rows}
        if group_by == "none" and not groups:
            groups = {"": 0.0}
        return {"groups": groups, "overflow": max(0, total - len(rows))}

    def _alert_metric_rollup(self, params: dict[str, Any], metric: str, group_by: str, max_groups: int,
                             lowest_first: bool) -> list[tuple] | None:
        """alert_metric's rows (group, value, groups in total) from the rollup
        when the window holds whole hours, else None."""
        keys = ([group_by] if group_by != "none" else []) + (["severity_bucket"] if metric == "error_count" else []) \
            + (["pod"] if metric == "distinct_pods" else [])
        grouped = self._grouped_counts(params, keys)
        if grouped is None:
            return None
        values: dict[str, float] = {}
        for row in grouped:
            g = str(row[0]) if group_by != "none" else ""
            n = int(row[-1])
            if metric == "count" or not keys:
                values[g] = values.get(g, 0) + n
            elif metric == "error_count":
                values[g] = values.get(g, 0) + (n if row[-2] == "error" else 0)
            else:  # distinct_pods: one row per (group, pod) present
                values[g] = values.get(g, 0) + 1
        ordered = sorted(values.items(), key=lambda kv: (kv[1] if lowest_first else -kv[1], kv[0]))
        return [(g, v, len(values)) for g, v in ordered[:max(1, int(max_groups))]]

    @_reading
    def metric_series(self, params: dict[str, Any], *, start_epoch: int, end_epoch: int, bucket_secs: int,
                      pods: bool = False, timeout_secs: float = FIELD_QUERY_TIMEOUT_SECS) -> dict[int, Any]:
        """Histogram buckets for a backtest: {bucket index: (total, errors)}
        over [start_epoch, end_epoch), or with pods {index: set of pods}.
        Same bucketing as query_histogram (epoch seconds, aligned to
        start_epoch). TimeoutError past timeout_secs."""
        base = {key: value for key, value in params.items() if key not in ("start", "end", "before")}
        if start_epoch % ROLLUP_SECS == 0:  # whole-hour buckets: from the rollup
            grouped = self._grouped_counts({**base, "start": start_epoch, "before": end_epoch},
                                           ["pod" if pods else "severity_bucket"], bucket=(start_epoch, bucket_secs))
            if grouped is not None:
                series: dict[int, Any] = {}
                for index, key, n in grouped:
                    if pods:
                        series.setdefault(int(index), set()).add(str(key))
                    else:
                        total, errors = series.get(int(index), (0, 0))
                        series[int(index)] = (total + int(n), errors + (int(n) if key == "error" else 0))
                return series
        where_sql, args = self._build_filters(base)
        select = "bucket, pod" if pods else "bucket, COUNT(*), COALESCE(SUM(severity_bucket = 'error'), 0)"
        group = "bucket, pod" if pods else "bucket"
        try:
            with self._time_limit(timeout_secs):
                rows = self._c().execute(
                    f"""
                    SELECT {select} FROM (
                        SELECT CAST((ts_epoch - ?) / ? AS INTEGER) AS bucket, severity_bucket, pod FROM records
                        WHERE {where_sql} AND ts_epoch >= ? AND ts_epoch < ?
                    ) GROUP BY {group}
                    """,
                    (start_epoch, bucket_secs, *args, start_epoch, end_epoch),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc):
                raise TimeoutError("backtest query timed out") from None
            raise
        out: dict[int, Any] = {}
        for row in rows:
            if pods:
                out.setdefault(int(row[0]), set()).add(str(row[1]))
            else:
                out[int(row[0])] = (int(row[1]), int(row[2]))
        return out

    @_locked
    def set_prefix_listed(self, prefix: str, at: str) -> None:
        """The poll start time of the latest complete listing of a prefix
        (alerts.watermark)."""
        current = self._prefix_listed()
        current[prefix] = at
        self._set_state("prefix_listed_ok", json.dumps(current, separators=(",", ":"), sort_keys=True))
        self._conn.commit()

    def _prefix_listed(self) -> dict[str, str]:
        try:
            value = json.loads(self._get_state("prefix_listed_ok") or "{}")
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    @_reading
    def prefix_progress(self) -> dict[str, dict[str, Any]]:
        """Per prefix: last listed key (cursor), latest complete listing, and
        the oldest object still failing (key, last_modified)."""
        out: dict[str, dict[str, Any]] = {}
        for prefix, at in self._prefix_listed().items():
            out.setdefault(prefix, {})["listed_ok_at"] = at
        for row in self._c().execute("SELECT prefix, last_key FROM prefix_state"):
            out.setdefault(str(row[0]), {})["cursor"] = str(row[1])
        for row in self._c().execute(
            "SELECT prefix, MIN(key), MIN(last_modified) FROM object_failures GROUP BY prefix"
        ):
            out.setdefault(str(row[0]), {})["failing"] = {"key": str(row[1]), "last_modified": str(row[2])}
        return out

    @_reading
    def top_values(self, field: str, *, limit: int = FACET_VALUES_MAX, start: str | None = None) -> list[str]:
        """The most frequent non-empty values of one filter field, optionally
        only from entries at or after `start`."""
        if field not in dict(FILTER_FIELDS):
            raise ValueError(f"Unknown filter field {field!r}")
        where_sql, args = self._build_filters({"start": start} if start else {})
        rows = self._c().execute(
            f"""
            SELECT {field} AS value, COUNT(*) AS count
            FROM records
            WHERE {where_sql} AND {field} IS NOT NULL AND {field} != ''
            GROUP BY {field}
            ORDER BY count DESC, value ASC
            LIMIT ?
            """,
            (*args, max(1, min(int(limit), FACET_VALUES_MAX))),
        ).fetchall()
        return [str(row[0]) for row in rows]

    @_reading
    def query_facets(self, params: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        where_sql, args = self._build_filters(params)
        fields = ["scope", "namespace", "pod", "container", "severity_bucket"]
        out: dict[str, list[dict[str, Any]]] = {}
        for field in fields:
            rows = self._c().execute(
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

    @contextmanager
    def _time_limit(self, timeout_secs: float):
        """Interrupt the queries run inside after timeout_secs; an interrupted
        query raises sqlite3.OperationalError ("interrupted")."""
        deadline = time.monotonic() + timeout_secs
        self._c().set_progress_handler(lambda: 1 if time.monotonic() >= deadline else 0, _PROGRESS_OPS)
        try:
            yield
        finally:
            self._c().set_progress_handler(None, 0)

    @_reading
    def query_fields(self, params: dict[str, Any], *, timeout_secs: float = FIELD_QUERY_TIMEOUT_SECS) -> dict[str, Any]:
        """Top values of each filter field under the current filters. A field's
        own equality filter is left out of its query, so its other values stay
        visible (its exclusions still apply). Each field's query gets
        timeout_secs; a field that runs out reports partial with no values."""
        fields: dict[str, Any] = {}
        any_partial = False
        names = [field for field, _ in FILTER_FIELDS]
        # From the rollup: one grouping by every field (equality filters left
        # out, exclusions kept), then each field's counts under the other
        # fields' equality filters, instead of one scan per field.
        combos = None
        if self.rollup_usable(params):
            try:
                with self._time_limit(timeout_secs * len(names)):
                    combos = self._grouped_counts({k: v for k, v in params.items() if k not in names}, names)
            except sqlite3.OperationalError as exc:
                if "interrupted" not in str(exc):
                    raise
                combos = None
        for position, (field, exclude_key) in enumerate(FILTER_FIELDS):
            where_sql, args = self._build_filters(params, skip_field=field)
            try:
                with self._time_limit(timeout_secs):
                    if combos is not None:  # whole hours from the rollup
                        wanted = [(i, params[f]) for i, f in enumerate(names) if f != field and params.get(f)]
                        counts: dict[str, int] = {}
                        for row in combos:
                            if all(row[i] == value for i, value in wanted):
                                counts[row[position]] = counts.get(row[position], 0) + int(row[-1])
                        ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
                        total = sum(counts.values())
                        rows = [(v, n, total, len(counts)) for v, n in ordered[:FIELD_TOP_VALUES]]
                    else:
                        rows = self._c().execute(
                            f"""
                            SELECT {field} AS value, COUNT(*) AS count,
                                   SUM(COUNT(*)) OVER () AS total, COUNT(*) OVER () AS distinct_count
                            FROM records
                            WHERE {where_sql}
                            GROUP BY {field}
                            ORDER BY count DESC, value ASC
                            LIMIT ?
                            """,
                            (*args, FIELD_TOP_VALUES),
                        ).fetchall()
            except sqlite3.OperationalError as exc:
                if "interrupted" not in str(exc):
                    raise
                any_partial = True
                fields[field] = {"param": field, "exclude_param": exclude_key, "values": [],
                                 "total": None, "distinct": None, "partial": True}
                continue
            fields[field] = {
                "param": field,
                "exclude_param": exclude_key,
                "values": [{"value": row[0], "count": int(row[1])} for row in rows],
                "total": int(rows[0][2]) if rows else 0,
                "distinct": int(rows[0][3]) if rows else 0,
                "partial": False,
            }
        return {"fields": fields, "partial": any_partial}

    @_reading
    def query_histogram(self, params: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        """Entry counts per time bucket (total and per severity) over the
        filtered range, every bucket present. Buckets are aligned to the
        bucket size in UTC epoch seconds (ts_epoch), so offsets and
        fractional seconds land in the right bucket. Without a start the
        range begins at the oldest matching entry; without an end it stops
        at now."""
        end_bound = _param_epoch(params.get("before"))
        if end_bound is None and params.get("end"):
            end_bound = _param_epoch(params.get("end")) + 1
        if end_bound is None:
            end_bound = (now or datetime.now(timezone.utc)).timestamp()
        end_epoch = math.floor(end_bound)
        start_bound = _param_epoch(params.get("start"))
        where_sql, args = self._build_filters(
            {key: value for key, value in params.items() if key not in ("start", "end", "before")}
        )
        if start_bound is not None:
            start_epoch = math.floor(start_bound)
        else:
            row = self._c().execute(f"SELECT MIN(ts_epoch) FROM records WHERE {where_sql}", args).fetchone()
            if row[0] is None:
                return {"bucket_secs": HISTOGRAM_BUCKET_SECS[0], "buckets": [], "truncated": False}
            start_epoch = math.floor(row[0])
        span = max(1, end_epoch - start_epoch)
        bucket_secs = next(
            (size for size in HISTOGRAM_BUCKET_SECS if span / size <= HISTOGRAM_TARGET_BUCKETS),
            HISTOGRAM_BUCKET_SECS[-1],
        )
        origin = start_epoch - start_epoch % bucket_secs
        count = max(1, -(-(end_epoch - origin) // bucket_secs))
        truncated = count > HISTOGRAM_MAX_BUCKETS
        if truncated:  # keep the newest buckets
            origin += (count - HISTOGRAM_MAX_BUCKETS) * bucket_secs
            count = HISTOGRAM_MAX_BUCKETS
        lo, hi = max(origin, start_epoch), min(origin + count * bucket_secs, end_epoch)
        filters = {key: value for key, value in params.items() if key not in ("start", "end", "before")}
        grouped = self._grouped_counts({**filters, "start": lo, "before": hi}, ["severity_bucket"],
                                       bucket=(origin, bucket_secs))
        if grouped is not None:  # buckets of whole hours: from the rollup
            pivot: dict[int, list[int]] = {}
            for index, severity, n in grouped:
                row = pivot.setdefault(int(index), [index, 0] + [0] * len(_HISTOGRAM_SEVERITIES))
                row[1] += int(n)
                if severity in _HISTOGRAM_SEVERITIES:
                    row[2 + _HISTOGRAM_SEVERITIES.index(severity)] += int(n)
            by_bucket = pivot
        else:
            severity_sql = ", ".join(f"SUM(severity_bucket = '{sev}')" for sev in _HISTOGRAM_SEVERITIES)
            rows = self._c().execute(
                f"""
                SELECT CAST((ts_epoch - ?) / ? AS INTEGER) AS bucket, COUNT(*), {severity_sql}
                FROM records
                WHERE {where_sql} AND ts_epoch >= ? AND ts_epoch < ?
                GROUP BY bucket
                """,
                (origin, bucket_secs, *args, lo, hi),
            ).fetchall()
            by_bucket = {int(row[0]): row for row in rows}
        buckets = []
        for index in range(count):
            row = by_bucket.get(index)
            entry = {
                "t": datetime.fromtimestamp(origin + index * bucket_secs, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total": int(row[1]) if row else 0,
            }
            for offset, sev in enumerate(_HISTOGRAM_SEVERITIES):
                entry[sev] = int(row[2 + offset] or 0) if row else 0
            buckets.append(entry)
        return {"bucket_secs": bucket_secs, "buckets": buckets, "truncated": truncated}

    def _dashboard_rollup(self, params: dict[str, Any], error_params: dict[str, Any],
                          top_errors: Any) -> dict[str, Any] | None:
        """query_dashboard from the rollup (whole hours) and raw edge rows;
        None when the rollup cannot serve these params. top_errors() runs
        only when the rollup is used (it needs messages: raw rows)."""
        groups = self._grouped_counts(params, ["scope", "namespace", "pod", "severity_bucket"])
        if groups is None:
            return None
        hourly = self._grouped_counts(params, ["severity_bucket"], bucket=(0, ROLLUP_SECS)) or []
        timeline = [(index, n) for index, _sev, n in hourly]
        if params.get("severity_bucket") in (None, "", "error"):
            # The error view is the same rows restricted to error: no second scan.
            errors = [(r[1], r[2], r[4]) for r in groups if r[3] == "error"]
            error_timeline = [(index, n) for index, sev, n in hourly if sev == "error"]
        else:
            errors = self._grouped_counts(error_params, ["namespace", "pod"]) or []
            error_timeline = self._grouped_counts(error_params, [], bucket=(0, ROLLUP_SECS)) or []

        def top(counter: dict[str, int], limit: int | None = DASHBOARD_LIST_MAX) -> list[dict[str, Any]]:
            ordered = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
            return [{"value": k, "count": v} for k, v in (ordered[:limit] if limit else ordered)]

        def tally(rows: list[tuple], index: int) -> dict[str, int]:
            out: dict[str, int] = {}
            for row in rows:
                out[row[index]] = out.get(row[index], 0) + int(row[-1])
            return out

        severity = tally(groups, 3)
        total = sum(severity.values())
        security = sum(int(r[-1]) for r in groups if r[0] == "security")
        timeline_map: dict[str, dict[str, Any]] = {}
        for rows, key in ((timeline, "total_logs"), (error_timeline, "error_logs")):
            for index, n in rows:
                bucket = datetime.fromtimestamp(int(index) * ROLLUP_SECS, timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")
                entry = timeline_map.setdefault(bucket, {"timestamp": bucket, "total_logs": 0, "error_logs": 0})
                entry[key] += int(n)
        return {
            "summary": {
                "total_logs": total,
                **{f"{sev}_count": severity.get(sev, 0) for sev in ("error", "warning", "info", "debug", "metrics")},
                "security_count": security,
                "unique_namespaces": len(tally(groups, 1)),
                "unique_pods": len(tally(groups, 2)),
            },
            "severity": top(severity, None),
            "namespaces": top(tally(groups, 1)),
            "error_namespaces": top(tally(errors, 0)),
            "error_pods": top(tally(errors, 1)),
            "top_errors": [{"value": row[0], "count": int(row[1] or 0)} for row in top_errors()],
            "timeline": [timeline_map[key] for key in sorted(timeline_map)],
        }

    @_reading
    def query_dashboard(self, params: dict[str, Any]) -> dict[str, Any]:
        where_sql, args = self._build_filters(params)
        error_params = {**params, "severity_bucket": "error"}
        error_where_sql, error_args = self._build_filters(error_params)
        if self.rollup_usable(params):
            from_rollup = self._dashboard_rollup(params, error_params,
                                                 lambda: self._top_errors(error_where_sql, error_args))
            if from_rollup is not None:
                return from_rollup

        summary_row = self._c().execute(
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

        severity_rows = self._c().execute(
            f"""
            SELECT severity_bucket AS value, COUNT(*) AS count
            FROM records
            WHERE {where_sql}
            GROUP BY severity_bucket
            ORDER BY count DESC, value ASC
            """,
            args,
        ).fetchall()

        namespace_rows = self._c().execute(
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

        error_namespace_rows = self._c().execute(
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

        error_pod_rows = self._c().execute(
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

        top_error_rows = self._top_errors(error_where_sql, error_args)

        timeline_total_rows = self._c().execute(
            f"""
            SELECT strftime('%Y-%m-%dT%H:00:00Z', CAST(ts_epoch AS INTEGER), 'unixepoch') AS bucket,
                   COUNT(*) AS total_count
            FROM records
            WHERE {where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            args,
        ).fetchall()

        timeline_error_rows = self._c().execute(
            f"""
            SELECT strftime('%Y-%m-%dT%H:00:00Z', CAST(ts_epoch AS INTEGER), 'unixepoch') AS bucket,
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
            if row[0] is None:  # not yet backfilled
                continue
            bucket = str(row[0])
            timeline_map[bucket] = {"timestamp": bucket, "total_logs": int(row[1] or 0), "error_logs": 0}
        for row in timeline_error_rows:
            if row[0] is None:
                continue
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

    def _top_errors(self, where_sql: str, args: list[Any]) -> list[Any]:
        return self._c().execute(
            f"""
            SELECT message AS value, COUNT(*) AS count
            FROM records
            WHERE {where_sql}
            GROUP BY message
            ORDER BY count DESC, value ASC
            LIMIT 10
            """,
            args,
        ).fetchall()

    def prune_records_before(self, cutoff: str | float, *, batch: int = PRUNE_BATCH) -> int:
        """Delete cached records (and their FTS rows) whose event time is
        before cutoff (epoch seconds or an ISO time), in batches that each
        commit and release the lock. The S3 source objects past retention are
        expired by the bucket lifecycle rule, so their ingest bookkeeping is
        dropped too. Returns records removed."""
        cutoff_epoch = _param_epoch(cutoff)
        if cutoff_epoch is None:
            raise ValueError("A prune cutoff is required")
        # Rows still waiting for their ts_epoch would never be pruned; finish
        # the backfill first (batched, so the lock is released in between).
        while self.ts_backfill_pending and self.backfill_ts_step():
            pass
        removed = 0
        while True:
            count = self._prune_batch(cutoff_epoch, batch)
            removed += count
            if count < batch:
                break
        self._prune_bookkeeping(cutoff_epoch, release=bool(removed))
        return removed

    @_locked
    def _prune_batch(self, cutoff: float, batch: int) -> int:
        ids = [int(row[0]) for row in self._conn.execute(
            "SELECT id FROM records WHERE ts_epoch < ? LIMIT ?", (cutoff, batch)
        )]
        if not ids:
            return 0
        ids_json = json.dumps(ids)
        self._rollup_apply(self._rollup_deltas("id IN (SELECT value FROM json_each(?))", [ids_json], -1))
        if self.fts_enabled:
            self._fts_delete_ids(ids_json)
        self._conn.execute("DELETE FROM records WHERE id IN (SELECT value FROM json_each(?))", (ids_json,))
        self._conn.commit()
        return len(ids)

    @_locked
    def _prune_bookkeeping(self, cutoff: float, *, release: bool) -> None:
        # S3 LastModified times (UTC, ISO); compared as epoch seconds.
        older = "CAST(strftime('%s', last_modified) AS INTEGER) < ?"
        self._conn.execute(f"DELETE FROM ingested_objects WHERE {older}", (math.floor(cutoff),))
        # Objects past retention are expired from the bucket; stop retrying them.
        self._conn.execute(f"DELETE FROM object_failures WHERE {older}", (math.floor(cutoff),))
        self._conn.commit()
        if release:
            self._release_free_pages()

    @_reading
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
        anchor_row = self._c().execute(
            f"SELECT {_RECORD_COLUMNS} FROM records WHERE id = ?", (record_id,)
        ).fetchone()
        if anchor_row is None:
            return None
        anchor = dict(anchor_row)
        lines_before = max(0, min(int(lines_before), CONTEXT_LINES_MAX))
        lines_after = max(0, min(int(lines_after), CONTEXT_LINES_MAX))
        group = (anchor["namespace"], anchor["pod"], anchor["container"])
        start_epoch = _param_epoch(start)
        before_epoch = _param_epoch(before)

        # Lower / upper time bounds (epoch seconds): the search window around
        # the record, narrowed by the caller's range.
        anchor_epoch = anchor["ts_epoch"]
        lower: float | None = None
        upper: float | None = None
        limited_by_window = anchor_epoch is not None
        if anchor_epoch is not None:
            lower = float(anchor_epoch) - window_secs
            upper = float(anchor_epoch) + window_secs
        else:
            anchor_epoch = 0.0  # not yet backfilled: only the row limits apply
        lower_from_range = start_epoch is not None and (lower is None or start_epoch > lower)
        upper_from_range = before_epoch is not None and (upper is None or before_epoch < upper)
        if lower_from_range:
            lower = start_epoch
        if upper_from_range:
            upper = before_epoch

        group_sql = "namespace = ? AND pod = ? AND container = ?"
        earlier_sql = f"SELECT {_RECORD_COLUMNS} FROM records WHERE {group_sql} " \
            "AND (ts_epoch < ? OR (ts_epoch = ? AND id < ?))"
        earlier_args: list[Any] = [*group, anchor_epoch, anchor_epoch, record_id]
        if lower is not None:
            earlier_sql += " AND ts_epoch >= ?"
            earlier_args.append(lower)
        earlier = self._c().execute(
            earlier_sql + " ORDER BY ts_epoch DESC, id DESC LIMIT ?", (*earlier_args, lines_before + 1)
        ).fetchall() if lines_before else []

        later_sql = f"SELECT {_RECORD_COLUMNS} FROM records WHERE {group_sql} " \
            "AND (ts_epoch > ? OR (ts_epoch = ? AND id > ?))"
        later_args: list[Any] = [*group, anchor_epoch, anchor_epoch, record_id]
        if upper is not None:
            later_sql += " AND ts_epoch < ?"
            later_args.append(upper)
        later = self._c().execute(
            later_sql + " ORDER BY ts_epoch ASC, id ASC LIMIT ?", (*later_args, lines_after + 1)
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
                "from": iso_from_epoch(lower) if lower is not None else None,
                "to": iso_from_epoch(upper) if upper is not None else None,
                "from_is_range": lower_from_range,
                "to_is_range": upper_from_range,
                "window_secs": window_secs if limited_by_window else None,
            },
            "lines_before": lines_before,
            "lines_after": lines_after,
        }

    @_reading
    def get_record_by_id(self, record_id: int) -> dict[str, Any] | None:
        """Fetch a single record by its row id, for per-line explain.
        Re-derives from storage rather than trusting client-supplied text."""
        row = self._c().execute(
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
        """The shared records connection, for maintenance and tests. Other
        threads read through their own connection (open_connection)."""
        return self._conn

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

    @_reading
    def get_state(self, name: str) -> str | None:
        """One app_state value without get_status()'s full-table counts."""
        return self._get_state(name)

    @_reading
    def object_counts(self, root: str) -> tuple[int, int]:
        """(objects ingested under <root>security/, all other objects)."""
        return count_objects_under(self._c(), root + "security/")

    @_reading
    def get_status(self) -> dict[str, Any]:
        last_polled_at = self._get_state("last_polled_at")
        last_successful_ingest_at = self._get_state("last_successful_ingest_at")
        last_object_last_modified = self._get_state("last_object_last_modified")
        last_error = self._get_state("last_error")
        total_records = int(self._c().execute("SELECT COUNT(*) FROM records").fetchone()[0])
        total_objects = int(self._c().execute("SELECT COUNT(*) FROM ingested_objects").fetchone()[0])
        latest = self._c().execute(
            "SELECT timestamp FROM records WHERE ts_epoch IS NOT NULL ORDER BY ts_epoch DESC LIMIT 1").fetchone()
        latest_record_timestamp = latest[0] if latest else None
        return {
            # Records whose timestamp did not parse; their ts_epoch is the S3
            # object's time (counted at ingest and by the backfill).
            "timestamp_fallbacks": int(self._get_state("ts_fallback_count") or 0),
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
        page_size = int(self._c().execute("PRAGMA page_size").fetchone()[0])
        pages = int(self._c().execute("PRAGMA page_count").fetchone()[0])
        free_pages = int(self._c().execute("PRAGMA freelist_count").fetchone()[0])
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
            remaining = int(self._c().execute(
                "SELECT COUNT(*) FROM records WHERE id > ? AND id <= ?", (done, upper)
            ).fetchone()[0])
            out["fts_migration"] = {"rows_remaining": remaining, "last_error": self.fts_migration_error}
        if not self.rollup_ready:
            done, upper = self._rollup_bounds()
            out["rollup_rebuild"] = {"ids_remaining": max(0, upper - done), "last_error": self.rollup_error}
        if self.ts_backfill_pending:
            # Until done, these rows are left out of time-filtered queries.
            out["ts_backfill"] = {"rows_remaining": self.ts_backfill_remaining(), "last_error": self.ts_backfill_error}
        return out
