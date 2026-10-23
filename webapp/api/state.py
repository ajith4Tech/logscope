"""Durable operator state (saved views, later alert rules) in its own SQLite
file, separate from the log cache: the cache can be wiped and rebuilt from S3,
this cannot.

The schema is versioned in `schema_version`; MIGRATIONS only ever grows (a
new feature appends a step, existing steps are never edited), and a database
written by a newer version is refused rather than modified.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .filters import FilterError, clean_text
from .filters import validate_filters as _validate_filters
from .storage import SQLITE_BUSY_TIMEOUT_SECS

STATE_DB_ENV = "LOGSCOPE_WEBAPP_STATE_DB_PATH"

# (version, statements). Append only.
MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (1, (
        """
        CREATE TABLE saved_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            description TEXT NOT NULL DEFAULT '',
            filters TEXT NOT NULL DEFAULT '{}',
            pinned INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT
        )
        """,
    )),
    # AI settings managed from the UI (one row, id 1) and per-call usage.
    # api_key_enc is a Fernet token (see ai_settings); the plain key is never
    # stored. prices is NULL until a price table is saved from the UI.
    (2, (
        """
        CREATE TABLE ai_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            provider TEXT,
            model TEXT,
            deep_model TEXT,
            base_url TEXT,
            api_key_enc TEXT,
            key_last4 TEXT,
            updated_at TEXT NOT NULL,
            feature_flags TEXT NOT NULL DEFAULT '{}',
            budgets TEXT NOT NULL DEFAULT '{}',
            prices TEXT
        )
        """,
        """
        CREATE TABLE ai_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            feature TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            tokens_in INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            cached_tokens INTEGER NOT NULL DEFAULT 0,
            cost_usd_est REAL,
            latency_ms INTEGER NOT NULL DEFAULT 0,
            outcome TEXT NOT NULL
                CHECK (outcome IN ('ok', 'error', 'cache_hit', 'budget_blocked', 'signature'))
        )
        """,
        "CREATE INDEX idx_ai_usage_ts ON ai_usage(ts)",
    )),
    # AI answers cached by log template (see ai_cache); helpful_* is feedback.
    (3, (
        """
        CREATE TABLE ai_cache (
            key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            template_id TEXT NOT NULL DEFAULT '',
            model_tier TEXT NOT NULL,
            response TEXT NOT NULL,
            created_at TEXT NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            last_hit_at TEXT,
            helpful_up INTEGER NOT NULL DEFAULT 0,
            helpful_down INTEGER NOT NULL DEFAULT 0
        )
        """,
        "CREATE INDEX idx_ai_cache_created ON ai_cache(created_at)",
    )),
    # One 👍/👎 per (cache entry, browser session); ai_usage rows can name what
    # they were about (e.g. "anomaly:42") so budget blocks are written once a day.
    (4, (
        """
        CREATE TABLE ai_cache_votes (
            key TEXT NOT NULL,
            client_id TEXT NOT NULL,
            vote INTEGER NOT NULL CHECK (vote IN (-1, 1)),
            voted_at TEXT NOT NULL,
            PRIMARY KEY (key, client_id)
        )
        """,
        "ALTER TABLE ai_usage ADD COLUMN subject TEXT",
        "CREATE INDEX idx_ai_usage_subject ON ai_usage(outcome, subject, ts)",
    )),
    # Alerts on saved views (see alerts.py / channels.py). url_enc and
    # secret_enc are Fernet tokens; the plain URL and secret are never stored.
    # Deleting a saved view disables its rules (trigger) and records why.
    (5, (
        """
        CREATE TABLE notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            type TEXT NOT NULL CHECK (type IN ('mattermost', 'slack', 'webhook')),
            url_enc TEXT NOT NULL,
            url_last6 TEXT NOT NULL DEFAULT '',
            secret_enc TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            view_id INTEGER REFERENCES saved_views(id) ON DELETE SET NULL,
            metric TEXT NOT NULL CHECK (metric IN ('count', 'error_count', 'distinct_pods')),
            op TEXT NOT NULL CHECK (op IN ('>', '>=', '<', '<=')),
            threshold REAL NOT NULL,
            window_s INTEGER NOT NULL,
            interval_s INTEGER NOT NULL,
            for_evals INTEGER NOT NULL DEFAULT 1,
            group_by TEXT NOT NULL DEFAULT 'none' CHECK (group_by IN ('none', 'namespace', 'pod')),
            max_groups INTEGER NOT NULL DEFAULT 20,
            urgency TEXT NOT NULL DEFAULT 'high',
            channel_ids TEXT NOT NULL DEFAULT '[]',
            renotify_s INTEGER NOT NULL DEFAULT 21600,
            notify_resolved INTEGER NOT NULL DEFAULT 1,
            mute_until TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            disabled_reason TEXT,
            labels TEXT NOT NULL DEFAULT '{}',
            ai_summary INTEGER NOT NULL DEFAULT 0,
            last_window_end TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER,
            group_key TEXT NOT NULL DEFAULT '',
            from_state TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL,
            streak INTEGER NOT NULL DEFAULT 0,
            value REAL,
            threshold REAL,
            window_start TEXT,
            window_end TEXT,
            notified INTEGER NOT NULL DEFAULT 0,
            muted INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            detail TEXT,
            ts TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_alert_events_rule ON alert_events(rule_id, group_key, id)",
        "CREATE INDEX idx_alert_events_ts ON alert_events(ts)",
        """
        CREATE TRIGGER saved_view_deleted_disables_alerts AFTER DELETE ON saved_views
        BEGIN
            INSERT INTO alert_events (rule_id, group_key, from_state, state, detail, ts)
                SELECT id, '', '', 'disabled', 'saved view ' || OLD.id || ' was deleted',
                       strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                FROM alert_rules WHERE view_id = OLD.id AND enabled = 1;
            UPDATE alert_rules SET enabled = 0, view_id = NULL,
                disabled_reason = 'Its saved view (' || OLD.name || ') was deleted',
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE view_id = OLD.id;
        END
        """,
    )),
    # Durable alert delivery: failed notifications back off (alerts.py
    # RETRY_SCHEDULE_SECS) for up to a day; restarts resume from here.
    (6, (
        "ALTER TABLE alert_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE alert_events ADD COLUMN next_attempt_at TEXT",
        "CREATE INDEX idx_alert_events_delivery ON alert_events(notified, next_attempt_at)",
    )),
)
# What identifies a state database (also one written before a later
# migration, e.g. a restored backup): tables added later are not required.
REQUIRED_TABLES = ("schema_version", "saved_views")

# Saved view limits.
VIEW_NAME_MAX = 80
VIEW_DESCRIPTION_MAX = 500
VIEWS_MAX = 200
SORT_ORDER_LIMIT = 2**31 - 1
# The filter set itself (keys, ranges, size limit) is defined and validated in filters.py.
_DESCRIPTION_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # newlines and tabs allowed


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def default_state_db_path() -> Path:
    """$XDG_DATA_HOME/logscope/state.sqlite, else ~/.local/share/logscope/.
    A relative XDG_DATA_HOME is ignored, as the XDG spec requires."""
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".local" / "share"
    return base / "logscope" / "state.sqlite"


def env_state_db_path() -> Path | None:
    value = os.environ.get(STATE_DB_ENV, "").strip()
    return Path(value).expanduser() if value else None


class ViewError(FilterError):
    """A saved-view request that cannot be applied; mapped to an HTTP status."""


class ViewNotFound(ViewError):
    status = 404


class ViewConflict(ViewError):
    status = 409


def _prepare_file(path: Path) -> None:
    """Directory 0700 when created here, database file 0600. SQLite creates
    its -wal/-shm files with the database file's permissions."""
    if not path.parent.exists():
        os.makedirs(path.parent, mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    os.close(fd)


class StateDB:
    """One connection guarded by its own lock (not the cache's)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        _prepare_file(self.path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self.migrate()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def schema_version(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
            return int(row[0] or 0)

    def migrate(self) -> int:
        """Apply pending migrations, each in its own transaction. Running it
        again is a no-op. Returns the resulting schema version."""
        latest = MIGRATIONS[-1][0]
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            current = self.schema_version()
            if current > latest:
                raise ValueError(
                    f"{self.path} has schema version {current}, newer than this version supports ({latest})"
                )
            for version, statements in MIGRATIONS:
                if version <= current:
                    continue
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    for sql in statements:
                        self._conn.execute(sql)
                    self._conn.execute(
                        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)", (version, _utc_now())
                    )
                    self._conn.execute("COMMIT")
                except BaseException:
                    self._conn.execute("ROLLBACK")
                    raise
            return self.schema_version()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ─── Saved views ─────────────────────────────────────────────────────────────


def _clean_text(value: Any, field: str, max_len: int) -> str:
    return clean_text(value, field, max_len, ViewError)


def validate_filters(raw: Any) -> dict[str, str]:
    """filters.validate_filters, failing with a ViewError."""
    try:
        return _validate_filters(raw)
    except ViewError:
        raise
    except FilterError as exc:
        raise ViewError(str(exc), exc.field) from None


def _clean_name(value: Any) -> str:
    return _clean_text(value, "name", VIEW_NAME_MAX)


def _clean_description(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ViewError("'description' must be a string", "description")
    text = value.strip()
    if len(text) > VIEW_DESCRIPTION_MAX:
        raise ViewError(f"'description' is longer than {VIEW_DESCRIPTION_MAX} characters", "description")
    if _DESCRIPTION_CONTROL_RE.search(text):
        raise ViewError("'description' contains control characters", "description")
    return text


def _clean_pinned(value: Any) -> int:
    if not isinstance(value, bool):
        raise ViewError("'pinned' must be true or false", "pinned")
    return int(value)


def _clean_sort_order(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > SORT_ORDER_LIMIT:
        raise ViewError(f"'sort_order' must be an integer between -{SORT_ORDER_LIMIT} and {SORT_ORDER_LIMIT}",
                        "sort_order")
    return value


_EDITABLE = {
    "name": _clean_name,
    "description": _clean_description,
    "filters": validate_filters,
    "pinned": _clean_pinned,
    "sort_order": _clean_sort_order,
}


def _view_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "description": row["description"],
        "filters": json.loads(row["filters"]),
        "pinned": bool(row["pinned"]),
        "sort_order": int(row["sort_order"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_used_at": row["last_used_at"],
    }


class SavedViews:
    def __init__(self, db: StateDB):
        self._db = db

    @staticmethod
    def _clean(body: Any, *, partial: bool) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ViewError("Request body must be a JSON object")
        unknown = sorted(str(key) for key in body if key not in _EDITABLE)
        if unknown:
            raise ViewError(f"Unknown field '{unknown[0]}'", unknown[0])
        if not partial and "name" not in body:
            raise ViewError("'name' is required", "name")
        return {key: clean(body[key]) for key, clean in _EDITABLE.items() if key in body}

    def _check_name_free(self, name: str, *, except_id: int | None = None) -> None:
        # The column is COLLATE NOCASE (ASCII only); casefold covers the rest.
        wanted = name.casefold()
        for row in self._db.conn.execute("SELECT id, name FROM saved_views"):
            if row["id"] != except_id and str(row["name"]).casefold() == wanted:
                raise ViewConflict(f"A saved view named '{row['name']}' already exists", "name")

    def _get(self, view_id: int) -> dict[str, Any]:
        row = self._db.conn.execute("SELECT * FROM saved_views WHERE id = ?", (view_id,)).fetchone()
        if row is None:
            raise ViewNotFound("Saved view not found")
        return _view_row(row)

    def list(self) -> list[dict[str, Any]]:
        with self._db.lock:
            rows = self._db.conn.execute(
                "SELECT * FROM saved_views ORDER BY pinned DESC, sort_order, name COLLATE NOCASE, id"
            ).fetchall()
        return [_view_row(row) for row in rows]

    def get(self, view_id: int) -> dict[str, Any]:
        with self._db.lock:
            return self._get(view_id)

    def _write(self, sql: str, args: tuple) -> sqlite3.Cursor:
        try:
            return self._db.conn.execute(sql, args)
        except sqlite3.IntegrityError:
            raise ViewConflict("A saved view with this name already exists", "name") from None

    def create(self, body: Any) -> dict[str, Any]:
        values = self._clean(body, partial=False)
        now = _utc_now()
        with self._db.lock:
            count = int(self._db.conn.execute("SELECT COUNT(*) FROM saved_views").fetchone()[0])
            if count >= VIEWS_MAX:
                raise ViewError(f"At most {VIEWS_MAX} saved views; delete one first")
            self._check_name_free(values["name"])
            if "sort_order" not in values:
                top = self._db.conn.execute("SELECT MAX(sort_order) FROM saved_views").fetchone()[0]
                values["sort_order"] = min(int(top) + 1, SORT_ORDER_LIMIT) if top is not None else 0
            cur = self._write(
                "INSERT INTO saved_views (name, description, filters, pinned, sort_order, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    values["name"],
                    values.get("description", ""),
                    json.dumps(values.get("filters", {}), sort_keys=True, ensure_ascii=False),
                    values.get("pinned", 0),
                    values["sort_order"],
                    now,
                    now,
                ),
            )
            return self._get(int(cur.lastrowid))

    def update(self, view_id: int, body: Any) -> dict[str, Any]:
        values = self._clean(body, partial=True)
        with self._db.lock:
            self._get(view_id)
            if not values:
                return self._get(view_id)
            if "name" in values:
                self._check_name_free(values["name"], except_id=view_id)
            if "filters" in values:
                values["filters"] = json.dumps(values["filters"], sort_keys=True, ensure_ascii=False)
            columns = list(values)  # names from _EDITABLE only
            self._write(
                f"UPDATE saved_views SET {', '.join(f'{c} = ?' for c in columns)}, updated_at = ? WHERE id = ?",
                (*(values[c] for c in columns), _utc_now(), view_id),
            )
            return self._get(view_id)

    def delete(self, view_id: int) -> None:
        with self._db.lock:
            if self._db.conn.execute("DELETE FROM saved_views WHERE id = ?", (view_id,)).rowcount == 0:
                raise ViewNotFound("Saved view not found")

    def mark_used(self, view_id: int) -> dict[str, Any]:
        with self._db.lock:
            self._get(view_id)
            self._db.conn.execute("UPDATE saved_views SET last_used_at = ? WHERE id = ?", (_utc_now(), view_id))
            return self._get(view_id)
