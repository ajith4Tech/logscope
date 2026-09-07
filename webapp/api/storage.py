from __future__ import annotations

import base64
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _encode_cursor(ts: str, record_id: int) -> str:
    payload = json.dumps({"ts": ts, "id": record_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[str, int] | None:
    if not cursor:
        return None
    pad = "=" * (-len(cursor) % 4)
    payload = base64.urlsafe_b64decode((cursor + pad).encode("ascii"))
    data = json.loads(payload.decode("utf-8"))
    return str(data["ts"]), int(data["id"])


class LogStorage:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.fts_enabled = False
        with self._lock:
            self._init_schema()

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
        try:
            cur.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS records_fts
                USING fts5(message, raw_line)
                """
            )
            self.fts_enabled = True
        except sqlite3.OperationalError:
            self.fts_enabled = False
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

    def get_prefix_cursor(self, prefix: str) -> str | None:
        row = self._conn.execute("SELECT last_key FROM prefix_state WHERE prefix = ?", (prefix,)).fetchone()
        return str(row[0]) if row else None

    def set_prefix_cursor(self, prefix: str, last_key: str) -> None:
        self._conn.execute(
            """
            INSERT INTO prefix_state(prefix, last_key, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(prefix) DO UPDATE SET last_key = excluded.last_key, updated_at = excluded.updated_at
            """,
            (prefix, last_key, _utc_now()),
        )

    def object_seen(self, bucket: str, key: str, etag: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM ingested_objects WHERE bucket = ? AND key = ? AND etag = ?",
            (bucket, key, etag),
        ).fetchone()
        return row is not None

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
                    record_id = cur.lastrowid
                    cur.execute(
                        "INSERT INTO records_fts(rowid, message, raw_line) VALUES (?, ?, ?)",
                        (record_id, record["message"], record["raw_line"]),
                    )
        self._conn.commit()
        return inserted

    def ingest_state(self, *, last_poll_at: str, last_successful_ingest_at: str | None, last_object_last_modified: str | None, last_error: str | None = None) -> None:
        self._set_state("last_polled_at", last_poll_at)
        if last_successful_ingest_at is not None:
            self._set_state("last_successful_ingest_at", last_successful_ingest_at)
        if last_object_last_modified is not None:
            self._set_state("last_object_last_modified", last_object_last_modified)
        if last_error is not None:
            self._set_state("last_error", last_error)
        self._conn.commit()

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
        if start:
            clauses.append("timestamp >= ?")
            args.append(start)
        if end:
            clauses.append("timestamp <= ?")
            args.append(end)
        q = params.get("q")
        if q:
            if self.fts_enabled:
                clauses.append("id IN (SELECT rowid FROM records_fts WHERE records_fts MATCH ?)")
                args.append(q)
            else:
                clauses.append("(LOWER(message) LIKE ? OR LOWER(raw_line) LIKE ?)")
                needle = f"%{str(q).lower()}%"
                args.extend([needle, needle])
        return " AND ".join(clauses), args

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
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

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
                """,
                args,
            ).fetchall()
            out[field] = [{"value": row[0], "count": int(row[1])} for row in rows]
        return out

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
        }