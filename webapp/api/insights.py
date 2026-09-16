from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .config import AppConfig, InsightsConfig


logger = logging.getLogger(__name__)

# Ports of the UI's message-normalization (webapp/ui/app.js ruleKeyOf) so the
# grouping keys used for anomaly detection are identical to the ones used for
# the viewer's dedupe feature. Parity is pinned by test_insights.py.
_FALCO_EVENT_TIME_RE = re.compile(r"\b\d{2}:\d{2}:\d{2}\.\d+:\s*")


def rule_key_of(message: str) -> str:
    text = str(message or "")
    text = _FALCO_EVENT_TIME_RE.sub("", text)
    detail_index = text.find(" | ")
    if detail_index > 0 and "=" in text[detail_index:]:
        text = text[:detail_index]
    return text


def compute_baseline(hourly_counts: list[int]) -> float:
    """Baseline = mean of per-hour counts across the baseline window."""
    if not hourly_counts:
        return 0.0
    return sum(hourly_counts) / len(hourly_counts)


def is_spike(current: int, baseline: float, multiplier: float, min_count: int) -> bool:
    """Spike when current >= multiplier*baseline AND current >= min_count.

    The min_count floor prevents alerting on tiny namespaces; when the
    baseline is 0 the floor alone decides, so brand-new activity must still
    cross min_count before it is called a spike.
    """
    if current < min_count:
        return False
    return baseline <= 0 or current >= multiplier * baseline


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AnomalyStore:
    """Owns the anomalies table and detection indexes. The records table stays
    untouched except for one additive index used by the windowed queries."""

    def __init__(self, db_path: Path):
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    namespace TEXT NOT NULL DEFAULT '',
                    pod TEXT NOT NULL DEFAULT '',
                    rule_key TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    detected_day TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    ai_summary TEXT,
                    ai_suggested_action TEXT,
                    ai_summarized_at TEXT,
                    UNIQUE(type, namespace, pod, rule_key, detected_day)
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_records_ts_ns ON records(timestamp, namespace)"
            )
            self._conn.commit()

    def upsert_anomaly(
        self,
        *,
        type: str,
        namespace: str,
        pod: str,
        rule_key: str,
        severity: str,
        evidence: dict[str, Any],
        detected_day: str,
    ) -> int:
        now = _utc_now_iso()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO anomalies (type, namespace, pod, rule_key, severity, evidence,
                                       detected_at, detected_day, updated_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
                ON CONFLICT(type, namespace, pod, rule_key, detected_day) DO UPDATE SET
                    evidence = excluded.evidence,
                    updated_at = excluded.updated_at
                """,
                (
                    type,
                    namespace,
                    pod,
                    rule_key,
                    severity,
                    json.dumps(evidence, separators=(",", ":")),
                    now,
                    detected_day,
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT id FROM anomalies WHERE type=? AND namespace=? AND pod=? AND rule_key=? AND detected_day=?",
                (type, namespace, pod, rule_key, detected_day),
            ).fetchone()
            return int(row["id"])

    def record_ai_failure(self, anomaly_id: int, error: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE anomalies SET ai_summarized_at=?, evidence=json_set(evidence, '$.ai_error', ?) WHERE id=?",
                (_utc_now_iso(), error, anomaly_id),
            )
            self._conn.commit()

    def save_ai_summary(self, anomaly_id: int, summary: str, action: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE anomalies SET ai_summary=?, ai_suggested_action=?, ai_summarized_at=? WHERE id=?",
                (summary, action, _utc_now_iso(), anomaly_id),
            )
            self._conn.commit()

    def pending_ai_anomalies(self, limit: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM anomalies WHERE ai_summarized_at IS NULL AND status='new' ORDER BY id LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def query_anomalies(self, params: dict[str, Any], *, limit: int) -> dict[str, Any]:
        clauses: list[str] = []
        args: list[Any] = []
        for field in ("status", "type", "namespace"):
            value = params.get(field)
            if value:
                clauses.append(f"{field} = ?")
                args.append(value)
        where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM anomalies{where_sql} ORDER BY detected_at DESC, id DESC LIMIT ?",
            (*args, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        items = [dict(row) for row in rows[:limit]]
        for item in items:
            item["evidence"] = json.loads(item["evidence"])
        return {"items": items, "has_more": has_more}

    _VALID_STATUSES = frozenset({"new", "reviewed", "dismissed"})

    def set_status(self, anomaly_id: int, status: str) -> bool:
        """Update the status of a single anomaly. Returns True if a row was updated."""
        if status not in self._VALID_STATUSES:
            raise ValueError(f"Invalid status {status!r}; must be one of {sorted(self._VALID_STATUSES)}")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE anomalies SET status=?, updated_at=? WHERE id=?",
                (status, _utc_now_iso(), anomaly_id),
            )
            self._conn.commit()
            return cur.rowcount > 0


class InsightsDetector:
    """Deterministic detection over the records table. All windows derive from
    a single `now` so the math is testable without sleeps or mocks."""

    def __init__(self, conn: sqlite3.Connection, cfg: InsightsConfig):
        self._conn = conn
        self.cfg = cfg

    def _hour_bounds(self, now: datetime) -> tuple[str, str]:
        hour_start = now.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        return hour_start.isoformat().replace("+00:00", "Z"), hour_end.isoformat().replace("+00:00", "Z")

    def _baseline_start(self, hour_start: datetime) -> str:
        start = hour_start - timedelta(hours=24 * self.cfg.baseline_window_days)
        return start.isoformat().replace("+00:00", "Z")

    def _window_rows(self, start: str, end: str, where: str = "") -> list[sqlite3.Row]:
        return self._conn.execute(
            f"SELECT timestamp, severity_bucket, namespace, pod, message FROM records WHERE timestamp >= ? AND timestamp < ?{where}",
            (start, end),
        ).fetchall()

    def _evidence(self, hour_start: str, hour_end: str, items: list, **extra: Any) -> dict[str, Any]:
        sample_messages: list[str] = []
        for r in items:
            try:
                msg = str(r["message"]).strip()
            except (KeyError, TypeError, IndexError):
                msg = ""
            if msg and msg not in sample_messages:
                sample_messages.append(msg)
            if len(sample_messages) >= 5:
                break

        evidence = {
            "window_start": hour_start,
            "window_end": hour_end,
            "current_count": len(items),
            "baseline_window_days": self.cfg.baseline_window_days,
            "sample_timestamps": [r["timestamp"] for r in items[: self.cfg.sample_timestamps_max]],
            "sample_messages": sample_messages,
        }
        evidence.update(extra)
        return evidence

    def detect_error_spikes(self, now: datetime, *, per_pod: bool = False) -> list[dict[str, Any]]:
        hour_start, hour_end = self._hour_bounds(now)
        baseline_start = self._baseline_start(datetime.fromisoformat(hour_start.replace("Z", "+00:00")))
        baseline_hours = max(1, 24 * self.cfg.baseline_window_days)
        current_rows = self._window_rows(hour_start, hour_end, " AND severity_bucket='error'")
        baseline_rows = self._window_rows(baseline_start, hour_start, " AND severity_bucket='error'")

        def key_of(row: sqlite3.Row) -> tuple[str, str]:
            return (row["namespace"], row["pod"]) if per_pod else (row["namespace"], "")

        current: dict[tuple[str, str], list] = {}
        for row in current_rows:
            current.setdefault(key_of(row), []).append(row)
        baseline_counts: dict[tuple[str, str], int] = {}
        for row in baseline_rows:
            baseline_counts[key_of(row)] = baseline_counts.get(key_of(row), 0) + 1

        anomalies = []
        for key, items in current.items():
            baseline_avg = compute_baseline([baseline_counts.get(key, 0) / baseline_hours] * baseline_hours)
            if not is_spike(len(items), baseline_avg, self.cfg.spike_multiplier, self.cfg.spike_min_count):
                continue
            anomalies.append(
                {
                    "type": "error_rate_spike",
                    "namespace": key[0],
                    "pod": key[1],
                    "rule_key": "",
                    "severity": "error",
                    "evidence": self._evidence(
                        hour_start, hour_end, items,
                        baseline_avg_per_hour=round(baseline_avg, 3),
                        multiplier=self.cfg.spike_multiplier,
                    ),
                }
            )
        return anomalies

    def detect_new_falco_rules(self, now: datetime) -> list[dict[str, Any]]:
        hour_start, hour_end = self._hour_bounds(now)
        current_rows = self._window_rows(hour_start, hour_end, " AND scope='security'")
        if not current_rows:
            return []
        prior_rows = self._conn.execute(
            "SELECT message FROM records WHERE timestamp < ? AND scope='security'",
            (hour_start,),
        ).fetchall()
        prior_keys = {rule_key_of(row["message"]) for row in prior_rows}
        grouped: dict[str, list] = {}
        for row in current_rows:
            key = rule_key_of(row["message"])
            if key not in prior_keys:
                grouped.setdefault(key, []).append(row)
        return [
            {
                "type": "new_falco_rule",
                "namespace": "",
                "pod": "",
                "rule_key": key,
                "severity": items[0]["severity_bucket"],
                "evidence": self._evidence(
                    hour_start, hour_end, items, first_seen_timestamp=items[0]["timestamp"]
                ),
            }
            for key, items in grouped.items()
        ]

    def detect_message_frequency(self, now: datetime) -> list[dict[str, Any]]:
        hour_start, hour_end = self._hour_bounds(now)
        baseline_start = self._baseline_start(datetime.fromisoformat(hour_start.replace("Z", "+00:00")))
        baseline_hours = max(1, 24 * self.cfg.baseline_window_days)
        current_rows = self._window_rows(hour_start, hour_end)
        baseline_rows = self._window_rows(baseline_start, hour_start)

        def key_of(row: sqlite3.Row) -> tuple[str, str]:
            return (row["namespace"], rule_key_of(row["message"]))

        current: dict[tuple[str, str], list] = {}
        for row in current_rows:
            current.setdefault(key_of(row), []).append(row)
        baseline_counts: dict[tuple[str, str], int] = {}
        for row in baseline_rows:
            baseline_counts[key_of(row)] = baseline_counts.get(key_of(row), 0) + 1

        anomalies = []
        for key, items in current.items():
            baseline_avg = compute_baseline([baseline_counts.get(key, 0) / baseline_hours] * baseline_hours)
            if not is_spike(
                len(items), baseline_avg, self.cfg.frequency_multiplier, self.cfg.frequency_min_count
            ):
                continue
            anomalies.append(
                {
                    "type": "message_frequency",
                    "namespace": key[0],
                    "pod": "",
                    "rule_key": key[1],
                    "severity": "",
                    "evidence": self._evidence(
                        hour_start, hour_end, items,
                        baseline_avg_per_hour=round(baseline_avg, 3),
                        multiplier=self.cfg.frequency_multiplier,
                    ),
                }
            )
        return anomalies

    def detect_severity_shift(self, now: datetime) -> list[dict[str, Any]]:
        hour_start, hour_end = self._hour_bounds(now)
        baseline_start = self._baseline_start(datetime.fromisoformat(hour_start.replace("Z", "+00:00")))
        current_rows = self._window_rows(hour_start, hour_end)
        baseline_rows = self._window_rows(baseline_start, hour_start)
        baseline_total = len(baseline_rows)
        if baseline_total == 0:
            return []

        current_by_ns: dict[str, list] = {}
        for row in current_rows:
            current_by_ns.setdefault(row["namespace"], []).append(row)
        baseline_counts: dict[str, dict[str, int]] = {}
        for row in baseline_rows:
            per_ns = baseline_counts.setdefault(row["namespace"], {})
            per_ns[row["severity_bucket"]] = per_ns.get(row["severity_bucket"], 0) + 1

        anomalies = []
        for namespace, rows in current_by_ns.items():
            ns_total = len(rows)
            counts: dict[str, int] = {}
            for row in rows:
                counts[row["severity_bucket"]] = counts.get(row["severity_bucket"], 0) + 1
            baseline_per_ns = baseline_counts.get(namespace, {})
            for bucket, current_count in counts.items():
                if current_count < self.cfg.shift_min_count:
                    continue
                current_share = current_count / ns_total
                baseline_share = baseline_per_ns.get(bucket, 0) / baseline_total
                if abs(current_share - baseline_share) < self.cfg.shift_share_delta:
                    continue
                bucket_rows = [r for r in rows if r["severity_bucket"] == bucket]
                anomalies.append(
                    {
                        "type": "severity_shift",
                        "namespace": namespace,
                        "pod": "",
                        "rule_key": "",
                        "severity": bucket,
                        "evidence": self._evidence(
                            hour_start, hour_end, bucket_rows,
                            current_share=round(current_share, 3),
                            baseline_share=round(baseline_share, 3),
                            baseline_total=baseline_total,
                        ),
                    }
                )
        return anomalies

    def detect_all(self, now: datetime) -> list[dict[str, Any]]:
        anomalies = list(self.detect_new_falco_rules(now))
        anomalies.extend(self.detect_error_spikes(now, per_pod=self.cfg.detect_per_pod))
        anomalies.extend(self.detect_message_frequency(now))
        anomalies.extend(self.detect_severity_shift(now))
        return anomalies


class InsightsJob:
    """Periodic detection + AI stage, following the ingest-loop pattern."""

    def __init__(
        self,
        cfg: AppConfig,
        records_conn: sqlite3.Connection,
        store: AnomalyStore,
        summarizer: Callable[[dict[str, Any]], dict[str, str] | None] | None = None,
    ):
        self.cfg = cfg
        self.store = store
        self.detector = InsightsDetector(records_conn, cfg.insights)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self._summarizer = summarizer

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # surfaced to status; never kills the loop
                self.last_error = str(exc)
            self._stop.wait(self.cfg.insights.detect_interval_secs)

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        now = now or datetime.now(timezone.utc)
        created = self.detect_once(now)
        summarized = self.summarize_pending()
        self.last_run_at = _utc_now_iso()
        self.last_error = None
        return {"anomalies_created": created, "anomalies_summarized": summarized}

    def detect_once(self, now: datetime) -> int:
        created = 0
        day = now.strftime("%Y-%m-%d")
        for anomaly in self.detector.detect_all(now):
            self.store.upsert_anomaly(
                type=anomaly["type"],
                namespace=anomaly["namespace"],
                pod=anomaly["pod"],
                rule_key=anomaly["rule_key"],
                severity=anomaly["severity"],
                evidence=anomaly["evidence"],
                detected_day=day,
            )
            created += 1
        return created

    def summarize_pending(self) -> int:
        summarizer = self._summarizer or (lambda anomaly: None)
        count = 0
        for anomaly in self.store.pending_ai_anomalies(self.cfg.ai.max_anomalies_per_tick):
            try:
                result = summarizer(anomaly)
            except Exception as exc:
                logger.warning("AI summarization failed for anomaly %s: %s", anomaly["id"], exc)
                continue
            if result:
                self.store.save_ai_summary(
                    int(anomaly["id"]), result["summary"], result["suggested_action"]
                )
                count += 1
        return count