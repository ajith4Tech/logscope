from __future__ import annotations

import functools
import json
import logging
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .actions import step_execution_fields
from .config import AppConfig, InsightsConfig
from .storage import SQLITE_BUSY_TIMEOUT_SECS


logger = logging.getLogger(__name__)

# Consecutive summarization failures before an anomaly is marked failed
# (shown as "AI error" in the UI) instead of being retried every tick, so a
# persistently failing anomaly cannot block newer ones from the per-tick quota.
_MAX_AI_ATTEMPTS_PER_ANOMALY = 3

# Rows read to build one anomaly's evidence (sample timestamps and up to five
# distinct messages). Counts always come from SQL aggregates, not from these.
_SAMPLE_SCAN_ROWS = 500
# Baseline windows are aggregated in slices of this many hours so no single
# query holds the database for the whole multi-day window.
_BASELINE_SLICE_HOURS = 24
_RULE_KEY_SQL_FUNCTION = "logscope_rule_key"

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


def _write(method):
    """Hold the store's lock and roll back a write that fails part-way, so a
    later commit cannot persist half of it."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            try:
                return method(self, *args, **kwargs)
            except BaseException:
                if self._conn.in_transaction:
                    try:
                        self._conn.rollback()
                    except sqlite3.Error:
                        logger.exception("Rolling back a failed anomaly write also failed")
                raise

    return wrapper


class AnomalyStore:
    """Owns the anomalies table and detection indexes. The records table stays
    untouched except for one additive index used by the windowed queries."""

    def __init__(self, db_path: Path):
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
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
                    ai_steps TEXT,
                    ai_summarized_at TEXT,
                    UNIQUE(type, namespace, pod, rule_key, detected_day)
                )
                """
            )
            cols = [info[1] for info in cur.execute("PRAGMA table_info(anomalies)").fetchall()]
            if "ai_steps" not in cols:
                cur.execute("ALTER TABLE anomalies ADD COLUMN ai_steps TEXT")
            if "ai_meta" not in cols:
                # {source: signature|cache|ai, tier, generated_at, cache_key}
                cur.execute("ALTER TABLE anomalies ADD COLUMN ai_meta TEXT")
            # Regenerate existing cached AI summaries that lack structured steps
            cur.execute(
                "UPDATE anomalies SET ai_summarized_at = NULL "
                "WHERE ai_steps IS NULL AND ai_summary IS NOT NULL AND status = 'new'"
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
        anomaly_id, _ = self.record_detection(
            type=type, namespace=namespace, pod=pod, rule_key=rule_key,
            severity=severity, evidence=evidence, detected_day=detected_day,
        )
        return anomaly_id

    @_write
    def record_detection(
        self,
        *,
        type: str,
        namespace: str,
        pod: str,
        rule_key: str,
        severity: str,
        evidence: dict[str, Any],
        detected_day: str,
    ) -> tuple[int, str]:
        """Insert or refresh one anomaly. Returns (id, outcome) where outcome is
        "created", "updated" (same occurrence, newer counts) or "recurred" (the
        same anomaly in a different hourly window of the same day).

        A recurrence replaces the evidence, so any AI summary, steps and AI
        error written for the earlier occurrence are cleared and the anomaly is
        summarized again; otherwise the old text would be shown as describing
        evidence it never saw. Within one occurrence the summary is kept (and a
        recorded AI error is preserved so failures are not retried every tick).
        """
        now = _utc_now_iso()
        evidence_json = json.dumps(evidence, separators=(",", ":"))
        key = (type, namespace, pod, rule_key, detected_day)
        with self._lock:
            row = self._conn.execute(
                "SELECT id, evidence FROM anomalies WHERE type=? AND namespace=? AND pod=? AND rule_key=? AND detected_day=?",
                key,
            ).fetchone()
            if row is None:
                cur = self._conn.execute(
                    """
                    INSERT INTO anomalies (type, namespace, pod, rule_key, severity, evidence,
                                           detected_at, detected_day, updated_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
                    """,
                    (type, namespace, pod, rule_key, severity, evidence_json, now, detected_day, now),
                )
                self._conn.commit()
                return int(cur.lastrowid), "created"
            anomaly_id = int(row["id"])
            try:
                previous = json.loads(row["evidence"])
            except (TypeError, ValueError):
                previous = {}
            old_window = previous.get("window_start") if isinstance(previous, dict) else None
            new_window = evidence.get("window_start")
            if old_window and new_window and new_window < old_window:
                # An older window (e.g. the previous hour, re-evaluated) never
                # replaces evidence for a newer occurrence.
                return anomaly_id, "unchanged"
            if old_window and new_window and old_window != new_window:
                self._conn.execute(
                    """
                    UPDATE anomalies SET evidence=?, severity=?, updated_at=?,
                        ai_summary=NULL, ai_suggested_action=NULL, ai_steps=NULL, ai_summarized_at=NULL,
                        ai_meta=NULL
                    WHERE id=?
                    """,
                    (evidence_json, severity, now, anomaly_id),
                )
                outcome = "recurred"
            else:
                self._conn.execute(
                    """
                    UPDATE anomalies SET
                        evidence = CASE
                            WHEN json_extract(evidence, '$.ai_error') IS NULL THEN ?
                            ELSE json_set(?, '$.ai_error', json_extract(evidence, '$.ai_error'))
                        END,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (evidence_json, evidence_json, now, anomaly_id),
                )
                outcome = "updated"
            self._conn.commit()
            return anomaly_id, outcome

    @_write
    def record_ai_failure(self, anomaly_id: int, error: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE anomalies SET ai_summarized_at=?, evidence=json_set(evidence, '$.ai_error', ?) WHERE id=?",
                (_utc_now_iso(), error, anomaly_id),
            )
            self._conn.commit()

    @_write
    def save_ai_summary(
        self,
        anomaly_id: int,
        summary: str,
        action: str,
        steps: list[dict[str, Any]] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        steps_json = json.dumps(steps, separators=(",", ":")) if steps is not None else None
        meta_json = json.dumps(meta, separators=(",", ":")) if meta else None
        with self._lock:
            self._conn.execute(
                "UPDATE anomalies SET ai_summary=?, ai_suggested_action=?, ai_steps=?, ai_summarized_at=?, ai_meta=? "
                "WHERE id=?",
                (summary, action, steps_json, _utc_now_iso(), meta_json, anomaly_id),
            )
            self._conn.commit()

    def pending_ai_anomalies(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM anomalies WHERE ai_summarized_at IS NULL AND status='new' ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def query_anomalies(self, params: dict[str, Any], *, limit: int) -> dict[str, Any]:
        clauses: list[str] = []
        args: list[Any] = []
        for field in ("id", "status", "type", "namespace"):
            value = params.get(field)
            if value:
                clauses.append(f"{field} = ?")
                args.append(value)
        where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM anomalies{where_sql} ORDER BY detected_at DESC, id DESC LIMIT ?",
                (*args, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        items = [dict(row) for row in rows[:limit]]
        for item in items:
            item["evidence"] = json.loads(item["evidence"])
            try:
                item["ai_meta"] = json.loads(item["ai_meta"]) if item.get("ai_meta") else None
            except ValueError:
                item["ai_meta"] = None
            raw_steps = item.get("ai_steps")
            if raw_steps:
                try:
                    item["ai_steps"] = json.loads(raw_steps)
                except Exception:
                    item["ai_steps"] = []
            else:
                item["ai_steps"] = []
            if not isinstance(item["ai_steps"], list):
                item["ai_steps"] = []
            for step in item["ai_steps"]:
                # Stored plans may predate the current parser or server-side
                # risk derivation (or carry a model-chosen label); re-derive
                # everything execution-related from the command text, so a
                # stale structured action is never offered to run.
                if isinstance(step, dict):
                    for stale in ("action", "is_supported", "exec_command", "ignored_args", "unsupported_reason"):
                        step.pop(stale, None)
                    step.update(step_execution_fields(step.get("command") or "", step.get("risk")))
        return {"items": items, "has_more": has_more}

    def get_anomaly(self, anomaly_id: int) -> dict[str, Any] | None:
        items = self.query_anomalies({"id": anomaly_id}, limit=1)["items"]
        return items[0] if items else None

    _VALID_STATUSES = frozenset({"new", "reviewed", "dismissed"})

    @_write
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


@dataclass(frozen=True)
class _Window:
    """One observation window and the baseline that precedes it."""

    start: datetime
    end: datetime            # end of observed data: hour end, or `now` for the open hour
    hour_end: datetime       # the hour's nominal end (reported as window_end)
    partial: bool
    baseline_start: datetime  # max(start - baseline window, first stored record)

    @property
    def hours(self) -> float:
        return (self.end - self.start).total_seconds() / 3600

    @property
    def baseline_hours(self) -> float:
        return (self.start - self.baseline_start).total_seconds() / 3600


class InsightsDetector:
    """Deterministic detection over the records table. All windows derive from
    a single `now` so the math is testable without sleeps or mocks.

    Each run looks at two hourly windows:
      * the previous, complete hour — evaluated on every run of the following
        hour, so its last minutes and late-arriving (late-ingested) records
        are counted;
      * the current hour, once `min_partial_window_minutes` of it have passed.
    Both use one rule: the expected count is the baseline's per-hour average
    times the hours actually observed, so a 20-minute window is compared with
    20 minutes' worth of baseline, not with a full hour.

    The baseline average divides by the history that actually exists (from
    the first stored record), not by the configured window, so a young install
    is not compared with a baseline diluted by days that were never collected.
    With less than `min_baseline_hours` of history no anomaly is raised
    ("learning"); `history_hours` and `learning` report this.

    Counting happens in SQL (GROUP BY), so memory does not grow with log
    volume, and multi-day baselines are read in day-sized slices. In the web
    app the detector owns a separate read connection; with WAL it then never
    waits on, or blocks, the ingest writer and HTTP queries."""

    def __init__(self, conn: sqlite3.Connection, cfg: InsightsConfig, lock: threading.RLock | None = None):
        self._conn = conn
        self.cfg = cfg
        # The owner's lock when conn is shared with other threads (LogStorage.lock).
        self._lock = lock or threading.RLock()
        self.history_hours: float | None = None
        self.learning = False
        with self._lock:
            self._conn.create_function(_RULE_KEY_SQL_FUNCTION, 1, rule_key_of, deterministic=True)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    @staticmethod
    def _parse(value: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _first_record_time(self) -> datetime | None:
        """Earliest stored event time, or None when there are no records. An
        unparseable value is treated as "history covers the whole window"."""
        row = self._query("SELECT MIN(timestamp) FROM records", ())
        if not row or not row[0][0]:
            return None
        return self._parse(row[0][0]) or datetime.min.replace(tzinfo=timezone.utc)

    def _windows(self, now: datetime) -> list[_Window]:
        """The windows to evaluate at `now`, oldest first. Updates
        history_hours / learning."""
        now = now.astimezone(timezone.utc).replace(microsecond=0)
        hour_start = now.replace(minute=0, second=0)
        span = timedelta(days=self.cfg.baseline_window_days)
        min_history = min(
            timedelta(hours=max(1.0, float(self.cfg.min_baseline_hours))), span
        )
        first = self._first_record_time()
        self.history_hours = (
            None if first is None else round(max(0.0, (hour_start - first).total_seconds() / 3600), 1)
        )
        candidates = [(hour_start - timedelta(hours=1), hour_start, hour_start, False)]
        if now - hour_start >= timedelta(minutes=float(self.cfg.min_partial_window_minutes)):
            candidates.append((hour_start, now, hour_start + timedelta(hours=1), True))
        windows = []
        for start, end, hour_end, partial in candidates:
            if first is None or start - first < min_history:
                continue  # not enough history before this window
            windows.append(_Window(start, end, hour_end, partial, max(start - span, first)))
        self.learning = not windows
        return windows

    def _slices(self, start: str, end: str) -> list[tuple[str, str]]:
        lo = datetime.fromisoformat(start.replace("Z", "+00:00"))
        hi = datetime.fromisoformat(end.replace("Z", "+00:00"))
        out: list[tuple[str, str]] = []
        while lo < hi:
            nxt = min(lo + timedelta(hours=_BASELINE_SLICE_HOURS), hi)
            out.append((self._iso(lo), self._iso(nxt)))
            lo = nxt
        return out

    def _query(self, sql: str, args: tuple) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def _counts(
        self, start: str, end: str, keys: tuple[str, ...], where: str = "", args: tuple = ()
    ) -> dict[tuple, int]:
        """{key tuple: row count} for start <= timestamp < end, aggregated in SQL
        one slice at a time. `keys` are SQL expressions (fixed by the callers)."""
        select = ", ".join(f"{expr} AS k{i}" for i, expr in enumerate(keys))
        group = ", ".join(f"k{i}" for i in range(len(keys)))
        out: dict[tuple, int] = {}
        for lo, hi in self._slices(start, end):
            rows = self._query(
                f"SELECT {select}, COUNT(*) FROM records "
                f"WHERE timestamp >= ? AND timestamp < ?{where} GROUP BY {group}",
                (lo, hi, *args),
            )
            for row in rows:
                key = tuple(row[i] for i in range(len(keys)))
                out[key] = out.get(key, 0) + int(row[len(keys)])
        return out

    @staticmethod
    def _add(*parts: dict[tuple, int]) -> dict[tuple, int]:
        out: dict[tuple, int] = {}
        for part in parts:
            for key, count in part.items():
                out[key] = out.get(key, 0) + count
        return out

    def _observed(self, windows: list[_Window], keys: tuple[str, ...], where: str = "", args: tuple = ()) -> list[dict]:
        return [self._counts(self._iso(w.start), self._iso(w.end), keys, where, args) for w in windows]

    def _baselines(
        self, windows: list[_Window], observed: list[dict], keys: tuple[str, ...], where: str, args: tuple
    ) -> list[dict[tuple, int]]:
        """Baseline counts for each window, sharing the long scan between the
        previous-hour and current-hour windows: their baselines differ only by
        one hour at each end, and the newer one's extra hour is exactly the
        previous window's observation."""
        if len(windows) == 2:
            prev, cur = windows
            core = self._counts(self._iso(cur.baseline_start), self._iso(prev.start), keys, where, args)
            head = self._counts(self._iso(prev.baseline_start), self._iso(cur.baseline_start), keys, where, args)
            return [self._add(head, core), self._add(core, observed[0])]
        return [
            self._counts(self._iso(w.baseline_start), self._iso(w.start), keys, where, args) for w in windows
        ]

    def _samples(self, window: _Window, where: str, args: tuple) -> list[sqlite3.Row]:
        """The first rows (by time) of one group, enough for its evidence."""
        limit = max(self.cfg.sample_timestamps_max, _SAMPLE_SCAN_ROWS)
        return self._query(
            "SELECT timestamp, severity_bucket, message FROM records "
            f"WHERE timestamp >= ? AND timestamp < ?{where} ORDER BY timestamp, id LIMIT ?",
            (self._iso(window.start), self._iso(window.end), *args, limit),
        )

    def _hours_with_data(self, start: datetime, end: datetime) -> int:
        """Clock hours in [start, end) holding at least one record of any
        namespace. Far below the baseline's length usually means an ingestion
        gap (an outage, not a quiet cluster), which dilutes the baseline."""
        hour = start.replace(minute=0, second=0, microsecond=0)
        found = 0
        while hour < end:
            lo, hi = max(hour, start), min(hour + timedelta(hours=1), end)
            if self._query("SELECT 1 FROM records WHERE timestamp >= ? AND timestamp < ? LIMIT 1",
                           (self._iso(lo), self._iso(hi))):
                found += 1
            hour += timedelta(hours=1)
        return found

    def _evidence(self, window: _Window, count: int, samples: list, **extra: Any) -> dict[str, Any]:
        sample_messages: list[str] = []
        for r in samples:
            try:
                msg = str(r["message"]).strip()
            except (KeyError, TypeError, IndexError):
                msg = ""
            if msg and msg not in sample_messages:
                sample_messages.append(msg)
            if len(sample_messages) >= 5:
                break

        evidence = {
            "window_start": self._iso(window.start),
            "window_end": self._iso(window.hour_end),
            "window_complete": not window.partial,
            "observed_minutes": round(window.hours * 60, 1),
            "current_count": count,
            "baseline_window_days": self.cfg.baseline_window_days,
            "baseline_hours": round(window.baseline_hours, 1),
            # Hours of the baseline that hold any data at all; empty hours are
            # averaged in as zero, so a gap here can make normal volume look
            # like a spike.
            "baseline_hours_with_data": self._hours_with_data(window.baseline_start, window.start),
            "sample_timestamps": [r["timestamp"] for r in samples[: self.cfg.sample_timestamps_max]],
            "sample_messages": sample_messages,
        }
        evidence.update(extra)
        return evidence

    @staticmethod
    def _in_list(column: str) -> str:
        # One bound JSON array instead of one parameter per value.
        return f" AND {column} IN (SELECT value FROM json_each(?))"

    def _rate_anomalies(
        self,
        now: datetime,
        *,
        type_: str,
        keys: tuple[str, ...],
        where: str,
        multiplier: float,
        min_count: int,
        describe: Callable[[tuple], tuple[str, str, str, str]],
        sample_filter: Callable[[tuple], tuple[str, tuple]],
        baseline_filter: Callable[[set[tuple]], tuple[str, tuple]],
    ) -> list[dict[str, Any]]:
        """Shared rule for error spikes and message frequency: a group is
        anomalous when its count in the window reaches `min_count` and is at
        least `multiplier` times the baseline's expected count for the same
        observed duration. The newest flagged window wins per group."""
        windows = self._windows(now)
        if not windows:
            return []
        observed = self._observed(windows, keys, where)
        candidates = {key for counts in observed for key, n in counts.items() if n >= min_count}
        if not candidates:
            return []
        extra_where, extra_args = baseline_filter(candidates)
        baselines = self._baselines(windows, observed, keys, where + extra_where, extra_args)

        found: dict[tuple, dict[str, Any]] = {}
        for window, counts, baseline in zip(windows, observed, baselines):
            for key, count in counts.items():
                if key not in candidates:
                    continue
                avg = baseline.get(key, 0) / max(window.baseline_hours, 1e-9)
                expected = avg * window.hours
                if not is_spike(count, expected, multiplier, min_count):
                    continue
                namespace, pod, rule_key, severity = describe(key)
                sample_where, sample_args = sample_filter(key)
                found[key] = {
                    "type": type_,
                    "namespace": namespace,
                    "pod": pod,
                    "rule_key": rule_key,
                    "severity": severity,
                    "evidence": self._evidence(
                        window, count, self._samples(window, sample_where, sample_args),
                        baseline_avg_per_hour=round(avg, 3),
                        expected_count=round(expected, 3),
                        multiplier=multiplier,
                    ),
                }
        return list(found.values())

    def detect_error_spikes(self, now: datetime, *, per_pod: bool = False) -> list[dict[str, Any]]:
        error_only = " AND severity_bucket='error'"
        return self._rate_anomalies(
            now,
            type_="error_rate_spike",
            keys=("namespace", "pod") if per_pod else ("namespace", "''"),
            where=error_only,
            multiplier=self.cfg.spike_multiplier,
            min_count=self.cfg.spike_min_count,
            describe=lambda key: (key[0], key[1], "", "error"),
            sample_filter=lambda key: (
                (error_only + " AND namespace = ? AND pod = ?", (key[0], key[1]))
                if per_pod else (error_only + " AND namespace = ?", (key[0],))
            ),
            baseline_filter=lambda keys: (
                self._in_list("namespace"), (json.dumps(sorted({k[0] for k in keys})),)
            ),
        )

    def detect_message_frequency(self, now: datetime) -> list[dict[str, Any]]:
        rule_key = f"{_RULE_KEY_SQL_FUNCTION}(message)"
        return self._rate_anomalies(
            now,
            type_="message_frequency",
            keys=("namespace", rule_key),
            where="",
            multiplier=self.cfg.frequency_multiplier,
            min_count=self.cfg.frequency_min_count,
            describe=lambda key: (key[0], "", key[1], ""),
            sample_filter=lambda key: (f" AND namespace = ? AND {rule_key} = ?", key),
            baseline_filter=lambda keys: (
                self._in_list("namespace") + self._in_list(rule_key),
                (json.dumps(sorted({k[0] for k in keys})), json.dumps(sorted({k[1] for k in keys}))),
            ),
        )

    def detect_new_falco_rules(self, now: datetime) -> list[dict[str, Any]]:
        """Falco rules firing in a window that did not fire in the baseline
        before it (at most baseline_window_days; less on a young install). The
        look-back is bounded so the cost does not grow with the cache's
        retention period."""
        windows = self._windows(now)
        if not windows:
            return []
        rule_key = f"{_RULE_KEY_SQL_FUNCTION}(message)"
        security = " AND scope='security'"
        observed = self._observed(windows, (rule_key,), security)
        candidates = sorted({key[0] for counts in observed for key in counts})
        if not candidates:
            return []
        in_candidates = (self._in_list(rule_key), (json.dumps(candidates),))
        seen_before = [
            {key[0] for key in baseline}
            for baseline in self._baselines(
                windows, observed, (rule_key,), security + in_candidates[0], in_candidates[1]
            )
        ]

        found: dict[str, dict[str, Any]] = {}
        for window, counts, seen in zip(windows, observed, seen_before):
            for (key,), count in counts.items():
                if key in seen or key in found:
                    continue  # known rule, or already reported for the earlier window
                samples = self._samples(window, f"{security} AND {rule_key} = ?", (key,))
                if not samples:
                    continue
                found[key] = {
                    "type": "new_falco_rule",
                    "namespace": "",
                    "pod": "",
                    "rule_key": key,
                    "severity": samples[0]["severity_bucket"],
                    "evidence": self._evidence(
                        window, count, samples, first_seen_timestamp=samples[0]["timestamp"]
                    ),
                }
        return list(found.values())

    def detect_severity_shift(self, now: datetime) -> list[dict[str, Any]]:
        """A namespace's share of lines in one severity bucket in the window
        versus that same namespace's share over its baseline. Both shares use
        the namespace's own total, so busy namespaces cannot dilute the
        baseline of quiet ones. A namespace with no baseline lines has nothing
        to shift from and is skipped (new error activity is the error-spike
        detector's job). Shares are ratios, so partial windows need no scaling."""
        windows = self._windows(now)
        if not windows:
            return []
        keys = ("namespace", "severity_bucket")
        observed = self._observed(windows, keys)
        namespaces = sorted({key[0] for counts in observed for key in counts})
        if not namespaces:
            return []
        baselines = self._baselines(windows, observed, keys, self._in_list("namespace"), (json.dumps(namespaces),))

        found: dict[tuple, dict[str, Any]] = {}
        for window, current, baseline in zip(windows, observed, baselines):
            current_totals: dict[str, int] = {}
            for (namespace, _), count in current.items():
                current_totals[namespace] = current_totals.get(namespace, 0) + count
            baseline_totals: dict[str, int] = {}
            for (namespace, _), count in baseline.items():
                baseline_totals[namespace] = baseline_totals.get(namespace, 0) + count
            for (namespace, bucket), current_count in sorted(current.items()):
                baseline_total = baseline_totals.get(namespace, 0)
                if baseline_total == 0 or current_count < self.cfg.shift_min_count:
                    continue
                current_share = current_count / current_totals[namespace]
                baseline_share = baseline.get((namespace, bucket), 0) / baseline_total
                if abs(current_share - baseline_share) < self.cfg.shift_share_delta:
                    continue
                samples = self._samples(window, " AND namespace = ? AND severity_bucket = ?", (namespace, bucket))
                found[(namespace, bucket)] = {
                    "type": "severity_shift",
                    "namespace": namespace,
                    "pod": "",
                    "rule_key": "",
                    "severity": bucket,
                    "evidence": self._evidence(
                        window, current_count, samples,
                        current_share=round(current_share, 3),
                        baseline_share=round(baseline_share, 3),
                        baseline_total=baseline_total,
                    ),
                }
        return list(found.values())

    def future_record_count(self, now: datetime, tolerance: timedelta = timedelta(minutes=5)) -> int:
        """Records stamped ahead of `now` (clock skew or a wrong timezone). No
        window ever evaluates them, so they are reported instead."""
        row = self._query("SELECT COUNT(*) FROM records WHERE timestamp > ?", (self._iso(now + tolerance),))
        return int(row[0][0]) if row else 0

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
        records_lock: threading.RLock | None = None,
        dispatcher: Callable[[list[dict[str, Any]]], int] | None = None,
    ):
        self.cfg = cfg
        self.store = store
        self.detector = InsightsDetector(records_conn, cfg.insights, records_lock)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_error_at: str | None = None
        self.last_duration_ms: int | None = None
        self.last_counts: dict[str, int] = {}
        self.consecutive_failures = 0
        self.future_dated_records = 0
        # Last AI provider failure (already key- and content-redacted by
        # ai_summary); detection keeps running while the provider is down.
        self.last_ai_error: str | None = None
        self.last_ai_error_at: str | None = None
        self._summarizer = summarizer
        # When set, pending anomalies are handed to this non-blocking queue
        # (summary_worker.SummaryWorker.enqueue) instead of being summarized
        # inline, so a slow provider never delays detection.
        self._dispatcher = dispatcher
        # anomaly id -> consecutive failures; only ids still pending are kept.
        self._ai_failures: dict[int, int] = {}

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.cfg.insights.enabled),
            "running": self._thread.is_alive(),
            "detect_interval_secs": self.cfg.insights.detect_interval_secs,
            "last_run_at": self.last_run_at,
            "last_duration_ms": self.last_duration_ms,
            "last_counts": dict(self.last_counts),
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
            "consecutive_failures": self.consecutive_failures,
            "last_ai_error": self.last_ai_error,
            "last_ai_error_at": self.last_ai_error_at,
            # True while there is less stored history than min_baseline_hours:
            # rate-based detection is waiting for a baseline.
            "learning": self.detector.learning,
            # Records timestamped more than 5 minutes ahead of the clock.
            "future_dated_records": self.future_dated_records,
            "history_hours": self.detector.history_hours,
            # Hours of history needed before rate-based detectors fire.
            "min_baseline_hours": min(
                max(1.0, float(self.cfg.insights.min_baseline_hours)), self.cfg.insights.baseline_window_days * 24.0
            ),
        }

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # logged and surfaced in /api/status; never kills the loop
                self.consecutive_failures += 1
                self.last_error = str(exc)[:500]
                self.last_error_at = _utc_now_iso()
                logger.exception("Insights run failed (%d in a row)", self.consecutive_failures)
            self._stop.wait(self.cfg.insights.detect_interval_secs)

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        started = time.monotonic()
        now = now or datetime.now(timezone.utc)
        counts = self.detect_once(now)
        self.future_dated_records = self.detector.future_record_count(now)
        if self._dispatcher is not None:
            counts["anomalies_queued"] = self.dispatch_pending()
        else:
            counts["anomalies_summarized"] = self.summarize_pending()
        self.last_duration_ms = int((time.monotonic() - started) * 1000)
        self.last_run_at = _utc_now_iso()
        self.last_counts = counts
        self.last_error = None
        self.consecutive_failures = 0
        return counts

    def detect_once(self, now: datetime) -> dict[str, int]:
        counts = {"anomalies_created": 0, "anomalies_updated": 0, "anomalies_recurred": 0, "anomalies_unchanged": 0}
        for anomaly in self.detector.detect_all(now):
            # The day of the window, not of the run: the previous hour checked
            # just after midnight belongs to the day before.
            day = str(anomaly["evidence"].get("window_start") or now.strftime("%Y-%m-%d"))[:10]
            _, outcome = self.store.record_detection(
                type=anomaly["type"],
                namespace=anomaly["namespace"],
                pod=anomaly["pod"],
                rule_key=anomaly["rule_key"],
                severity=anomaly["severity"],
                evidence=anomaly["evidence"],
                detected_day=day,
            )
            counts[f"anomalies_{outcome}"] += 1
        return counts

    def dispatch_pending(self) -> int:
        """Hand pending anomalies to the summary queue; returns how many it took."""
        limit = max(50, self.cfg.ai.max_anomalies_per_tick * 10)
        try:
            return int(self._dispatcher(self.store.pending_ai_anomalies(limit)) or 0)  # type: ignore[misc]
        except Exception as exc:  # the queue must never fail detection
            logger.warning("Could not queue anomalies for AI summaries (%s)", type(exc).__name__)
            return 0

    def summarize_pending(self) -> int:
        summarizer = self._summarizer or (lambda anomaly: None)
        count = 0
        pending = self.store.pending_ai_anomalies(self.cfg.ai.max_anomalies_per_tick)
        pending_ids = {int(a["id"]) for a in pending}
        self._ai_failures = {k: v for k, v in self._ai_failures.items() if k in pending_ids}
        for anomaly in pending:
            anomaly_id = int(anomaly["id"])
            try:
                result = summarizer(anomaly)
            except Exception as exc:
                self.last_ai_error = str(exc)[:500]
                self.last_ai_error_at = _utc_now_iso()
                failures = self._ai_failures.get(anomaly_id, 0) + 1
                logger.warning(
                    "AI summarization failed for anomaly %s (attempt %d/%d): %s",
                    anomaly_id, failures, _MAX_AI_ATTEMPTS_PER_ANOMALY, exc,
                )
                if failures >= _MAX_AI_ATTEMPTS_PER_ANOMALY:
                    # Provider error messages are already key-redacted.
                    self.store.record_ai_failure(anomaly_id, str(exc)[:500])
                    self._ai_failures.pop(anomaly_id, None)
                else:
                    self._ai_failures[anomaly_id] = failures
                continue
            self._ai_failures.pop(anomaly_id, None)
            self.last_ai_error = None
            if result:
                self.store.save_ai_summary(
                    int(anomaly["id"]),
                    result["summary"],
                    result.get("suggested_action", ""),
                    result.get("steps"),
                )
                count += 1
        return count
