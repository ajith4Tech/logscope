"""Web -> runtime correlation: security incidents.

A web-attack anomaly (anomalies.attack_type set by a web signature, see
explain.classify_anomaly) followed by a Falco event (records with
scope='security') concerning the same namespace becomes one security incident.

Matching (Correlator.run_once, called by the insights job after each
detection run, so no extra thread):
  * candidates: anomalies with an attack_type, status new or reviewed (never
    suppressed_cold_start or dismissed), whose window ended within
    webapp.security.lookback_s, not linked to an incident yet and not already
    closed without a match for this window;
  * Falco events from the attack's first evidence line (the first sample
    timestamp, else the window start) to window_end + correlation_window_s,
    whose target (k8s.ns/k8s.pod output fields) is the anomaly's namespace;
  * an event still inside its target pod's (or namespace's) cold-start grace
    is never a match: start-up artifacts (an entrypoint shell) are not a
    post-attack chain;
  * the earliest event in the same or an adjacent pod (same ReplicaSet /
    StatefulSet name) gives confidence high, severity critical, and opens the
    incident at once; a namespace-only match (confidence medium, severity
    high) is taken only once the window is complete, so a later same-pod
    event in the window still wins;
  * a window that completes (ingest watermark past its end) without a match
    is recorded as checked and never re-opened;
  * except a web_behavioral occurrence (behavioral.py), which is updated in
    place while the behavior continues: its check keeps a checked_until
    point and is not final while the occurrence is open (quiet for less than
    webapp.security.behavioral.cooldown_s since its last request). Each run
    re-checks it from max(checked_until, attack start) to its horizon; once
    it is closed and checked to its horizon the check becomes final.

State is in the cache database next to the anomalies it links
(security_incidents, security_correlation_checks); one incident per
(web anomaly, Falco record) pair (UNIQUE) and at most one per anomaly. A
restart rebuilds from those tables: incidents whose notification or AI
summary was not handed off yet are resumed, nothing is created or sent twice.

Notifications go through the alert delivery queue (alerts.AlertEngine
.notify_external: durable, retried with backoff, never a sleep in process),
not gated by any alert rule. Content: identifiers, attack type, Falco rule,
times and a deep link; log-derived text is redacted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import re
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .ai_settings import INCIDENT_FEATURE
from .ai_summary import redact_text
from .channels import Message
from .explain import anomaly_signature, anomaly_template_summary, fill, templatize_text
from .insights import falco_target, rule_key_of
from .storage import SQLITE_BUSY_TIMEOUT_SECS

logger = logging.getLogger(__name__)

GROUP_PREFIX = "security_incident:"
AI_FLAG = "incident_correlation_ai"
INCIDENT_STATES = ("open", "acknowledged", "resolved")
CANDIDATE_BATCH = 200
FALCO_SCAN_ROWS = 2000
_BY_MAX = 80
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TEXT_RULE_RE = re.compile(r"^(?P<rule>[^:]{1,200}):\s*\d{2}:\d{2}:\d{2}\.\d+:\s*(?P<priority>[A-Za-z]+)?")
_TRAILING_POD_PART_RE = re.compile(r"-[a-z0-9]+$")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS security_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        namespace TEXT NOT NULL,
        pod TEXT,
        web_anomaly_id INTEGER NOT NULL REFERENCES anomalies(id),
        falco_record_id INTEGER NOT NULL,
        attack_type TEXT NOT NULL,
        attack_confidence TEXT,
        confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium')),
        severity TEXT NOT NULL CHECK (severity IN ('critical', 'high')),
        state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'acknowledged', 'resolved')),
        web_started_at TEXT,
        web_window_end TEXT,
        falco_ts TEXT NOT NULL,
        gap_s REAL,
        falco_rule TEXT NOT NULL DEFAULT '',
        falco_evidence TEXT NOT NULL DEFAULT '{}',
        opened_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        acknowledged_at TEXT,
        acknowledged_by TEXT,
        resolved_at TEXT,
        resolved_by TEXT,
        notified TEXT NOT NULL DEFAULT 'pending' CHECK (notified IN ('pending', 'queued', 'skipped')),
        notify_event_id INTEGER,
        ai_summary TEXT,
        ai_meta TEXT,
        ai_state TEXT,
        UNIQUE (web_anomaly_id, falco_record_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_security_incidents_state ON security_incidents(state, id)",
    "CREATE INDEX IF NOT EXISTS idx_security_incidents_anomaly ON security_incidents(web_anomaly_id)",
    # A web-attack anomaly's window that completed without a match: never
    # correlated again (a recurrence in a new window is checked on its own).
    """
    CREATE TABLE IF NOT EXISTS security_correlation_checks (
        anomaly_id INTEGER NOT NULL,
        window_start TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN ('incident', 'no_match')),
        checked_at TEXT NOT NULL,
        PRIMARY KEY (anomaly_id, window_start)
    )
    """,
)
# Added after the table shipped (ALTERed in when missing): how far a
# non-final check has searched (epoch seconds), and whether it is final.
# Existing rows, and every one-shot (signature) check, are final.
_CHECK_COLUMNS = (
    ("checked_until", "ALTER TABLE security_correlation_checks ADD COLUMN checked_until REAL"),
    ("final", "ALTER TABLE security_correlation_checks ADD COLUMN final INTEGER NOT NULL DEFAULT 1"),
)
BEHAVIORAL_TYPE = "web_behavioral"


class IncidentError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _evidence(anomaly: dict[str, Any]) -> dict[str, Any]:
    raw = anomaly.get("evidence")
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _json_object(raw: Any) -> dict[str, Any] | None:
    text = str(raw or "")
    start = text.find("{")
    if start < 0:
        return None
    try:
        data = json.loads(text[start:])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def falco_target_of(record: dict[str, Any]) -> tuple[str | None, str | None]:
    """(namespace, pod) a Falco record concerns: the k8s.ns=/k8s.pod= output
    fields in its text, else output_fields of its JSON line."""
    ns, pod = falco_target(str(record.get("message") or ""))
    if ns:
        return ns, pod
    data = _json_object(record.get("message")) or _json_object(record.get("raw_line")) or {}
    fields = data.get("output_fields") if isinstance(data.get("output_fields"), dict) else {}
    ns = fields.get("k8s.ns.name") or fields.get("k8s.ns")
    pod = fields.get("k8s.pod.name") or fields.get("k8s.pod")
    return (str(ns) if ns else None, str(pod) if pod else None)


def falco_rule_of(record: dict[str, Any]) -> tuple[str, str]:
    """(rule name, priority) of a Falco record: from its JSON line, else from
    the text form "<rule>: <hh:mm:ss.ns>: <Priority> <output>"."""
    data = _json_object(record.get("message")) or _json_object(record.get("raw_line")) or {}
    if isinstance(data.get("rule"), str) and data["rule"].strip():
        return data["rule"].strip()[:200], str(data.get("priority") or "")[:20]
    text = str(record.get("message") or "")
    match = _TEXT_RULE_RE.match(text)
    if match:
        return match.group("rule").strip(), (match.group("priority") or "")[:20]
    return redact_text(rule_key_of(text))[:200], ""


def workload_of(pod: str) -> str:
    """The pod's controller-level name: the last "-suffix" removed, so pods of
    one ReplicaSet (web-7d9f8b6c5d-x2kqp / -abcde) or StatefulSet (db-0 / db-1)
    are adjacent."""
    return _TRAILING_POD_PART_RE.sub("", pod or "")


def _attack_start(evidence: dict[str, Any]) -> datetime | None:
    samples = evidence.get("sample_timestamps") or []
    first = _parse(samples[0]) if samples and isinstance(samples[0], str) else None
    return first or _parse(evidence.get("window_start"))


def _gap_text(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    seconds = int(round(seconds))
    minutes, secs = divmod(abs(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min {secs} s" if minutes else f"{secs} s"


def _write(method):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            try:
                return method(self, *args, **kwargs)
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.rollback()
                raise

    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class IncidentStore:
    """security_incidents and security_correlation_checks, in the cache
    database next to the anomalies they link (own connection and lock)."""

    def __init__(self, db_path: Path):
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            for statement in _SCHEMA:  # additive: an existing database gains the tables
                self._conn.execute(statement)
            columns = {r[1] for r in self._conn.execute("PRAGMA table_info(security_correlation_checks)")}
            for name, statement in _CHECK_COLUMNS:
                if name not in columns:
                    self._conn.execute(statement)
            self._conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    # -- reads -------------------------------------------------------------------

    @staticmethod
    def _view(row: Any) -> dict[str, Any]:
        item = dict(row)
        for key, default in (("falco_evidence", {}), ("ai_meta", None)):
            try:
                item[key] = json.loads(item[key]) if item.get(key) else default
            except ValueError:
                item[key] = default
        return item

    def get(self, incident_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM security_incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._view(row) if row else None

    def list(self, *, state: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        where, args = ("WHERE state = ?", (state,)) if state else ("", ())
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM security_incidents {where} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        return [self._view(r) for r in rows]

    def counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT state, COUNT(*) FROM security_incidents GROUP BY state").fetchall()
        return {str(r[0]): int(r[1]) for r in rows}

    def pending(self, column: str) -> list[int]:
        """Incidents whose notification (column="notified") or AI summary
        (column="ai_state") has not been handed off yet."""
        sql = {"notified": "notified = 'pending'", "ai_state": "ai_state IS NULL"}[column]
        with self._lock:
            return [int(r[0]) for r in self._conn.execute(f"SELECT id FROM security_incidents WHERE {sql} ORDER BY id")]

    # -- writes ------------------------------------------------------------------

    @_write
    def create(self, values: dict[str, Any], *, window_start: str, now: datetime) -> int | None:
        """The incident and its check row in one transaction; None when this
        (anomaly, record) pair or this anomaly already has an incident."""
        stamp = _iso(now)
        with self._lock:
            if self._conn.execute("SELECT 1 FROM security_incidents WHERE web_anomaly_id = ?",
                                  (values["web_anomaly_id"],)).fetchone():
                return None
            columns = list(values)
            cur = self._conn.execute(
                f"INSERT OR IGNORE INTO security_incidents ({', '.join(columns)}, opened_at, updated_at) "
                f"VALUES ({', '.join('?' for _ in columns)}, ?, ?)", (*values.values(), stamp, stamp))
            if cur.rowcount == 0:
                self._conn.rollback()
                return None
            incident_id = int(cur.lastrowid)
            self._conn.execute(
                "INSERT OR REPLACE INTO security_correlation_checks (anomaly_id, window_start, outcome, checked_at) "
                "VALUES (?, ?, 'incident', ?)", (values["web_anomaly_id"], window_start, stamp))
            self._conn.commit()
            return incident_id

    @_write
    def record_no_match(self, anomaly_id: int, window_start: str, now: datetime, *,
                        checked_until: float | None = None, final: bool = True) -> None:
        """A check without a match. final (the default, one-shot anomalies):
        never correlated again. Not final (an open web_behavioral occurrence):
        searched up to checked_until, re-checked from there on later runs."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO security_correlation_checks "
                "(anomaly_id, window_start, outcome, checked_at, checked_until, final) "
                "VALUES (?, ?, 'no_match', ?, ?, ?) "
                "ON CONFLICT (anomaly_id, window_start) DO UPDATE SET checked_at = excluded.checked_at, "
                "checked_until = MAX(COALESCE(checked_until, 0), COALESCE(excluded.checked_until, 0)), "
                "final = excluded.final WHERE outcome = 'no_match' AND final = 0",
                (anomaly_id, window_start, _iso(now), checked_until, int(final)))
            self._conn.commit()

    @_write
    def mark_notified(self, incident_id: int, notified: str, event_id: int | None) -> None:
        with self._lock:
            self._conn.execute("UPDATE security_incidents SET notified = ?, notify_event_id = ? WHERE id = ?",
                               (notified, event_id, incident_id))
            self._conn.commit()

    @_write
    def set_ai(self, incident_id: int, state: str, *, summary: str | None = None,
               meta: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE security_incidents SET ai_state = ?, ai_summary = COALESCE(?, ai_summary), "
                "ai_meta = COALESCE(?, ai_meta) WHERE id = ?",
                (state, summary, json.dumps(meta, separators=(",", ":")) if meta else None, incident_id))
            self._conn.commit()

    @_write
    def transition(self, incident_id: int, action: str, by: str, now: datetime) -> dict[str, Any]:
        """acknowledge (open -> acknowledged) or resolve (open|acknowledged ->
        resolved). IncidentError 404 / 409 otherwise."""
        stamp = _iso(now)
        with self._lock:
            row = self._conn.execute("SELECT state FROM security_incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None:
                raise IncidentError("Incident not found", status=404)
            state = row["state"]
            if action == "acknowledge":
                if state != "open":
                    raise IncidentError(f"An incident that is {state} cannot be acknowledged")
                self._conn.execute(
                    "UPDATE security_incidents SET state = 'acknowledged', acknowledged_at = ?, acknowledged_by = ?, "
                    "updated_at = ? WHERE id = ?", (stamp, by, stamp, incident_id))
            elif action == "resolve":
                if state == "resolved":
                    raise IncidentError("The incident is already resolved")
                self._conn.execute(
                    "UPDATE security_incidents SET state = 'resolved', resolved_at = ?, resolved_by = ?, "
                    "updated_at = ? WHERE id = ?", (stamp, by, stamp, incident_id))
            else:
                raise IncidentError("Unknown action", status=404)
            self._conn.commit()
        return self.get(incident_id) or {}


def clean_actor(body: Any) -> str:
    """Who acknowledged/resolved, from an optional {"by": "..."}; "admin"."""
    if body is None:
        return "admin"
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object")
    unknown = sorted(str(k) for k in body if k != "by")
    if unknown:
        raise ValueError(f"Unknown field '{unknown[0]}'")
    by = body.get("by")
    if by is None or by == "":
        return "admin"
    if not isinstance(by, str) or len(by.strip()) > _BY_MAX or _CONTROL_RE.search(by):
        raise ValueError(f"'by' must be at most {_BY_MAX} characters without control characters")
    return by.strip() or "admin"


class Correlator:
    """One correlation pass per insights run (see the module docstring).

    records_conn reads anomalies and records (its own connection in the web
    app); `notify(incident) -> alert event id | None` queues the durable
    notification (None: no channel configured, skipped); `ai_dispatch(id)`
    hands the incident to the AI worker without blocking; complete_until(now)
    is how far the data is complete (the ingest watermark), default now."""

    def __init__(self, cfg: Any, store: IncidentStore, records_conn: sqlite3.Connection, *,
                 notify: Callable[[dict[str, Any]], int | None] | None = None,
                 ai_dispatch: Callable[[int], Any] | None = None,
                 complete_until: Callable[[datetime], datetime | None] | None = None):
        self.cfg = cfg
        self.store = store
        self._records = records_conn
        self._records_lock = threading.RLock()
        self._notify = notify
        self._ai_dispatch = ai_dispatch
        self._complete_until = complete_until or (lambda now: now)
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_counts: dict[str, int] = {}
        self._rebuilt = False
        self._first_seen_memo: dict[tuple[str, str | None], float | None] = {}

    @property
    def window_s(self) -> float:
        return float(self.cfg.security.correlation_window_s)

    @property
    def grace_s(self) -> float:
        grace = self.cfg.security.cold_start_grace_s
        return float(self.cfg.insights.cold_start_grace_s if grace is None else grace)

    def _rows(self, sql: str, args: tuple) -> list[dict[str, Any]]:
        with self._records_lock:
            cur = self._records.execute(sql, args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]

    # -- restart -------------------------------------------------------------------

    def rebuild(self) -> dict[str, int]:
        """Resume what a restart interrupted: incidents created but not yet
        handed to delivery (notify is idempotent per incident) or to the AI
        worker. Processed anomalies need nothing: the tables exclude them."""
        resumed = {"notify_resumed": 0, "ai_resumed": 0}
        for incident_id in self.store.pending("notified"):
            incident = self.store.get(incident_id)
            if incident and self._hand_off_notification(incident):
                resumed["notify_resumed"] += 1
        if self._ai_dispatch is not None:
            for incident_id in self.store.pending("ai_state"):
                self._ai_dispatch(incident_id)
                resumed["ai_resumed"] += 1
        self._rebuilt = True
        return resumed

    # -- one pass ------------------------------------------------------------------

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        if not self.cfg.security.correlation_enabled:
            return {}
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        counts = {"incidents_created": 0, "correlation_checked": 0, "correlation_no_match": 0}
        try:
            if not self._rebuilt:
                counts.update(self.rebuild())
            complete = self._complete_until(now)
            self._first_seen_memo = {}  # one lookup per (namespace, pod) per pass
            for anomaly in self._candidates(now):
                counts["correlation_checked"] += 1
                outcome = self._correlate(anomaly, now, complete)
                if outcome == "incident":
                    counts["incidents_created"] += 1
                elif outcome == "no_match":
                    counts["correlation_no_match"] += 1
            self.last_error = None
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}"[:200]
            raise
        finally:
            self.last_run_at = _iso(now)
        self.last_counts = counts
        return counts

    def _candidates(self, now: datetime) -> list[dict[str, Any]]:
        cutoff = _iso(now - timedelta(seconds=float(self.cfg.security.lookback_s) + self.window_s))
        return self._rows(
            """
            SELECT a.*, c.checked_until AS correlation_checked_until FROM anomalies a
            LEFT JOIN security_correlation_checks c
              ON c.anomaly_id = a.id AND c.window_start = json_extract(a.evidence, '$.window_start')
            WHERE a.attack_type IS NOT NULL AND a.attack_type != ''
              AND a.status IN ('new', 'reviewed')
              AND json_extract(a.evidence, '$.window_end') >= ?
              AND NOT EXISTS (SELECT 1 FROM security_incidents i WHERE i.web_anomaly_id = a.id)
              -- no check yet, or a non-final one (an open web_behavioral occurrence)
              AND (c.anomaly_id IS NULL OR (c.outcome = 'no_match' AND c.final = 0))
            ORDER BY a.id LIMIT ?
            """, (cutoff, CANDIDATE_BATCH))

    def _first_seen(self, namespace: str, pod: str | None) -> float | None:
        key = (namespace, pod or None)
        if key not in self._first_seen_memo:
            self._first_seen_memo[key] = self._query_first_seen(namespace, pod)
        return self._first_seen_memo[key]

    def _query_first_seen(self, namespace: str, pod: str | None) -> float | None:
        sql, args = "SELECT MIN(ts_epoch) FROM records WHERE namespace = ?", [namespace]
        if pod:
            sql += " AND pod = ?"
            args.append(pod)
        rows = self._rows(sql, tuple(args))
        value = next(iter(rows[0].values())) if rows else None
        return float(value) if value is not None else None

    def _in_cold_start(self, ts_epoch: float, namespace: str, pod: str | None) -> bool:
        """True when the event happened within the grace after its target
        pod (or, without a pod, its namespace) was first seen: the same
        guard insights applies to new_falco_rule, at the event's own time."""
        grace = self.grace_s
        if grace <= 0:
            return False
        first = self._first_seen(namespace, pod)
        return first is not None and ts_epoch < first + grace

    def _correlate(self, anomaly: dict[str, Any], now: datetime, complete: datetime | None) -> str:
        evidence = _evidence(anomaly)
        window_start = str(evidence.get("window_start") or "")
        window_end = _parse(evidence.get("window_end"))
        started = _attack_start(evidence)
        namespace = str(anomaly.get("namespace") or "")
        if window_end is None or started is None or not namespace:
            return "skipped"
        horizon = window_end + timedelta(seconds=self.window_s)
        window_complete = complete is not None and complete >= horizon
        behavioral = anomaly.get("type") == BEHAVIORAL_TYPE
        lower = started
        if behavioral and anomaly.get("correlation_checked_until") is not None:
            # Searched up to here on an earlier run: continue from there.
            lower = max(started, datetime.fromtimestamp(float(anomaly["correlation_checked_until"]), timezone.utc))
        same, other = self._match(anomaly, namespace, lower, horizon)
        record, high = (same, True) if same is not None else (other, False)
        if record is None or (not high and not window_complete):
            if not behavioral:
                if record is None and window_complete:
                    self.store.record_no_match(int(anomaly["id"]), window_start, now)
                    return "no_match"
                return "waiting"  # an incomplete window: a (same-pod) match may still come
            return self._behavioral_progress(anomaly, evidence, window_start, now, complete, horizon,
                                             lower, pending=record is not None)
        incident_id = self._open(anomaly, evidence, record, high, started, window_start, now)
        return "incident" if incident_id is not None else "exists"

    def _occurrence_closed(self, evidence: dict[str, Any], now: datetime) -> bool:
        """A web_behavioral occurrence is over once it has been quiet for
        cooldown_s since its last request (as AnomalyStore.record_behavioral
        decides: a later request then opens a new row)."""
        last = _parse(evidence.get("last_seen")) or _parse(evidence.get("window_end"))
        cooldown = float(self.cfg.security.behavioral.cooldown_s)
        return last is None or (now - last).total_seconds() > cooldown

    def _behavioral_progress(self, anomaly: dict[str, Any], evidence: dict[str, Any], window_start: str,
                             now: datetime, complete: datetime | None, horizon: datetime, lower: datetime,
                             *, pending: bool) -> str:
        """No incident this run for an updating web_behavioral occurrence:
        record how far it has been searched (to the watermark, at most its
        horizon), and make the check final once the occurrence is closed and
        searched to its horizon. A namespace-only match still waiting for its
        window to complete (pending) holds the point where it is."""
        if complete is None or pending:
            return "waiting"
        reached = min(complete, horizon)
        final = complete >= horizon and self._occurrence_closed(evidence, now)
        if reached <= lower and not final:
            return "waiting"
        self.store.record_no_match(int(anomaly["id"]), window_start, now,
                                   checked_until=max(reached, lower).timestamp(), final=final)
        return "no_match" if final else "checked"

    def _match(self, anomaly: dict[str, Any], namespace: str, start: datetime,
               end: datetime) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """(earliest same/adjacent-pod event, earliest namespace-only event)."""
        rows = self._rows(
            "SELECT id, timestamp, ts_epoch, namespace, pod, container, message, raw_line FROM records "
            "WHERE scope = 'security' AND ts_epoch >= ? AND ts_epoch <= ? AND instr(message, ?) > 0 "
            "ORDER BY ts_epoch, id LIMIT ?", (start.timestamp(), end.timestamp(), namespace, FALCO_SCAN_ROWS))
        pod = str(anomaly.get("pod") or "")
        other = None
        for row in rows:
            target_ns, target_pod = falco_target_of(row)
            if target_ns != namespace or self._in_cold_start(float(row["ts_epoch"]), namespace, target_pod):
                continue
            if pod and target_pod and (target_pod == pod or workload_of(target_pod) == workload_of(pod)):
                return row, other
            if other is None:
                other = row
        return None, other

    def _open(self, anomaly: dict[str, Any], evidence: dict[str, Any], record: dict[str, Any], high: bool,
              started: datetime, window_start: str, now: datetime) -> int | None:
        rule, priority = falco_rule_of(record)
        target_ns, target_pod = falco_target_of(record)
        falco_at = datetime.fromtimestamp(float(record["ts_epoch"]), timezone.utc)
        snapshot = {
            "record_id": int(record["id"]), "timestamp": record["timestamp"], "rule": rule, "priority": priority,
            "target_namespace": target_ns, "target_pod": target_pod,
            "source": f"{record['namespace']}/{record['pod']}/{record['container']}",
            # Redacted and bounded: the record itself may be pruned later.
            "output": redact_text(str(record.get("message") or ""))[:500],
        }
        values = {
            "namespace": anomaly["namespace"], "pod": anomaly.get("pod") or target_pod or None,
            "web_anomaly_id": int(anomaly["id"]), "falco_record_id": int(record["id"]),
            "attack_type": anomaly["attack_type"], "attack_confidence": anomaly.get("attack_confidence"),
            "confidence": "high" if high else "medium", "severity": "critical" if high else "high",
            "web_started_at": _iso(started), "web_window_end": evidence.get("window_end"),
            "falco_ts": _iso(falco_at), "gap_s": round((falco_at - started).total_seconds(), 1),
            "falco_rule": rule, "falco_evidence": json.dumps(snapshot, separators=(",", ":")),
        }
        incident_id = self.store.create(values, window_start=window_start, now=now)
        if incident_id is None:
            return None
        logger.warning("Security incident %s opened: %s attack on %s followed by Falco rule %r (confidence %s)",
                       incident_id, values["attack_type"], values["namespace"], rule, values["confidence"])
        incident = self.store.get(incident_id)
        if incident is not None:
            self._hand_off_notification(incident)
        if self._ai_dispatch is not None:
            self._ai_dispatch(incident_id)
        return incident_id

    def _hand_off_notification(self, incident: dict[str, Any]) -> bool:
        """Queue the incident's notification once. Left pending (retried on
        the next run) when queueing fails."""
        if self._notify is None:
            self.store.mark_notified(int(incident["id"]), "skipped", None)
            return True
        try:
            event_id = self._notify(incident)
        except Exception as exc:  # noqa: BLE001 - the incident is recorded; delivery is resumed later
            logger.warning("Queueing the notification of incident %s failed (%s)", incident["id"],
                           type(exc).__name__)
            return False
        self.store.mark_notified(int(incident["id"]), "queued" if event_id is not None else "skipped", event_id)
        return True

    def status(self) -> dict[str, Any]:
        return {"enabled": bool(self.cfg.security.correlation_enabled), "last_run_at": self.last_run_at,
                "last_error": self.last_error, "last_counts": dict(self.last_counts),
                "incidents": self.store.counts()}


# ─── Notification content ────────────────────────────────────────────────────


def _inline(value: Any, limit: int = 120) -> str:
    text = " ".join(redact_text(str(value or "")).replace("`", "'").split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return f"`{text or '—'}`"


def incident_links(incident: dict[str, Any], public_url: str) -> dict[str, str]:
    """Logs tab over both events (a minute either side), and the incident."""
    if not public_url:
        return {}
    start = _parse(incident.get("web_started_at"))
    end = _parse(incident.get("falco_ts"))
    params = {"tab": "logs"}
    if start and end:
        params.update({"from": _iso(min(start, end) - timedelta(minutes=1)),
                       "to": _iso(max(start, end) + timedelta(minutes=1))})
    return {"logs": f"{public_url}/?{urlencode(params)}",
            "incident": f"{public_url}/?{urlencode({'tab': 'insights', 'incident': incident['id']})}"}


def incident_message(incident: dict[str, Any], *, public_url: str = "",
                     when: Callable[[Any], str] = lambda v: str(v or "?")) -> Message:
    """Identifiers, the attack type, the Falco rule, both times and the gap,
    links; the AI summary when it is ready by delivery time. No log lines."""
    severity = str(incident.get("severity") or "high").upper()
    where = str(incident.get("namespace") or "?") + (f"/{incident['pod']}" if incident.get("pod") else "")
    title = f"{severity} · Security incident #{incident['id']} · web attack followed by runtime event in {where}"
    match = ("same or adjacent pod" if incident.get("confidence") == "high" else "same namespace, another pod")
    lines = [
        f"**Namespace** {_inline(incident.get('namespace'))}"
        + (f" · **Pod** {_inline(incident.get('pod'))}" if incident.get("pod") else ""),
        f"**Web attack** {_inline(incident.get('attack_type'), 40)} (signature confidence "
        f"{incident.get('attack_confidence') or 'n/a'}) · started {when(incident.get('web_started_at'))}",
        f"**Falco rule** {_inline(incident.get('falco_rule'), 160)} at {when(incident.get('falco_ts'))}",
        f"**Gap** {_gap_text(incident.get('gap_s'))} · **Correlation** {incident.get('confidence')} ({match})",
    ]
    if incident.get("ai_summary"):
        lines.append(f"**AI summary** {' '.join(redact_text(str(incident['ai_summary'])).split())[:600]}")
    links = incident_links(incident, public_url)
    data = {
        "kind": "security_incident", "incident_id": incident["id"], "severity": incident.get("severity"),
        "confidence": incident.get("confidence"), "namespace": incident.get("namespace"), "pod": incident.get("pod"),
        "attack_type": incident.get("attack_type"), "attack_confidence": incident.get("attack_confidence"),
        "falco_rule": redact_text(str(incident.get("falco_rule") or ""))[:200],
        "web_started_at": incident.get("web_started_at"), "falco_ts": incident.get("falco_ts"),
        "gap_s": incident.get("gap_s"), "url": links.get("logs"), "incident_url": links.get("incident"),
    }
    link_items = [("Logs for both events", links["logs"]), ("Incident", links["incident"])] if links else []
    return Message(title=title, lines=lines, links=link_items, data=data)


# ─── AI summary (off the detection path) ─────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a Kubernetes security assistant for Logscope. A web-attack anomaly and a Falco runtime event "
    "concerning the same namespace were correlated into one security incident. Using ONLY the provided fields, "
    "write one paragraph (at most five sentences) on what most likely happened and what to check first. "
    "State uncertainty plainly; do not invent facts, hosts or commands. "
    'Reply with exactly one JSON object: {"summary": "<paragraph>"}.'
)


class IncidentAi:
    """The "what likely happened" paragraph for a new incident, cheapest
    first: both halves answered by signatures (free), then the AI cache, then
    one metered call (incident_summary). Over budget: skipped, not retried.
    Runs on its own thread; enqueue() never blocks."""

    def __init__(self, store: IncidentStore, anomalies: Any, *, kb: Any, service: Any, settings: Any,
                 cache: Any, complete: Callable[[str, dict[str, Any], Any], dict[str, Any]],
                 configured: Callable[[], bool]):
        self.store = store
        self.anomalies = anomalies
        self.kb = kb
        self.service = service
        self.settings = settings
        self.cache = cache
        self.complete = complete
        self.configured = configured
        self._queue: queue.Queue[int] = queue.Queue(maxsize=200)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def enqueue(self, incident_id: int) -> None:
        try:
            self._queue.put_nowait(int(incident_id))
        except queue.Full:
            logger.warning("Incident AI queue full; incident %s left without a summary", incident_id)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="incident-ai")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                incident_id = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self.process(incident_id)

    def drain(self) -> list[str]:
        """Process everything queued now (tests, and shutdown-free callers)."""
        out = []
        while True:
            try:
                out.append(self.process(self._queue.get_nowait()))
            except queue.Empty:
                return out

    @staticmethod
    def _values(incident: dict[str, Any]) -> dict[str, str]:
        return {"namespace": str(incident.get("namespace") or ""), "pod": str(incident.get("pod") or ""),
                "container": ""}

    def _cache_key(self, incident: dict[str, Any]) -> str:
        rule = hashlib.sha1(str(incident.get("falco_rule") or "").encode(), usedforsecurity=False).hexdigest()[:16]
        return f"incident:fast:{incident.get('attack_type')}:{incident.get('confidence')}:{rule}"

    def process(self, incident_id: int) -> str:
        try:
            return self._process(incident_id)
        except Exception as exc:  # noqa: BLE001 - never retried in a loop; visible in /api/status
            self.last_error = f"{type(exc).__name__}"
            logger.warning("Incident %s AI summary failed (%s)", incident_id, type(exc).__name__)
            self.store.set_ai(incident_id, "error")
            return "error"

    def _process(self, incident_id: int) -> str:
        incident = self.store.get(incident_id)
        if incident is None or incident.get("ai_state"):
            return "done"
        if not self.settings.enabled(AI_FLAG):
            self.store.set_ai(incident_id, "disabled")
            return "disabled"
        anomaly = self.anomalies.get_anomaly(int(incident["web_anomaly_id"]))
        falco = incident.get("falco_evidence") or {}
        web_rule = anomaly_signature(self.kb, anomaly) if anomaly else None
        falco_rule = self.kb.match(falco.get("output") or "", str(incident.get("falco_rule") or ""))
        if web_rule is not None and falco_rule is not None:
            summary = self._signature_summary(incident, web_rule, falco_rule)
            self.service.signature_hit(INCIDENT_FEATURE)
            self.store.set_ai(incident_id, "done", summary=summary,
                              meta={"source": "signature", "signatures": [web_rule.id, falco_rule.id]})
            return "signature"
        if not self.configured():
            self.store.set_ai(incident_id, "unavailable")
            return "unavailable"
        values = self._values(incident)
        key = self._cache_key(incident)
        entry = self.cache.get(key)
        if entry and entry["response"].get("summary"):
            self.service.cache_hit(INCIDENT_FEATURE, "fast")
            summary = fill(entry["response"], values)["summary"]
            self.store.set_ai(incident_id, "done", summary=summary,
                              meta={"source": "cache", "cache_key": key, "generated_at": entry["created_at"]})
            return "cache"
        payload = self._payload(incident, anomaly, web_rule, falco_rule)
        result = self.service.call(
            INCIDENT_FEATURE, lambda cfg: self.complete(_SYSTEM_PROMPT, payload, cfg), tier="fast",
            input_chars=len(json.dumps(payload, ensure_ascii=False, default=str)),
            subjects=[f"incident:{incident_id}"])
        if not isinstance(result, dict) or result.get("degraded"):
            # Budget blocked (or no answer): skip silently, as auto-triage does.
            self.store.set_ai(incident_id, "budget_blocked" if isinstance(result, dict) else "error")
            return "budget_blocked" if isinstance(result, dict) else "error"
        summary = " ".join(redact_text(str(result.get("summary") or "")).split())[:1200]
        if not summary:
            self.store.set_ai(incident_id, "error")
            return "error"
        stored = {"summary": templatize_text(summary, values, command=False), "steps": [], "_templated": True}
        self.cache.put(key, kind="incident", tier="fast", response=stored)
        self.store.set_ai(incident_id, "done", summary=summary,
                          meta={"source": "ai", "tier": "fast", "cache_key": key})
        return "ai"

    @staticmethod
    def _signature_summary(incident: dict[str, Any], web_rule: Any, falco_rule: Any) -> str:
        where = str(incident.get("namespace") or "") + (f"/{incident['pod']}" if incident.get("pod") else "")
        place = "in the same pod" if incident.get("confidence") == "high" else "in another pod of the namespace"
        return (f"{web_rule.title} ({incident.get('attack_type')}, signature confidence "
                f"{incident.get('attack_confidence') or 'n/a'}) against {where} was followed "
                f"{_gap_text(incident.get('gap_s'))} later {place} by the Falco rule "
                f"'{incident.get('falco_rule')}': {falco_rule.title}. {falco_rule.explanation} "
                "Together this suggests the web attack may have reached code execution or file access in the "
                "workload; treat it as a possible compromise until the runtime event is explained.")

    @staticmethod
    def _payload(incident: dict[str, Any], anomaly: dict[str, Any] | None, web_rule: Any,
                 falco_rule: Any) -> dict[str, Any]:
        web: dict[str, Any] = {"namespace": incident.get("namespace"), "pod": incident.get("pod"),
                               "attack_type": incident.get("attack_type"),
                               "signature_confidence": incident.get("attack_confidence"),
                               "started_at": incident.get("web_started_at")}
        if anomaly is not None:
            web["anomaly_type"] = anomaly.get("type")
            web["pattern"] = anomaly.get("rule_key")
            if anomaly.get("ai_summary"):
                web["earlier_explanation"] = anomaly["ai_summary"]
        if web_rule is not None:
            web["signature"] = {"title": web_rule.title, "explanation": web_rule.explanation}
        falco = incident.get("falco_evidence") or {}
        runtime: dict[str, Any] = {"falco_rule": incident.get("falco_rule"), "priority": falco.get("priority"),
                                   "at": incident.get("falco_ts"), "target_pod": falco.get("target_pod"),
                                   "output": falco.get("output")}
        if falco_rule is not None:
            runtime["signature"] = {"title": falco_rule.title, "explanation": falco_rule.explanation}
        return {"web_attack": web, "runtime_event": runtime,
                "correlation": {"gap_seconds": incident.get("gap_s"), "match": incident.get("confidence")}}


def incident_detail(store: IncidentStore, incident_id: int, *, anomalies: Any, storage: Any, kb: Any,
                    public_url: str = "") -> dict[str, Any]:
    """One incident with both halves' evidence: the web anomaly (as the
    Insights tab shows it) and the Falco record (redacted; the stored
    snapshot when the record has been pruned)."""
    incident = store.get(incident_id)
    if incident is None:
        raise IncidentError("Incident not found", status=404)
    anomaly = anomalies.get_anomaly(int(incident["web_anomaly_id"]))
    if anomaly is not None:
        anomaly["template_summary"] = anomaly_template_summary(kb, anomaly)
    record = storage.get_record_by_id(int(incident["falco_record_id"]))
    falco: dict[str, Any] = dict(incident.get("falco_evidence") or {})
    if record is not None:
        falco.update({"available": True, "severity_bucket": record.get("severity_bucket"),
                      "output": redact_text(str(record.get("message") or ""))[:2000]})
    else:
        falco["available"] = False
    incident["web_anomaly"] = anomaly
    incident["falco_record"] = falco
    incident["links"] = incident_links(incident, public_url)
    return incident


__all__ = ["Correlator", "GROUP_PREFIX", "INCIDENT_STATES", "IncidentAi", "IncidentError", "IncidentStore", "clean_actor",
           "falco_rule_of", "falco_target_of", "incident_detail", "incident_message", "workload_of"]
