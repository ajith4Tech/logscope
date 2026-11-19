"""Per-source-IP web behavior: brute force, scanning and floods.

Signatures and message_frequency group on a message template, so a scanner
that requests 50 different paths once each (50 templates at count 1) stays
under every volume floor. This module groups access-log records (records
with http_meta) by (namespace, client_ip) over a trailing window instead.

Per group, on each insights run (no thread of its own): total requests,
distinct paths (query string removed), the most repeated path and its
401/403 share, the 401/403/404/5xx breakdown, and the attack types of web
signatures already matched for this IP (read from anomalies whose sample
lines carry the IP, as classified at detection time; no matching here).

Subtypes (webapp.security.behavioral.*), one anomaly per subtype matched:
  brute_force  one path >= brute_force_min_repeats requests, of which at least
               brute_force_auth_fail_ratio are 401/403
  scanning     >= scanning_min_paths distinct paths with at least
               scanning_not_found_ratio 404s, or a scanner signature
               already matched for this IP
  flood        >= flood_requests requests in window_s, whatever the status

Skipped entirely: source IPs inside trusted_cidrs; requests whose User-Agent
contains a trusted_user_agents string are left out of the counts; groups
whose first request falls inside the namespace's cold-start grace
(webapp.insights.cold_start_grace_s, the existing guard), since start-up
health checks can look like a flood.

Stored as anomalies of type web_behavioral, rule_key "<subtype>:<client_ip>",
pod = the group's busiest pod ("-" when the access log has none), with
attack_type = subtype and attack_confidence set at creation (so the security
incident correlator uses them unchanged). A continuing behavior updates its
open row; cooldown_s of quiet ends the occurrence (AnomalyStore
.record_behavioral).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .ai_summary import redact_text

logger = logging.getLogger(__name__)

TYPE = "web_behavioral"
SUBTYPES = ("brute_force", "scanning", "flood")
# Bounds one run: aggregated (namespace, ip, pod, path, status) rows read.
MAX_GROUP_ROWS = 200_000
TOP_PATHS = 5
SCANNER_ATTACK_TYPES = frozenset({"scanner"})

# One row per (namespace, client_ip, pod, path, status) in the window. The
# literal "http_meta IS NOT NULL" lets SQLite use the partial index
# idx_records_http_epoch (storage._RECORD_INDEXES), which holds access-log
# rows only.
GROUP_SQL = """
SELECT namespace,
       json_extract(http_meta, '$.client_ip') AS client_ip,
       pod,
       json_extract(http_meta, '$.path') AS path,
       CAST(json_extract(http_meta, '$.status') AS INTEGER) AS status,
       COUNT(*) AS n,
       MIN(ts_epoch) AS first_ts,
       MAX(ts_epoch) AS last_ts
FROM records
WHERE ts_epoch >= ? AND ts_epoch < ? AND http_meta IS NOT NULL
  AND json_extract(http_meta, '$.client_ip') IS NOT NULL{ua_filter}
GROUP BY namespace, client_ip, pod, path, status
LIMIT ?
"""


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path_key(path: Any) -> str:
    """The path without its query string ("/?author=3" -> "/")."""
    return str(path or "").split("?", 1)[0] or "/"


@dataclass
class Group:
    namespace: str
    client_ip: str
    total: int = 0
    first_ts: float = float("inf")
    last_ts: float = 0.0
    statuses: dict[str, int] = field(default_factory=lambda: {"401": 0, "403": 0, "404": 0, "5xx": 0, "other": 0})
    paths: dict[str, list[int]] = field(default_factory=dict)  # path -> [requests, 401/403]
    pods: dict[str, int] = field(default_factory=dict)

    def add(self, row: dict[str, Any]) -> None:
        n = int(row["n"])
        status = int(row["status"] or 0)
        self.total += n
        self.first_ts = min(self.first_ts, float(row["first_ts"]))
        self.last_ts = max(self.last_ts, float(row["last_ts"]))
        bucket = str(status) if status in (401, 403, 404) else ("5xx" if 500 <= status <= 599 else "other")
        self.statuses[bucket] += n
        counts = self.paths.setdefault(_path_key(row["path"]), [0, 0])
        counts[0] += n
        if status in (401, 403):
            counts[1] += n
        pod = str(row["pod"] or "-")
        self.pods[pod] = self.pods.get(pod, 0) + n

    @property
    def top_path(self) -> tuple[str, int, int]:
        path, (count, auth_fail) = max(self.paths.items(), key=lambda item: (item[1][0], item[0]))
        return path, count, auth_fail

    @property
    def pod(self) -> str:
        return max(self.pods.items(), key=lambda item: (item[1], item[0]))[0] if self.pods else "-"


class BehavioralDetector:
    """One pass per insights run over [now - window_s, now). `records_conn`
    reads records and anomalies; anomalies are written through `store`
    (insights.AnomalyStore.record_behavioral)."""

    def __init__(self, cfg: Any, records_conn: sqlite3.Connection, store: Any, *,
                 clock: Callable[[], datetime] | None = None):
        self.cfg = cfg
        self._conn = records_conn
        self._lock = threading.RLock()
        self.store = store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_counts: dict[str, int] = {}
        self._first_seen: dict[str, float | None] = {}

    @property
    def bcfg(self) -> Any:
        return self.cfg.security.behavioral

    def _rows(self, sql: str, args: tuple) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]

    # -- one pass ------------------------------------------------------------------

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        if not self.bcfg.enabled:
            return {}
        now = (now or self._clock()).astimezone(timezone.utc)
        counts = {"behavioral_created": 0, "behavioral_updated": 0, "behavioral_skipped": 0}
        try:
            self._first_seen = {}
            start = now - timedelta(seconds=float(self.bcfg.window_s))
            groups = self.groups(start, now)
            signatures = self._signature_types(groups, start)
            for group in groups.values():
                if self._skipped(group):
                    counts["behavioral_skipped"] += 1
                    continue
                for anomaly in self.evaluate(group, signatures.get((group.namespace, group.client_ip), set()), now):
                    _, outcome = self.store.record_behavioral(
                        **anomaly, now=now, cooldown_s=float(self.bcfg.cooldown_s))
                    counts[f"behavioral_{outcome}"] += 1
            self.last_error = None
        except Exception as exc:
            self.last_error = type(exc).__name__
            raise
        finally:
            self.last_run_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.last_counts = counts
        return counts

    def query(self) -> tuple[str, tuple]:
        """The grouping SQL and its trusted-User-Agent arguments."""
        agents = [a.lower() for a in self.bcfg.trusted_user_agents]
        ua_filter = ""
        if agents:
            ua = "lower(COALESCE(json_extract(http_meta, '$.user_agent'), ''))"
            ua_filter = "\n  AND NOT (" + " OR ".join(f"instr({ua}, ?) > 0" for _ in agents) + ")"
        return GROUP_SQL.format(ua_filter=ua_filter), tuple(agents)

    def groups(self, start: datetime, end: datetime) -> dict[tuple[str, str], Group]:
        sql, agent_args = self.query()
        rows = self._rows(sql, (start.timestamp(), end.timestamp(), *agent_args, MAX_GROUP_ROWS))
        if len(rows) >= MAX_GROUP_ROWS:
            logger.warning("Behavioral detection read its cap of %d groups; some traffic was not evaluated",
                           MAX_GROUP_ROWS)
        groups: dict[tuple[str, str], Group] = {}
        for row in rows:
            key = (str(row["namespace"]), str(row["client_ip"]))
            groups.setdefault(key, Group(*key)).add(row)
        return groups

    def _signature_types(self, groups: dict[tuple[str, str], Group], start: datetime) -> dict[tuple, set[str]]:
        """Attack types of web signatures already matched (anomalies classified
        at detection time) whose sample lines carry the group's IP."""
        if not groups:
            return {}
        namespaces = sorted({ns for ns, _ in groups})
        rows = self._rows(
            "SELECT namespace, attack_type, evidence FROM anomalies WHERE type != ? AND attack_type IS NOT NULL "
            "AND namespace IN (SELECT value FROM json_each(?)) AND json_extract(evidence, '$.window_end') >= ?",
            (TYPE, json.dumps(namespaces), start.strftime("%Y-%m-%dT%H:%M:%SZ")))
        out: dict[tuple, set[str]] = {}
        for row in rows:
            try:
                messages = json.loads(row["evidence"]).get("sample_messages") or []
            except (TypeError, ValueError, AttributeError):
                continue
            text = "\n".join(m for m in messages if isinstance(m, str))
            for ns, ip in groups:
                if ns == row["namespace"] and re.search(rf"(?<![\w.:]){re.escape(ip)}(?![\w.:])", text):
                    out.setdefault((ns, ip), set()).add(str(row["attack_type"]))
        return out

    # -- skips ---------------------------------------------------------------------

    def _trusted_ip(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip.strip().strip("[]"))
        except ValueError:
            return False  # not an address: never trusted
        for cidr in self.bcfg.trusted_cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _namespace_first_seen(self, namespace: str) -> float | None:
        if namespace not in self._first_seen:
            rows = self._rows("SELECT MIN(ts_epoch) AS first FROM records WHERE namespace = ?", (namespace,))
            first = rows[0]["first"] if rows else None
            self._first_seen[namespace] = float(first) if first is not None else None
        return self._first_seen[namespace]

    def _in_cold_start(self, group: Group) -> bool:
        """The group's first request falls inside its namespace's cold-start
        grace (the insights guard, measured at event time)."""
        grace = float(self.cfg.insights.cold_start_grace_s)
        first = self._namespace_first_seen(group.namespace)
        return grace > 0 and first is not None and group.first_ts < first + grace

    def _skipped(self, group: Group) -> bool:
        return self._trusted_ip(group.client_ip) or self._in_cold_start(group)

    # -- subtypes ------------------------------------------------------------------

    def evaluate(self, group: Group, signature_types: set[str], now: datetime) -> list[dict[str, Any]]:
        """The anomalies (record_behavioral arguments) this group raises."""
        b = self.bcfg
        path, repeats, auth_fail = group.top_path
        auth_ratio = auth_fail / repeats if repeats else 0.0
        not_found_ratio = group.statuses["404"] / group.total if group.total else 0.0
        distinct = len(group.paths)
        scanner_signature = bool(signature_types & SCANNER_ATTACK_TYPES)
        found: list[tuple[str, str]] = []
        if repeats >= b.brute_force_min_repeats and auth_ratio >= b.brute_force_auth_fail_ratio:
            high = repeats >= 2 * b.brute_force_min_repeats and auth_ratio >= 0.9
            found.append(("brute_force", "high" if high else "medium"))
        if (distinct >= b.scanning_min_paths and not_found_ratio >= b.scanning_not_found_ratio) or scanner_signature:
            high = scanner_signature or distinct >= 2 * b.scanning_min_paths
            found.append(("scanning", "high" if high else "medium"))
        if group.total >= b.flood_requests:
            found.append(("flood", "medium" if group.total >= 2 * b.flood_requests else "low"))
        if not found:
            return []
        top_paths = sorted(group.paths.items(), key=lambda item: (-item[1][0], item[0]))[:TOP_PATHS]
        evidence = {
            "client_ip": group.client_ip,
            # window_start / first_seen / sample_timestamps are kept from the
            # occurrence's first run (record_behavioral); the correlator reads
            # the attack start from sample_timestamps[0].
            "window_start": _iso(group.first_ts),
            "first_seen": _iso(group.first_ts),
            "sample_timestamps": [_iso(group.first_ts)],
            # The latest run that saw the behavior; the correlator looks
            # correlation_window_s past it.
            "window_end": _iso(now.timestamp()),
            # The latest matching request: cooldown_s of quiet counts from here.
            "last_seen": _iso(group.last_ts),
            "window_complete": True,
            "window_s": float(b.window_s),
            "observed_minutes": round(float(b.window_s) / 60, 1),
            "current_count": group.total,
            "total_requests": group.total,
            "distinct_paths": distinct,
            "max_path_repeat": repeats,
            "top_path": redact_text(path)[:200],
            "top_path_auth_fail_ratio": round(auth_ratio, 3),
            "not_found_ratio": round(not_found_ratio, 3),
            "status_counts": dict(group.statuses),
            "top_paths": [{"path": redact_text(p)[:200], "count": c[0]} for p, c in top_paths],
            "pods": dict(sorted(group.pods.items(), key=lambda item: -item[1])[:5]),
            "signature_attack_types": sorted(signature_types),
            "last_request": _iso(group.last_ts),
            # Behavioral evidence carries no raw log lines.
            "sample_messages": [],
        }
        out = []
        for subtype, confidence in found:
            out.append({
                "namespace": group.namespace, "pod": group.pod, "rule_key": f"{subtype}:{group.client_ip}",
                "severity": "warning", "evidence": {**evidence, "subtype": subtype},
                "attack_type": subtype, "attack_confidence": confidence,
            })
        return out

    def status(self) -> dict[str, Any]:
        return {"enabled": bool(self.bcfg.enabled), "last_run_at": self.last_run_at,
                "last_error": self.last_error, "last_counts": dict(self.last_counts)}


__all__ = ["BehavioralDetector", "GROUP_SQL", "SUBTYPES", "TYPE"]
