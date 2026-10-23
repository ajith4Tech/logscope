"""Alerts on saved views.

A rule counts what a saved view matches (count, error_count or
distinct_pods) over a sliding window and compares it with a threshold,
optionally per namespace or pod. Every window ends at the ingest watermark,
never at "now": the newest data is incomplete until Vector has flushed it to
S3 and a poll has read it.

Watermark (compute_watermark): per S3 prefix, everything an event could be in
had been flushed by the start of the prefix's latest complete listing minus
Vector's batch timeout; an object that is still failing holds its prefix back
to the object's key time. The watermark is the oldest of those, minus a safety
margin. Past 3× the batch timeout behind, the pipeline is stale: rules with
< or <= (absence rules) cannot tell "quiet" from "not ingested yet" and report
"unknown" without changing state, and one pipeline_stale alert goes to the
default (environment) channel.

States per (rule, group): ok → pending (until for_evals consecutive breaches)
→ firing → resolved → ok; an evaluation that cannot be made (timeout, stale
pipeline, no watermark) is "unknown" and changes nothing. Notifications: on
firing, every renotify_s while firing, and on resolved when notify_resolved.
A muted rule records events but sends nothing. Every transition is an
alert_events row, and the in-memory state is rebuilt from them at start, so
a restart neither forgets a firing alert nor notifies it again.

Delivery is durable: a notification is an alert_events row with
notified = queued and its next_attempt_at; the delivery thread sends what is
due, so a restart resumes pending (and backing-off) deliveries from the
database. When no channel accepts it, it is retried after 30 s, 1, 2, 5, 10
and 30 min, then hourly, until a day after the event; then it is
failed_final (an admin can still "retry now"). Once a newer transition of the
same (rule, group) has been delivered, older firing notifications still
waiting are superseded and never sent.

Messages carry counts, templates (patterns.py) and redacted exemplars, the
matching signature's title and a deep link; never raw log lines. An optional
per-rule AI summary uses the fast tier, metered as alert_summary, and is
skipped (delivery continues) when a budget is exhausted.
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from .ai_summary import compact_log_payload, redact_text
from .channels import ENV_CHANNEL_ID, ChannelStore, Deliverer, Message
from .filters import FilterError, iso_js, validate_filters
from .patterns import digest_records
from .state import StateDB

logger = logging.getLogger(__name__)

AI_FEATURE = "alert_summary"
RULES_MAX = 100
METRICS = ("count", "error_count", "distinct_pods")
OPS = ("<", "<=", ">", ">=")
ABSENCE_OPS = ("<", "<=")
GROUP_BYS = ("none", "namespace", "pod")
URGENCIES = ("low", "medium", "high", "urgent")
WINDOW_RANGE = (300, 86400)
INTERVAL_RANGE = (60, 3600)
FOR_RANGE = (1, 10)
MAX_GROUPS = 20
RENOTIFY_DEFAULT = 6 * 3600
RENOTIFY_RANGE = (300, 7 * 86400)
MUTE_MAX_SECS = 30 * 86400
LABELS_MAX = 20
CHANNELS_PER_RULE = 10
KEEP_DAYS = 30
PRUNE_BATCH = 1000
PRUNE_EVERY_SECS = 3600
QUERY_TIMEOUT_SECS = 2.0
BACKTEST_MAX_SECS = 7 * 86400
BACKTEST_MAX_BUCKETS = 20000
BACKTEST_SERIES_POINTS = 1000
SAMPLE_ROWS = 500
SPARK_POINTS = 30
STALE_FACTOR = 3
PIPELINE_GROUP = "pipeline_stale"
# alert_events.notified: what happened to the notification of this event.
# NOTIFY_FAILED is only found in rows written before durable delivery.
NOTIFY_NONE, NOTIFY_SENT, NOTIFY_QUEUED, NOTIFY_FAILED, NOTIFY_FAILED_FINAL, NOTIFY_SUPERSEDED = 0, 1, 2, 3, 4, 5
_NOTIFY_NAMES = {NOTIFY_NONE: "no", NOTIFY_SENT: "sent", NOTIFY_QUEUED: "queued", NOTIFY_FAILED: "failed",
                 NOTIFY_FAILED_FINAL: "failed_final", NOTIFY_SUPERSEDED: "superseded"}
# Delay before retry n (1-based) of a notification no channel accepted; after
# the last, hourly. No retry is scheduled later than DELIVERY_GIVE_UP_SECS
# after the event: it is failed_final instead.
RETRY_SCHEDULE_SECS = (30, 60, 120, 300, 600, 1800)
RETRY_HOURLY_SECS = 3600
DELIVERY_GIVE_UP_SECS = 24 * 3600
DELIVERY_BATCH = 200
_LABEL_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_STATE_ORDER = {"firing": 4, "pending": 3, "unknown": 2, "resolved": 1, "ok": 0}
# Saved-view URL keys -> storage filter parameters.
_VIEW_PARAMS = {"scope": "scope", "ns": "namespace", "pod": "pod", "ctr": "container", "sev": "severity_bucket",
                "q": "q", "qmode": "qmode"}
_EXCLUDE_KEYS = ("xscope", "xns", "xpod", "xctr", "xsev")
_GROUP_PARAM = {"namespace": ("namespace", "ns"), "pod": ("pod", "pod")}
_METRIC_LABELS = {"count": "entries", "error_count": "error entries", "distinct_pods": "distinct pods"}


class RuleError(Exception):
    def __init__(self, message: str, field: str | None = None, status: int = 422):
        super().__init__(message)
        self.field = field
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def breached(value: float, op: str, threshold: float) -> bool:
    return {"<": value < threshold, "<=": value <= threshold, ">": value > threshold,
            ">=": value >= threshold}[op]


def view_params(filters: dict[str, str]) -> dict[str, Any]:
    """A saved view's URL filters as storage parameters, time range left out
    (an alert window replaces it)."""
    out: dict[str, Any] = {}
    for key, param in _VIEW_PARAMS.items():
        if filters.get(key):
            out[param] = filters[key]
    for key in _EXCLUDE_KEYS:
        if filters.get(key):
            out[key] = [v for v in str(filters[key]).split(",") if v]
    return out


# ─── Watermark ───────────────────────────────────────────────────────────────


def _key_time(prefix: str, key: str, time_format: str) -> datetime | None:
    if not time_format or not key.startswith(prefix):
        return None
    width = len(datetime(2000, 1, 1).strftime(time_format))
    try:
        return datetime.strptime(key[len(prefix):len(prefix) + width], time_format).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def compute_watermark(progress: dict[str, dict[str, Any]], prefixes: list[str], now: datetime, *,
                      batch_timeout: int, margin: int, time_format: str) -> dict[str, Any]:
    """{"at": watermark or None, "lag_secs", "stale", "prefixes": [...]}.
    A prefix never listed completely makes the watermark unknown (None)."""
    items = []
    complete_times: list[datetime | None] = []
    for prefix in prefixes:
        info = progress.get(prefix) or {}
        listed = _parse(info.get("listed_ok_at"))
        complete = listed - timedelta(seconds=batch_timeout) if listed else None
        cursor_time = _key_time(prefix, str(info.get("cursor") or ""), time_format)
        failing_since = None
        failing = info.get("failing")
        if failing:
            failing_since = _key_time(prefix, str(failing.get("key") or ""), time_format)
            if failing_since is None:
                modified = _parse(failing.get("last_modified"))
                failing_since = modified - timedelta(seconds=batch_timeout) if modified else None
            if complete is not None and failing_since is not None and failing_since < complete:
                complete = failing_since
        complete_times.append(complete)
        items.append({
            "prefix": prefix,
            "listed_ok_at": iso_js(listed) if listed else None,
            "cursor_time": iso_js(cursor_time) if cursor_time else None,
            "failing_since": iso_js(failing_since) if failing_since else None,
            "complete_up_to": iso_js(complete) if complete else None,
        })
    at = None
    if complete_times and all(c is not None for c in complete_times):
        at = min(c for c in complete_times if c is not None) - timedelta(seconds=margin)
        at = at.replace(microsecond=0)
    lag = (now - at).total_seconds() if at else None
    stale = at is not None and lag > STALE_FACTOR * batch_timeout
    return {"at": iso_js(at) if at else None, "lag_secs": int(lag) if lag is not None else None,
            "stale": stale, "stale_after_secs": STALE_FACTOR * batch_timeout, "prefixes": items}


# ─── Rules ───────────────────────────────────────────────────────────────────


def _int_in(body: dict, key: str, low: int, high: int, default: int | None = None) -> int:
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise RuleError(f"'{key}' must be a whole number from {low} to {high}", key)
    return value


def _bool(body: dict, key: str, default: bool) -> int:
    value = body.get(key, default)
    if not isinstance(value, bool):
        raise RuleError(f"'{key}' must be true or false", key)
    return int(value)


def _choice(body: dict, key: str, choices: tuple, default: str | None = None) -> str:
    value = body.get(key, default)
    if value not in choices:
        raise RuleError(f"'{key}' must be one of {list(choices)}", key)
    return value


def _labels(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > LABELS_MAX:
        raise RuleError(f"'labels' must be an object with at most {LABELS_MAX} entries", "labels")
    out = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _LABEL_KEY_RE.match(key):
            raise RuleError("Label names are 1-64 characters of letters, digits and ._-", "labels")
        if not isinstance(item, str) or len(item) > 200 or _CONTROL_RE.search(item):
            raise RuleError(f"Label '{key}' must be a string of at most 200 characters", "labels")
        out[key] = item
    return out


_FIELDS = ("name", "view_id", "metric", "op", "threshold", "window_s", "interval_s", "for_evals", "group_by",
           "max_groups", "urgency", "channel_ids", "renotify_s", "notify_resolved", "enabled", "labels",
           "ai_summary")


def _rule_row(row: Any) -> dict[str, Any]:
    out = dict(row)
    out["channel_ids"] = json.loads(out.get("channel_ids") or "[]")
    out["labels"] = json.loads(out.get("labels") or "{}")
    for key in ("notify_resolved", "enabled", "ai_summary"):
        out[key] = bool(out[key])
    return out


class AlertRules:
    def __init__(self, db: StateDB, channels: ChannelStore, *, clock: Callable[[], datetime] = _now):
        self._db = db
        self._channels = channels
        self._clock = clock

    def _clean(self, body: Any, *, current: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise RuleError("Request body must be a JSON object")
        unknown = sorted(str(k) for k in body if k not in _FIELDS)
        if unknown:
            raise RuleError(f"Unknown field '{unknown[0]}'", unknown[0])
        merged = {**(current or {}), **body}
        values: dict[str, Any] = {}
        name = merged.get("name")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80 or _CONTROL_RE.search(name):
            raise RuleError("'name' is required (at most 80 characters)", "name")
        values["name"] = name.strip()
        view_id = merged.get("view_id")
        if "view_id" in body or current is None:
            if isinstance(view_id, bool) or not isinstance(view_id, int):
                raise RuleError("'view_id' must be the id of a saved view", "view_id")
            if self._db.conn.execute("SELECT 1 FROM saved_views WHERE id = ?", (view_id,)).fetchone() is None:
                raise RuleError("Saved view not found", "view_id")
        values["view_id"] = view_id
        values["metric"] = _choice(merged, "metric", METRICS)
        values["op"] = _choice(merged, "op", OPS)
        threshold = merged.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold) \
                or abs(threshold) > 1e12:
            raise RuleError("'threshold' must be a number", "threshold")
        values["threshold"] = float(threshold)
        values["window_s"] = _int_in(merged, "window_s", *WINDOW_RANGE)
        values["interval_s"] = _int_in(merged, "interval_s", *INTERVAL_RANGE)
        values["for_evals"] = _int_in(merged, "for_evals", *FOR_RANGE, default=1)
        values["group_by"] = _choice(merged, "group_by", GROUP_BYS, "none")
        values["max_groups"] = _int_in(merged, "max_groups", 1, MAX_GROUPS, default=MAX_GROUPS)
        values["urgency"] = _choice(merged, "urgency", URGENCIES, "high")
        channel_ids = merged.get("channel_ids", [])
        known = self._channels.ids()
        if not isinstance(channel_ids, list) or len(channel_ids) > CHANNELS_PER_RULE or any(
                isinstance(c, bool) or not isinstance(c, int) for c in channel_ids):
            raise RuleError(f"'channel_ids' must list at most {CHANNELS_PER_RULE} channel ids", "channel_ids")
        missing = [c for c in channel_ids if c not in known]
        if missing and "channel_ids" in body:
            raise RuleError(f"Channel {missing[0]} not found", "channel_ids")
        values["channel_ids"] = json.dumps(sorted(set(channel_ids)))
        renotify = merged.get("renotify_s", RENOTIFY_DEFAULT)
        if renotify != 0:
            renotify = _int_in({"renotify_s": renotify}, "renotify_s", *RENOTIFY_RANGE)
        values["renotify_s"] = renotify
        values["notify_resolved"] = _bool(merged, "notify_resolved", True)
        values["enabled"] = _bool(merged, "enabled", True)
        values["labels"] = json.dumps(_labels(merged.get("labels")), sort_keys=True)
        values["ai_summary"] = _bool(merged, "ai_summary", False)
        if values["enabled"] and values["view_id"] is None:
            raise RuleError("Attach a saved view before enabling this rule", "view_id")
        return values

    def _name_free(self, name: str, except_id: int | None = None) -> None:
        for row in self._db.conn.execute("SELECT id, name FROM alert_rules"):
            if row["id"] != except_id and str(row["name"]).casefold() == name.casefold():
                raise RuleError(f"A rule named '{row['name']}' already exists", "name", status=409)

    def _get(self, rule_id: int) -> dict[str, Any]:
        row = self._db.conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise RuleError("Alert rule not found", status=404)
        return _rule_row(row)

    def get(self, rule_id: int) -> dict[str, Any]:
        with self._db.lock:
            return self._get(rule_id)

    def list(self) -> list[dict[str, Any]]:
        with self._db.lock:
            rows = self._db.conn.execute("SELECT * FROM alert_rules ORDER BY name COLLATE NOCASE, id").fetchall()
        return [_rule_row(r) for r in rows]

    def view_filters(self, view_id: int | None) -> dict[str, str] | None:
        if view_id is None:
            return None
        with self._db.lock:
            row = self._db.conn.execute("SELECT filters FROM saved_views WHERE id = ?", (view_id,)).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["filters"])
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def create(self, body: Any) -> dict[str, Any]:
        now = iso_js(self._clock())
        with self._db.lock:
            values = self._clean(body, current=None)
            if int(self._db.conn.execute("SELECT COUNT(*) FROM alert_rules").fetchone()[0]) >= RULES_MAX:
                raise RuleError(f"At most {RULES_MAX} alert rules; delete one first")
            self._name_free(values["name"])
            columns = list(values)
            cur = self._db.conn.execute(
                f"INSERT INTO alert_rules ({', '.join(columns)}, created_at, updated_at) "
                f"VALUES ({', '.join('?' for _ in columns)}, ?, ?)", (*values.values(), now, now))
            return self._get(int(cur.lastrowid))

    def update(self, rule_id: int, body: Any) -> tuple[dict[str, Any], bool]:
        """(rule, changed evaluation): True when what the rule measures changed."""
        with self._db.lock:
            current = self._get(rule_id)
            base = {k: current[k] for k in _FIELDS}
            values = self._clean(body, current=base)
            self._name_free(values["name"], rule_id)
            if values["enabled"]:
                values["disabled_reason"] = None
            columns = list(values)
            self._db.conn.execute(
                f"UPDATE alert_rules SET {', '.join(f'{c} = ?' for c in columns)}, updated_at = ? WHERE id = ?",
                (*values.values(), iso_js(self._clock()), rule_id))
            rule = self._get(rule_id)
        measured = ("view_id", "metric", "op", "threshold", "window_s", "group_by", "max_groups")
        return rule, any(rule[k] != current[k] for k in measured) or (current["enabled"] and not rule["enabled"])

    def delete(self, rule_id: int) -> None:
        with self._db.lock:
            self._get(rule_id)
            self._db.conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            self._db.conn.execute("DELETE FROM alert_events WHERE rule_id = ?", (rule_id,))

    def mute(self, rule_id: int, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise RuleError("Request body must be a JSON object")
        now = self._clock()
        if body.get("until") is not None:
            until = _parse(body["until"]) if isinstance(body["until"], str) else None
            if until is None:
                raise RuleError("'until' must be an ISO-8601 time", "until")
        else:
            duration = body.get("duration")
            if isinstance(duration, str):
                match = re.fullmatch(r"(\d{1,5})([mhd])", duration.strip())
                duration = int(match.group(1)) * {"m": 60, "h": 3600, "d": 86400}[match.group(2)] if match else None
            if isinstance(duration, bool) or not isinstance(duration, int):
                raise RuleError("Give 'until' (ISO time) or 'duration' (seconds, or e.g. 1h, 4h, 24h)", "duration")
            until = now + timedelta(seconds=duration)
        if not now < until <= now + timedelta(seconds=MUTE_MAX_SECS):
            raise RuleError("A mute must end in the future and within 30 days", "until")
        with self._db.lock:
            self._get(rule_id)
            self._db.conn.execute("UPDATE alert_rules SET mute_until = ? WHERE id = ?", (iso_js(until), rule_id))
            return self._get(rule_id)

    def unmute(self, rule_id: int) -> dict[str, Any]:
        with self._db.lock:
            self._get(rule_id)
            self._db.conn.execute("UPDATE alert_rules SET mute_until = NULL WHERE id = ?", (rule_id,))
            return self._get(rule_id)


# ─── Evaluation ──────────────────────────────────────────────────────────────


@dataclass
class GroupState:
    state: str = "ok"
    streak: int = 0
    value: float | None = None
    last_notified_at: datetime | None = None
    since: str | None = None
    last_window_end: datetime | None = None
    last_result: str = "ok"  # the latest evaluation, including "unknown"


@dataclass
class RuleRuntime:
    last_eval_at: datetime | None = None
    last_window_end: datetime | None = None
    overflow: int = 0
    unknown_reason: str | None = None
    spark: list[float] = field(default_factory=list)


class AlertEngine:
    def __init__(self, *, db: StateDB, storage: Any, rules: AlertRules, channels: ChannelStore,
                 deliverer: Deliverer | None = None, signatures: Any = None, prefixes: Callable[[], list[str]],
                 time_format: str = "", display_tz: str = "UTC", public_url: str = "",
                 batch_timeout: int = 600, margin: int = 120, tick_secs: float = 30.0,
                 ai_service: Any = None, ai_fn: Callable[[dict, Any], Any] | None = None,
                 ai_configured: Callable[[], bool] = lambda: False, clock: Callable[[], datetime] = _now):
        self._db = db
        self._storage = storage
        self.rules = rules
        self.channels = channels
        self.deliverer = deliverer or Deliverer()
        self._kb = signatures
        self._prefixes = prefixes
        self._time_format = time_format
        self._tz = timezone.utc if display_tz.upper() == "UTC" else ZoneInfo(display_tz)
        self._tz_name = display_tz
        self._public_url = public_url.rstrip("/")
        self.batch_timeout = batch_timeout
        self.margin = margin
        self.tick_secs = tick_secs
        self._ai = ai_service
        self._ai_fn = ai_fn
        self._ai_configured = ai_configured
        self._clock = clock
        self._lock = threading.RLock()
        self._groups: dict[tuple[int | None, str], GroupState] = {}
        self._runtime: dict[int, RuleRuntime] = {}
        self._wake = threading.Event()  # set when a notification is queued
        self._stop = threading.Event()
        self._started = clock()
        self._last_prune: datetime | None = None
        self._threads: list[threading.Thread] = []
        self.last_tick_at: str | None = None
        self.last_error: str | None = None
        self.rebuild()

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
        for target, name in ((self._eval_loop, "alert-evaluator"), (self._delivery_loop, "alert-delivery")):
            thread = threading.Thread(target=target, daemon=True, name=name)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for thread in self._threads:
            thread.join(timeout=5)

    def _eval_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
                self.last_error = None
            except Exception as exc:  # noqa: BLE001 - never kills the loop; visible in /api/status
                self.last_error = type(exc).__name__
                logger.warning("Alert evaluation failed (%s)", type(exc).__name__)
            self._stop.wait(self.tick_secs)

    def _delivery_loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.tick_secs)
            self._wake.clear()
            try:
                self.deliver_pending()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Alert delivery run failed (%s)", type(exc).__name__)

    # -- persistence -----------------------------------------------------------------

    def rebuild(self) -> None:
        """State per (rule, group) from alert_events: the latest event gives
        the state (and pending streak); the latest event that tried to notify
        gives the renotify clock. Undelivered notifications need nothing:
        they are still queued in the table, with their next attempt."""
        with self._db.lock:
            rows = self._db.conn.execute(
                "SELECT e.* FROM alert_events e JOIN (SELECT MAX(id) AS id FROM alert_events "
                "GROUP BY rule_id, group_key) last ON last.id = e.id").fetchall()
            notified = self._db.conn.execute(
                "SELECT rule_id, group_key, MAX(ts) FROM alert_events WHERE notified != 0 "
                "GROUP BY rule_id, group_key").fetchall()
        groups: dict[tuple[int | None, str], GroupState] = {}
        for row in rows:
            state = row["state"] if row["state"] in ("ok", "pending", "firing", "resolved") else "ok"
            groups[(row["rule_id"], row["group_key"])] = GroupState(
                state=state, streak=int(row["streak"] or 0), value=row["value"], since=row["ts"],
                last_window_end=_parse(row["window_end"]), last_result=state)
        for rule_id, group_key, ts in notified:
            groups.setdefault((rule_id, group_key), GroupState()).last_notified_at = _parse(ts)
        with self._lock:
            self._groups = groups
            # The last evaluated window: a restart does not evaluate it again.
            for rule in self.rules.list():
                end = _parse(rule.get("last_window_end"))
                if end is not None:
                    self._runtime.setdefault(rule["id"], RuleRuntime()).last_window_end = end

    def _event(self, rule_id: int | None, group: str, from_state: str, state: str, *, streak: int = 0,
               value: float | None = None, threshold: float | None = None, window: tuple[datetime, datetime] | None
               = None, notify: bool = False, muted: bool = False, detail: str | None = None) -> int:
        now = iso_js(self._clock())
        with self._db.lock:
            cur = self._db.conn.execute(
                "INSERT INTO alert_events (rule_id, group_key, from_state, state, streak, value, threshold, "
                "window_start, window_end, notified, muted, detail, ts, next_attempt_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rule_id, group, from_state, state, streak, value, threshold,
                 iso_js(window[0]) if window else None, iso_js(window[1]) if window else None,
                 NOTIFY_QUEUED if notify else NOTIFY_NONE, int(muted), detail, now, now if notify else None))
        if notify:
            self._wake.set()
        return int(cur.lastrowid)

    def prune(self) -> int:
        """Events older than KEEP_DAYS in batches, keeping the latest event of
        every (rule, group): the state is rebuilt from it."""
        cutoff = iso_js(self._clock() - timedelta(days=KEEP_DAYS))
        removed = 0
        for _ in range(20):
            with self._db.lock:
                count = self._db.conn.execute(
                    "DELETE FROM alert_events WHERE id IN (SELECT id FROM alert_events WHERE ts < ? AND id NOT IN "
                    "(SELECT MAX(id) FROM alert_events GROUP BY rule_id, group_key) LIMIT ?)",
                    (cutoff, PRUNE_BATCH)).rowcount
            removed += count
            if count < PRUNE_BATCH:
                break
        return removed

    def forget(self, rule_id: int, reason: str, *, record: bool = True) -> None:
        """A rule's measurement changed (or it was disabled or deleted): its
        groups restart from ok, with an event each unless the rule is gone."""
        with self._lock:
            keys = [key for key in self._groups if key[0] == rule_id]
            for key in keys:
                group = self._groups.pop(key)
                if record and group.state != "ok":
                    self._event(rule_id, key[1], group.state, "ok", detail=reason)
            self._runtime.pop(rule_id, None)

    def has_state(self, rule_id: int) -> bool:
        with self._lock:
            return any(key[0] == rule_id for key in self._groups) or rule_id in self._runtime

    # -- watermark -------------------------------------------------------------------

    def watermark(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or self._clock()
        mark = compute_watermark(self._storage.prefix_progress(), self._prefixes(), now,
                                 batch_timeout=self.batch_timeout, margin=self.margin, time_format=self._time_format)
        # Never listed since start: unknown at first, stale once that lasts.
        if mark["at"] is None and (now - self._started).total_seconds() > STALE_FACTOR * self.batch_timeout:
            mark["stale"] = True
        return mark

    # -- one tick --------------------------------------------------------------------

    def tick(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or self._clock()
        mark = self.watermark(now)
        at = _parse(mark["at"])
        self._pipeline_alert(mark, now)
        evaluated = 0
        for rule in self.rules.list():
            if not rule["enabled"]:
                if self.has_state(rule["id"]):
                    self.forget(rule["id"], rule.get("disabled_reason") or "rule disabled")
                continue
            runtime = self._runtime.setdefault(rule["id"], RuleRuntime())
            if at is None:
                self._mark_unknown(rule, runtime, "the ingest watermark is not known yet", now)
                continue
            if runtime.last_window_end is not None and \
                    (at - runtime.last_window_end).total_seconds() < rule["interval_s"]:
                continue  # not due: the watermark has not moved an interval on
            if mark["stale"] and rule["op"] in ABSENCE_OPS:
                self._mark_unknown(rule, runtime, "the pipeline is stale", now)
                continue
            self.evaluate(rule, at, now)
            evaluated += 1
        if self._last_prune is None or (now - self._last_prune).total_seconds() >= PRUNE_EVERY_SECS:
            self._last_prune = now
            self.prune()
        self.last_tick_at = iso_js(now)
        return {"watermark": mark["at"], "stale": mark["stale"], "evaluated": evaluated}

    def _mark_unknown(self, rule: dict[str, Any], runtime: RuleRuntime, reason: str, now: datetime) -> None:
        with self._lock:
            runtime.unknown_reason = reason
            runtime.last_eval_at = now
            if rule["group_by"] == "none":
                self._groups.setdefault((rule["id"], ""), GroupState())
            for key, group in self._groups.items():
                if key[0] == rule["id"]:
                    group.last_result = "unknown"  # the state itself is unchanged

    def evaluate(self, rule: dict[str, Any], at: datetime, now: datetime) -> dict[str, Any]:
        """One evaluation of a rule over [at - window, at]."""
        runtime = self._runtime.setdefault(rule["id"], RuleRuntime())
        window = (at - timedelta(seconds=rule["window_s"]), at)
        filters = self.rules.view_filters(rule["view_id"])
        if filters is None:
            self._mark_unknown(rule, runtime, "its saved view is missing", now)
            return {"unknown": True}
        params = {**view_params(filters), "start": iso_js(window[0]), "end": iso_js(window[1])}
        try:
            result = self._storage.alert_metric(
                params, metric=rule["metric"], group_by=rule["group_by"], max_groups=rule["max_groups"],
                lowest_first=rule["op"] in ABSENCE_OPS, timeout_secs=QUERY_TIMEOUT_SECS)
        except TimeoutError:
            self._mark_unknown(rule, runtime, f"the count took longer than {QUERY_TIMEOUT_SECS:g} s", now)
            return {"unknown": True}
        values: dict[str, float | None] = dict(result["groups"])
        with self._lock:
            known = [key[1] for key, g in self._groups.items() if key[0] == rule["id"] and g.state != "ok"]
        for group_key in known:
            if group_key not in values:
                # Gone from the results: zero, unless it may have been cut off.
                values[group_key] = None if result["overflow"] else 0.0
        muted = bool(rule["mute_until"]) and (_parse(rule["mute_until"]) or now) > now
        with self._db.lock:
            self._db.conn.execute("UPDATE alert_rules SET last_window_end = ? WHERE id = ?", (iso_js(at), rule["id"]))
        transitions = []
        with self._lock:
            runtime.last_eval_at = now
            runtime.last_window_end = at
            runtime.overflow = int(result["overflow"])
            runtime.unknown_reason = None
            numeric = [v for v in values.values() if v is not None]
            if numeric:
                pick = min(numeric) if rule["op"] in ABSENCE_OPS else max(numeric)
                runtime.spark = (runtime.spark + [pick])[-SPARK_POINTS:]
            for group_key, value in values.items():
                change = self._step(rule, group_key, value, window, now, muted, result["overflow"])
                if change:
                    transitions.append(change)
        return {"values": values, "overflow": result["overflow"], "transitions": transitions}

    def _step(self, rule: dict[str, Any], group_key: str, value: float | None, window: tuple[datetime, datetime],
              now: datetime, muted: bool, overflow: int) -> str | None:
        key = (rule["id"], group_key)
        group = self._groups.setdefault(key, GroupState())
        if value is None:
            group.last_result = "unknown"
            return None
        group.value = value
        group.last_window_end = window[1]
        hit = breached(value, rule["op"], rule["threshold"])
        before = group.state
        args = {"value": value, "threshold": rule["threshold"], "window": window, "muted": muted}
        detail = f"{overflow} more groups not evaluated" if overflow else None

        def record(state: str, *, notify: bool = False) -> str:
            notify = notify and not muted
            self._event(rule["id"], group_key, before, state, streak=group.streak, notify=notify,
                        detail=detail, **args)
            group.state, group.since = state, iso_js(now)
            if notify:
                group.last_notified_at = now
            return state

        changed = None
        if hit:
            if before in ("ok", "resolved", "pending"):
                group.streak = group.streak + 1 if before == "pending" else 1
                if group.streak >= rule["for_evals"]:
                    changed = record("firing", notify=True)
                else:
                    changed = record("pending")
            elif before == "firing":
                due = rule["renotify_s"] and group.last_notified_at is not None and \
                    (now - group.last_notified_at).total_seconds() >= rule["renotify_s"]
                if not muted and (group.last_notified_at is None or due):
                    # First notification after a mute, or a reminder.
                    changed = record("firing", notify=True)
        else:
            group.streak = 0
            if before == "firing":
                changed = record("resolved", notify=bool(rule["notify_resolved"]))
            elif before in ("pending", "resolved"):
                changed = record("ok")
        group.last_result = group.state
        return changed

    # -- pipeline_stale -------------------------------------------------------------

    def _pipeline_alert(self, mark: dict[str, Any], now: datetime) -> None:
        key = (None, PIPELINE_GROUP)
        with self._lock:
            group = self._groups.setdefault(key, GroupState())
            if mark["stale"] and group.state != "firing":
                detail = json.dumps({"watermark": mark["at"], "lag_secs": mark["lag_secs"]})
                self._event(None, PIPELINE_GROUP, group.state, "firing", notify=True, detail=detail)
                group.state, group.since, group.last_notified_at = "firing", iso_js(now), now
            elif not mark["stale"] and group.state == "firing":
                detail = json.dumps({"watermark": mark["at"], "lag_secs": mark["lag_secs"]})
                self._event(None, PIPELINE_GROUP, "firing", "resolved", notify=True, detail=detail)
                group.state, group.since = "ok", iso_js(now)

    # -- delivery ---------------------------------------------------------------------

    def deliver_pending(self, now: datetime | None = None) -> int:
        """Attempt every queued notification that is due, oldest first.
        Returns how many were attempted."""
        now = now or self._clock()
        with self._db.lock:
            due = [int(row[0]) for row in self._db.conn.execute(
                "SELECT id FROM alert_events WHERE notified = ? AND (next_attempt_at IS NULL OR next_attempt_at <= ?) "
                "ORDER BY id LIMIT ?", (NOTIFY_QUEUED, iso_js(now), DELIVERY_BATCH))]
        done = 0
        for event_id in due:
            if self._stop.is_set():
                break  # still queued in the table: the next start resumes it
            self._deliver(event_id, now)
            done += 1
        return done

    def _deliver(self, event_id: int, now: datetime) -> None:
        with self._db.lock:
            event = self._db.conn.execute("SELECT * FROM alert_events WHERE id = ?", (event_id,)).fetchone()
        if event is None or event["notified"] != NOTIFY_QUEUED:
            return  # superseded or retried meanwhile
        event = dict(event)
        if event["rule_id"] is None:
            channel_ids = [ENV_CHANNEL_ID]
            message = self.pipeline_message(event)
        else:
            try:
                rule = self.rules.get(event["rule_id"])
            except RuleError:
                self._set_delivery(event, NOTIFY_FAILED_FINAL, "the rule was deleted")
                return
            channel_ids = rule["channel_ids"]
            if not channel_ids:
                self._set_delivery(event, NOTIFY_FAILED_FINAL, "no channels")
                return
            # A retry does not ask the AI again: one metered call per notification.
            message = self.message(rule, event, ai=not event.get("attempts"))
        errors = []
        sent = 0
        for channel_id in channel_ids:
            channel = self.channels.get(channel_id)
            if channel is None or not channel.enabled or not channel.url:
                errors.append(f"channel {channel_id}: not available")
                continue
            failure = self.deliverer.send(channel, message)
            if failure:
                errors.append(f"channel {channel_id}: {failure}")
            else:
                sent += 1
        error = "; ".join(errors)[:1000] or None
        if sent:
            self._set_delivery(event, NOTIFY_SENT, error)
            self._supersede_older(event)
            return
        attempts = int(event.get("attempts") or 0) + 1
        next_at = now + timedelta(seconds=retry_delay(attempts))
        created = _parse(event["ts"]) or now
        if (next_at - created).total_seconds() > DELIVERY_GIVE_UP_SECS:
            self._set_delivery(event, NOTIFY_FAILED_FINAL, error)
        else:
            self._set_delivery(event, NOTIFY_QUEUED, error, next_attempt_at=next_at)

    def _set_delivery(self, event: dict[str, Any], status: int, error: str | None, *,
                      next_attempt_at: datetime | None = None) -> None:
        """Record one delivery attempt of an event."""
        with self._db.lock:
            self._db.conn.execute(
                "UPDATE alert_events SET notified = ?, error = ?, attempts = attempts + 1, next_attempt_at = ? "
                "WHERE id = ?",
                (status, error, iso_js(next_attempt_at) if next_attempt_at else None, event["id"]))

    def _supersede_older(self, event: dict[str, Any]) -> None:
        """A newer transition of this (rule, group) went out: older firing
        notifications still waiting describe a state that is over."""
        with self._db.lock:
            self._db.conn.execute(
                "UPDATE alert_events SET notified = ?, next_attempt_at = NULL, "
                "error = 'superseded by event ' || ? WHERE rule_id IS ? AND group_key = ? AND id < ? "
                "AND notified = ? AND state = 'firing'",
                (NOTIFY_SUPERSEDED, event["id"], event["rule_id"], event["group_key"], event["id"], NOTIFY_QUEUED))

    def retry_now(self, event_id: int) -> dict[str, Any]:
        """Admin "retry now": a queued (backing off) or failed notification is
        due immediately. A failed_final one gets one more attempt; if that
        fails too it stays failed_final (it is past the retry window)."""
        with self._db.lock:
            row = self._db.conn.execute("SELECT * FROM alert_events WHERE id = ?", (event_id,)).fetchone()
            if row is None:
                raise RuleError("Alert event not found", status=404)
            if row["notified"] not in (NOTIFY_QUEUED, NOTIFY_FAILED, NOTIFY_FAILED_FINAL):
                raise RuleError(f"A notification that is {_NOTIFY_NAMES.get(row['notified'], 'unknown')} "
                                "cannot be retried", status=409)
            self._db.conn.execute("UPDATE alert_events SET notified = ?, next_attempt_at = ? WHERE id = ?",
                                  (NOTIFY_QUEUED, iso_js(self._clock()), event_id))
            row = self._db.conn.execute("SELECT * FROM alert_events WHERE id = ?", (event_id,)).fetchone()
        self._wake.set()
        return _event_view(row)

    def delivery_status(self) -> dict[str, Any]:
        """Notifications waiting (with how many are retrying) and the oldest
        due time, for /api/status."""
        with self._db.lock:
            row = self._db.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(attempts > 0), 0), MIN(next_attempt_at) FROM alert_events "
                "WHERE notified = ?", (NOTIFY_QUEUED,)).fetchone()
        return {"pending": int(row[0]), "retrying": int(row[1]), "next_attempt_at": row[2]}

    # -- message content -----------------------------------------------------------------

    def _when(self, value: Any) -> str:
        parsed = _parse(value)
        if parsed is None:
            return "?"
        return parsed.astimezone(self._tz).strftime("%Y-%m-%d %H:%M:%S") + f" {self._tz_name}"

    def deep_link(self, filters: dict[str, str], rule: dict[str, Any], group_key: str, start: str,
                  end: str) -> str | None:
        if not self._public_url:
            return None
        params = {k: v for k, v in filters.items() if k not in ("range", "from", "to")}
        if rule["group_by"] in _GROUP_PARAM and group_key:
            params[_GROUP_PARAM[rule["group_by"]][1]] = group_key
        params.update({"from": start, "to": end})
        if rule.get("view_id") is not None:
            params["view"] = str(rule["view_id"])
        return f"{self._public_url}/?{urlencode(params)}"

    def _sample(self, filters: dict[str, str], rule: dict[str, Any], group_key: str, start: str,
                end: str) -> list[dict[str, Any]]:
        params = {**view_params(filters), "start": start, "end": end}
        if rule["group_by"] in _GROUP_PARAM and group_key:
            params[_GROUP_PARAM[rule["group_by"]][0]] = group_key
        try:
            return list(self._storage.query_logs(params, limit=SAMPLE_ROWS).get("items") or [])
        except Exception as exc:  # noqa: BLE001 - a message without patterns is still sent
            logger.warning("Alert message sample failed (%s)", type(exc).__name__)
            return []

    def message(self, rule: dict[str, Any], event: dict[str, Any], *, ai: bool = True) -> Message:
        state = event["state"]
        filters = self.rules.view_filters(rule["view_id"]) or {}
        start, end = event["window_start"], event["window_end"]
        group_key = event["group_key"]
        value = event["value"]
        metric = _METRIC_LABELS.get(rule["metric"], rule["metric"])
        label = {"firing": "FIRING", "resolved": "RESOLVED"}.get(state, state.upper())
        title = f"{label} · {rule['name']} · urgency {rule['urgency']}"
        lines = [f"**Value** {value:g} {metric} {rule['op']} threshold {rule['threshold']:g}"
                 if value is not None else f"**Threshold** {rule['op']} {rule['threshold']:g} {metric}"]
        if group_key:
            lines.append(f"**{rule['group_by'].capitalize()}** {_inline(group_key)}")
        lines.append(f"**Window** {self._when(start)} → {self._when(end)} ({rule['window_s'] // 60} min)")
        if event.get("detail"):
            lines.append(f"_{_inline(event['detail'], 200, code=False)}_")
        templates: list[dict[str, Any]] = []
        signature = None
        ai_text = None
        if state == "firing" and start and end:
            records = self._sample(filters, rule, group_key, start, end)
            digest = digest_records(records, top=3, exemplars=1, redact=redact_text)
            for item in digest["templates"]:
                templates.append({"template": redact_text(item["template"])[:300], "count": item["count"],
                                  "exemplar": (item.get("exemplars") or [""])[0]})
            if templates:
                lines.append("**Top patterns in the window**")
                lines += [f"- {t['count']}× {_inline(t['template'], 160)}" for t in templates]
            if self._kb is not None:
                for record in records[:50]:
                    match = self._kb.match_record(record)
                    if match is not None:
                        signature = match.title
                        lines.append(f"**Known pattern** {_inline(signature, 120, code=False)}")
                        break
            if ai and rule.get("ai_summary"):
                ai_text = self._ai_summary(rule, records, filters)
                if ai_text:
                    lines.append(f"**AI summary** {_inline(ai_text, 600, code=False)}")
        url = self.deep_link(filters, rule, group_key, start, end) if start and end else None
        data = {
            "rule": {"id": rule["id"], "name": rule["name"], "metric": rule["metric"], "op": rule["op"],
                     "urgency": rule["urgency"]},
            "group": {"by": rule["group_by"], "key": group_key} if group_key else None,
            "value": value, "threshold": rule["threshold"],
            "window": {"start": start, "end": end, "seconds": rule["window_s"]},
            "state": state, "url": url, "labels": rule["labels"], "templates": templates,
            "signature": signature,
        }
        if ai_text:
            data["ai_summary"] = ai_text
        return Message(title=title, lines=lines, links=[("Open in Logscope", url)] if url else [], data=data)

    def pipeline_message(self, event: dict[str, Any]) -> Message:
        try:
            detail = json.loads(event.get("detail") or "{}")
        except ValueError:
            detail = {}
        stale = event["state"] == "firing"
        lag = detail.get("lag_secs")
        title = "FIRING · Logscope pipeline is stale" if stale else "RESOLVED · Logscope pipeline caught up"
        lines = [f"**Data complete up to** {self._when(detail.get('watermark'))}"
                 + (f" ({int(lag) // 60} min behind)" if lag is not None else "")]
        if stale:
            lines.append("Absence rules (< and <=) report unknown until ingestion catches up.")
        url = f"{self._public_url}/?tab=pipeline" if self._public_url else None
        data = {"rule": {"id": None, "name": "pipeline_stale"}, "group": None, "value": lag, "threshold": None,
                "window": None, "state": event["state"], "url": url, "labels": {}, "templates": []}
        return Message(title=title, lines=lines, links=[("Pipeline", url)] if url else [], data=data)

    def _ai_summary(self, rule: dict[str, Any], records: list[dict[str, Any]], filters: dict[str, str]) -> str | None:
        """Optional; fast tier, metered as alert_summary. Skipped without
        error when AI is off, over budget or failing."""
        if self._ai is None or self._ai_fn is None or not records or not self._ai_configured():
            return None
        payload = compact_log_payload(records, filters, sample_limit_reached=len(records) >= SAMPLE_ROWS, top=5)
        try:
            result = self._ai.call(AI_FEATURE, lambda cfg: self._ai_fn(payload, cfg), tier="fast",
                                   input_chars=len(json.dumps(payload, ensure_ascii=False)))
        except Exception as exc:  # noqa: BLE001 - delivery must not depend on AI
            logger.warning("Alert AI summary failed (%s)", type(exc).__name__)
            return None
        if not isinstance(result, dict) or result.get("degraded"):
            return None
        return redact_text(str(result.get("summary") or ""))[:600] or None

    # -- API views -------------------------------------------------------------------

    def rule_status(self, rule: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        now = now or self._clock()
        with self._lock:
            runtime = self._runtime.get(rule["id"]) or RuleRuntime()
            groups = [(key[1], g) for key, g in self._groups.items() if key[0] == rule["id"]]
        group_items = sorted(
            ({"group": k, "state": g.state, "result": g.last_result, "value": g.value, "since": g.since}
             for k, g in groups if g.state != "ok" or g.value is not None or g.last_result == "unknown"),
            key=lambda item: (-_STATE_ORDER.get(item["state"], 0), item["group"]))
        states = [g.state for _, g in groups] or ["ok"]
        state = max(states, key=lambda s: _STATE_ORDER.get(s, 0))
        if state in ("ok", "resolved") and any(g.last_result == "unknown" for _, g in groups):
            state = "unknown"
        if runtime.unknown_reason and state in ("ok", "resolved"):
            state = "unknown"
        muted = bool(rule["mute_until"]) and (_parse(rule["mute_until"]) or now) > now
        values = [g.value for _, g in groups if g.value is not None]
        return {
            "state": "disabled" if not rule["enabled"] else state,
            "muted": muted,
            "last_value": (min(values) if rule["op"] in ABSENCE_OPS else max(values)) if values else None,
            "last_eval_at": iso_js(runtime.last_eval_at) if runtime.last_eval_at else None,
            "last_window_end": iso_js(runtime.last_window_end) if runtime.last_window_end else None,
            "unknown_reason": runtime.unknown_reason,
            "overflow": runtime.overflow,
            "groups": group_items[:MAX_GROUPS + 5],
            "spark": list(runtime.spark),
        }

    def firing_count(self) -> int:
        with self._lock:
            rules = {key[0] for key, g in self._groups.items() if g.state == "firing" and key[0] is not None}
        return len(rules)

    def pipeline_firing(self) -> bool:
        with self._lock:
            group = self._groups.get((None, PIPELINE_GROUP))
            return bool(group and group.state == "firing")

    def events(self, *, rule_id: int | None = None, state: str | None = None, since: str | None = None,
               before_id: int | None = None, limit: int = 50) -> dict[str, Any]:
        """Newest first; keyset paging on id (next_cursor = the last id)."""
        where, args = ["1 = 1"], []
        if rule_id is not None:
            where.append("rule_id = ?")
            args.append(rule_id)
        if state:
            where.append("state = ?")
            args.append(state)
        if since:
            where.append("ts >= ?")
            args.append(since)
        if before_id is not None:
            where.append("id < ?")
            args.append(before_id)
        limit = max(1, min(int(limit), 200))
        with self._db.lock:
            rows = self._db.conn.execute(
                f"SELECT * FROM alert_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                (*args, limit + 1)).fetchall()
        items = [_event_view(r) for r in rows[:limit]]
        return {"items": items, "next_cursor": items[-1]["id"] if len(rows) > limit else None}

    def test_channel(self, channel_id: int) -> dict[str, Any]:
        channel = self.channels.get(channel_id)
        if channel is None:
            raise RuleError("Channel not found", status=404)
        message = Message(title="Logscope test notification",
                          lines=["This channel receives Logscope alerts."], links=[],
                          data={"rule": None, "group": None, "value": None, "threshold": None, "window": None,
                                "state": "test", "url": None, "labels": {}, "templates": []})
        failure = self.deliverer.send(channel, message)
        return {"ok": failure is None, "error": failure}


def retry_delay(attempts: int) -> int:
    """Seconds before the next try after `attempts` failed ones."""
    if attempts <= len(RETRY_SCHEDULE_SECS):
        return RETRY_SCHEDULE_SECS[max(1, attempts) - 1]
    return RETRY_HOURLY_SECS


def _event_view(row: Any) -> dict[str, Any]:
    """An alert_events row for the API: notified as a name ("retrying" for
    a queued one that has failed before)."""
    item = dict(row)
    status = item["notified"]
    name = _NOTIFY_NAMES.get(status, "no")
    if status == NOTIFY_QUEUED and int(item.get("attempts") or 0) > 0:
        name = "retrying"
    item["notified"] = name
    item["muted"] = bool(item["muted"])
    item["retryable"] = status in (NOTIFY_QUEUED, NOTIFY_FAILED, NOTIFY_FAILED_FINAL)
    return item


def _inline(value: Any, limit: int = 120, *, code: bool = True) -> str:
    """Log-derived text for a chat message: redacted, one line, bounded, no
    backticks that could break the markup."""
    text = " ".join(redact_text(str(value or "")).replace("`", "'").split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return f"`{text or '—'}`" if code else text


# ─── Backtest ────────────────────────────────────────────────────────────────


def _clean_backtest(body: Any, rules: AlertRules) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise RuleError("Request body must be a JSON object")
    if body.get("view_id") is not None:
        filters = rules.view_filters(body["view_id"] if isinstance(body["view_id"], int) else None)
        if filters is None:
            raise RuleError("Saved view not found", "view_id")
    else:
        try:
            filters = validate_filters(body.get("filters") or {})
        except FilterError as exc:
            raise RuleError(str(exc), exc.field) from None
    threshold = body.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(threshold):
        raise RuleError("'threshold' must be a number", "threshold")
    range_s = body.get("range_s", BACKTEST_MAX_SECS)
    if isinstance(body.get("range"), str):
        range_s = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": BACKTEST_MAX_SECS}.get(body["range"])
    if isinstance(range_s, bool) or not isinstance(range_s, int) or not 3600 <= range_s <= BACKTEST_MAX_SECS:
        raise RuleError("'range_s' must be from 3600 to 604800 (7 days)", "range_s")
    return {
        "filters": filters, "metric": _choice(body, "metric", METRICS), "op": _choice(body, "op", OPS),
        "threshold": float(threshold), "window_s": _int_in(body, "window_s", *WINDOW_RANGE),
        "interval_s": _int_in(body, "interval_s", *INTERVAL_RANGE),
        "for_evals": _int_in(body, "for_evals", *FOR_RANGE, default=1), "range_s": range_s,
    }


def backtest(storage: Any, rules: AlertRules, body: Any, *, end: datetime) -> dict[str, Any]:
    """Replays a rule (ungrouped) over history from histogram buckets:
    evaluations every interval_s over range_s ending at `end` (the
    watermark), each over the preceding window_s. Read-only; the query is
    capped at QUERY_TIMEOUT_SECS (TimeoutError)."""
    spec = _clean_backtest(body, rules)
    window, interval = spec["window_s"], spec["interval_s"]
    bucket = math.gcd(window, interval)
    approximate = False
    if bucket < 60:
        bucket, approximate = 60, True
    range_s = -(-spec["range_s"] // interval) * interval
    while (range_s + window) // bucket > BACKTEST_MAX_BUCKETS:
        bucket *= 2
        approximate = True
    end_epoch = int(end.timestamp())
    end_epoch -= end_epoch % bucket
    origin = end_epoch - range_s - window
    origin -= origin % bucket
    pods = spec["metric"] == "distinct_pods"
    data = storage.metric_series(view_params(spec["filters"]), start_epoch=origin, end_epoch=end_epoch,
                                 bucket_secs=bucket, pods=pods, timeout_secs=QUERY_TIMEOUT_SECS)
    per_window = max(1, round(window / bucket))
    series = []
    t = end_epoch - range_s
    while t <= end_epoch:
        last = (t - origin) // bucket  # buckets [last - per_window, last)
        first = last - per_window
        if pods:
            seen: set[str] = set()
            for index in range(first, last):
                seen |= data.get(index, set())
            value = float(len(seen))
        else:
            column = 1 if spec["metric"] == "error_count" else 0
            value = float(sum(data[i][column] for i in range(first, last) if i in data))
        series.append((t, value))
        t += interval
    fires = []
    state, streak = "ok", 0
    for t, value in series:
        if breached(value, spec["op"], spec["threshold"]):
            streak += 1
            if state != "firing" and streak >= spec["for_evals"]:
                state = "firing"
                fires.append({"at": iso_js(datetime.fromtimestamp(t, timezone.utc)), "value": value})
        else:
            streak, state = 0, "ok"
    stride = max(1, -(-len(series) // BACKTEST_SERIES_POINTS))
    points = []
    for i in range(0, len(series), stride):
        chunk = series[i:i + stride]
        pick = min(chunk, key=lambda p: p[1]) if spec["op"] in ABSENCE_OPS else max(chunk, key=lambda p: p[1])
        points.append({"t": iso_js(datetime.fromtimestamp(chunk[-1][0], timezone.utc)), "value": pick[1]})
    return {
        "fired": len(fires), "fires": fires[:200], "evaluations": len(series),
        "range": {"start": iso_js(datetime.fromtimestamp(end_epoch - range_s, timezone.utc)),
                  "end": iso_js(datetime.fromtimestamp(end_epoch, timezone.utc))},
        "bucket_secs": bucket, "approximate": approximate, "series": points,
    }
