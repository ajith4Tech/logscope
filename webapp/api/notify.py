"""Optional Mattermost notifications for Insights anomalies.

When a notification is sent
  * Once per anomaly occurrence: an anomaly row plus the hourly window it was
    detected in (evidence.window_start). Later Insights runs that only refresh
    the counts of the same occurrence send nothing.
  * Only when the anomaly's urgency (anomaly_urgency below) is at or above
    webapp.mattermost.min_urgency, and its status is not "dismissed".
  * A recurrence (the same type/namespace/pod/rule in a new window, or on a
    new day) is sent again only if nothing was sent or queued for that key in
    the last renotify_after_hours; otherwise it is recorded as "suppressed".
  * Occurrences whose window started more than max_age_hours ago are never
    sent, so enabling notifications does not replay old anomalies.

Delivery runs on its own thread, so a slow or failing Mattermost never delays
ingestion or the Insights loop. Each attempt has a short timeout; transient
failures (timeouts, connection errors, 408/429/5xx) are retried with backoff
up to MAX_ATTEMPTS, then the notification is marked "failed". Every outcome is
stored in anomaly_notifications and summarised in /api/status.

The webhook URL is a credential (it alone authorises posting). It is read
from the environment variable named in webapp.mattermost.webhook_url_env and
never logged, stored, or returned by the API.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import error, request
from urllib.parse import urlencode

from .ai_summary import redact_text
from .config import URGENCY_ORDER, AppConfig
from .storage import SQLITE_BUSY_TIMEOUT_SECS, utc_stamp

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECS = 30
SEND_TIMEOUT_SECS = 10
MAX_ATTEMPTS = 5
RETRY_BASE_SECS = 60
RETRY_MAX_SECS = 3600
MAX_SENDS_PER_RUN = 10
# Notification rows are bookkeeping; older ones are deleted.
KEEP_DAYS = 30
_TRANSIENT_HTTP = {408, 425, 429, 500, 502, 503, 504}


class DeliveryError(Exception):
    def __init__(self, message: str, *, transient: bool):
        super().__init__(message)
        self.transient = transient


def anomaly_urgency(anomaly: dict[str, Any], evidence: dict[str, Any]) -> str:
    """Deterministic urgency of one anomaly, compared with min_urgency.

    new_falco_rule     error bucket -> urgent, warning -> high, else medium
    error_rate_spike   high
    severity_shift     a rising share of error -> high, of warning -> medium,
                       anything else (including a falling share) -> low
    message_frequency  medium
    other              low
    """
    kind = str(anomaly.get("type") or "")
    severity = str(anomaly.get("severity") or "")
    if kind == "new_falco_rule":
        return {"error": "urgent", "warning": "high"}.get(severity, "medium")
    if kind == "error_rate_spike":
        return "high"
    if kind == "severity_shift":
        try:
            rising = float(evidence.get("current_share", 0)) > float(evidence.get("baseline_share", 0))
        except (TypeError, ValueError):
            rising = False
        if not rising:
            return "low"
        return {"error": "high", "warning": "medium"}.get(severity, "low")
    if kind == "message_frequency":
        return "medium"
    return "low"


_TYPE_LABELS = {
    "error_rate_spike": "Error spike",
    "message_frequency": "Frequency spike",
    "new_falco_rule": "New Falco rule",
    "severity_shift": "Severity shift",
}


def _inline(value: Any, limit: int = 120) -> str:
    """A log-derived value as inline code: redacted, single line, bounded,
    with characters that would break Mattermost markdown removed."""
    text = redact_text(str(value or ""))
    text = " ".join(text.replace("`", "'").split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return f"`{text}`" if text else "`—`"


def investigation_links(anomaly: dict[str, Any], evidence: dict[str, Any], base_url: str) -> dict[str, str]:
    """UI links using the same URL parameters as the frontend (app.js)."""
    if not base_url:
        return {}
    links = {"anomaly": f"{base_url}/?{urlencode({'tab': 'insights', 'anomaly': anomaly['id']})}"}
    params: dict[str, str] = {"tab": "logs"}
    if anomaly.get("namespace"):
        params["ns"] = str(anomaly["namespace"])
    if anomaly.get("pod"):
        params["pod"] = str(anomaly["pod"])
    kind = anomaly.get("type")
    if kind == "error_rate_spike":
        params["sev"] = "error"
    elif kind == "severity_shift" and anomaly.get("severity"):
        params["sev"] = str(anomaly["severity"])
    elif kind == "new_falco_rule":
        params["scope"] = "security"
    if evidence.get("window_start") and evidence.get("window_end"):
        params["from"] = str(evidence["window_start"])
        params["to"] = str(evidence["window_end"])
    links["logs"] = f"{base_url}/?{urlencode(params)}"
    return links


def format_message(anomaly: dict[str, Any], evidence: dict[str, Any], urgency: str, base_url: str) -> str:
    """Concise Mattermost markdown. Carries identifiers and counts only: no
    sample log messages and no AI text (both may hold log content)."""
    kind = str(anomaly.get("type") or "")
    lines = [f"#### Logscope anomaly: {_TYPE_LABELS.get(kind, kind or 'anomaly')} · urgency {urgency}"]
    where = [f"**Namespace** {_inline(anomaly.get('namespace') or 'cluster')}"]
    if anomaly.get("pod"):
        where.append(f"**Pod** {_inline(anomaly['pod'])}")
    if anomaly.get("severity"):
        where.append(f"**Severity** {_inline(anomaly['severity'], 20)}")
    lines.append(" · ".join(where))
    if anomaly.get("rule_key"):
        lines.append(f"**Rule / message** {_inline(anomaly['rule_key'], 200)}")
    start, end = evidence.get("window_start"), evidence.get("window_end")
    if start:
        progress = "" if evidence.get("window_complete", True) else " (hour in progress)"
        lines.append(f"**Window** {_inline(start, 30)} → {_inline(end, 30)} UTC{progress}")
    count = evidence.get("current_count")
    if kind in ("error_rate_spike", "message_frequency") and count is not None:
        lines.append(f"**Observed** {count} vs ≈{evidence.get('expected_count', '?')} expected "
                     f"(threshold ×{evidence.get('multiplier', '?')})")
    elif kind == "severity_shift":
        lines.append(f"**Share** {evidence.get('current_share', '?')} now vs "
                     f"{evidence.get('baseline_share', '?')} baseline ({count} entries)")
    elif kind == "new_falco_rule" and count is not None:
        lines.append(f"**Hits** {count} in the window; not seen in the baseline")
    links = investigation_links(anomaly, evidence, base_url)
    if links:
        lines.append(f"[Open in Logscope]({links['anomaly']}) · [Logs for this window]({links['logs']})")
    lines.append(f"_Anomaly #{anomaly['id']} · status {anomaly.get('status') or 'new'}_")
    return "\n".join(lines)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never re-post the payload elsewhere
        return None


def post_webhook(url: str, payload: dict[str, Any], timeout: float = SEND_TIMEOUT_SECS) -> None:
    """POST to an incoming webhook. Raises DeliveryError whose message never
    contains the URL (it is a credential)."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "logscope-webapp/1.0",
    })
    opener = request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read(4096)
    except error.HTTPError as exc:
        raise DeliveryError(f"HTTP {exc.code}", transient=exc.code in _TRANSIENT_HTTP) from None
    except (error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DeliveryError(f"network error ({type(reason).__name__})", transient=True) from None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS anomaly_notifications (
    anomaly_id INTEGER NOT NULL,
    window_start TEXT NOT NULL,
    type TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod TEXT NOT NULL,
    rule_key TEXT NOT NULL,
    urgency TEXT NOT NULL,
    status TEXT NOT NULL,          -- pending | sent | failed | suppressed | cancelled | superseded
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    next_attempt_at TEXT NOT NULL,
    last_attempt_at TEXT,
    sent_at TEXT,
    PRIMARY KEY (anomaly_id, window_start)
)
"""


def _iso_z(value: datetime) -> str:
    """Second precision, the format of evidence.window_start."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp(value: datetime) -> str:
    """Microsecond precision, the format of utc_stamp() (created_at etc.)."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class MattermostNotifier:
    """Queues and delivers anomaly notifications on its own thread."""

    def __init__(
        self,
        cfg: AppConfig,
        db_path: Path,
        *,
        sender: Callable[[str, dict[str, Any]], None] = post_webhook,
    ):
        self.cfg = cfg.mattermost
        self._sender = sender
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            # Additive: existing databases gain the table on first start.
            self._conn.execute(_SCHEMA)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_anomaly_notifications_key "
                "ON anomaly_notifications(type, namespace, pod, rule_key, created_at)"
            )
            self._conn.commit()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="mattermost-notifier")
        self.last_run_at: str | None = None
        self.last_run_error: str | None = None

    # -- configuration ---------------------------------------------------------

    def _webhook_url(self) -> str:
        url = os.environ.get(self.cfg.webhook_url_env, "").strip() if self.cfg.webhook_url_env else ""
        return url if url.lower().startswith(("https://", "http://")) else ""

    @property
    def configured(self) -> bool:
        """Enabled and a usable webhook URL is present. Nothing is queued or
        sent otherwise."""
        return bool(self.cfg.enabled and self._webhook_url())

    # -- lifecycle ---------------------------------------------------------------

    def start(self) -> None:
        if not self.cfg.enabled:
            return
        if not self._webhook_url():
            logger.warning(
                "Mattermost notifications are enabled but %s is not set to an http(s) URL; not sending",
                self.cfg.webhook_url_env,
            )
            return
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=SEND_TIMEOUT_SECS + 5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
                self.last_run_error = None
            except Exception as exc:  # never kills the loop; visible in /api/status
                self.last_run_error = f"{type(exc).__name__}"
                logger.warning("Mattermost notification run failed (%s)", type(exc).__name__)
            self._stop.wait(POLL_INTERVAL_SECS)

    # -- one run -------------------------------------------------------------------

    def run_once(self, now: datetime | None = None) -> dict[str, int]:
        if not self.configured:
            return {"queued": 0, "suppressed": 0, "sent": 0, "failed": 0, "retrying": 0}
        now = now or datetime.now(timezone.utc)
        counts = self._queue(now)
        counts.update(self._deliver(now))
        self._prune(now)
        self.last_run_at = _iso_z(now)
        return counts

    def _queue(self, now: datetime) -> dict[str, int]:
        cutoff = _iso_z(now - timedelta(hours=self.cfg.max_age_hours))
        renotify_since = _stamp(now - timedelta(hours=self.cfg.renotify_after_hours))
        threshold = URGENCY_ORDER[self.cfg.min_urgency]
        queued = suppressed = 0
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT a.* FROM anomalies a
                LEFT JOIN anomaly_notifications n
                  ON n.anomaly_id = a.id AND n.window_start = json_extract(a.evidence, '$.window_start')
                WHERE n.anomaly_id IS NULL
                  AND a.status != 'dismissed'
                  AND json_extract(a.evidence, '$.window_start') >= ?
                ORDER BY a.id
                LIMIT 200
                """,
                (cutoff,),
            ).fetchall()
            for row in rows:
                anomaly = dict(row)
                evidence = _evidence(anomaly)
                urgency = anomaly_urgency(anomaly, evidence)
                if URGENCY_ORDER[urgency] < threshold:
                    continue  # re-evaluated next run; never stored
                key = (anomaly["type"], anomaly["namespace"], anomaly["pod"], anomaly["rule_key"])
                recent = self._conn.execute(
                    "SELECT 1 FROM anomaly_notifications WHERE type = ? AND namespace = ? AND pod = ? "
                    "AND rule_key = ? AND status IN ('pending', 'sent') AND created_at >= ? LIMIT 1",
                    (*key, renotify_since),
                ).fetchone()
                status = "suppressed" if recent else "pending"
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO anomaly_notifications
                        (anomaly_id, window_start, type, namespace, pod, rule_key, urgency, status,
                         created_at, next_attempt_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (anomaly["id"], str(evidence.get("window_start")), *key, urgency, status,
                     utc_stamp(), utc_stamp()),
                )
                if status == "pending":
                    queued += 1
                else:
                    suppressed += 1
            self._conn.commit()
        return {"queued": queued, "suppressed": suppressed}

    def _deliver(self, now: datetime) -> dict[str, int]:
        sent = failed = retrying = 0
        with self._lock:
            due = [dict(r) for r in self._conn.execute(
                "SELECT * FROM anomaly_notifications WHERE status = 'pending' AND next_attempt_at <= ? "
                "ORDER BY created_at LIMIT ?",
                (utc_stamp(), MAX_SENDS_PER_RUN),
            ).fetchall()]
        url = self._webhook_url()
        for item in due:
            if self._stop.is_set():
                break
            ident = (item["anomaly_id"], item["window_start"])
            with self._lock:
                row = self._conn.execute("SELECT * FROM anomalies WHERE id = ?", (item["anomaly_id"],)).fetchone()
            anomaly = dict(row) if row else None
            evidence = _evidence(anomaly) if anomaly else {}
            if anomaly is None or anomaly.get("status") == "dismissed":
                self._finish(ident, "cancelled", None)
                continue
            if str(evidence.get("window_start")) != item["window_start"]:
                # A newer window replaced this occurrence; it is queued on its own.
                self._finish(ident, "superseded", None)
                continue
            text = format_message(anomaly, evidence, item["urgency"], self.cfg.link_base_url)
            try:
                self._sender(url, {"text": text, "username": "Logscope"})
            except DeliveryError as exc:
                attempts = int(item["attempts"]) + 1
                if exc.transient and attempts < MAX_ATTEMPTS:
                    delay = min(RETRY_BASE_SECS * 2 ** (attempts - 1), RETRY_MAX_SECS)
                    self._retry(ident, attempts, str(exc), delay)
                    retrying += 1
                else:
                    self._finish(ident, "failed", str(exc), attempts=attempts)
                    failed += 1
                logger.warning("Mattermost notification for anomaly %s not delivered (attempt %d): %s",
                               item["anomaly_id"], attempts, exc)
                continue
            except Exception as exc:  # unexpected sender failure: keep the URL out of messages
                attempts = int(item["attempts"]) + 1
                self._finish(ident, "failed", f"unexpected error ({type(exc).__name__})", attempts=attempts)
                failed += 1
                logger.warning("Mattermost notification for anomaly %s failed (%s)",
                               item["anomaly_id"], type(exc).__name__)
                continue
            self._finish(ident, "sent", None, attempts=int(item["attempts"]) + 1, sent=True)
            sent += 1
        return {"sent": sent, "failed": failed, "retrying": retrying}

    def _retry(self, ident: tuple, attempts: int, message: str, delay: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE anomaly_notifications SET attempts = ?, last_error = ?, last_attempt_at = ?, "
                "next_attempt_at = ? WHERE anomaly_id = ? AND window_start = ?",
                (attempts, message[:300], utc_stamp(), utc_stamp(delay), *ident),
            )
            self._conn.commit()

    def _finish(self, ident: tuple, status: str, message: str | None, *, attempts: int | None = None,
                sent: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE anomaly_notifications SET status = ?, last_error = COALESCE(?, last_error), "
                "attempts = COALESCE(?, attempts), last_attempt_at = CASE WHEN ? IS NULL THEN last_attempt_at "
                "ELSE ? END, sent_at = CASE WHEN ? THEN ? ELSE sent_at END "
                "WHERE anomaly_id = ? AND window_start = ?",
                (status, message[:300] if message else None, attempts, attempts, utc_stamp(),
                 1 if sent else 0, utc_stamp(), *ident),
            )
            self._conn.commit()

    def _prune(self, now: datetime) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM anomaly_notifications WHERE created_at < ?",
                (_stamp(now - timedelta(days=KEEP_DAYS)),),
            )
            self._conn.commit()

    # -- visibility ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Counts and the latest delivery problem. Never the webhook URL."""
        out: dict[str, Any] = {
            "enabled": bool(self.cfg.enabled),
            "configured": self.configured,
            "running": self._thread.is_alive(),
            "min_urgency": self.cfg.min_urgency,
            "links": bool(self.cfg.link_base_url),
            "last_run_at": self.last_run_at,
            "last_run_error": self.last_run_error,
        }
        if not self.cfg.enabled:
            return out
        with self._lock:
            counts = {row[0]: int(row[1]) for row in self._conn.execute(
                "SELECT status, COUNT(*) FROM anomaly_notifications GROUP BY status"
            )}
            last_sent = self._conn.execute("SELECT MAX(sent_at) FROM anomaly_notifications").fetchone()[0]
            problem = self._conn.execute(
                "SELECT anomaly_id, status, attempts, last_error, last_attempt_at FROM anomaly_notifications "
                "WHERE last_error IS NOT NULL AND status IN ('pending', 'failed') "
                "ORDER BY last_attempt_at DESC LIMIT 1"
            ).fetchone()
        out.update({
            "counts": counts,
            "last_sent_at": last_sent,
            "last_problem": dict(problem) if problem else None,
        })
        return out


def _evidence(anomaly: dict[str, Any]) -> dict[str, Any]:
    raw = anomaly.get("evidence")
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
