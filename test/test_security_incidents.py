"""Web -> runtime correlation (webapp/api/security.py): a web-attack anomaly
followed by a genuine Falco event in the same pod/namespace becomes one
security incident.

Fixture: test/fixtures/web_runtime_chain/chain.json (a Wave-B-shaped wp-login
brute force at 10:46 in a pod up since 09:05, then a Falco event a few
minutes later, outside the cold-start grace). Covers: attack_type persisted
on the anomaly, same-pod (critical/high) and namespace-only (high/medium)
matches, same-pod preference, no match / no retroactive incident, cold-start
exclusion, restart idempotency, durable (non-sleeping) notification, the AI
summary (signature first, budget respected), the API's auth split, and the
wp_attack_replay negative case.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_alerts import ADMIN, AUTH, Sent, _listed, _prefixes, served  # noqa: E402,F401
from test_alerts import _app as _alerts_app  # noqa: E402
from test_alerts import _env as _alerts_env  # noqa: E402,F401
from test_production import JSON, _request  # noqa: E402
from test_wp_regression import _replay as _wp_replay  # noqa: E402

from webapp.api.alerts import NOTIFY_QUEUED, NOTIFY_SENT, RETRY_SCHEDULE_SECS  # noqa: E402
from webapp.api.channels import Deliverer, DeliveryError  # noqa: E402
from webapp.api.config import InsightsConfig, SecurityConfig, load_app_config  # noqa: E402
from webapp.api.explain import classify_anomaly  # noqa: E402
from webapp.api.insights import AnomalyStore, InsightsJob  # noqa: E402
from webapp.api.parser import make_record  # noqa: E402
from webapp.api.security import (  # noqa: E402
    Correlator,
    IncidentStore,
    falco_rule_of,
    falco_target_of,
    workload_of,
)
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.signatures import SignatureKB, load_rules  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402

FIXTURE = ROOT / "test" / "fixtures" / "web_runtime_chain" / "chain.json"
CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"
WP_POD = "wordpress-7d79967bc8-qjt4c"


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text())


NOW = datetime.fromisoformat(_fixture()["now"].replace("Z", "+00:00"))
AFTER_WINDOW = NOW + timedelta(minutes=16)  # window end 11:00 + 900 s correlation window has passed


def _records(spec: dict) -> list[dict]:
    """One fixture spec through the real ingest path (make_record)."""
    start = datetime.fromisoformat(spec["start"].replace("Z", "+00:00"))
    out = []
    for i in range(spec["count"]):
        ts = datetime.fromtimestamp(start.timestamp() + i * spec["step_s"], timezone.utc)
        message = spec["message"].replace("{i}", str(i)).replace("{ip}", str((i % 250) + 1))
        raw = f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')} - {spec['namespace']} - {spec['pod']}/{spec['container']} - {message}"
        record = make_record(raw_line=raw, source_bucket=spec["bucket"],
                             source_scope="security" if spec["scope"] == "security" else "namespace",
                             source_key=f"chain/{spec['name']}", source_etag="e", line_number=i,
                             infra_namespaces=())
        assert record is not None
        out.append(record)
    return out


def _load(storage: LogStorage, *variants: str) -> None:
    fixture = _fixture()
    specs = list(fixture["specs"])
    for variant in variants:
        specs += fixture["falco"][variant]
    for spec in specs:
        storage.insert_records(_records(spec))


def _cfg(**security):
    base = load_app_config(CONFIG)
    insights = InsightsConfig(
        enabled=True, detect_interval_secs=300, baseline_window_days=7,
        spike_multiplier=3.0, spike_min_count=10, shift_share_delta=0.25, shift_min_count=20,
        frequency_multiplier=5.0, frequency_min_count=30, detect_per_pod=False,
        sample_timestamps_max=10, min_baseline_hours=24, min_partial_window_minutes=15,
        cold_start_grace_s=600, min_baseline_samples=5,
    )
    return replace(base, insights=insights, security=replace(SecurityConfig(), **security))


class Harness:
    """Storage, detection (with the signature classifier) and the correlator
    on one database, without the web app; notifications are recorded."""

    def __init__(self, tmp_path: Path, *variants: str, **security):
        self.db = tmp_path / "cache.sqlite"
        self.storage = LogStorage(self.db)
        _load(self.storage, *variants)
        self.cfg = _cfg(**security)
        self.anomalies = AnomalyStore(self.db)
        self.kb = SignatureKB(load_rules())
        self.job = InsightsJob(self.cfg, self.storage._conn, self.anomalies,
                               classifier=lambda a: classify_anomaly(self.kb, self.anomalies, a))
        self.incidents = IncidentStore(self.db)
        self.notified: list[int] = []
        self.correlator = Correlator(self.cfg, self.incidents, self.storage._conn, notify=self._notify)

    def _notify(self, incident: dict) -> int:
        self.notified.append(int(incident["id"]))
        return 1000 + int(incident["id"])

    def add(self, variant: str) -> None:
        for spec in _fixture()["falco"][variant]:
            self.storage.insert_records(_records(spec))

    def web_anomaly(self) -> dict:
        items = self.anomalies.query_anomalies({"type": "message_frequency", "namespace": "sec-test"},
                                               limit=50)["items"]
        brute = [a for a in items if "wp-login" in a["rule_key"]]
        assert len(brute) == 1, items
        return brute[0]


# ─── Part 1: attack_type persisted on the anomaly ────────────────────────────


def test_attack_type_is_persisted_on_the_anomaly(tmp_path):
    h = Harness(tmp_path)
    h.job.detect_once(NOW)
    anomaly = h.web_anomaly()
    # Stored in queryable columns, not only in the explain response / ai_meta.
    assert anomaly["attack_type"] == "brute-force"
    assert anomaly["attack_confidence"] in ("low", "medium", "high")
    with h.anomalies._lock:
        row = h.anomalies._conn.execute(
            "SELECT COUNT(*) FROM anomalies WHERE attack_type = 'brute-force'").fetchone()
    assert row[0] == 1
    # A non-web anomaly gets no attack_type.
    others = [a for a in h.anomalies.query_anomalies({}, limit=50)["items"] if a["id"] != anomaly["id"]]
    assert all(not a.get("attack_type") for a in others)


# ─── Part 3: matching ────────────────────────────────────────────────────────


def test_same_pod_falco_event_opens_a_critical_high_confidence_incident(tmp_path):
    h = Harness(tmp_path, "same_pod")
    h.job.detect_once(NOW)
    counts = h.correlator.run_once(NOW)  # same pod: no need to wait for the window to complete
    assert counts["incidents_created"] == 1
    [incident] = h.incidents.list()
    anomaly = h.web_anomaly()
    assert incident["severity"] == "critical" and incident["confidence"] == "high"
    assert incident["state"] == "open" and incident["namespace"] == "sec-test" and incident["pod"] == WP_POD
    assert incident["web_anomaly_id"] == anomaly["id"] and incident["attack_type"] == "brute-force"
    assert incident["falco_rule"] == "Terminal shell in container"
    assert incident["web_started_at"] == "2026-11-02T10:46:00Z"
    assert incident["falco_ts"] == "2026-11-02T10:50:30Z" and incident["gap_s"] == 270.0
    assert incident["falco_evidence"]["target_pod"] == WP_POD  # from the JSON output_fields
    assert h.notified == [incident["id"]]
    assert incident["notified"] == "queued" and incident["notify_event_id"] == 1000 + incident["id"]
    # Re-evaluation (detection and correlation again) never duplicates it.
    h.job.detect_once(NOW + timedelta(minutes=5))
    assert h.correlator.run_once(AFTER_WINDOW)["incidents_created"] == 0
    assert len(h.incidents.list()) == 1 and h.notified == [incident["id"]]


def test_namespace_only_match_is_medium_confidence_high_severity(tmp_path):
    h = Harness(tmp_path, "other_pod")
    h.job.detect_once(NOW)
    # Window not complete yet: a same-pod event could still arrive, so wait.
    assert h.correlator.run_once(NOW)["incidents_created"] == 0
    assert h.correlator.run_once(AFTER_WINDOW)["incidents_created"] == 1
    [incident] = h.incidents.list()
    assert incident["confidence"] == "medium" and incident["severity"] == "high"
    assert incident["namespace"] == "sec-test" and incident["falco_evidence"]["target_pod"] == "mysql-0"
    assert incident["falco_rule"] == "Run shell untrusted"


def test_a_same_pod_event_later_in_the_window_beats_an_earlier_namespace_only_one(tmp_path):
    h = Harness(tmp_path, "other_pod", "late_inside_window")
    h.job.detect_once(NOW)
    h.correlator.run_once(NOW)  # 11:05 is in the window but the run is at 11:00 (not ingested yet)
    h.correlator.run_once(AFTER_WINDOW)
    [incident] = h.incidents.list()
    assert incident["confidence"] == "high" and incident["severity"] == "critical"
    assert incident["falco_ts"] == "2026-11-02T11:05:00Z"  # earliest same-pod, not the 10:52 mysql-0 one


def test_no_falco_event_means_no_incident_and_none_retroactively(tmp_path):
    h = Harness(tmp_path)
    h.job.detect_once(NOW)
    first = h.correlator.run_once(NOW)
    assert first["incidents_created"] == 0 and first["correlation_no_match"] == 0  # window still open
    closed = h.correlator.run_once(AFTER_WINDOW)
    assert closed["correlation_no_match"] == 1 and h.incidents.list() == []
    # A Falco event inside the (closed) window ingested afterwards: no incident.
    h.add("late_inside_window")
    later = h.correlator.run_once(AFTER_WINDOW + timedelta(minutes=30))
    assert later["incidents_created"] == 0 and later["correlation_checked"] == 0
    assert h.incidents.list() == [] and h.notified == []


def test_falco_event_inside_cold_start_is_not_a_match(tmp_path):
    h = Harness(tmp_path, "cold_start_pod")
    h.job.detect_once(NOW)
    h.correlator.run_once(NOW)
    assert h.correlator.run_once(AFTER_WINDOW)["correlation_no_match"] == 1
    assert h.incidents.list() == []
    # Control: the same data without the cold-start guard would correlate (an
    # adjacent replica of the attacked pod -> high), so the guard is what excluded it.
    unguarded = Harness(tmp_path / "unguarded", "cold_start_pod", cold_start_grace_s=0)
    unguarded.job.detect_once(NOW)
    unguarded.correlator.run_once(NOW)
    [incident] = unguarded.incidents.list()
    assert incident["confidence"] == "high"
    assert incident["falco_evidence"]["target_pod"] == "wordpress-7d79967bc8-n3wpd"


def test_wp_attack_replay_still_produces_no_incident(tmp_path):
    """Negative case: wp_attack_replay's Falco event is the container's own
    start-up shell (inside cold start, and before the attack), not a
    post-attack chain."""
    store, job, now, _ = _wp_replay(tmp_path)
    kb = SignatureKB(load_rules())
    job.classifier = lambda a: classify_anomaly(kb, store, a)
    job.detect_once(now)
    web = [a for a in store.query_anomalies({"status": "new"}, limit=200)["items"] if a.get("attack_type")]
    assert {a["attack_type"] for a in web} >= {"enumeration", "brute-force"}  # the web half is there
    incidents = IncidentStore(tmp_path / "webapp.sqlite")
    correlator = Correlator(job.cfg, incidents, job.detector._conn)
    correlator.run_once(now)
    closed = correlator.run_once(now + timedelta(hours=2))
    assert closed["correlation_no_match"] == len(web)
    assert incidents.list() == []
    # The shell targets the attacked pod but is a start-up artifact: inside its cold-start grace.
    shell_ts = datetime(2026, 11, 2, 9, 5, 5, tzinfo=timezone.utc).timestamp()
    assert correlator._in_cold_start(shell_ts, "sec-test", WP_POD)


def test_helpers():
    assert workload_of("wordpress-7d79967bc8-qjt4c") == workload_of("wordpress-7d79967bc8-n3wpd")
    assert workload_of("mysql-0") == workload_of("mysql-1") != workload_of("wordpress-7d79967bc8-qjt4c")
    text = {"message": "Run shell untrusted: 10:52:10.123456789: Notice Shell spawned (k8s.ns=a k8s.pod=b-0)"}
    assert falco_rule_of(text) == ("Run shell untrusted", "Notice")
    assert falco_target_of(text) == ("a", "b-0")
    js = {"message": json.dumps({"rule": "Write below etc", "priority": "Error",
                                 "output_fields": {"k8s.ns.name": "x", "k8s.pod.name": "y"}})}
    assert falco_rule_of(js) == ("Write below etc", "Error") and falco_target_of(js) == ("x", "y")


# ─── Notification, restart, AI, API (the web app) ────────────────────────────


class Flaky:
    def __init__(self):
        self.down = True
        self.calls = 0
        self.delivered: list[dict] = []

    def guarded(self, url, body, headers, timeout=10):
        self.calls += 1
        if self.down:
            raise DeliveryError("HTTP 503", transient=True)
        self.delivered.append(json.loads(body))

    def trusted(self, url, payload, timeout=10):
        self.guarded(url, json.dumps(payload).encode(), {})


def _webapp(tmp_path, *variants, channel: bool = True, ai: dict | None = None, load: bool = True, **alerts):
    app = _alerts_app(tmp_path, ai=ai, public_url="https://logscope.example.com", **alerts)
    app.clock.t = NOW
    app.alerts._started = NOW
    _listed(app, NOW)
    if load:
        _load(app.storage, *variants)
    app.cfg = replace(app.cfg, insights=_cfg().insights)
    app.insights.cfg = app.cfg
    app.insights.detector.cfg = app.cfg.insights
    app.correlator.cfg = app.cfg
    if channel:
        created = app.alert_channels.create({"name": "sec", "type": "webhook", "url": "https://hooks.example/s"})
        app.cfg = replace(app.cfg, security=replace(app.cfg.security, notify_channel_ids=(created["id"],)))
    return app


def _alert_events(app) -> list[dict]:
    with app.state_db.lock:
        return [dict(r) for r in app.state_db.conn.execute("SELECT * FROM alert_events ORDER BY id")]


def _deliveries(app) -> list[dict]:
    with app.state_db.lock:
        return [dict(r) for r in app.state_db.conn.execute("SELECT * FROM alert_deliveries ORDER BY event_id")]


def _no_sleep(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("delivery must not sleep in process; retries are scheduled in the database")

    monkeypatch.setattr(time, "sleep", boom)


def test_notification_uses_durable_delivery_not_an_in_process_retry(tmp_path, monkeypatch):
    app = _webapp(tmp_path, "same_pod")
    hook = Flaky()
    app.alerts.deliverer = Deliverer(guarded=hook.guarded, trusted=hook.trusted)
    app.insights.detect_once(NOW)
    app.correlator.run_once(NOW)
    [incident] = app.incidents.list()
    [event] = _alert_events(app)
    assert incident["notified"] == "queued" and incident["notify_event_id"] == event["id"]
    assert event["rule_id"] is None and event["group_key"] == f"security_incident:{incident['id']}"
    assert event["notified"] == NOTIFY_QUEUED

    _no_sleep(monkeypatch)
    started = time.monotonic()
    assert app.alerts.deliver_pending() == 1
    assert time.monotonic() - started < 5 and hook.calls == 1  # one attempt, then back to the queue
    [delivery] = _deliveries(app)
    assert delivery["state"] == "queued" and delivery["attempts"] == 1
    assert delivery["next_attempt_at"] == "2026-11-02T11:00:30.000Z"  # RETRY_SCHEDULE_SECS[0] later
    assert RETRY_SCHEDULE_SECS[0] == 30
    assert app.alerts.deliver_pending() == 0  # not due yet: nothing is retried inside the pass

    app.clock.t = NOW + timedelta(seconds=30)
    hook.down = False
    app.alerts.deliver_pending()
    assert _alert_events(app)[0]["notified"] == NOTIFY_SENT
    [payload] = hook.delivered
    assert payload["kind"] == "security_incident" and payload["incident_id"] == incident["id"]
    assert payload["namespace"] == "sec-test" and payload["pod"] == WP_POD
    assert payload["attack_type"] == "brute-force" and payload["falco_rule"] == "Terminal shell in container"
    assert payload["web_started_at"] == "2026-11-02T10:46:00Z" and payload["falco_ts"] == "2026-11-02T10:50:30Z"
    assert payload["gap_s"] == 270.0 and payload["severity"] == "critical"
    assert payload["url"] == ("https://logscope.example.com/?tab=logs&from=2026-11-02T10%3A45%3A00Z"
                              "&to=2026-11-02T10%3A51%3A30Z")
    text = json.dumps(payload)
    assert "wp-login" not in text and "10.42.0." not in text and "sh -i" not in text  # no raw log lines
    message = app._incident_event_message(_alert_events(app)[0])
    assert any(line.startswith("**Gap** 4 min 30 s") for line in message.lines)


def test_no_channel_configured_records_the_incident_without_error(tmp_path):
    app = _webapp(tmp_path, "same_pod", channel=False)
    app.insights.detect_once(NOW)
    assert app.correlator.run_once(NOW)["incidents_created"] == 1
    [incident] = app.incidents.list()
    assert incident["notified"] == "skipped" and incident["notify_event_id"] is None
    assert _alert_events(app) == []


def test_environment_channel_is_the_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("MATTERMOST_WEBHOOK_URL", "https://mattermost.example/hooks/abc")
    app = _webapp(tmp_path, "same_pod", channel=False)
    app.insights.detect_once(NOW)
    app.correlator.run_once(NOW)
    app.alerts.deliver_pending()
    [sent] = app.sent.items
    assert sent["url"] == "https://mattermost.example/hooks/abc"
    assert "Security incident" in sent["payload"]["text"] and "brute-force" in sent["payload"]["text"]


def test_restart_does_not_duplicate_the_incident_or_resend(tmp_path):
    app = _webapp(tmp_path, "same_pod")
    app.insights.detect_once(NOW)
    app.correlator.run_once(NOW)
    app.alerts.deliver_pending()
    assert len(app.sent.items) == 1 and len(_alert_events(app)) == 1

    def restarted() -> WebApp:
        again = WebApp(app.cfg)
        again.alerts._clock = app.clock
        again.alerts._started = NOW
        again.sent = Sent()
        again.alerts.deliverer = Deliverer(guarded=again.sent.guarded, trusted=again.sent.trusted)
        return again

    # A plain restart, mid-cycle: detection and correlation run again.
    second = restarted()
    second.insights.detect_once(NOW + timedelta(minutes=5))
    second.correlator.run_once(NOW + timedelta(minutes=5))
    second.alerts.deliver_pending()
    assert len(second.incidents.list()) == 1 and len(_alert_events(second)) == 1 and second.sent.items == []

    # A crash between queueing the notification and marking the incident.
    with second.incidents._lock:
        second.incidents.conn.execute("UPDATE security_incidents SET notified = 'pending', notify_event_id = NULL")
        second.incidents.conn.commit()
    third = restarted()
    counts = third.correlator.run_once(NOW + timedelta(minutes=10))
    assert counts["notify_resumed"] == 1 and counts["incidents_created"] == 0
    third.alerts.deliver_pending()
    [incident] = third.incidents.list()
    assert incident["notified"] == "queued" and incident["notify_event_id"] == _alert_events(third)[0]["id"]
    assert len(_alert_events(third)) == 1 and third.sent.items == []


AI = {"provider": "openai", "model": "gpt-fast", "api_key_env": "LS_TEST_AI_KEY"}


def _usage(app) -> list[tuple]:
    with app.state_db.lock:
        return [tuple(r) for r in app.state_db.conn.execute(
            "SELECT feature, outcome FROM ai_usage WHERE feature = 'incident_summary' ORDER BY id")]


def _incident_with_ai(tmp_path, monkeypatch, variant, *, budget=None):
    monkeypatch.setenv("LS_TEST_AI_KEY", "sk-test-0123456789abcdef")
    app = _webapp(tmp_path, variant, ai=AI)
    if budget is not None:
        app.ai_settings.update({"budgets": {"daily_calls": {"incident_summary": budget}}})
    calls = []
    app.incident_ai.complete = lambda system, payload, cfg: calls.append(payload) or {
        "summary": "A brute force against wordpress was followed by a shell in mysql-0; possible lateral move."}
    app.clock.t = NOW + timedelta(minutes=40)  # watermark (listed - 720 s) past 11:15: namespace-only may open
    _listed(app, app.clock.t)
    app.insights.detect_once(NOW)
    app.correlator.run_once(app.clock.t)
    return app, calls


def test_ai_summary_is_signature_first_when_both_halves_are_known(tmp_path, monkeypatch):
    app, calls = _incident_with_ai(tmp_path, monkeypatch, "same_pod")
    assert app.incident_ai.drain() == ["signature"]  # web (wp-login) and Falco (terminal shell) signatures
    [incident] = app.incidents.list()
    assert calls == [] and incident["ai_meta"]["source"] == "signature"
    assert "'Terminal shell in container'" in incident["ai_summary"] and "brute-force" in incident["ai_summary"]
    assert _usage(app) == [("incident_summary", "signature")]


def test_ai_summary_respects_the_budget_and_skips_cleanly(tmp_path, monkeypatch):
    app, calls = _incident_with_ai(tmp_path, monkeypatch, "other_pod", budget=0)
    assert app.incident_ai.drain() == ["budget_blocked"]
    [incident] = app.incidents.list()
    assert calls == [] and incident["ai_summary"] is None and incident["ai_state"] == "budget_blocked"
    assert _usage(app) == [("incident_summary", "budget_blocked")]
    # Not retried: a later hand-off (e.g. a restart) finds it settled.
    app.incident_ai.enqueue(incident["id"])
    assert app.incident_ai.drain() == ["done"] and calls == []
    # The incident and its notification are unaffected.
    assert incident["state"] == "open" and incident["notified"] == "queued"


def test_ai_summary_one_metered_call_when_under_budget_then_cached(tmp_path, monkeypatch):
    app, calls = _incident_with_ai(tmp_path, monkeypatch, "other_pod")
    assert app.incident_ai.drain() == ["ai"]
    [incident] = app.incidents.list()
    assert len(calls) == 1 and incident["ai_meta"]["source"] == "ai"
    assert incident["ai_summary"].startswith("A brute force against wordpress")
    sent = calls[0]
    assert sent["web_attack"]["attack_type"] == "brute-force"
    assert sent["runtime_event"]["falco_rule"] == "Run shell untrusted"
    assert _usage(app) == [("incident_summary", "ok")]
    # Same attack type + Falco rule again: served from the cache, no new call.
    with app.incidents._lock:
        app.incidents.conn.execute("UPDATE security_incidents SET ai_state = NULL, ai_summary = NULL")
        app.incidents.conn.commit()
    app.incident_ai.enqueue(incident["id"])
    assert app.incident_ai.drain() == ["cache"] and len(calls) == 1


def test_ai_flag_off_skips(tmp_path, monkeypatch):
    monkeypatch.setenv("LS_TEST_AI_KEY", "sk-test-0123456789abcdef")
    app = _webapp(tmp_path, "other_pod", ai=AI)
    app.ai_settings.update({"flags": {"incident_correlation_ai": False}})
    assert app.ai_settings.enabled("incident_correlation_ai") is False
    app.clock.t = NOW + timedelta(minutes=40)
    _listed(app, app.clock.t)
    app.insights.detect_once(NOW)
    app.correlator.run_once(app.clock.t)
    assert app.incident_ai.drain() == ["disabled"] and _usage(app) == []


def test_flag_is_on_by_default(tmp_path):
    app = _webapp(tmp_path, load=False, channel=False)
    assert app.ai_settings.enabled("incident_correlation_ai") is True


# ─── API ─────────────────────────────────────────────────────────────────────


@pytest.fixture()
def incident_app(tmp_path):
    app = _webapp(tmp_path, "same_pod")
    app.insights.detect_once(NOW)
    app.correlator.run_once(NOW)
    return app


def test_api_reads_are_open_and_writes_need_the_admin_token(incident_app, served):
    app = incident_app
    server = served(app)
    [incident] = app.incidents.list()
    status, listing = _request(server, "GET", "/api/security/incidents")
    assert status == 200 and [i["id"] for i in listing["items"]] == [incident["id"]]
    assert listing["counts"] == {"open": 1}
    assert _request(server, "GET", "/api/security/incidents?state=resolved")[1]["items"] == []
    assert _request(server, "GET", "/api/security/incidents?state=bogus")[0] == 400

    status, detail = _request(server, "GET", f"/api/security/incidents/{incident['id']}")
    assert status == 200
    detail = detail["incident"]
    assert detail["web_anomaly"]["id"] == incident["web_anomaly_id"]
    assert detail["web_anomaly"]["template_summary"]["attack_type"] == "brute-force"
    assert detail["falco_record"]["available"] is True and detail["falco_record"]["rule"] == "Terminal shell in container"
    assert "raw_line" not in detail["falco_record"]
    assert _request(server, "GET", "/api/security/incidents/999")[0] == 404

    path = f"/api/security/incidents/{incident['id']}"
    assert _request(server, "POST", f"{path}/acknowledge", body="{}", headers=JSON)[0] == 401
    bad = {**JSON, "Authorization": "Bearer wrong-token-0123456789"}
    assert _request(server, "POST", f"{path}/resolve", body="{}", headers=bad)[0] == 401
    # The Origin check applies on top of the token.
    evil = {**AUTH, "Origin": "https://evil.example"}
    assert _request(server, "POST", f"{path}/acknowledge", body="{}", headers=evil)[0] == 403
    assert app.incidents.get(incident["id"])["state"] == "open"

    status, acked = _request(server, "POST", f"{path}/acknowledge", body="{}", headers=AUTH)
    assert status == 200 and acked["incident"]["state"] == "acknowledged"
    assert acked["incident"]["acknowledged_by"] == "admin"
    assert _request(server, "POST", f"{path}/acknowledge", body="{}", headers=AUTH)[0] == 409
    status, resolved = _request(server, "POST", f"{path}/resolve", body=json.dumps({"by": "oncall"}), headers=AUTH)
    assert status == 200 and resolved["incident"]["state"] == "resolved"
    assert resolved["incident"]["resolved_by"] == "oncall" and resolved["incident"]["resolved_at"]
    assert _request(server, "POST", f"{path}/resolve", body="{}", headers=AUTH)[0] == 409
    assert _request(server, "GET", path)[1]["incident"]["state"] == "resolved"
    assert ADMIN  # the token the AUTH header carries


def test_status_reports_correlation(incident_app):
    status = incident_app.status()["security"]
    assert status["enabled"] is True and status["incidents"] == {"open": 1}
    assert status["last_counts"]["incidents_created"] == 1
