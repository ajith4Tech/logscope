"""Alerts on saved views: watermark, evaluator state machine, restart
rebuild, stale pipeline, grouping, delivery (channel types, HMAC, retries,
SSRF guard), secrecy of webhook URLs, API auth, backtest, message content,
AI summary opt-in, and the anomaly-notifier starvation fix."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import sqlite3
import sys
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_production import CONFIG, JSON, _request, _serve  # noqa: E402

from webapp.api import ai_settings, channels  # noqa: E402
from webapp.api.ai_settings import ClientRateLimiter  # noqa: E402
from webapp.api.alerts import AlertEngine, compute_watermark  # noqa: E402
from webapp.api.channels import (  # noqa: E402
    ChannelError,
    Deliverer,
    DeliveryError,
    check_destination,
    check_url_shape,
    post_guarded,
)
from webapp.api.config import load_app_config, source_prefixes  # noqa: E402
from webapp.api.filters import iso_js  # noqa: E402
from webapp.api.notify import URGENCY_RANK_SQL, MattermostNotifier, anomaly_urgency  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402

ADMIN = "admin-token-for-alert-tests-0123456789"
NOW = datetime(2026, 10, 21, 6, 0, tzinfo=timezone.utc)
WM = NOW - timedelta(seconds=600 + 120)  # listed at NOW: batch timeout 600 + margin 120
AUTH = {**JSON, "Authorization": f"Bearer {ADMIN}"}
_BASE = {"scope": "namespaces/payments", "namespace": "payments", "pod": "api-0", "container": "app",
         "severity_bucket": "error", "raw_line": "r", "source_etag": "e", "is_falco": 0, "source_key": "k"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in (ai_settings.SECRET_KEY_ENV, ai_settings.SECRET_KEY_PREVIOUS_ENV, "MATTERMOST_WEBHOOK_URL",
                 channels.ALLOWED_HOSTS_ENV, "LS_TEST_AI_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(ai_settings.ADMIN_TOKEN_ENV, ADMIN)
    monkeypatch.setenv("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", "0")


class Clock:
    def __init__(self, t: datetime):
        self.t = t

    def __call__(self) -> datetime:
        return self.t


class Sent:
    """Captures deliveries: trusted (env channel) and guarded (UI channels)."""

    def __init__(self):
        self.items: list[dict] = []

    def trusted(self, url, payload, timeout=10):
        self.items.append({"url": url, "payload": payload})

    def guarded(self, url, body, headers, timeout=10):
        self.items.append({"url": url, "payload": json.loads(body), "headers": headers})


def _app(tmp_path, *, ai: dict | None = None, **alerts) -> WebApp:
    cfg = load_app_config(CONFIG)
    cfg = replace(cfg, webapp=replace(cfg.webapp, db_path=tmp_path / "cache.sqlite",
                                      state_db_path=tmp_path / "state" / "state.sqlite"),
                  alerts=replace(cfg.alerts, **alerts))
    if ai:
        cfg = replace(cfg, ai=replace(cfg.ai, **ai))
    app = WebApp(cfg)
    clock = Clock(NOW)
    app.alerts._clock = clock
    app.alert_rules._clock = clock
    app.alerts._started = NOW
    app.clock = clock
    app.sent = Sent()
    app.alerts.deliverer = Deliverer(sleep=lambda s: None, guarded=app.sent.guarded, trusted=app.sent.trusted)
    _listed(app, NOW)
    return app


def _prefixes(app) -> list[str]:
    return [p["prefix"] for p in source_prefixes(app.cfg)]


def _listed(app, at: datetime, **per_prefix: datetime) -> None:
    for i, prefix in enumerate(_prefixes(app)):
        app.storage.set_prefix_listed(prefix, iso_js(per_prefix.get(f"p{i}", at)))


def _advance(app, secs: int) -> dict:
    app.clock.t += timedelta(seconds=secs)
    _listed(app, app.clock.t)
    result = app.alerts.tick()
    app.alerts.deliver_pending()
    return result


def _records(app, items: list[tuple[datetime, dict]]) -> None:
    rows = []
    for i, (ts, extra) in enumerate(items):
        rows.append({**_BASE, "message": f"request failed id {i}", "line_number": i + 1 + len(rows) * 0,
                     "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), **extra})
    for j, row in enumerate(rows):
        row["line_number"] = j + 1
        row["source_key"] = f"k-{id(items)}"
    app.storage.insert_records(rows)


def _view(app, filters: dict | None = None, name: str | None = None) -> int:
    name = name or f"payments errors {len(app.views.list()) + 1}"
    return app.views.create({"name": name, "filters": filters or {"ns": "payments"}})["id"]


def _rule(app, **overrides) -> dict:
    body = {"name": "too many errors", "view_id": overrides.pop("view_id", None) or _view(app),
            "metric": "count", "op": ">", "threshold": 10, "window_s": 300, "interval_s": 60, "for_evals": 1,
            "channel_ids": [], **overrides}
    return app.alert_rules.create(body)


def _events(app, rule_id=None) -> list[dict]:
    with app.state_db.lock:
        if rule_id is None:
            rows = app.state_db.conn.execute("SELECT * FROM alert_events ORDER BY id").fetchall()
        else:
            rows = app.state_db.conn.execute("SELECT * FROM alert_events WHERE rule_id = ? ORDER BY id",
                                             (rule_id,)).fetchall()
    return [dict(r) for r in rows]


class Scripted:
    """The real storage, except alert_metric answers from a script."""

    def __init__(self, real, values):
        self.real = real
        self.values = list(values)
        self.calls: list[dict] = []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def alert_metric(self, params, **kwargs):
        self.calls.append(params)
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return {"groups": value if isinstance(value, dict) else {"": float(value)}, "overflow": 0}


@pytest.fixture()
def served():
    servers = []

    def start(app):
        server = _serve(app)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


class Hook:
    """A local webhook receiver; answers the queued status codes, then 200."""

    def __init__(self, codes=()):
        self.requests: list[dict] = []
        self.codes = list(codes)
        hook = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                hook.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                code = hook.codes.pop(0) if hook.codes else 200
                self.send_response(code)
                if 300 <= code < 400:
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/elsewhere")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, path="/hook") -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ─── Watermark ───────────────────────────────────────────────────────────────


def test_watermark_from_listings_with_lagging_stale_and_failing_prefixes():
    fmt = "%Y/%m/%d/%H_%M_%S_"
    prefixes = ["logs/error/", "logs/info/"]
    t = NOW
    listed = lambda when: iso_js(when)  # noqa: E731
    both = {p: {"listed_ok_at": listed(t)} for p in prefixes}
    mark = compute_watermark(both, prefixes, t, batch_timeout=600, margin=120, time_format=fmt)
    assert mark["at"] == iso_js(t - timedelta(seconds=720)) and mark["lag_secs"] == 720 and not mark["stale"]

    lagging = {**both, "logs/info/": {"listed_ok_at": listed(t - timedelta(minutes=10))}}
    mark = compute_watermark(lagging, prefixes, t, batch_timeout=600, margin=120, time_format=fmt)
    assert mark["at"] == iso_js(t - timedelta(minutes=10, seconds=720)) and not mark["stale"]
    info = next(p for p in mark["prefixes"] if p["prefix"] == "logs/info/")
    assert info["complete_up_to"] == iso_js(t - timedelta(minutes=20))

    stale = {**both, "logs/info/": {"listed_ok_at": listed(t - timedelta(minutes=40))}}
    mark = compute_watermark(stale, prefixes, t, batch_timeout=600, margin=120, time_format=fmt)
    assert mark["stale"] and mark["lag_secs"] == 40 * 60 + 720 and mark["stale_after_secs"] == 1800

    # A failing object holds its prefix back to the object's key time.
    failing = {**both, "logs/error/": {"listed_ok_at": listed(t), "cursor": "logs/error/2026/10/21/05_59_00_a.gz",
                                       "failing": {"key": "logs/error/2026/10/21/05_30_00_x.gz",
                                                   "last_modified": listed(t)}}}
    mark = compute_watermark(failing, prefixes, t, batch_timeout=600, margin=120, time_format=fmt)
    assert mark["at"] == iso_js(datetime(2026, 10, 21, 5, 28, tzinfo=timezone.utc))
    assert mark["prefixes"][0]["cursor_time"] == iso_js(datetime(2026, 10, 21, 5, 59, tzinfo=timezone.utc))

    never = {"logs/error/": {"listed_ok_at": listed(t)}}
    assert compute_watermark(never, prefixes, t, batch_timeout=600, margin=120, time_format=fmt)["at"] is None


def test_watermark_in_status_and_ingest_records_listings(tmp_path, served):
    app = _app(tmp_path)
    server = served(app)
    status = _request(server, "GET", "/api/status")[1]
    assert status["watermark"]["at"] == iso_js(WM)
    assert {p["prefix"] for p in status["watermark"]["prefixes"]} == set(_prefixes(app))
    assert status["alerts"]["firing"] == 0


def test_windows_end_at_the_watermark_not_now(tmp_path):
    app = _app(tmp_path)
    inside = [(WM - timedelta(seconds=s), {}) for s in (10, 100, 250)]
    after = [(WM + timedelta(seconds=s), {}) for s in (30, 300, 600)]  # newer than the watermark
    _records(app, inside + after + [(WM - timedelta(seconds=400), {})])
    rule = _rule(app, threshold=0)
    app.alerts.tick()
    event = _events(app, rule["id"])[-1]
    assert (event["state"], event["value"]) == ("firing", 3.0)
    assert event["window_end"] == iso_js(WM) and event["window_start"] == iso_js(WM - timedelta(seconds=300))


# ─── State machine ───────────────────────────────────────────────────────────


def test_state_machine_for_evals_renotify_resolved_and_mute(tmp_path):
    app = _app(tmp_path, public_url="https://logscope.example.com")
    rule = _rule(app, for_evals=2, renotify_s=300, notify_resolved=True, channel_ids=[])
    hook_channel = app.alert_channels.create({"name": "ops", "type": "webhook", "url": "https://hooks.example/a"})
    app.alert_rules.update(rule["id"], {"channel_ids": [hook_channel["id"]]})
    script = Scripted(app.storage, [20, 20, 20, 20, 20, 20, 20, 5, 5, 20, 5, 20, 20, 20])
    app.alerts._storage = script
    states = []
    for _ in range(14):
        _advance(app, 60)
        states.append(app.alerts.rule_status(app.alert_rules.get(rule["id"]))["state"])
        if len(states) == 11:  # mute for an hour before the next breaches
            app.alert_rules.mute(rule["id"], {"duration": "1h"})
    app.alerts._storage = script.real
    assert states[:2] == ["pending", "firing"]
    events = [(e["from_state"], e["state"], e["notified"], e["muted"]) for e in _events(app, rule["id"])]
    assert events == [
        ("ok", "pending", 0, 0),
        ("pending", "firing", 1, 0),        # 2nd consecutive breach: notified
        ("firing", "firing", 1, 0),         # renotify after 300 s (5 evaluations later)
        ("firing", "resolved", 1, 0),       # resolved: notified
        ("resolved", "ok", 0, 0),
        ("ok", "pending", 0, 0),            # one breach, then back to ok
        ("pending", "ok", 0, 0),
        ("ok", "pending", 0, 1),            # muted: recorded, never sent
        ("pending", "firing", 0, 1),
    ]
    assert len(app.sent.items) == 3
    assert [i["payload"]["state"] for i in app.sent.items] == ["firing", "firing", "resolved"]
    # Unmuted: the firing alert that was never sent is notified once.
    app.alert_rules.unmute(rule["id"])
    app.alerts._storage = Scripted(app.storage, [20, 20])
    _advance(app, 60)
    _advance(app, 60)
    assert len(app.sent.items) == 4 and app.sent.items[-1]["payload"]["state"] == "firing"


def test_restart_rebuilds_state_without_duplicate_notifications(tmp_path):
    app = _app(tmp_path)
    channel = app.alert_channels.create({"name": "ops", "type": "slack", "url": "https://hooks.example/s"})
    firing = _rule(app, name="firing rule", channel_ids=[channel["id"]])
    pending = _rule(app, name="pending rule", for_evals=3, view_id=_view(app, name="v2"),
                    channel_ids=[channel["id"]])
    app.alerts._storage = Scripted(app.storage, [50, 50, 50, 50])  # rules evaluate in name order
    _advance(app, 60)
    _advance(app, 60)
    assert len(app.sent.items) == 1  # "firing rule" fired once; "pending rule" is at 2 of 3

    restarted = AlertEngine(
        db=app.state_db, storage=Scripted(app.storage, [50, 50]), rules=app.alert_rules,
        channels=app.alert_channels, deliverer=app.alerts.deliverer, prefixes=lambda: _prefixes(app),
        time_format="%Y/%m/%d/%H_%M_%S_", clock=app.clock)
    assert restarted.rule_status(app.alert_rules.get(firing["id"]))["state"] == "firing"
    assert restarted.rule_status(app.alert_rules.get(pending["id"]))["state"] == "pending"
    restarted.tick()  # same watermark: nothing is due again
    assert len(restarted._storage.values) == 2
    app.clock.t += timedelta(seconds=60)
    _listed(app, app.clock.t)
    restarted.tick()
    restarted.deliver_pending()
    sent = [i["payload"]["text"] for i in app.sent.items]
    assert len(sent) == 2 and "pending rule" in sent[1]  # third breach after the restart fires it
    assert [e["state"] for e in _events(app, firing["id"])] == ["firing"]  # no second firing event


def test_unknown_evaluations_change_nothing(tmp_path):
    app = _app(tmp_path)
    rule = _rule(app, for_evals=2)
    app.alerts._storage = Scripted(app.storage, [20, TimeoutError("slow"), 20])
    _advance(app, 60)
    _advance(app, 60)
    status = app.alerts.rule_status(app.alert_rules.get(rule["id"]))
    assert status["state"] == "pending" and "longer than 2 s" in status["unknown_reason"]
    assert status["groups"][0]["result"] == "unknown"
    _advance(app, 60)
    assert [e["state"] for e in _events(app, rule["id"])] == ["pending", "firing"]


# ─── Stale pipeline ──────────────────────────────────────────────────────────


def test_absence_rule_suppressed_when_stale_and_one_pipeline_alert(tmp_path, monkeypatch):
    monkeypatch.setenv("MATTERMOST_WEBHOOK_URL", "https://chat.example/hooks/default-channel")
    app = _app(tmp_path)
    absence = _rule(app, name="no logs", op="<", threshold=1, channel_ids=[0])
    spike = _rule(app, name="spike", threshold=0, view_id=_view(app, name="v2"), channel_ids=[0])
    _records(app, [(NOW - timedelta(minutes=54), {})])  # inside the stale window
    stale_at = NOW - timedelta(minutes=40)
    for _ in range(3):
        app.clock.t += timedelta(seconds=60)
        _listed(app, stale_at)  # no listing has succeeded for 40+ minutes
        app.alerts.tick()
        app.alerts.deliver_pending()
    assert app.alerts.rule_status(app.alert_rules.get(absence["id"]))["state"] == "unknown"
    assert _events(app, absence["id"]) == []
    pipeline = _events(app)
    pipeline = [e for e in pipeline if e["rule_id"] is None]
    assert [(e["group_key"], e["state"]) for e in pipeline] == [("pipeline_stale", "firing")]
    texts = [i["payload"]["text"] for i in app.sent.items]
    assert sum("pipeline is stale" in t for t in texts) == 1
    assert all(i["url"] == "https://chat.example/hooks/default-channel" for i in app.sent.items)
    assert _events(app, spike["id"])[0]["state"] == "firing"  # > rules keep working on a stale pipeline
    _advance(app, 60)  # caught up
    pipeline = [e for e in _events(app) if e["rule_id"] is None]
    assert [e["state"] for e in pipeline] == ["firing", "resolved"]
    assert app.alerts.rule_status(app.alert_rules.get(absence["id"]))["state"] in ("firing", "pending")


# ─── Grouping ────────────────────────────────────────────────────────────────


def test_group_by_namespace_with_max_groups_overflow(tmp_path):
    app = _app(tmp_path)
    rows = []
    for n in range(25):
        rows += [(WM - timedelta(seconds=30 + i), {"namespace": f"ns-{n:02d}"}) for i in range(n + 1)]
    _records(app, rows)
    rule = _rule(app, view_id=_view(app, {"sev": "error"}), group_by="namespace", threshold=0)
    app.alerts.tick()
    status = app.alerts.rule_status(app.alert_rules.get(rule["id"]))
    firing = [g for g in status["groups"] if g["state"] == "firing"]
    assert len(firing) == 20 and status["overflow"] == 5
    assert {g["group"] for g in firing} == {f"ns-{n:02d}" for n in range(5, 25)}  # the busiest 20
    assert all(e["detail"] == "5 more groups not evaluated" for e in _events(app, rule["id"]))


def test_deleting_a_view_disables_its_rule(tmp_path, served):
    app = _app(tmp_path)
    rule = _rule(app)
    view_id = rule["view_id"]
    server = served(app)
    assert _request(server, "DELETE", f"/api/views/{view_id}")[0] == 200
    after = app.alert_rules.get(rule["id"])
    assert after["enabled"] is False and after["view_id"] is None and "deleted" in after["disabled_reason"]
    assert [e["state"] for e in _events(app, rule["id"])] == ["disabled"]
    app.alerts.tick()
    assert [e["state"] for e in _events(app, rule["id"])] == ["disabled"]
    status, payload = _request(server, "PATCH", f"/api/alerts/rules/{rule['id']}", body=json.dumps(
        {"enabled": True}), headers=AUTH)
    assert status == 422 and payload["field"] == "view_id"


# ─── Delivery ────────────────────────────────────────────────────────────────


def _fire(app, channel_ids, *, value=20):
    rule = _rule(app, channel_ids=channel_ids, labels={"team": "payments"})
    app.alerts._storage = Scripted(app.storage, [value])
    app.alerts.tick()
    app.alerts._storage = app.alerts._storage.real
    app.alerts.deliver_pending()
    return rule


def test_delivery_to_each_channel_type_with_hmac(tmp_path, monkeypatch):
    monkeypatch.setenv(channels.ALLOWED_HOSTS_ENV, "127.0.0.1")
    hook = Hook()
    try:
        app = _app(tmp_path, public_url="https://logscope.example.com")
        app.alerts.deliverer = Deliverer(sleep=lambda s: None)
        secret = "s3cret-for-hmac-signing-0123"
        ids = [app.alert_channels.create({"name": "mm", "type": "mattermost", "url": hook.url("/mm")})["id"],
               app.alert_channels.create({"name": "slack", "type": "slack", "url": hook.url("/slack")})["id"],
               app.alert_channels.create({"name": "hook", "type": "webhook", "url": hook.url("/wh"),
                                          "secret": secret})["id"]]
        rule = _fire(app, ids)
        by_path = {r["path"]: r for r in hook.requests}
        assert set(by_path) == {"/mm", "/slack", "/wh"}
        mm = json.loads(by_path["/mm"]["body"])
        assert mm["username"] == "Logscope" and mm["text"].startswith("#### FIRING · too many errors")
        assert "[Open in Logscope](https://logscope.example.com/?" in mm["text"]
        slack = json.loads(by_path["/slack"]["body"])
        assert slack["text"].startswith("*FIRING") and "<https://logscope.example.com/?" in slack["text"]
        wh = by_path["/wh"]
        body = json.loads(wh["body"])
        assert set(body) >= {"rule", "group", "value", "threshold", "window", "state", "url", "labels", "templates"}
        assert (body["value"], body["threshold"], body["state"], body["labels"]) == (20.0, 10.0, "firing",
                                                                                     {"team": "payments"})
        expected = "sha256=" + hmac.new(secret.encode(), wh["body"], hashlib.sha256).hexdigest()
        assert wh["headers"]["X-Logscope-Signature"] == expected
        assert "X-Logscope-Signature" not in by_path["/mm"]["headers"]
        assert _events(app, rule["id"])[0]["notified"] == 1
    finally:
        hook.close()


def test_delivery_retries_then_records_the_failure(tmp_path, monkeypatch):
    monkeypatch.setenv(channels.ALLOWED_HOSTS_ENV, "127.0.0.1")
    hook = Hook(codes=[500, 503])
    delays = []
    try:
        app = _app(tmp_path)
        app.alerts.deliverer = Deliverer(sleep=delays.append)
        channel = app.alert_channels.create({"name": "hook", "type": "webhook", "url": hook.url()})
        ok_rule = _fire(app, [channel["id"]])
        assert len(hook.requests) == 3 and delays == [1.0, 2.0]  # two retries with backoff, then 200
        assert _events(app, ok_rule["id"])[0]["notified"] == 1
        app.alert_rules.delete(ok_rule["id"])
        delays.clear()
        hook.codes = [500] * 5
        failed = _fire(app, [channel["id"]])
        assert len(hook.requests) == 3 + 5 and delays == [1.0, 2.0, 4.0, 8.0]
        event = _events(app, failed["id"])[0]
        # Still queued: durable delivery retries it later (see the backoff tests).
        assert event["notified"] == 2 and event["attempts"] == 1
        assert event["error"] == f"channel {channel['id']}: HTTP 500"
        # A permanent error is not retried.
        hook.codes = [404]
        before = len(hook.requests)
        assert Deliverer(sleep=delays.append).send(app.alert_channels.get(channel["id"]),
                                                   app.alerts.message(app.alert_rules.get(failed["id"]), event))
        assert len(hook.requests) == before + 1
    finally:
        hook.close()


# ─── SSRF guard ──────────────────────────────────────────────────────────────


def _resolver(*ips):
    return lambda host, port, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]


@pytest.mark.parametrize("ip", ["169.254.169.254", "fd00:ec2::254", "10.0.0.5", "192.168.1.10", "172.16.0.1",
                                "127.0.0.1", "0.0.0.0"])
def test_ssrf_refuses_metadata_private_and_loopback(ip):
    with pytest.raises(DeliveryError) as exc:
        check_destination("https://hooks.example.com/x", resolve=_resolver(ip))
    assert not exc.value.transient and "refused" in str(exc.value)
    assert "hooks.example.com" not in str(exc.value)


def test_ssrf_allowed_hosts_and_mixed_answers(monkeypatch):
    assert check_destination("https://hooks.example.com/x", resolve=_resolver("93.184.216.34"))[2] == "93.184.216.34"
    with pytest.raises(DeliveryError):  # one bad address is enough to refuse
        check_destination("https://hooks.example.com/x", resolve=_resolver("93.184.216.34", "10.1.2.3"))
    monkeypatch.setenv(channels.ALLOWED_HOSTS_ENV, "mattermost.internal")
    assert check_destination("http://mattermost.internal/h", resolve=_resolver("10.1.2.3"))[2] == "10.1.2.3"
    with pytest.raises(DeliveryError):  # metadata stays refused for an allowed host
        check_destination("https://mattermost.internal/h", resolve=_resolver("169.254.169.254"))
    with pytest.raises(DeliveryError):
        check_destination("https://169.254.169.254/latest/meta-data/")


def test_http_refused_and_redirects_not_followed(tmp_path, served, monkeypatch):
    with pytest.raises(ChannelError):
        check_url_shape("http://hooks.example.com/x")
    with pytest.raises(DeliveryError) as exc:
        post_guarded("http://hooks.example.com/x", b"{}", {})
    assert "https" in str(exc.value) and not exc.value.transient
    app = _app(tmp_path)
    server = served(app)
    status, payload = _request(server, "POST", "/api/alerts/channels", body=json.dumps(
        {"name": "plain", "type": "slack", "url": "http://hooks.example.com/x"}), headers=AUTH)
    assert status == 422 and payload["field"] == "url"

    monkeypatch.setenv(channels.ALLOWED_HOSTS_ENV, "127.0.0.1")
    hook = Hook(codes=[302])
    try:
        with pytest.raises(DeliveryError) as exc:
            post_guarded(hook.url("/hook"), b"{}", {"Content-Type": "application/json"})
        assert "redirect refused" in str(exc.value) and not exc.value.transient
        assert [r["path"] for r in hook.requests] == ["/hook"]
    finally:
        hook.close()


# ─── Secrecy and auth ────────────────────────────────────────────────────────


def test_webhook_urls_never_in_responses_or_logs(tmp_path, served, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(channels.ALLOWED_HOSTS_ENV, "127.0.0.1")
    monkeypatch.setenv("MATTERMOST_WEBHOOK_URL", "https://chat.example/hooks/ENVHOOKSECRET987")
    hook = Hook(codes=[500] * 20)
    try:
        app = _app(tmp_path)
        app.alerts.deliverer = Deliverer(sleep=lambda s: None)
        server = served(app)
        marker = "UIHOOKSECRET4242abcdef"
        status, created = _request(server, "POST", "/api/alerts/channels", body=json.dumps(
            {"name": "ops", "type": "webhook", "url": hook.url(f"/hooks/{marker}"),
             "secret": "hmac-secret-value-0000"}), headers=AUTH)
        assert status == 201 and created["channel"]["url_hint"] == "…abcdef"
        cid = created["channel"]["id"]
        rule = _fire(app, [cid, 0])
        bodies = [
            _request(server, "GET", "/api/alerts/channels")[1],
            _request(server, "GET", "/api/alerts/rules")[1],
            _request(server, "GET", f"/api/alerts/events?rule={rule['id']}")[1],
            _request(server, "GET", "/api/status")[1],
            _request(server, "POST", f"/api/alerts/channels/{cid}/test", headers=AUTH)[1],
            _request(server, "PATCH", f"/api/alerts/channels/{cid}", body=json.dumps({"name": "ops2"}),
                     headers=AUTH)[1],
        ]
        text = json.dumps(bodies) + caplog.text
        for secret in (marker, "ENVHOOKSECRET987", "hmac-secret-value-0000", "127.0.0.1:"):
            assert secret not in text, secret
        assert "HTTP 500" in json.dumps(bodies[2])  # the failure is recorded, without the URL
        raw = (tmp_path / "state" / "state.sqlite").read_bytes()
        assert marker.encode() not in raw and b"hmac-secret-value-0000" not in raw
    finally:
        hook.close()


def test_admin_token_for_writes_and_open_mute(tmp_path, served):
    app = _app(tmp_path)
    server = served(app)
    view_id = _view(app)
    rule_body = {"name": "r", "view_id": view_id, "metric": "count", "op": ">", "threshold": 1,
                 "window_s": 300, "interval_s": 60}
    channel_body = {"name": "c", "type": "slack", "url": "https://hooks.example/x"}
    for method, path, body in (("POST", "/api/alerts/channels", channel_body), ("POST", "/api/alerts/rules", rule_body)):
        assert _request(server, method, path, body=json.dumps(body), headers=JSON)[0] == 401
        assert _request(server, method, path, body=json.dumps(body),
                        headers={**JSON, "Authorization": "Bearer wrong"})[0] == 401
    status, channel = _request(server, "POST", "/api/alerts/channels", body=json.dumps(channel_body), headers=AUTH)
    assert status == 201
    status, rule = _request(server, "POST", "/api/alerts/rules", body=json.dumps(rule_body), headers=AUTH)
    assert status == 201
    rid, cid = rule["rule"]["id"], channel["channel"]["id"]
    for method, path in (("PATCH", f"/api/alerts/rules/{rid}"), ("DELETE", f"/api/alerts/rules/{rid}"),
                         ("PATCH", f"/api/alerts/channels/{cid}"), ("DELETE", f"/api/alerts/channels/{cid}"),
                         ("POST", f"/api/alerts/channels/{cid}/test")):
        assert _request(server, method, path, body=json.dumps({}), headers=JSON)[0] == 401, (method, path)
    # Mute and unmute: no admin token, but the Origin check applies.
    status, muted = _request(server, "POST", f"/api/alerts/rules/{rid}/mute", body=json.dumps({"duration": "4h"}),
                             headers=JSON)
    assert status == 200 and muted["rule"]["mute_until"]
    assert _request(server, "DELETE", f"/api/alerts/rules/{rid}/mute")[1]["rule"]["mute_until"] is None
    assert _request(server, "POST", f"/api/alerts/rules/{rid}/mute", body=json.dumps({"duration": 3600}),
                    headers={**JSON, "Origin": "https://evil.example"})[0] == 403
    assert _request(server, "POST", f"/api/alerts/rules/{rid}/mute", body=json.dumps({"duration": "90d"}),
                    headers=JSON)[0] == 422
    app.mute_limiter = ClientRateLimiter(max_failures=2)
    codes = [_request(server, "POST", f"/api/alerts/rules/{rid}/mute", body=json.dumps({"duration": "1h"}),
                      headers=JSON)[0] for _ in range(3)]
    assert codes == [200, 200, 429]
    # Reads are open.
    assert _request(server, "GET", "/api/alerts/rules")[0] == 200
    assert _request(server, "GET", "/api/alerts/channels")[0] == 200


def test_rule_validation_and_limits(tmp_path):
    app = _app(tmp_path)
    view_id = _view(app)
    base = {"name": "r", "view_id": view_id, "metric": "count", "op": ">", "threshold": 1, "window_s": 300,
            "interval_s": 60}
    for bad, field in (({"window_s": 299}, "window_s"), ({"window_s": 86401}, "window_s"),
                       ({"interval_s": 30}, "interval_s"), ({"for_evals": 11}, "for_evals"),
                       ({"metric": "p99"}, "metric"), ({"op": "=="}, "op"), ({"group_by": "container"}, "group_by"),
                       ({"max_groups": 21}, "max_groups"), ({"channel_ids": [99]}, "channel_ids"),
                       ({"view_id": 999}, "view_id"), ({"labels": {"bad key": "x"}}, "labels"),
                       ({"threshold": "ten"}, "threshold"), ({"bogus": 1}, "bogus")):
        with pytest.raises(Exception) as exc:
            app.alert_rules.create({**base, **bad})
        assert getattr(exc.value, "field", None) == field, bad
    for i in range(100):
        app.alert_rules.create({**base, "name": f"r{i}"})
    with pytest.raises(Exception, match="At most 100"):
        app.alert_rules.create({**base, "name": "one too many"})


# ─── Backtest ────────────────────────────────────────────────────────────────


def test_backtest_against_known_fixtures(tmp_path, served):
    app = _app(tmp_path)
    burst = lambda at, n, **extra: [(at + timedelta(seconds=i), {"pod": f"api-{i % 4}", **extra})  # noqa: E731
                                   for i in range(n)]
    day = datetime(2026, 10, 21, tzinfo=timezone.utc)
    _records(app, burst(day.replace(hour=1, minute=2), 10) + burst(day.replace(hour=3, minute=31), 10)
             + burst(day.replace(hour=4, minute=10), 3)
             + burst(day.replace(hour=2), 20, namespace="other"))  # outside the view
    view_id = _view(app)
    server = served(app)
    body = {"view_id": view_id, "metric": "count", "op": ">", "threshold": 5, "window_s": 300,
            "interval_s": 300, "for_evals": 1, "range_s": 86400}
    status, result = _request(server, "POST", "/api/alerts/backtest", body=json.dumps(body), headers=JSON)
    assert status == 200, result
    assert result["fired"] == 2
    assert [f["at"] for f in result["fires"]] == ["2026-10-21T01:05:00.000Z", "2026-10-21T03:35:00.000Z"]
    assert [f["value"] for f in result["fires"]] == [10.0, 10.0]
    assert result["range"]["end"] == "2026-10-21T05:45:00.000Z"  # the watermark (05:48), on a bucket
    assert result["ends_at_watermark"] is True and result["bucket_secs"] == 300
    assert max(p["value"] for p in result["series"]) == 10.0
    assert _request(server, "POST", "/api/alerts/backtest", body=json.dumps({**body, "for_evals": 2}),
                    headers=JSON)[1]["fired"] == 0
    pods = _request(server, "POST", "/api/alerts/backtest", body=json.dumps(
        {**body, "metric": "distinct_pods", "threshold": 3}), headers=JSON)[1]
    assert pods["fired"] == 2 and pods["fires"][0]["value"] == 4.0
    filters = _request(server, "POST", "/api/alerts/backtest", body=json.dumps(
        {**{k: v for k, v in body.items() if k != "view_id"}, "filters": {"ns": "other"}, "threshold": 15}),
        headers=JSON)[1]
    assert filters["fired"] == 1 and filters["fires"][0]["at"] == "2026-10-21T02:05:00.000Z"
    assert _request(server, "POST", "/api/alerts/backtest", body=json.dumps({**body, "range_s": 8 * 86400}),
                    headers=JSON)[0] == 422
    assert app.alert_rules.list() == [] and _events(app) == []  # read-only


# ─── Message content and AI ──────────────────────────────────────────────────


def test_notification_is_redacted_with_patterns_signature_and_deep_link(tmp_path):
    app = _app(tmp_path, public_url="https://logscope.example.com", display_tz="Asia/Kolkata")
    rows = [(WM - timedelta(seconds=20 + i), {"message": f"login failed password=hunter2 for user {i}"})
            for i in range(6)]
    rows += [(WM - timedelta(seconds=100 + i), {"message": f"container OOMKilled restart {i}"}) for i in range(3)]
    rows += [(WM - timedelta(seconds=200), {"message": "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"})]
    _records(app, rows)
    channel = app.alert_channels.create({"name": "hook", "type": "webhook", "url": "https://hooks.example/a"})
    view_id = _view(app, {"ns": "payments", "sev": "error", "range": "24h"})
    rule = _rule(app, view_id=view_id, threshold=5, channel_ids=[channel["id"]])
    app.alerts.tick()
    app.alerts.deliver_pending()
    payload = app.sent.items[0]["payload"]
    text = json.dumps(payload)
    assert "hunter2" not in text and "ghp_abcdef" not in text and "[REDACTED" in text
    assert [t["count"] for t in payload["templates"]] == [6, 3, 1]
    assert payload["signature"].startswith("Container killed for exceeding its memory limit")
    url = payload["url"]
    assert url.startswith("https://logscope.example.com/?") and "ns=payments" in url and "sev=error" in url
    assert f"view={view_id}" in url and "range=" not in url
    assert "from=2026-10-21T05%3A43%3A00.000Z" in url and "to=2026-10-21T05%3A48%3A00.000Z" in url
    message = app.alerts.message(app.alert_rules.get(rule["id"]), _events(app, rule["id"])[0])
    window = next(line for line in message.lines if line.startswith("**Window**"))
    assert "2026-10-21 11:13:00 Asia/Kolkata → 2026-10-21 11:18:00 Asia/Kolkata" in window
    assert not any("hunter2" in line for line in message.lines)
    # Without public_url there is no link.
    app.alerts._public_url = ""
    assert app.alerts.message(app.alert_rules.get(rule["id"]), _events(app, rule["id"])[0]).data["url"] is None


def test_ai_summary_off_by_default_and_budget_respecting(tmp_path, monkeypatch):
    monkeypatch.setenv("LS_TEST_AI_KEY", "sk-test-0123456789abcdef")
    app = _app(tmp_path, ai={"provider": "openai", "model": "gpt-fast", "api_key_env": "LS_TEST_AI_KEY"})
    calls = []
    app.alerts._ai_fn = lambda payload, cfg: calls.append(cfg.model) or {"summary": "Login failures spiked."}
    _records(app, [(WM - timedelta(seconds=10 + i), {}) for i in range(3)])
    channel = app.alert_channels.create({"name": "hook", "type": "webhook", "url": "https://hooks.example/a"})

    plain = _rule(app, name="plain", threshold=1, channel_ids=[channel["id"]])
    app.alerts.tick()
    app.alerts.deliver_pending()
    assert calls == [] and "ai_summary" not in app.sent.items[-1]["payload"]
    app.alert_rules.delete(plain["id"])

    app.ai_settings.update({"budgets": {"daily_calls": {"alert_summary": 0}}})
    blocked = _rule(app, name="blocked", threshold=1, ai_summary=True, channel_ids=[channel["id"]],
                    view_id=_view(app, name="v2"))
    app.alerts.tick()
    app.alerts.deliver_pending()
    assert calls == [] and len(app.sent.items) == 2 and "ai_summary" not in app.sent.items[-1]["payload"]
    assert _events(app, blocked["id"])[0]["notified"] == 1  # delivered anyway
    app.alert_rules.delete(blocked["id"])

    app.ai_settings.update({"budgets": {"daily_calls": {"alert_summary": None}}})
    _rule(app, name="with ai", threshold=1, ai_summary=True, channel_ids=[channel["id"]],
          view_id=_view(app, name="v3"))
    app.alerts.tick()
    app.alerts.deliver_pending()
    assert calls == ["gpt-fast"] and app.sent.items[-1]["payload"]["ai_summary"] == "Login failures spiked."
    with app.state_db.lock:
        usage = [tuple(r) for r in app.state_db.conn.execute("SELECT feature, outcome FROM ai_usage ORDER BY id")]
    assert usage == [("alert_summary", "budget_blocked"), ("alert_summary", "ok")]


# ─── Anomaly notifier starvation ─────────────────────────────────────────────


def _insert_anomaly(conn, kind, severity, evidence, rule_key):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO anomalies (type, namespace, pod, rule_key, severity, evidence, detected_at, detected_day, "
        "updated_at, status) VALUES (?, 'ns', '', ?, ?, ?, ?, '2026-10-21', ?, 'new')",
        (kind, rule_key, severity, json.dumps(evidence), now, now))


def test_urgent_anomaly_not_starved_by_300_low_urgency_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("LS_TEST_MM", "https://chat.example/hooks/x")
    app = _app(tmp_path)
    cfg = replace(app.cfg, mattermost=replace(app.cfg.mattermost, enabled=True, webhook_url_env="LS_TEST_MM",
                                              min_urgency="high"))
    sent = []
    notifier = MattermostNotifier(cfg, cfg.webapp.db_path, sender=lambda url, payload: sent.append(payload))
    window = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(cfg.webapp.db_path)
    for i in range(300):  # falling severity share: urgency low
        _insert_anomaly(conn, "severity_shift", "error",
                        {"window_start": window, "current_share": 0.1, "baseline_share": 0.5}, f"low-{i}")
    _insert_anomaly(conn, "new_falco_rule", "error", {"window_start": window, "current_count": 3}, "urgent")
    conn.commit()
    counts = notifier.run_once(datetime.now(timezone.utc))
    assert counts["queued"] == 1 and counts["sent"] == 1
    assert "New Falco rule" in sent[0]["text"] and "urgent" in sent[0]["text"]

    # The SQL urgency rank agrees with anomaly_urgency.
    samples = [("new_falco_rule", "error", {}), ("new_falco_rule", "warning", {}), ("new_falco_rule", "info", {}),
               ("error_rate_spike", "error", {}), ("message_frequency", "info", {}), ("other", "", {}),
               ("severity_shift", "error", {"current_share": 0.6, "baseline_share": 0.2}),
               ("severity_shift", "warning", {"current_share": 0.6, "baseline_share": 0.2}),
               ("severity_shift", "info", {"current_share": 0.6, "baseline_share": 0.2}),
               ("severity_shift", "error", {"current_share": 0.1, "baseline_share": 0.2})]
    order = {"low": 0, "medium": 1, "high": 2, "urgent": 3}
    for kind, severity, evidence in samples:
        rank = conn.execute(f"SELECT {URGENCY_RANK_SQL} FROM (SELECT ? AS type, ? AS severity, ? AS evidence) a",
                            (kind, severity, json.dumps(evidence))).fetchone()[0]
        assert rank == order[anomaly_urgency({"type": kind, "severity": severity}, evidence)], (kind, severity)
    conn.close()
    notifier.stop()


def test_events_pruned_after_30_days_keeping_each_groups_latest(tmp_path):
    app = _app(tmp_path)
    rule = _rule(app)
    old = iso_js(NOW - timedelta(days=31))
    with app.state_db.lock:
        for state in ("pending", "firing", "resolved"):
            app.state_db.conn.execute(
                "INSERT INTO alert_events (rule_id, group_key, state, ts) VALUES (?, '', ?, ?)", (rule["id"], state, old))
        app.state_db.conn.executemany(
            "INSERT INTO alert_events (rule_id, group_key, state, ts) VALUES (?, 'g', 'ok', ?)",
            [(rule["id"], old)] * 2500)
        app.state_db.conn.execute(
            "INSERT INTO alert_events (rule_id, group_key, state, ts) VALUES (?, 'g', 'firing', ?)",
            (rule["id"], iso_js(NOW)))
    assert app.alerts.prune() == 2 + 2500  # three batches; the latest event of every group stays
    events = _events(app, rule["id"])
    assert [(e["group_key"], e["state"]) for e in events] == [("", "resolved"), ("g", "firing")]
