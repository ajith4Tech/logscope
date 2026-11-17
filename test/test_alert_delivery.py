"""Durable alert delivery on a fake clock: backoff through an outage and
recovery, a restart in the middle of a backoff, superseded notifications,
giving up after a day (failed_final) and the admin "retry now"."""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_alerts import AUTH, Scripted, _app, _env, _events, _listed, _prefixes, _rule, served  # noqa: E402,F401
from test_production import _request  # noqa: E402

from webapp.api.alerts import (  # noqa: E402
    DELIVERY_GIVE_UP_SECS,
    NOTIFY_FAILED_FINAL,
    NOTIFY_QUEUED,
    NOTIFY_SENT,
    NOTIFY_SUPERSEDED,
    RETRY_SCHEDULE_SECS,
    AlertEngine,
    retry_delay,
)
from webapp.api.channels import Deliverer, DeliveryError  # noqa: E402
from webapp.api.filters import iso_js  # noqa: E402


class Flaky:
    """A webhook that is down while `down` is set."""

    def __init__(self):
        self.down = True
        self.calls: list[str] = []
        self.delivered: list[dict] = []

    def guarded(self, url, body, headers, timeout=10):
        self.calls.append(url)
        if self.down:
            raise DeliveryError("HTTP 503", transient=True)
        self.delivered.append(json.loads(body))

    def trusted(self, url, payload, timeout=10):
        self.guarded(url, json.dumps(payload).encode(), {})


def _setup(tmp_path, values):
    app = _app(tmp_path)
    hook = Flaky()
    app.alerts.deliverer = Deliverer(guarded=hook.guarded, trusted=hook.trusted)
    channel = app.alert_channels.create({"name": "ops", "type": "webhook", "url": "https://hooks.example/a"})
    rule = _rule(app, channel_ids=[channel["id"]])
    app.alerts._storage = Scripted(app.storage, values)
    return app, hook, rule


def _tick(app, secs: int) -> None:
    """Advance the clock, re-list S3 (the watermark moves) and evaluate."""
    app.clock.t += timedelta(seconds=secs)
    _listed(app, app.clock.t)
    app.alerts.tick()


def _wait(app, secs: float, engine=None) -> int:
    """Advance the clock only and run due deliveries."""
    app.clock.t += timedelta(seconds=secs)
    return (engine or app.alerts).deliver_pending()


def test_retry_schedule():
    assert [retry_delay(n) for n in range(1, 10)] == [30, 60, 120, 300, 600, 1800, 3600, 3600, 3600]
    assert RETRY_SCHEDULE_SECS == (30, 60, 120, 300, 600, 1800)


def test_outage_backs_off_and_recovery_delivers(tmp_path):
    app, hook, rule = _setup(tmp_path, [20])
    _tick(app, 60)
    assert app.alerts.deliver_pending() == 1
    event = _events(app, rule["id"])[0]
    assert (event["notified"], event["attempts"]) == (NOTIFY_QUEUED, 1)
    assert event["next_attempt_at"] == iso_js(app.clock.t + timedelta(seconds=30))
    assert app.alerts.events(rule_id=rule["id"])["items"][0]["notified"] == "retrying"

    assert _wait(app, 29) == 0                    # not due yet: nothing is sent early
    assert _wait(app, 1) == 1                     # second try at +30 s, still down
    event = _events(app, rule["id"])[0]
    assert event["attempts"] == 2 and event["next_attempt_at"] == iso_js(app.clock.t + timedelta(seconds=60))
    assert _wait(app, 60) == 1                    # third try at +60 s, still down
    assert _events(app, rule["id"])[0]["next_attempt_at"] == iso_js(app.clock.t + timedelta(seconds=120))

    hook.down = False                             # recovery
    assert _wait(app, 119) == 0
    assert _wait(app, 1) == 1
    event = _events(app, rule["id"])[0]
    assert (event["notified"], event["attempts"], event["next_attempt_at"]) == (NOTIFY_SENT, 4, None)
    assert len(hook.calls) == 4 and [d["state"] for d in hook.delivered] == ["firing"]
    assert app.alerts.delivery_status() == {"pending": 0, "retrying": 0, "next_attempt_at": None}
    assert _wait(app, 3600) == 0                  # never sent twice


def test_restart_mid_backoff_resumes_from_the_database(tmp_path):
    app, hook, rule = _setup(tmp_path, [20])
    _tick(app, 60)
    app.alerts.deliver_pending()
    assert _wait(app, 30) == 1                    # 2nd attempt fails: next try in 60 s
    due = _events(app, rule["id"])[0]["next_attempt_at"]
    app.alerts.stop()

    restarted = AlertEngine(
        db=app.state_db, storage=Scripted(app.storage, []), rules=app.alert_rules, channels=app.alert_channels,
        deliverer=app.alerts.deliverer, prefixes=lambda: _prefixes(app), time_format="%Y/%m/%d/%H_%M_%S_",
        clock=app.clock)
    assert restarted.rule_status(app.alert_rules.get(rule["id"]))["state"] == "firing"
    assert restarted.delivery_status()["retrying"] == 1
    hook.down = False
    assert _wait(app, 59, restarted) == 0         # the backoff survives the restart
    assert iso_js(app.clock.t) < due
    assert _wait(app, 1, restarted) == 1
    assert _events(app, rule["id"])[0]["notified"] == NOTIFY_SENT
    assert [d["state"] for d in hook.delivered] == ["firing"]
    assert [e["state"] for e in _events(app, rule["id"])] == ["firing"]  # no new transition, no duplicate


def test_newer_transition_delivered_first_supersedes_older_firing(tmp_path):
    app, hook, rule = _setup(tmp_path, [20, 5])
    _tick(app, 60)                                # firing, 1st attempt fails (next +30 s)
    app.alerts.deliver_pending()
    assert _wait(app, 30) == 1                    # 2nd attempt fails (next +60 s)
    hook.down = False
    _tick(app, 30)                                # value 5: resolved, due now; firing due in 30 s
    assert app.alerts.deliver_pending() == 1
    firing, resolved = _events(app, rule["id"])
    assert (firing["state"], resolved["state"]) == ("firing", "resolved")
    assert resolved["notified"] == NOTIFY_SENT
    assert firing["notified"] == NOTIFY_SUPERSEDED and firing["next_attempt_at"] is None
    assert firing["error"] == f"superseded by event {resolved['id']}"
    assert _wait(app, 3600) == 0                  # the stale firing message is never sent
    assert [d["state"] for d in hook.delivered] == ["resolved"]
    views = {e["state"]: e for e in app.alerts.events(rule_id=rule["id"])["items"]}
    assert views["firing"]["notified"] == "superseded" and views["firing"]["retryable"] is False


def test_gives_up_after_a_day_as_failed_final_and_retry_now(tmp_path, served):
    app, hook, rule = _setup(tmp_path, [20])
    _tick(app, 60)
    created = app.clock.t
    app.alerts.deliver_pending()
    while _events(app, rule["id"])[0]["notified"] == NOTIFY_QUEUED:
        due = _events(app, rule["id"])[0]["next_attempt_at"]
        app.clock.t = created + timedelta(seconds=1)
        while iso_js(app.clock.t) < due:
            app.clock.t += timedelta(seconds=30)
        assert app.alerts.deliver_pending() == 1
    event = _events(app, rule["id"])[0]
    assert event["notified"] == NOTIFY_FAILED_FINAL and event["next_attempt_at"] is None
    # 30 s, 1, 2, 5, 10, 30 min, then hourly: 30 attempts fit in the day.
    assert event["attempts"] == len(hook.calls) == 30
    assert (app.clock.t - created).total_seconds() <= DELIVERY_GIVE_UP_SECS
    assert app.alerts.events(rule_id=rule["id"])["items"][0]["notified"] == "failed_final"
    assert _wait(app, 7 * 86400) == 0             # nothing more on its own

    server = served(app)
    path = f"/api/alerts/events/{event['id']}/retry"
    assert _request(server, "POST", path, headers={"Content-Type": "application/json"})[0] == 401
    status, payload = _request(server, "POST", path, headers=AUTH)
    assert status == 200 and payload["event"]["notified"] == "retrying"
    hook.down = False
    assert app.alerts.deliver_pending() == 1
    assert _events(app, rule["id"])[0]["notified"] == NOTIFY_SENT
    status, payload = _request(server, "POST", path, headers=AUTH)   # nothing left to retry
    assert status == 409 and "sent" in payload["error"]
    assert _request(server, "POST", "/api/alerts/events/999999/retry", headers=AUTH)[0] == 404


def test_retries_do_not_repeat_the_ai_summary(tmp_path):
    app, hook, rule = _setup(tmp_path, [20])
    app.alert_rules.update(rule["id"], {"ai_summary": True})
    calls = []
    app.alerts._ai_configured = lambda: True
    app.alerts._ai = type("Svc", (), {"call": lambda self, feature, fn, **kw: calls.append(feature) or {
        "summary": "disk filled up"}})()
    app.alerts._ai_fn = lambda payload, cfg: None
    in_window = app.clock.t - timedelta(seconds=700)   # windows end at the watermark (~11 min behind)
    app.storage.insert_records([{"timestamp": iso_js(in_window), "severity_bucket": "error",
                                 "scope": "namespaces/payments", "namespace": "payments", "pod": "api-0",
                                 "container": "app", "message": "boom", "raw_line": "r", "source_key": "k",
                                 "source_etag": "e", "line_number": 1, "is_falco": 0}])
    _tick(app, 60)
    app.alerts.deliver_pending()                  # first attempt: one AI call, delivery fails
    assert _wait(app, 30) == 1 and _wait(app, 60) == 1
    assert calls == ["alert_summary"]


class TwoHooks:
    """Channel URLs ending in /a and /b; each can be down on its own."""

    def __init__(self):
        self.down = {"a": False, "b": True}
        self.calls: list[str] = []

    def guarded(self, url, body, headers, timeout=10):
        name = url.rsplit("/", 1)[-1]
        self.calls.append(name)
        assert timeout == 10                      # every send gets the 10 s timeout
        if self.down[name]:
            raise DeliveryError("HTTP 503", transient=True)

    def trusted(self, url, payload, timeout=10):
        raise AssertionError("no environment channel here")


def _two_channels(tmp_path, values):
    app = _app(tmp_path)
    hooks = TwoHooks()
    app.alerts.deliverer = Deliverer(guarded=hooks.guarded, trusted=hooks.trusted)
    a = app.alert_channels.create({"name": "a", "type": "webhook", "url": "https://hooks.example/a"})
    b = app.alert_channels.create({"name": "b", "type": "webhook", "url": "https://hooks.example/b"})
    rule = _rule(app, channel_ids=[a["id"], b["id"]])
    app.alerts._storage = Scripted(app.storage, values)
    return app, hooks, rule, a["id"], b["id"]


def _deliveries(app, event_id):
    item = next(i for i in app.alerts.events()["items"] if i["id"] == event_id)
    return {d["channel_id"]: d for d in item["deliveries"]}


def test_each_channel_is_retried_on_its_own(tmp_path):
    app, hooks, rule, a, b = _two_channels(tmp_path, [20])
    _tick(app, 60)
    app.alerts.deliver_pending()
    event = _events(app, rule["id"])[0]
    assert sorted(hooks.calls) == ["a", "b"]
    assert event["notified"] == NOTIFY_QUEUED and event["error"] == f"channel {b}: HTTP 503"
    per = _deliveries(app, event["id"])
    assert (per[a]["state"], per[b]["state"], per[b]["attempts"]) == ("sent", "retrying", 1)

    assert _wait(app, 30) == 1                   # only b is due again; a is never sent twice
    assert hooks.calls[2:] == ["b"]
    hooks.down["b"] = False
    assert _wait(app, 60) == 1
    assert hooks.calls[3:] == ["b"]
    event = _events(app, rule["id"])[0]
    assert (event["notified"], event["error"], event["next_attempt_at"]) == (NOTIFY_SENT, None, None)
    assert {d["state"] for d in _deliveries(app, event["id"]).values()} == {"sent"}


def test_event_settles_when_every_channel_is_sent_or_failed_final(tmp_path):
    app, hooks, rule, a, b = _two_channels(tmp_path, [20])
    _tick(app, 60)
    created = app.clock.t
    app.alerts.deliver_pending()
    while _events(app, rule["id"])[0]["notified"] == NOTIFY_QUEUED:
        app.clock.t = max(app.clock.t, created) + timedelta(seconds=3600)
        app.alerts.deliver_pending()
    event = _events(app, rule["id"])[0]
    per = _deliveries(app, event["id"])
    assert (per[a]["state"], per[b]["state"]) == ("sent", "failed_final")
    assert event["notified"] == NOTIFY_SENT        # settled: a got it, b gave up
    assert event["error"] == f"channel {b}: HTTP 503"
    assert hooks.calls.count("a") == 1
    # "Retry now" re-queues only the channel that gave up.
    assert app.alerts.events(rule_id=rule["id"])["items"][0]["retryable"] is True
    hooks.down["b"] = False
    view = app.alerts.retry_now(event["id"])
    assert {d["channel_id"]: d["state"] for d in view["deliveries"]} == {a: "sent", b: "retrying"}
    app.alerts.deliver_pending()
    assert hooks.calls.count("a") == 1 and _deliveries(app, event["id"])[b]["state"] == "sent"
    assert app.alerts.events(rule_id=rule["id"])["items"][0]["retryable"] is False


def test_a_pass_stops_starting_sends_at_its_deadline(tmp_path):
    clock = {"t": 0.0}
    app, hooks, rule, a, b = _two_channels(tmp_path, [{"x": 20.0, "y": 20.0, "z": 20.0}])
    app.alert_rules.update(rule["id"], {"group_by": "pod"})
    app.alerts._monotonic = lambda: clock["t"]
    hooks.down["b"] = False

    def slow(url, body, headers, timeout=10):
        clock["t"] += 25                           # each send uses most of its timeout
        hooks.calls.append(url.rsplit("/", 1)[-1])

    app.alerts.deliverer = Deliverer(guarded=slow, trusted=hooks.trusted)
    _tick(app, 60)
    assert app.alerts.deliver_pending(deadline_secs=60) == 2   # 3 events due; the deadline cuts the pass
    assert len(hooks.calls) == 3                   # event 1: a+b; event 2: a, then the deadline
    states = [e["notified"] for e in _events(app, rule["id"])]
    assert states == [NOTIFY_SENT, NOTIFY_QUEUED, NOTIFY_QUEUED]
    app.alerts.deliver_pending(deadline_secs=600)  # the next pass finishes, sending nothing twice
    assert [e["notified"] for e in _events(app, rule["id"])] == [NOTIFY_SENT] * 3
    assert len(hooks.calls) == 6
