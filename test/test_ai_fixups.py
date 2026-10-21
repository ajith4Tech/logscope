"""Admin lockout order, feedback limits and votes, placeholder rebinding of
cached answers, once-a-day budget blocks per anomaly, and opening a v0.3.0
state database with the current code."""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_ai_cost import _anomaly, _configured_app, _counting_openai, _line, _record  # noqa: E402
from test_ai_settings import ADMIN, ENV_KEY, JSON, _app, _auth, _clean_env, _ids, _request, _usage_rows, served  # noqa: E402,F401
from webapp.api import dbtool  # noqa: E402
from webapp.api.explain import fill, templatize, templatize_text  # noqa: E402
from webapp.api.state import MIGRATIONS, SavedViews, StateDB  # noqa: E402

V030_STATE = ROOT / "test" / "fixtures" / "state-v0.3.0.sqlite"


# ─── 1. Admin auth ───────────────────────────────────────────────────────────


def _settings(server, token):
    return _request(server, "GET", "/api/settings/ai", headers=_auth(token))[0]


def test_correct_token_after_failures_then_wrong_tokens_locked(tmp_path, served):
    server = served(_app(tmp_path))
    assert [_settings(server, f"wrong-{i}") for i in range(10)] == [401] * 10
    assert _settings(server, ADMIN) == 200  # failures never lock out the right token
    assert _settings(server, "wrong-10") == 429
    assert _settings(server, ADMIN) == 200


def test_correct_token_first_then_wrong_tokens_reach_the_limit(tmp_path, served):
    server = served(_app(tmp_path))
    assert _settings(server, ADMIN) == 200
    assert [_settings(server, f"wrong-{i}") for i in range(11)] == [401] * 10 + [429]
    assert _settings(server, ADMIN) == 200
    assert _settings(server, "wrong-x") == 429


# ─── 2. Feedback ─────────────────────────────────────────────────────────────


def _cached_key(app, server):
    app.storage.insert_records([_record("lease lost on shard 1", i=1)])
    return _line(server, _ids(app)[0])[1]["cache_key"]


def _vote(server, key, value, client):
    headers = {**JSON, **({"X-Logscope-Client": client} if client else {})}
    return _request(server, "POST", "/api/ai/feedback", body=json.dumps({"key": key, "vote": value}),
                    headers=headers)


def test_feedback_is_rate_limited_per_ip(tmp_path, served, monkeypatch):
    _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    server = served(app)
    key = _cached_key(app, server)
    statuses = [_vote(server, key, "up", f"client-{i:04d}")[0] for i in range(31)]
    assert statuses == [200] * 30 + [429]


def test_one_vote_per_client_and_a_repeat_replaces_it(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    server = served(app)
    key = _cached_key(app, server)
    rid = _ids(app)[0]
    assert _vote(server, key, "down", None)[0] == 400  # no client id
    assert _vote(server, key, "down", "bad id!")[0] == 400
    for _ in range(5):  # one client voting again and again is still one vote
        assert _vote(server, key, "down", "client-aaaa")[1] == {"ok": True, "key": key, "helpful_up": 0,
                                                                "helpful_down": 1}
    assert _line(server, rid)[1]["source"] == "cache" and len(calls) == 1
    # A repeat vote replaces the earlier one.
    assert _vote(server, key, "up", "client-aaaa")[1]["helpful_up"] == 1
    assert _vote(server, key, "down", "client-bbbb")[1] == {"ok": True, "key": key, "helpful_up": 1,
                                                            "helpful_down": 1}
    assert _vote(server, key, "down", "client-cccc")[1]["helpful_down"] == 2  # net 1: kept
    assert _line(server, rid)[1]["source"] == "cache" and len(calls) == 1
    _vote(server, key, "down", "client-aaaa")  # aaaa changes its mind: 3 down, 0 up
    assert _line(server, rid)[1]["source"] == "ai" and len(calls) == 2


# ─── 3. Rebinding ────────────────────────────────────────────────────────────

SOURCE = {"namespace": "default", "pod": "web-7d9f8b6c5d-x2kqp", "container": "app"}
PROSE = ("The default retry policy of the application gave up: container app in namespace default "
         "(pod web-7d9f8b6c5d-x2kqp) cannot reach default-backend; see default/web-7d9f8b6c5d-x2kqp.")


def test_templatize_replaces_whole_names_only():
    out = templatize_text(PROSE, SOURCE, command=False)
    assert out == ("The default retry policy of the application gave up: container {container} in namespace "
                   "{namespace} (pod {pod}) cannot reach default-backend; see {namespace}/{pod}.")
    assert templatize_text("kubectl -n default logs web-7d9f8b6c5d-x2kqp -c app --tail 50", SOURCE,
                           command=True) == "kubectl -n {namespace} logs {pod} -c {container} --tail 50"
    # Longest first: a pod name containing the namespace stays whole.
    assert templatize_text("pod shop-db-0 in shop", {"namespace": "shop", "pod": "shop-db-0", "container": ""},
                           command=True) == "pod {pod} in {namespace}"


def test_served_answer_gets_the_new_records_names_and_valid_commands():
    stored = templatize({"summary": PROSE, "suggested_action": "", "steps": [
        {"title": "Logs of app", "command": "kubectl -n default logs web-7d9f8b6c5d-x2kqp -c app --tail 50",
         "explanation": "Shows why the app container in default fails.", "risk": "read-only"}]}, SOURCE)
    served_answer = fill(stored, {"namespace": "shop", "pod": "api-5c4b8d7f9-m2n8q", "container": "main"})
    assert served_answer["summary"] == (
        "The default retry policy of the application gave up: container main in namespace shop "
        "(pod api-5c4b8d7f9-m2n8q) cannot reach default-backend; see shop/api-5c4b8d7f9-m2n8q.")
    [step] = served_answer["steps"]
    assert step["command"] == "kubectl -n shop logs api-5c4b8d7f9-m2n8q -c main --tail 50"
    assert step["is_supported"] and step["exec_command"].startswith("kubectl logs api-5c4b8d7f9-m2n8q -n shop")
    # "app" as a plain word (no "container"/quotes/path next to it) is left alone in prose.
    assert step["title"] == "Logs of app" and step["explanation"] == "Shows why the main container in default fails."
    # Names this record lacks: the command is dropped, not run with a hole in it.
    no_pod = fill(stored, {"namespace": "shop", "pod": "", "container": ""})
    assert no_pod["steps"][0]["command"] == "" and not no_pod["steps"][0]["is_supported"]


def test_cache_hit_end_to_end_with_default_and_app(tmp_path, served, monkeypatch):
    answer = {"summary": "Container app in namespace default uses the default timeout of the application.",
              "steps": [{"title": "Describe", "command": "kubectl -n default describe pod web-0",
                         "explanation": "Status of the app container.", "risk": "read-only"}]}
    calls = _counting_openai(monkeypatch, answer)
    app = _configured_app(tmp_path, monkeypatch)
    app.storage.insert_records([_record("worker lost lease", namespace="default", pod="web-0", container="app", i=1),
                                _record("worker lost lease", namespace="default", pod="web-1", container="app", i=2)])
    server = served(app)
    first, second = _ids(app)
    assert _line(server, first)[1]["summary"] == answer["summary"]
    with app.state_db.lock:
        stored = json.loads(app.state_db.conn.execute("SELECT response FROM ai_cache").fetchone()[0])
    assert stored["summary"] == ("Container {container} in namespace {namespace} uses the default timeout of the "
                                 "application.")
    assert stored["steps"][0]["command"] == "kubectl -n {namespace} describe pod {pod}"
    hit = _line(server, second)[1]
    assert hit["source"] == "cache" and len(calls) == 1
    assert hit["steps"][0]["command"] == "kubectl -n default describe pod web-1" and hit["steps"][0]["is_supported"]


# ─── 4. Budget blocks ────────────────────────────────────────────────────────


def test_budget_blocked_rows_once_per_anomaly_per_utc_day(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    app.ai_settings.update({"flags": {"anomaly_auto_summary": True},
                            "budgets": {"daily_calls": {"anomaly_auto_summary": 0, "anomaly_manual_summary": 0,
                                                        "explain_line": 0}}})
    one = app.anomaly_store.get_anomaly(_anomaly(app, rule_key="rule a", messages=("weird a",)))
    two = app.anomaly_store.get_anomaly(_anomaly(app, rule_key="rule b", messages=("weird b",)))
    worker = app.summary_worker
    for _ in range(3):  # three detection runs re-offer the same pending anomalies
        worker.enqueue([one, two])
        worker.process(worker.take_batch(timeout=0))
    blocked = [r for r in _usage_rows(app) if r["outcome"] == "budget_blocked"]
    assert sorted(r["subject"] for r in blocked) == ["anomaly:" + str(one["id"]), "anomaly:" + str(two["id"])]
    server = served(app)
    for _ in range(2):  # a manual click on an anomaly blocked today adds nothing
        assert _request(server, "POST", f"/api/anomalies/{one['id']}/summarize", body="{}",
                        headers=JSON)[1]["degraded"] is True
    assert len([r for r in _usage_rows(app) if r["outcome"] == "budget_blocked"]) == 2
    # Tomorrow (UTC) gets one more row per anomaly.
    tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
    app.ai_meter._clock = lambda: tomorrow
    worker.enqueue([one])
    worker.process(worker.take_batch(timeout=0))
    worker.enqueue([one])
    worker.process(worker.take_batch(timeout=0))
    assert len([r for r in _usage_rows(app) if r["outcome"] == "budget_blocked"]) == 3
    # Requests that are not about an anomaly are each recorded.
    app.ai_meter._clock = lambda: datetime.now(timezone.utc)
    app.storage.insert_records([_record("lease lost on shard 1", i=1)])
    for _ in range(2):
        assert _line(server, _ids(app)[0])[1]["degraded"] is True
    line_blocks = [r for r in _usage_rows(app) if r["outcome"] == "budget_blocked" and r["feature"] == "explain_line"]
    assert len(line_blocks) == 2 and calls == []


# ─── 6. Migration from v0.3.0 ────────────────────────────────────────────────


def test_v030_state_database_opens_with_the_current_code(tmp_path, capsys):
    """test/fixtures/state-v0.3.0.sqlite was written by the v0.3.0 code (schema
    version 1) with three saved views."""
    path = tmp_path / "state.sqlite"
    shutil.copy(V030_STATE, path)
    raw = sqlite3.connect(path)
    assert raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
    before = [tuple(r) for r in raw.execute("SELECT * FROM saved_views ORDER BY id")]
    raw.close()
    assert len(before) == 3

    db = StateDB(path)
    assert db.schema_version() == MIGRATIONS[-1][0]
    views = SavedViews(db).list()
    assert {v["name"] for v in views} == {"Errors in shop", "Falco last week", "Incident 2026-09-07"}
    after = [tuple(r) for r in db.conn.execute("SELECT * FROM saved_views ORDER BY id")]
    assert after == before  # untouched, column for column
    pinned = next(v for v in views if v["name"] == "Errors in shop")
    assert pinned["pinned"] and pinned["filters"] == {"ns": "shop", "range": "24h", "sev": "error"}
    tables = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"ai_settings", "ai_usage", "ai_cache", "ai_cache_votes"} <= tables
    # Still writable through the current API.
    SavedViews(db).create({"name": "After upgrade", "filters": {"ns": "billing"}})
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    assert StateDB(path).migrate() == MIGRATIONS[-1][0]  # idempotent

    assert dbtool.main(["verify", "--state", str(path)]) == 0
    out = capsys.readouterr().out
    assert "integrity: ok" in out and "'saved_views': 4" in out and f"'schema_version': {MIGRATIONS[-1][0]}" in out
