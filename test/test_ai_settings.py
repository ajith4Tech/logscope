"""AI settings from the UI: admin token, encrypted key storage, precedence,
base_url allowlist, hot reload, feature flags, usage metering and budgets."""

from __future__ import annotations

import io
import json
import logging
import os
import sqlite3
import stat
import sys
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import error

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_production import CONFIG, JSON, _raw, _request, _serve  # noqa: E402
from webapp.api import ai_settings  # noqa: E402
from webapp.api.ai_settings import (  # noqa: E402
    AuthFailureLimiter,
    SecretBox,
    SettingsError,
    cost_usd,
    estimate_tokens,
    validate_base_url,
)
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.state import StateDB  # noqa: E402

KEY = "sk-test-UIKEY-0123456789abcdefWXYZ"
ENV_KEY = "sk-test-ENVKEY-9876543210zyxw"
ADMIN = "admin-token-for-tests-0123456789abcdef"
_BASE = {"severity_bucket": "error", "scope": "infra", "namespace": "ns", "pod": "p", "container": "c",
         "raw_line": "r", "source_etag": "e", "is_falco": 0, "timestamp": "2026-09-07T00:00:00Z"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (ai_settings.ADMIN_TOKEN_ENV, ai_settings.SECRET_KEY_ENV, ai_settings.SECRET_KEY_PREVIOUS_ENV,
                 ai_settings.ALLOWED_HOSTS_ENV, "LS_TEST_AI_KEY", "LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE",
                 *ai_settings.FIELD_ENV.values()):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", "0")


def _app(tmp_path, *, admin: str | None = ADMIN, records: int = 0, mattermost: bool = False, **ai) -> WebApp:
    if admin is not None:
        os.environ[ai_settings.ADMIN_TOKEN_ENV] = admin
    cfg = load_app_config(CONFIG)
    cfg = replace(cfg, webapp=replace(cfg.webapp, db_path=tmp_path / "webapp.sqlite"),
                  ai=replace(cfg.ai, **{"provider": "openai", "model": "", "api_key_env": "LS_TEST_AI_KEY", **ai}))
    if mattermost:
        cfg = replace(cfg, mattermost=replace(cfg.mattermost, enabled=True, webhook_url_env="LS_TEST_MM_URL"))
    app = WebApp(cfg)
    if records:
        app.storage.insert_records(
            [{**_BASE, "message": f"m{i}", "source_key": "k", "line_number": i} for i in range(1, records + 1)])
    return app


def _ids(app) -> list[int]:
    return sorted(r["id"] for r in app.storage.query_logs({}, limit=100)["items"])


def _auth(token: str = ADMIN) -> dict[str, str]:
    return {**JSON, "Authorization": f"Bearer {token}"}


def _put(server, body: dict, token: str = ADMIN):
    return _request(server, "PUT", "/api/settings/ai", body=json.dumps(body), headers=_auth(token))


def _usage_rows(app) -> list[dict]:
    with app.state_db.lock:
        return [dict(r) for r in app.state_db.conn.execute("SELECT * FROM ai_usage ORDER BY id")]


class _Resp:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return self._data


ANSWER = {"summary": "Upstream timeout.", "steps": [
    {"title": "Check pod", "command": "kubectl -n ns get pod p", "explanation": "State.", "risk": "read-only"}]}


def _fake_openai(monkeypatch, *, usage=None, seen=None):
    def urlopen(req, timeout=0):
        body = json.loads(req.data)
        if seen is not None:
            seen.append({"url": req.full_url, "model": body["model"],
                         "auth": dict((k.lower(), v) for k, v in req.headers.items()).get("authorization")})
        payload = {"choices": [{"message": {"content": json.dumps(ANSWER)}}]}
        if usage is not None:
            payload["usage"] = usage
        return _Resp(payload)

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", urlopen)


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


# ─── Admin token ─────────────────────────────────────────────────────────────


def test_admin_token_generated_once_with_0600_and_only_its_path_logged(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    app = _app(tmp_path, admin=None)
    path = app.state_db.path.parent / "admin.token"
    token = path.read_text().strip()
    assert app.admin_token == token and len(token) >= 40 and app.admin_token_source == "file"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert str(path) in caplog.text and token not in caplog.text
    # Generated once: a second start reads the same file.
    assert _app(tmp_path, admin=None).admin_token == token


def test_admin_token_from_env_creates_no_file(tmp_path):
    app = _app(tmp_path, admin="from-env-token-xyz")
    assert app.admin_token == "from-env-token-xyz" and app.admin_token_source == "env"
    assert not (app.state_db.path.parent / "admin.token").exists()


def test_settings_require_the_bearer_token_and_same_origin(tmp_path, served):
    server = served(_app(tmp_path))
    assert _request(server, "GET", "/api/settings/ai")[0] == 401
    status, headers, _ = _raw(server, "GET", "/api/settings/ai", headers={"Authorization": "Bearer wrong"})
    assert status == 401 and headers["www-authenticate"].startswith("Bearer")
    assert _request(server, "GET", "/api/settings/ai", headers={"Authorization": f"Basic {ADMIN}"})[0] == 401
    assert _put(server, {"model": "m"}, token="nope")[0] == 401
    status, headers, _ = _raw(server, "GET", "/api/settings/ai", headers=_auth())
    assert status == 200 and headers["cache-control"] == "no-store"
    # The Origin check runs as well, for GET too.
    assert _request(server, "GET", "/api/settings/ai",
                    headers={**_auth(), "Origin": "https://evil.example"})[0] == 403
    assert _request(server, "PUT", "/api/settings/ai", body=json.dumps({"model": "m"}),
                    headers={**_auth(), "Origin": "https://evil.example"})[0] == 403
    # PUT elsewhere is still not implemented.
    assert _raw(server, "PUT", "/")[0] == 501


def test_admin_token_compared_in_constant_time(tmp_path, served, monkeypatch):
    calls = []
    real = ai_settings.hmac.compare_digest
    monkeypatch.setattr(ai_settings.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))
    server = served(_app(tmp_path))
    assert _request(server, "GET", "/api/settings/ai", headers=_auth("wrong-token"))[0] == 401
    assert _request(server, "GET", "/api/settings/ai", headers=_auth())[0] == 200
    assert calls == [(b"wrong-token", ADMIN.encode()), (ADMIN.encode(), ADMIN.encode())]


def test_admin_token_brute_force_is_rate_limited_per_ip(tmp_path, served):
    server = served(_app(tmp_path))
    for i in range(10):
        assert _request(server, "GET", "/api/settings/ai", headers=_auth(f"guess-{i}"))[0] == 401
    status, headers, _ = _raw(server, "GET", "/api/settings/ai", headers=_auth("guess-11"))
    assert status == 429 and int(headers["retry-after"]) >= 1
    assert _request(server, "GET", "/api/settings/ai", headers=_auth())[0] == 200  # the right token still works

    limiter = AuthFailureLimiter(max_failures=3, window_secs=0.3)
    for _ in range(3):
        limiter.fail("10.0.0.1")
    assert limiter.retry_after("10.0.0.1") > 0 and limiter.retry_after("10.0.0.2") == 0
    time.sleep(0.35)
    assert limiter.retry_after("10.0.0.1") == 0  # the window slides


# ─── Secret storage ──────────────────────────────────────────────────────────


def test_secret_box_round_trip_and_generated_master_key(tmp_path):
    box = SecretBox(tmp_path)
    key_file = tmp_path / "secret.key"
    assert box.available and stat.S_IMODE(key_file.stat().st_mode) == 0o600
    token = box.encrypt(KEY)
    assert KEY not in token and box.decrypt(token) == KEY
    assert SecretBox(tmp_path).decrypt(token) == KEY  # same file, same key
    assert SecretBox(tmp_path / "other").decrypt(token) is None


def test_stored_key_never_returned_or_logged(tmp_path, served, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    _fake_openai(monkeypatch)
    app = _app(tmp_path, records=1)
    server = served(app)
    bodies = []
    status, payload = _put(server, {"model": "gpt-test", "api_key": KEY})
    bodies.append(json.dumps(payload))
    assert status == 200 and payload["key_set"] is True and payload["key_source"] == "ui"
    assert payload["key_last4"] == "WXYZ"
    for path in ("/api/settings/ai", "/api/settings/ai/usage", "/api/status"):
        bodies.append(json.dumps(_request(server, "GET", path, headers=_auth())[1]))
    bodies.append(json.dumps(_request(server, "POST", "/api/settings/ai/test", headers=_auth())[1]))
    bodies.append(json.dumps(_request(server, "POST", "/api/explain-line", body=json.dumps({"id": _ids(app)[0]}),
                                      headers=JSON)[1]))
    # An empty api_key keeps the key.
    status, payload = _put(server, {"api_key": "", "deep_model": "gpt-deep"})
    bodies.append(json.dumps(payload))
    assert payload["key_set"] is True
    for body in bodies:
        assert KEY not in body and "api_key_enc" not in body
    with app.state_db.lock:
        stored = app.state_db.conn.execute("SELECT api_key_enc, key_last4 FROM ai_settings").fetchone()
    assert stored["api_key_enc"] and KEY not in stored["api_key_enc"] and stored["key_last4"] == "WXYZ"
    assert KEY.encode() not in app.state_db.path.read_bytes()
    assert KEY not in caplog.text and KEY not in repr(app.ai_settings.effective())
    # "__clear__" removes it.
    status, payload = _put(server, {"api_key": "__clear__"})
    assert payload["key_set"] is False and payload["key_source"] == "none"


# ─── Precedence ──────────────────────────────────────────────────────────────


def test_env_key_and_env_fields_win_over_ui_values(tmp_path, served, monkeypatch):
    app = _app(tmp_path, model="config-model")
    server = served(app)
    assert _put(server, {"model": "ui-model", "api_key": KEY})[1]["model"] == "ui-model"
    payload = _request(server, "GET", "/api/settings/ai", headers=_auth())[1]
    assert payload["sources"]["model"] == "ui" and payload["key_source"] == "ui"
    assert app.ai_settings.effective().api_key == KEY

    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    monkeypatch.setenv("LOGSCOPE_AI_MODEL", "env-model")
    app.ai_settings.invalidate()
    payload = _request(server, "GET", "/api/settings/ai", headers=_auth())[1]
    assert payload["key_source"] == "env" and payload["key_set"] is True and payload["key_last4"] == "zyxw"
    assert payload["model"] == "env-model" and payload["sources"]["model"] == "env"
    assert app.ai_settings.effective().api_key == ENV_KEY
    # Env-pinned values are read-only from the UI.
    status, payload = _put(server, {"api_key": "sk-another-key-123456"})
    assert status == 409 and payload["field"] == "api_key"
    assert _put(server, {"model": "x"})[0] == 409
    assert ENV_KEY not in json.dumps(_request(server, "GET", "/api/settings/ai", headers=_auth())[1])

    # Clearing the UI value falls back to config.yaml.
    monkeypatch.delenv("LOGSCOPE_AI_MODEL")
    app.ai_settings.invalidate()
    payload = _put(server, {"model": ""})[1]
    assert payload["model"] == "config-model" and payload["sources"]["model"] == "config"


# ─── base_url ────────────────────────────────────────────────────────────────


def test_base_url_allowlist_and_https_rule(tmp_path, served, monkeypatch):
    for ok in ("https://api.openai.com/v1/", "https://openrouter.ai/api/v1", "https://api.anthropic.com",
               "https://generativelanguage.googleapis.com", "http://localhost:11434/v1",
               "http://127.0.0.1:8080", "http://[::1]:9000/v1", ""):
        validate_base_url(ok)
    assert validate_base_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"
    for bad in ("https://evil.example/v1", "http://api.openai.com/v1", "ftp://api.openai.com",
                "https://user:pw@api.openai.com", "https://api.openai.com.evil.example",
                "https://api.openai.com/v1?x=1", "https://api.openai.com:99999", "not a url", 5):
        with pytest.raises(SettingsError) as exc:
            validate_base_url(bad)
        assert exc.value.status == 422

    monkeypatch.setenv(ai_settings.ALLOWED_HOSTS_ENV, "gw.example.internal, llm.corp.example")
    assert validate_base_url("https://gw.example.internal/v1") == "https://gw.example.internal/v1"
    with pytest.raises(SettingsError):
        validate_base_url("http://gw.example.internal/v1")  # https still required

    server = served(_app(tmp_path))
    status, payload = _put(server, {"base_url": "https://evil.example/v1"})
    assert status == 422 and payload["field"] == "base_url"
    assert _put(server, {"base_url": "http://api.openai.com"})[0] == 422
    assert _put(server, {"base_url": "https://llm.corp.example/v1"})[1]["base_url"] == "https://llm.corp.example/v1"
    for body in ({"provider": "bogus"}, {"model": "has space"}, {"api_key": "short"}, {"unknown": 1},
                 {"flags": {"nope": True}}, {"flags": {"explain_line": "yes"}},
                 {"budgets": {"daily_tokens": -1}}, {"prices": {"m": {"input": 1}}}):
        assert _put(server, body)[0] == 422, body


# ─── Hot reload ──────────────────────────────────────────────────────────────


def test_changes_apply_without_restart(tmp_path, served, monkeypatch):
    seen = []
    _fake_openai(monkeypatch, seen=seen)
    app = _app(tmp_path, records=3)
    server = served(app)
    ids = _ids(app)
    assert _request(server, "POST", "/api/explain-line", body=json.dumps({"id": ids[0]}), headers=JSON)[0] == 400
    assert _request(server, "GET", "/api/status")[1]["ai_configured"] is False

    _put(server, {"model": "model-one", "api_key": KEY})
    assert _request(server, "GET", "/api/status")[1]["ai_configured"] is True
    assert _request(server, "POST", "/api/explain-line", body=json.dumps({"id": ids[0]}), headers=JSON)[0] == 200
    _put(server, {"model": "model-two", "base_url": "http://localhost:9/v1"})
    assert _request(server, "POST", "/api/explain-line", body=json.dumps({"id": ids[1]}), headers=JSON)[0] == 200
    assert [(s["model"], s["url"]) for s in seen] == [
        ("model-one", "https://api.openai.com/v1/chat/completions"),
        ("model-two", "http://localhost:9/v1/chat/completions"),
    ]
    assert seen[0]["auth"] == f"Bearer {KEY}"


# ─── Feature flags ───────────────────────────────────────────────────────────


def test_disabled_features_answer_403(tmp_path, served, monkeypatch):
    _fake_openai(monkeypatch)
    app = _app(tmp_path, model="m", records=1)
    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    server = served(app)
    flags = _request(server, "GET", "/api/status")[1]["ai_features"]
    assert flags == {"explain_line": True, "explain_filtered": True, "anomaly_auto_summary": False,
                     "anomaly_manual_summary": True, "nl_filters": True}
    _put(server, {"flags": {"explain_line": False, "explain_filtered": False, "anomaly_manual_summary": False}})
    status, payload = _request(server, "POST", "/api/explain-line", body=json.dumps({"id": _ids(app)[0]}),
                               headers=JSON)
    assert (status, payload) == (403, {"error": "ai_feature_disabled", "feature": "explain_line"})
    status, payload = _request(server, "POST", "/api/explain?namespace=ns")
    assert status == 403 and payload["error"] == "ai_feature_disabled"
    status, payload = _request(server, "POST", "/api/anomalies/1/summarize", headers=JSON)
    assert status == 403 and payload["feature"] == "anomaly_manual_summary"
    assert _request(server, "GET", "/api/status")[1]["ai_features"]["explain_line"] is False
    assert _usage_rows(app) == []  # nothing reached the provider or the meter

    # anomaly_auto_summary is off by default: nothing is queued for the worker.
    urgent = {"id": 1, "type": "new_falco_rule", "severity": "error", "namespace": "", "rule_key": "x",
              "evidence": "{}"}
    assert app.summary_worker.enqueue([urgent]) == 0
    _put(server, {"flags": {"anomaly_auto_summary": True}})
    assert app.summary_worker.enqueue([urgent]) == 1


# ─── Metering ────────────────────────────────────────────────────────────────


def test_metering_rows_for_ok_cache_hit_error_and_budget_blocked(tmp_path, served, monkeypatch):
    _fake_openai(monkeypatch, usage={"prompt_tokens": 1000, "completion_tokens": 200,
                                     "prompt_tokens_details": {"cached_tokens": 400}})
    app = _app(tmp_path, model="gpt-test", records=3)
    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    server = served(app)
    _put(server, {"prices": {"gpt-test": {"input": 2.0, "output": 10.0, "cached": 0.5}}})
    ids = _ids(app)
    line = lambda i: _request(server, "POST", "/api/explain-line", body=json.dumps({"id": i}), headers=JSON)  # noqa: E731
    assert line(ids[0])[0] == 200
    assert line(ids[0])[1]["cached"] is True

    def failing(req, timeout=0):
        raise error.HTTPError(req.full_url, 400, "Bad Request", {},
                              io.BytesIO(json.dumps({"error": {"message": f"bad key {ENV_KEY}"}}).encode()))

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", failing)
    status, payload = line(ids[1])
    assert status == 502 and ENV_KEY not in payload["error"]
    _put(server, {"budgets": {"daily_calls": {"explain_line": 2}}})
    status, payload = line(ids[2])
    assert status == 200 and payload["degraded"] is True and payload["reason"] == "budget"

    rows = _usage_rows(app)
    assert [r["outcome"] for r in rows] == ["ok", "cache_hit", "error", "budget_blocked"]
    ok, hit, err, blocked = rows
    assert (ok["feature"], ok["provider"], ok["model"]) == ("explain_line", "openai", "gpt-test")
    assert (ok["tokens_in"], ok["tokens_out"], ok["cached_tokens"]) == (1000, 200, 400)
    # 600 × $2 + 400 × $0.5 + 200 × $10 per million
    assert ok["cost_usd_est"] == pytest.approx((600 * 2.0 + 400 * 0.5 + 200 * 10.0) / 1e6)
    assert ok["latency_ms"] >= 0 and ok["ts"].endswith("Z")
    assert (hit["tokens_in"], hit["cost_usd_est"]) == (0, 0.0)
    assert err["tokens_in"] > 0 and err["tokens_out"] == 0  # no usage reported: input estimated
    assert blocked["tokens_in"] == 0

    summary = _request(server, "GET", "/api/settings/ai/usage?days=7", headers=_auth())[1]
    today = summary["today"]["by_feature"]["explain_line"]
    assert (today["calls"], today["errors"], today["cache_hits"], today["blocked"]) == (2, 1, 1, 1)
    assert today["cache_hit_pct"] == pytest.approx(33.3)
    assert len(summary["by_day"]) == 7 and summary["by_day"][-1]["calls"] == 2


def test_missing_usage_is_estimated_and_unknown_model_cost_is_null(tmp_path, monkeypatch):
    _fake_openai(monkeypatch)  # no usage fields
    app = _app(tmp_path, model="unpriced-model", records=1)
    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    app.api_explain_line({"id": _ids(app)[0]})
    row = _usage_rows(app)[0]
    assert row["outcome"] == "ok" and row["cost_usd_est"] is None
    assert row["tokens_in"] > 100 and row["tokens_out"] > 5  # chars/4 of prompt and answer
    out_chars = len(json.dumps({"summary": ANSWER["summary"], "steps": app.api_explain_line(
        {"id": _ids(app)[0]})["steps"]}, ensure_ascii=False))
    assert row["tokens_out"] == estimate_tokens(out_chars)


def test_cost_calculation():
    prices = {"m": {"input": 3.0, "output": 15.0, "cached": 0.3}, "n": {"input": 1.0, "output": 2.0}}
    assert cost_usd(prices, "m", 1_000_000, 1_000_000, 0) == pytest.approx(18.0)
    assert cost_usd(prices, "m", 1_000_000, 0, 500_000) == pytest.approx(1.65)
    assert cost_usd(prices, "M", 1_000_000, 0, 0) == pytest.approx(3.0)  # case-insensitive match
    assert cost_usd(prices, "n", 1_000_000, 0, 1_000_000) == pytest.approx(1.0)  # cached defaults to input
    assert cost_usd(prices, "unknown", 10, 10, 0) is None
    assert estimate_tokens(0) == 0 and estimate_tokens(9) == 3


# ─── Budgets ─────────────────────────────────────────────────────────────────


def test_budget_cutoff_80_percent_warning_and_mattermost_notice(tmp_path, served, monkeypatch):
    _fake_openai(monkeypatch, usage={"prompt_tokens": 40, "completion_tokens": 40})
    monkeypatch.setenv("LS_TEST_MM_URL", "https://chat.example/hooks/abc")
    app = _app(tmp_path, model="gpt-test", records=3, mattermost=True)
    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    sent = []
    app.notifier._sender = lambda url, payload: sent.append(payload["text"])
    server = served(app)
    _put(server, {"budgets": {"daily_tokens": 100}})
    ids = _ids(app)
    explain = lambda i: _request(server, "POST", "/api/explain-line", body=json.dumps({"id": i}), headers=JSON)  # noqa: E731

    assert _request(server, "GET", "/api/status")[1]["ai_warnings"] == []
    assert "degraded" not in explain(ids[0])[1]  # 80 of 100 tokens
    status = _request(server, "GET", "/api/status")[1]
    assert status["ai_budget"] == [{"budget": "daily_tokens", "used": 80, "limit": 100, "ratio": 0.8}]
    assert status["ai_warnings"] == ["AI budget daily_tokens is at 80% today (UTC)"]
    for _ in range(50):
        if sent:
            break
        time.sleep(0.02)
    assert len(sent) == 1 and "daily_tokens" in sent[0] and "80%" in sent[0]

    assert "degraded" not in explain(ids[1])[1]  # under the limit before the call: 160 after it
    status, payload = explain(ids[2])
    assert status == 200 and payload["degraded"] is True and payload["reason"] == "budget"
    assert "skipped" in _request(server, "GET", "/api/status")[1]["ai_warnings"][0]
    time.sleep(0.1)
    assert len(sent) == 1  # one notice per budget per day

    # Budgets apply per UTC day: tomorrow starts from zero.
    tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
    app.ai_meter._clock = lambda: tomorrow
    assert app.ai_meter.check("explain_line") is None


def test_per_feature_daily_calls_do_not_block_other_features(tmp_path):
    app = _app(tmp_path, model="m")
    app.ai_settings.update({"budgets": {"daily_calls": {"explain_line": 1}}})
    app.ai_meter.record("explain_line", "ok", provider="openai", model="m")
    app.ai_meter.record("explain_filtered", "cache_hit", provider="openai", model="m")
    assert app.ai_meter.check("explain_line") == "daily_calls.explain_line"
    assert app.ai_meter.check("explain_filtered") is None


# ─── Test endpoint ───────────────────────────────────────────────────────────


def test_settings_test_endpoint_reports_ok_and_sanitized_errors(tmp_path, served, monkeypatch):
    seen = []
    _fake_openai(monkeypatch, seen=seen, usage={"prompt_tokens": 9, "completion_tokens": 1})
    app = _app(tmp_path)
    server = served(app)
    status, payload = _request(server, "POST", "/api/settings/ai/test", headers=_auth())
    assert status == 200 and payload["ok"] is False and "model" in payload["error"].lower()
    _put(server, {"model": "gpt-ping", "api_key": KEY})
    status, payload = _request(server, "POST", "/api/settings/ai/test", headers=_auth())
    assert status == 200 and payload["ok"] is True and payload["model"] == "gpt-ping"
    assert payload["latency_ms"] >= 0 and "error" not in payload and len(seen) == 1

    def failing(req, timeout=0):
        raise error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(
            json.dumps({"error": {"message": f"Incorrect API key provided: {KEY}"}}).encode()))

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", failing)
    status, payload = _request(server, "POST", "/api/settings/ai/test", headers=_auth())
    assert status == 200 and payload["ok"] is False and "HTTP 401" in payload["error"]
    assert KEY not in payload["error"] and KEY[-12:] not in payload["error"]
    assert [r["outcome"] for r in _usage_rows(app)] == ["ok", "error"]
    assert {r["feature"] for r in _usage_rows(app)} == {"settings_test"}
    assert _request(server, "POST", "/api/settings/ai/test")[0] == 401


# ─── Master key rotation ─────────────────────────────────────────────────────


def test_rotated_master_key_reports_unusable_key_instead_of_crashing(tmp_path, served, monkeypatch, caplog):
    from cryptography.fernet import Fernet

    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setenv(ai_settings.SECRET_KEY_ENV, old)
    app = _app(tmp_path, model="m")
    app.ai_settings.update({"api_key": KEY})
    assert app.ai_configured()
    app.state_db.close()

    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(ai_settings.SECRET_KEY_ENV, new)
    app = _app(tmp_path, model="m")
    server = served(app)
    payload = _request(server, "GET", "/api/settings/ai", headers=_auth())[1]
    assert payload["key_set"] is False and payload["key_source"] == "none"
    assert any("cannot be decrypted" in w for w in payload["warnings"])
    status = _request(server, "GET", "/api/status")[1]
    assert status["ai_configured"] is False and any("not usable" in w for w in status["ai_warnings"])
    assert KEY not in caplog.text
    # Entering the key again stores it under the new master key.
    assert _put(server, {"api_key": KEY})[1]["key_set"] is True
    server.shutdown()
    server.server_close()
    app.state_db.close()

    # Documented rotation: new key + LOGSCOPE_SECRET_KEY_PREVIOUS re-encrypts on start.
    newest = Fernet.generate_key().decode()
    monkeypatch.setenv(ai_settings.SECRET_KEY_ENV, newest)
    monkeypatch.setenv(ai_settings.SECRET_KEY_PREVIOUS_ENV, new)
    app = _app(tmp_path, model="m")
    assert app.ai_settings.public_view()["key_set"] is True
    app.state_db.close()
    monkeypatch.delenv(ai_settings.SECRET_KEY_PREVIOUS_ENV)
    assert _app(tmp_path, model="m").ai_settings.effective().api_key == KEY


def test_invalid_master_key_disables_storage_only(tmp_path, monkeypatch):
    monkeypatch.setenv(ai_settings.SECRET_KEY_ENV, "too-short")
    app = _app(tmp_path, model="m")
    view = app.ai_settings.public_view()
    assert view["key_storage_available"] is False and view["key_set"] is False
    with pytest.raises(SettingsError) as exc:
        app.ai_settings.update({"api_key": KEY})
    assert exc.value.field == "api_key"
    # A long passphrase is accepted (HKDF-derived key).
    monkeypatch.setenv(ai_settings.SECRET_KEY_ENV, "x" * 40)
    assert SecretBox(tmp_path).available


def test_state_migration_adds_ai_tables_to_a_v1_database(tmp_path):
    path = tmp_path / "state.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    conn.execute("INSERT INTO schema_version VALUES (1, '2026-01-01T00:00:00Z')")
    conn.execute("CREATE TABLE saved_views (id INTEGER PRIMARY KEY, name TEXT)")
    conn.commit()
    conn.close()
    db = StateDB(path)
    tables = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"ai_settings", "ai_usage", "ai_cache"} <= tables and db.schema_version() >= 2
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute("INSERT INTO ai_usage (ts, feature, outcome) VALUES ('t', 'f', 'bogus')")
