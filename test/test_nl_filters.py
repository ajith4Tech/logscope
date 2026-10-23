"""Natural-language filters (POST /api/ai/filters) with a fake provider, the
shared filter validator, and the qmode URL / saved-view round trip."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_production import CONFIG, JSON, _request, _serve  # noqa: E402

from webapp.api import ai_settings, nl_filters  # noqa: E402
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.filters import FilterError, sanitize_filters, validate_filters  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.state import ViewError  # noqa: E402
from webapp.api.state import validate_filters as view_validate_filters  # noqa: E402

KEY = "sk-test-NLKEY-0123456789abcdef"
ADMIN = "admin-token-for-tests-0123456789abcdef"
NOW = datetime(2026, 10, 21, 6, 30, tzinfo=timezone.utc)  # 12:00 in Asia/Kolkata
LOG_SECRET = "log-content-must-not-be-sent-7731"
_BASE = {"scope": "infra", "pod": "web-0", "container": "app", "raw_line": "r", "source_etag": "e",
         "is_falco": 0, "timestamp": "2026-10-21T05:00:00Z", "message": LOG_SECRET, "source_key": "k"}
_RECORDS = [
    {"namespace": "payments", "severity_bucket": "error", "pod": "payments-api-7f9c"},
    {"namespace": "kube-system", "severity_bucket": "info", "container": "coredns"},
    {"namespace": "billing", "severity_bucket": "warning", "container": "nginx"},
    {"namespace": "", "severity_bucket": "warning", "scope": "security"},
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (ai_settings.ADMIN_TOKEN_ENV, ai_settings.SECRET_KEY_ENV, ai_settings.SECRET_KEY_PREVIOUS_ENV,
                 "LS_TEST_AI_KEY", *ai_settings.FIELD_ENV.values()):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", "0")
    monkeypatch.setenv(ai_settings.ADMIN_TOKEN_ENV, ADMIN)
    monkeypatch.setenv("LS_TEST_AI_KEY", KEY)


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


def _app(tmp_path, **ai) -> WebApp:
    cfg = load_app_config(CONFIG)
    cfg = replace(cfg, webapp=replace(cfg.webapp, db_path=tmp_path / "webapp.sqlite"),
                  ai=replace(cfg.ai, **{"provider": "openai", "model": "gpt-fast", "deep_model": "gpt-deep",
                                        "api_key_env": "LS_TEST_AI_KEY", **ai}))
    app = WebApp(cfg)
    app.storage.insert_records([{**_BASE, **r, "line_number": i} for i, r in enumerate(_RECORDS, 1)])
    app.nl_filters._clock = lambda: NOW
    return app


class _Resp:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return self._data


def _provider(monkeypatch, *replies):
    """OpenAI-compatible fake: each call answers the next reply (a dict is
    sent as JSON, a str as is; the last one repeats). Returns the requests."""
    seen: list[dict] = []
    queue = list(replies)

    def urlopen(req, timeout=0):
        body = json.loads(req.data)
        seen.append({"model": body["model"], "system": body["messages"][0]["content"],
                     "user": json.loads(body["messages"][1]["content"])})
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        content = reply if isinstance(reply, str) else json.dumps(reply)
        return _Resp({"choices": [{"message": {"content": content}}],
                      "usage": {"prompt_tokens": 900, "completion_tokens": 40}})

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", urlopen)
    return seen


def _ask(server, text, tz="Asia/Kolkata", current=None, headers=None):
    body = {"text": text, "tz": tz}
    if current is not None:
        body["current"] = current
    return _request(server, "POST", "/api/ai/filters", body=json.dumps(body), headers={**JSON, **(headers or {})})


def _usage(app) -> list[tuple[str, str]]:
    with app.state_db.lock:
        return [(r["feature"], r["outcome"]) for r in
                app.state_db.conn.execute("SELECT feature, outcome FROM ai_usage ORDER BY id")]


def _put_settings(server, body):
    return _request(server, "PUT", "/api/settings/ai", body=json.dumps(body),
                    headers={**JSON, "Authorization": f"Bearer {ADMIN}"})


def _answer(filters, **extra):
    return {"filters": filters, "explanation": "Shown logs.", "confidence": 0.9, **extra}


# ─── Happy path and the prompt ───────────────────────────────────────────────


def test_happy_path_proposes_filters_with_the_fast_model(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({"ns": "payments", "sev": "error", "range": "1h"}))
    app = _app(tmp_path)
    server = served(app)
    status, payload = _ask(server, "errors in payments in the last hour")
    assert status == 200
    assert payload == {"filters": {"ns": "payments", "sev": "error", "range": "1h"}, "explanation": "Shown logs.",
                       "warnings": [], "confidence": 0.9, "cached": False}
    assert len(seen) == 1 and seen[0]["model"] == "gpt-fast"
    # Static instructions first (cacheable), then the dynamic context.
    assert seen[0]["system"].startswith(nl_filters.SYSTEM_PROMPT)
    user = seen[0]["user"]
    assert user["request"] == "errors in payments in the last hour"
    assert user["timezone"] == "Asia/Kolkata" and user["now_utc"] == "2026-10-21T06:30:00.000Z"
    assert user["now_local"].startswith("2026-10-21T12:00:00")
    vocab = user["vocabulary"]
    assert set(vocab) == {"scopes", "namespaces", "containers", "severities", "top_pods_7d"}
    assert "payments" in vocab["namespaces"] and "payments-api-7f9c" in vocab["top_pods_7d"]
    assert "security" in vocab["scopes"] and "error" in vocab["severities"]
    assert LOG_SECRET not in json.dumps(seen[0])  # no log content
    assert len(nl_filters.SYSTEM_PROMPT) + len(json.dumps(user)) < 6000
    assert _usage(app) == [("nl_filters", "ok")]


def test_no_time_in_the_request_keeps_the_current_range(tmp_path, served, monkeypatch):
    _provider(monkeypatch, _answer({"sev": "error"}))
    server = served(_app(tmp_path))
    status, payload = _ask(server, "only errors", current={"ns": "billing", "range": "6h"})
    assert status == 200 and payload["filters"] == {"sev": "error", "range": "6h"}


# ─── Time ────────────────────────────────────────────────────────────────────


def test_relative_and_absolute_times_in_asia_kolkata(tmp_path, served, monkeypatch):
    seen = _provider(
        monkeypatch,
        _answer({"from": "now-30m"}),
        _answer({"from": "2026-10-20T09:00:00", "to": "2026-10-20T11:00:00"}),
        _answer({"from": "2026-10-20T09:00:00+05:30", "to": "now"}),
        _answer({"range": "24h", "from": "2026-10-20T09:00:00"}),
    )
    server = served(_app(tmp_path))
    status, payload = _ask(server, "last 30 minutes")
    assert status == 200 and payload["filters"] == {"from": "2026-10-21T06:00:00.000Z"}
    # A local time without an offset is in the operator's zone (UTC+05:30).
    status, payload = _ask(server, "yesterday from 9 to 11am")
    assert payload["filters"] == {"from": "2026-10-20T03:30:00.000Z", "to": "2026-10-20T05:30:00.000Z"}
    status, payload = _ask(server, "since 9am yesterday")
    assert payload["filters"] == {"from": "2026-10-20T03:30:00.000Z"}  # "to": "now" is an open end
    status, payload = _ask(server, "both kinds of time")
    assert payload["filters"] == {"from": "2026-10-20T03:30:00.000Z"}
    assert any("exact from/to" in w for w in payload["warnings"])
    assert len(seen) == 4


def test_cached_answers_are_per_local_day(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({"from": "2026-10-20T09:00:00"}))
    app = _app(tmp_path)
    server = served(app)
    assert _ask(server, "since yesterday 9am")[1]["cached"] is False
    assert _ask(server, "since yesterday 9am")[1]["cached"] is True
    app.nl_filters._clock = lambda: datetime(2026, 10, 21, 19, 0, tzinfo=timezone.utc)  # 00:30 next day in IST
    assert _ask(server, "since yesterday 9am")[1]["cached"] is False
    assert len(seen) == 2


# ─── JSON handling ───────────────────────────────────────────────────────────


def test_invalid_json_is_retried_once_with_a_reminder(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, "Sure! Here are the filters: {\"filters\": {}}", _answer({"ns": "billing"}))
    app = _app(tmp_path)
    server = served(app)
    status, payload = _ask(server, "billing logs")
    assert status == 200 and payload["filters"] == {"ns": "billing"}
    assert len(seen) == 2
    reminder = "not a valid JSON object"
    assert reminder not in seen[0]["system"] and reminder in seen[1]["system"]
    assert seen[1]["user"] == seen[0]["user"]
    assert _usage(app) == [("nl_filters", "ok")]  # one metered request covering both attempts


def test_invalid_json_twice_fails(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, "not json", "```json\n[1, 2]\n```")
    app = _app(tmp_path)
    server = served(app)
    status, payload = _ask(server, "billing logs")
    assert status == 502 and "valid JSON" in payload["error"]
    assert len(seen) == 2
    assert _usage(app) == [("nl_filters", "error")]
    with app.state_db.lock:
        assert app.state_db.conn.execute("SELECT COUNT(*) FROM ai_cache").fetchone()[0] == 0


# ─── Server-side checks ──────────────────────────────────────────────────────


def test_unknown_keys_and_invalid_values_are_stripped(tmp_path, served, monkeypatch):
    _provider(monkeypatch, _answer({"ns": "payments", "status_code": "500", "host": "db-1", "range": "2h",
                                    "qmode": "fuzzy", "sev": ["error"]}))
    server = served(_app(tmp_path))
    status, payload = _ask(server, "payments 500s on db-1 in the last 2 hours")
    assert status == 200 and payload["filters"] == {"ns": "payments"}
    text = " ".join(payload["warnings"])
    for key in ("status_code", "host", "range", "qmode", "sev"):
        assert f"'{key}'" in text


def test_namespaces_fuzzy_matched_or_dropped(tmp_path, served, monkeypatch):
    _provider(monkeypatch, _answer({"ns": "paymnts", "xns": "kube-systm,unknown-ns,kube-system", "ctr": "NGINX",
                                    "pod": "no-such-pod"}))
    server = served(_app(tmp_path))
    status, payload = _ask(server, "payments without kube system")
    assert status == 200
    assert payload["filters"] == {"ns": "payments", "xns": "kube-system", "ctr": "nginx"}
    warnings = payload["warnings"]
    assert "Namespace “paymnts” is not in the cached logs; using “payments”" in warnings
    assert "Namespace “kube-systm” is not in the cached logs; using “kube-system”" in warnings
    assert "Namespace “unknown-ns” is not in the cached logs; dropped" in warnings
    assert "Pod “no-such-pod” is not in the cached logs; dropped" in warnings
    assert not any("NGINX" in w for w in warnings)  # a case-only difference is no warning


def test_unsupported_intent_goes_into_the_search_text(tmp_path, served, monkeypatch):
    _provider(monkeypatch,
              _answer({"ns": "billing"}, unsupported=["slower than 2s"]),
              _answer({"q": "timeout OR refused", "qmode": "raw"}, unsupported=["status 5xx"]))
    server = served(_app(tmp_path))
    status, payload = _ask(server, "requests slower than 2s in billing")
    assert status == 200 and payload["filters"] == {"ns": "billing", "q": "slower than 2s"}
    assert payload["warnings"] == ["No filter for “slower than 2s”; searching the log text for it instead"]
    status, payload = _ask(server, "timeouts or refused with status 5xx")
    assert payload["filters"] == {"q": 'timeout OR refused "status 5xx"', "qmode": "raw"}


def test_text_length_and_input_limits(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({}))
    server = served(_app(tmp_path))
    for body in ({"text": "", "tz": "UTC"}, {"text": "   ", "tz": "UTC"}, {"text": "x" * 501, "tz": "UTC"},
                 {"text": "ok", "tz": "Mars/Olympus"}, {"text": "ok"}, {"text": 5, "tz": "UTC"}):
        status, payload = _request(server, "POST", "/api/ai/filters", body=json.dumps(body), headers=JSON)
        assert status == 400, body
    assert seen == []
    assert _ask(server, "x" * 500, tz="UTC")[0] == 200
    assert len(seen[0]["user"]["request"]) == 500


# ─── Gates: flag, configuration, budget, rate limit, Origin ──────────────────


def test_flag_off_returns_403(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({}))
    app = _app(tmp_path)
    server = served(app)
    assert _put_settings(server, {"flags": {"nl_filters": False}})[0] == 200
    status, payload = _ask(server, "errors")
    assert (status, payload) == (403, {"error": "ai_feature_disabled", "feature": "nl_filters"})
    assert seen == [] and _usage(app) == []


def test_ai_disabled_returns_503(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({}))
    server = served(_app(tmp_path, model=""))
    status, payload = _ask(server, "errors")
    assert status == 503 and payload["error"] == "ai_disabled"
    assert seen == []


def test_budget_returns_503(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({"sev": "error"}))
    app = _app(tmp_path)
    server = served(app)
    assert _put_settings(server, {"budgets": {"daily_calls": {"nl_filters": 1}}})[0] == 200
    assert _ask(server, "errors")[0] == 200
    status, payload = _ask(server, "warnings")
    assert status == 503 and payload["error"] == "budget" and payload["budget"] == "daily_calls.nl_filters"
    assert _ask(server, "errors")[0] == 200  # a cached answer is still served
    assert len(seen) == 1
    assert _usage(app) == [("nl_filters", "ok"), ("nl_filters", "budget_blocked"), ("nl_filters", "cache_hit")]


def test_rate_limit_and_origin_check(tmp_path, served, monkeypatch):
    monkeypatch.setenv("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", "1")
    seen = _provider(monkeypatch, _answer({"sev": "error"}))
    server = served(_app(tmp_path))
    own = f"http://127.0.0.1:{server.server_address[1]}"
    for origin in ("https://evil.example", "null"):
        status, payload = _ask(server, "errors", headers={"Origin": origin})
        assert (status, payload) == (403, {"error": "Cross-origin request rejected"})
    status, _ = _request(server, "POST", "/api/ai/filters", body=json.dumps({"text": "errors", "tz": "UTC"}),
                         headers={**JSON, "Sec-Fetch-Site": "cross-site"})
    assert status == 403
    assert seen == []
    assert _ask(server, "errors", headers={"Origin": own})[0] == 200
    status, payload = _ask(server, "warnings", headers={"Origin": own})
    assert status == 429 and "rate limit" in payload["error"]
    assert _ask(server, "errors", headers={"Origin": own})[0] == 200  # cached: not rate limited
    assert len(seen) == 1


def test_cache_hit_is_metered_as_cache_hit(tmp_path, served, monkeypatch):
    seen = _provider(monkeypatch, _answer({"ns": "payments"}))
    app = _app(tmp_path)
    server = served(app)
    first = _ask(server, "Payments   logs")[1]
    second = _ask(server, "  payments logs ")[1]
    assert (first["cached"], second["cached"]) == (False, True)
    assert first["filters"] == second["filters"] == {"ns": "payments"}
    assert len(seen) == 1
    assert _usage(app) == [("nl_filters", "ok"), ("nl_filters", "cache_hit")]
    # A different zone is a different request.
    assert _ask(server, "payments logs", tz="UTC")[1]["cached"] is False


def test_user_text_is_never_logged(tmp_path, served, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    marker = "zebra-unicorn-4711 password=hunter2"
    _provider(monkeypatch, "not json", "still not json", _answer({"q": marker}, unsupported=[marker]))
    server = served(_app(tmp_path))
    assert _ask(server, marker)[0] == 502
    assert _ask(server, marker)[0] == 200
    assert _ask(server, marker)[0] == 200  # cache hit
    assert _ask(server, marker + "x" * 600)[0] == 400
    assert caplog.records  # the access log did run
    assert "zebra-unicorn" not in caplog.text and "hunter2" not in caplog.text


# ─── Shared validator ────────────────────────────────────────────────────────


def test_views_and_nl_filters_share_one_validator():
    raw = {"ns": "payments", "q": "a OR b", "qmode": "raw", "xns": ["kube-system", "kube-system"], "range": "1h"}
    assert validate_filters(raw) == view_validate_filters(raw) == {
        "ns": "payments", "q": "a OR b", "qmode": "raw", "xns": "kube-system", "range": "1h"}
    with pytest.raises(FilterError):
        validate_filters({"bogus": "x"})
    with pytest.raises(ViewError):  # saved views keep their own error type
        view_validate_filters({"bogus": "x"})
    filters, warnings = sanitize_filters({"bogus": "x", "ns": "ok", "xns": ["a", 5, "b"], "from": "nope"})
    assert filters == {"ns": "ok", "xns": "a,b"} and len(warnings) == 3
    assert validate_filters(filters) == filters


# ─── qmode round trip ────────────────────────────────────────────────────────


def test_qmode_round_trips_through_saved_views(tmp_path, served, monkeypatch):
    server = served(_app(tmp_path))
    filters = {"q": "timeout OR refused", "qmode": "raw", "ns": "payments"}
    status, payload = _request(server, "POST", "/api/views", body=json.dumps({"name": "raw", "filters": filters}),
                               headers=JSON)
    assert status == 201, payload
    view_id = payload["view"]["id"]
    status, payload = _request(server, "GET", f"/api/views/{view_id}")
    assert payload["view"]["filters"] == filters
    # phrase is the default and is not stored, like in the URL.
    status, payload = _request(server, "POST", "/api/views",
                               body=json.dumps({"name": "phrase", "filters": {"q": "x", "qmode": "phrase"}}),
                               headers=JSON)
    assert payload["view"]["filters"] == {"q": "x"}


_NODE_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const elements = new Map();
function makeEl(id) {
  const base = { id, value: '', checked: false, hidden: false, disabled: false, textContent: '', innerHTML: '',
    title: '', className: '', options: [], style: {}, dataset: {}, children: [],
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } } };
  return new Proxy(base, { get(t, p) { return p in t ? t[p] : (typeof p === 'string' ? () => makeEl('') : undefined); } });
}
const document = { getElementById(id) { if (!elements.has(id)) elements.set(id, makeEl(id)); return elements.get(id); },
  addEventListener() {}, querySelector() { return makeEl(''); }, querySelectorAll() { return []; },
  createElement() { return makeEl(''); }, body: makeEl('body'), documentElement: makeEl('html') };
const window = { location: { search: '', pathname: '/', href: 'http://x/' }, history: { pushState() {}, replaceState() {} },
  addEventListener() {}, setInterval() { return 0; }, clearInterval() {}, setTimeout() { return 0; }, clearTimeout() {},
  sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} }, matchMedia() { return { matches: false, addEventListener() {} }; } };
const ctx = { document, window, console, URLSearchParams, Intl, Date, Math, JSON, Map, Set, Promise, Number, String,
  Array, Object, Error, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
  fetch: () => Promise.reject(new Error('offline')), HTMLElement: class {}, HTMLButtonElement: class {},
  HTMLInputElement: class {}, HTMLSelectElement: class {}, Element: class {}, Node: class {}, navigator: {},
  AbortController: class { abort() {} get signal() { return {}; } }, requestAnimationFrame() {}, ResizeObserver: class { observe() {} } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx);
const run = (code) => vm.runInContext(code, ctx);
run(`el('rangePreset').value = 'today'; el('start').value = ''; el('q').value = 'timeout OR refused'; el('qmodeRaw').checked = true;`);
const built = run('buildUrlParams().toString()');
const parsed = run(`parseUrlState(${JSON.stringify('?' + built)})`);
const noQuery = run(`parseUrlState('?qmode=raw')`);
const viewFilters = run('currentViewFilters()');
run(`el('qmodeRaw').checked = false;`);
const phrase = run('buildUrlParams().toString()');
const query = run(`el('qmodeRaw').checked = true; queryFromFilters()`);
process.stdout.write(JSON.stringify({ built, parsed: { q: parsed.q, qmode: parsed.qmode }, noQuery: noQuery.qmode,
  viewFilters, phrase, query }));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_qmode_round_trips_through_the_ui_url_state(tmp_path):
    harness = tmp_path / "harness.js"
    harness.write_text(_NODE_HARNESS)
    out = subprocess.run(["node", str(harness), str(ROOT / "webapp" / "ui" / "app.js")], capture_output=True,
                         text=True, timeout=60, env={**os.environ, "TZ": "UTC"})
    assert out.returncode == 0, out.stderr[-2000:]
    result = json.loads(out.stdout)
    assert "qmode=raw" in result["built"]
    assert result["parsed"] == {"q": "timeout OR refused", "qmode": "raw"}
    assert result["noQuery"] == "phrase"  # qmode without a search is dropped
    assert result["viewFilters"]["qmode"] == "raw" and result["viewFilters"]["q"] == "timeout OR refused"
    assert "qmode" not in result["phrase"]
    assert result["query"]["qmode"] == "raw"
    # applyUrlState restores the toggle from the parsed URL.
    source = (ROOT / "webapp" / "ui" / "app.js").read_text()
    assert "el('qmodeRaw').checked = parsed.qmode === 'raw';" in source
