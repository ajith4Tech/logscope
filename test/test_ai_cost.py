"""AI cost reductions: template cache (shared across pods/IPs, single-flight,
TTL, feedback, regenerate), compact inputs, model tiers and the deep budget,
the bounded summary worker and batching, local models, prompt caching."""

from __future__ import annotations

import json
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_ai_settings import (  # noqa: E402,F401
    ADMIN,
    ANSWER,
    ENV_KEY,
    JSON,
    _app,
    _clean_env,
    _ids,
    _put,
    _request,
    _Resp,
    _usage_rows,
    served,
)
from webapp.api import ai_summary  # noqa: E402
from webapp.api.ai_cache import AiCache, SingleFlight  # noqa: E402
from webapp.api.ai_summary import (  # noqa: E402
    _EXPLAIN_SYSTEM_PROMPT,
    _UNTRUSTED_INPUT_RULES,
    compact_log_payload,
    prepare_untrusted_payload,
)
from webapp.api.config import AiConfig  # noqa: E402
from webapp.api.explain import anomaly_template_summary  # noqa: E402
from webapp.api.insights import InsightsJob  # noqa: E402
from webapp.api.state import StateDB  # noqa: E402
from webapp.api.storage import open_connection  # noqa: E402

FIXTURE = ROOT / "test" / "fixtures" / "explain_sample.jsonl"
STEP_ANSWER = {"summary": "Pod web-a is timing out to 10.0.0.1.", "steps": [
    {"title": "Describe", "command": "kubectl -n shop describe pod web-a", "explanation": "State.", "risk": "read-only"}]}


def _record(message, *, pod="web-a", namespace="shop", container="app", i=1):
    return {"severity_bucket": "error", "scope": f"namespaces/{namespace}", "namespace": namespace, "pod": pod,
            "container": container, "raw_line": message, "source_etag": "e", "is_falco": 0,
            "timestamp": f"2026-09-07T10:00:{i:02d}Z", "message": message, "source_key": f"k{i}", "line_number": i}


def _counting_openai(monkeypatch, answer=STEP_ANSWER, *, delay: threading.Event | None = None, usage=None):
    calls = []

    def urlopen(req, timeout=0):
        body = json.loads(req.data)
        calls.append({"url": req.full_url, "model": body["model"], "body": body,
                      "auth": {k.lower(): v for k, v in req.headers.items()}.get("authorization")})
        if delay is not None:
            delay.wait(5)
        payload = {"choices": [{"message": {"content": json.dumps(answer)}}]}
        if usage:
            payload["usage"] = usage
        return _Resp(payload)

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", urlopen)
    return calls


def _configured_app(tmp_path, monkeypatch, **ai):
    app = _app(tmp_path, **{"model": "gpt-fast", **ai})
    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    return app


def _line(server, record_id, **options):
    return _request(server, "POST", "/api/explain-line", body=json.dumps({"id": record_id, **options}), headers=JSON)


# ─── Cache ───────────────────────────────────────────────────────────────────


def test_cache_hits_across_pods_and_ips_for_the_same_template(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    app.storage.insert_records([
        _record("upstream 10.0.0.1:8080 slow, request 4411 took 2.5s", pod="web-a", i=1),
        _record("upstream 10.0.9.77:8080 slow, request 98 took 17ms", pod="web-b", i=2),
        _record("upstream 10.0.9.77:8080 slow, request 98 took 17ms", pod="web-c", namespace="other", i=3),
    ])
    server = served(app)
    first, second, other = _ids(app)
    status, a = _line(server, first)
    assert status == 200 and a["source"] == "ai" and a["tier"] == "fast" and a["cache_key"]
    status, b = _line(server, second)
    assert status == 200 and b["source"] == "cache" and b["cached"] is True and b["age_secs"] >= 0
    assert len(calls) == 1
    # The cached plan is rebound to this record's pod.
    assert b["steps"][0]["command"] == "kubectl -n shop describe pod web-b" and b["steps"][0]["is_supported"]
    assert "web-b" in b["summary"] and "web-a" not in b["summary"]
    # Another namespace is another template id: a new call.
    assert _line(server, other)[1]["source"] == "ai" and len(calls) == 2
    # Persistent: a restart (new front) still hits.
    app.ai_cache._front.clear()
    assert _line(server, second)[1]["source"] == "cache" and len(calls) == 2
    assert [r["outcome"] for r in _usage_rows(app)] == ["ok", "cache_hit", "ok", "cache_hit"]


def test_single_flight_shares_one_provider_call(tmp_path, monkeypatch):
    gate = threading.Event()
    calls = _counting_openai(monkeypatch, delay=gate)
    app = _configured_app(tmp_path, monkeypatch)
    app.storage.insert_records([_record(f"worker {i} lost lease on shard 7", pod=f"w-{i}", i=i) for i in (1, 2, 3)])
    results = []
    threads = [threading.Thread(target=lambda rid=rid: results.append(app.api_explain_line({"id": rid})))
               for rid in _ids(app)]
    for t in threads:
        t.start()
    for _ in range(100):
        if app.ai_cache.flight.in_flight() and len(calls) == 1:
            break
        time.sleep(0.01)
    time.sleep(0.2)  # the other two are waiting on the same key
    gate.set()
    for t in threads:
        t.join(5)
    assert len(calls) == 1 and len(results) == 3
    assert sorted(r["source"] for r in results) == ["ai", "cache", "cache"]
    assert sorted(r["outcome"] for r in _usage_rows(app)) == ["cache_hit", "cache_hit", "ok"]

    flight = SingleFlight()
    with pytest.raises(RuntimeError):
        flight.do("k", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert flight.do("k", lambda: 5) == (5, False)  # a failure is not remembered


def test_ttl_expiry(tmp_path, monkeypatch):
    now = [datetime(2026, 9, 7, tzinfo=timezone.utc)]
    cache = AiCache(StateDB(tmp_path / "s.sqlite"), ttl_hours=168, clock=lambda: now[0])
    cache.put("line:fast:x:error", kind="line", tier="fast", response={"summary": "s", "steps": [{}]})
    now[0] += timedelta(days=6, hours=23)
    assert cache.get("line:fast:x:error")["hits"] == 1
    now[0] += timedelta(hours=2)
    assert cache.get("line:fast:x:error") is None
    assert cache.stats()["entries"] == 0  # removed, not just hidden

    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path / "app", monkeypatch, cache_ttl_hours=1)
    app.storage.insert_records([_record("lease lost on shard 1", i=1)])
    rid = _ids(app)[0]
    app.api_explain_line({"id": rid})
    assert app.api_explain_line({"id": rid})["source"] == "cache"
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    app.ai_cache._clock = lambda: later
    assert app.api_explain_line({"id": rid})["source"] == "ai" and len(calls) == 2


def test_thumbs_down_drops_the_entry_and_regenerate_bypasses(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    app.storage.insert_records([_record("lease lost on shard 1", i=1)])
    server = served(app)
    rid = _ids(app)[0]
    key = _line(server, rid)[1]["cache_key"]
    assert _line(server, rid)[1]["source"] == "cache"
    # Regenerate: a new call, which replaces the cached answer.
    assert _line(server, rid, regenerate=True)[1]["source"] == "ai" and len(calls) == 2
    vote = lambda client, value: _request(server, "POST", "/api/ai/feedback",  # noqa: E731
                                          body=json.dumps({"key": key, "vote": value}),
                                          headers={**JSON, "X-Logscope-Client": client})
    assert vote("client-aaaa", "down")[1]["helpful_down"] == 1
    assert _line(server, rid)[1]["source"] == "cache"  # 1 net 👎: kept
    vote("client-bbbb", "down")
    assert _line(server, rid)[1]["source"] == "ai" and len(calls) == 3  # 2 net 👎: dropped on this request
    with app.state_db.lock:
        row = app.state_db.conn.execute("SELECT helpful_up, helpful_down, hits FROM ai_cache").fetchone()
        votes = app.state_db.conn.execute("SELECT COUNT(*) FROM ai_cache_votes").fetchone()[0]
    assert tuple(row) == (0, 0, 0) and votes == 0  # the new answer starts fresh
    assert vote("client-aaaa", "up")[0] == 200
    assert _request(server, "POST", "/api/ai/feedback", body=json.dumps({"key": "nope", "vote": "up"}),
                    headers={**JSON, "X-Logscope-Client": "client-aaaa"})[0] == 404
    assert vote("client-aaaa", "meh")[0] == 400


# ─── Compact inputs ──────────────────────────────────────────────────────────


def _fixture_rows():
    return [json.loads(line) for line in FIXTURE.read_text().splitlines() if line.strip()]


def _old_payload(rows):
    """What /api/explain sent before: up to 50 raw rows."""
    sample = [{"timestamp": r["timestamp"], "severity": r["severity_bucket"], "namespace": r["namespace"],
               "pod": r["pod"], "container": r["container"], "message": r["message"]} for r in rows[:50]]
    return {"filters": {"namespace": "shop"}, "total_matching_exceeds_sample": True, "sample_size": len(sample),
            "log_sample": sample}


def _size(payload):
    return len(json.dumps(prepare_untrusted_payload(payload), separators=(",", ":"), ensure_ascii=False))


def test_compact_payload_is_under_a_quarter_of_the_old_one(capsys):
    rows = _fixture_rows()
    old = _size(_old_payload(rows))
    compact = compact_log_payload(rows[:50], {"namespace": "shop"}, sample_limit_reached=True)
    new = _size(compact)
    assert new < 0.25 * old, (new, old)
    assert len(compact["templates"]) == 4 and all(len(t["exemplars"]) <= 3 for t in compact["templates"])
    assert sum(t["count"] for t in compact["templates"]) == 50
    # Even the full 60-row fixture (the new path samples up to 500 rows) stays small.
    assert _size(compact_log_payload(rows, {}, sample_limit_reached=False)) < 0.25 * old
    system = len(_EXPLAIN_SYSTEM_PROMPT + _UNTRUSTED_INPUT_RULES)
    with capsys.disabled():
        print(f"\n[estimate] filtered explain on {FIXTURE.name}: input ≈ {(old + system) // 4} tokens before, "
              f"≈ {(new + system) // 4} after (payload {old} → {new} chars, system prompt ≈ {system // 4} tokens)")


def test_static_prompt_first_and_anomaly_evidence_compacted():
    payload = ai_summary.build_prompt_payload({"type": "error_rate_spike", "namespace": "shop", "evidence": {
        "current_count": 40, "sample_messages": [f"timeout to 10.0.0.{i} after {i}s" for i in range(5)],
        "sample_timestamps": [f"2026-09-07T10:0{i}:00Z" for i in range(5)]}})
    evidence = payload["evidence"]
    assert "sample_messages" not in evidence and evidence["current_count"] == 40
    [template] = evidence["sample_templates"]
    assert template["template"] == "timeout to <IP> after <DUR>" and template["count"] == 5
    assert len(template["exemplars"]) == 3 and template["last_seen"] == "2026-09-07T10:04:00Z"


def test_explain_filtered_sends_templates_and_caches_by_template_shape(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    rows = _fixture_rows()
    app.storage.insert_records([{**r, "raw_line": r["message"], "source_etag": "e", "is_falco": 0,
                                 "source_key": "fx", "line_number": i} for i, r in enumerate(rows)])
    server = served(app)
    status, first = _request(server, "POST", "/api/explain?namespace=shop")
    assert status == 200 and first["source"] == "ai" and first["sample_count"] == 60
    sent = json.loads(calls[0]["body"]["messages"][1]["content"])
    assert "log_sample" not in sent and len(sent["templates"]) == 4
    assert calls[0]["body"]["messages"][0]["role"] == "system"  # static content first
    # Another filter over the same data has the same template shape: cached.
    assert _request(server, "POST", "/api/explain?container=app")[1]["source"] == "cache" and len(calls) == 1


# ─── Tiers ───────────────────────────────────────────────────────────────────


def test_deep_tier_uses_deep_model_separate_cache_and_budget(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch, deep_model="gpt-deep")
    app.storage.insert_records([_record("lease lost on shard 1", i=1)])
    server = served(app)
    rid = _ids(app)[0]
    assert _line(server, rid)[1]["tier"] == "fast"
    deep = _line(server, rid, tier="deep")[1]
    assert deep["source"] == "ai" and deep["tier"] == "deep"  # not answered by the fast cache
    assert [c["model"] for c in calls] == ["gpt-fast", "gpt-deep"]
    assert _line(server, rid, tier="deep")[1]["source"] == "cache"
    _put(server, {"budgets": {"daily_calls": {"deep_analysis": 1}}})
    blocked = _line(server, rid, tier="deep", regenerate=True)[1]
    assert blocked["degraded"] is True and blocked["budget"] == "daily_calls.deep_analysis"
    assert _line(server, rid, regenerate=True)[1]["source"] == "ai"  # the fast tier is unaffected
    rows = [(r["feature"], r["model"], r["outcome"]) for r in _usage_rows(app)]
    assert rows == [("explain_line", "gpt-fast", "ok"), ("deep_analysis", "gpt-deep", "ok"),
                    ("deep_analysis", "gpt-deep", "cache_hit"), ("deep_analysis", "gpt-deep", "budget_blocked"),
                    ("explain_line", "gpt-fast", "ok")]
    assert _line(server, rid, tier="huge")[0] == 400


# ─── Anomalies: free summary, worker, batching ───────────────────────────────


def _anomaly(app, *, type_="new_falco_rule", namespace="", severity="error", rule_key="Odd binary ran",
             messages=("odd binary /tmp/x ran",), window="2026-09-07T10:00:00Z", day="2026-09-07"):
    return app.anomaly_store.upsert_anomaly(
        type=type_, namespace=namespace, pod="", rule_key=rule_key, severity=severity, detected_day=day,
        evidence={"window_start": window, "current_count": 12, "expected_count": 3.0, "baseline_avg_per_hour": 3.0,
                  "observed_minutes": 60, "baseline_window_days": 7, "sample_messages": list(messages)})


def test_anomalies_get_a_free_template_summary(tmp_path, served):
    app = _app(tmp_path)
    _anomaly(app, type_="error_rate_spike", namespace="shop", rule_key="",
             messages=("dial tcp 10.0.0.1:5432: connect: connection refused",
                       "dial tcp 10.0.0.2:5432: connect: connection refused"))
    server = served(app)
    [item] = _request(server, "GET", "/api/anomalies")[1]["items"]
    summary = item["template_summary"]
    assert summary["headline"] == "12 error lines in shop in 60 min, 4× the 3 expected from the last 7 days."
    assert summary["counts"]["ratio"] == 4.0
    assert summary["templates"] == [{"template": "dial tcp <IP>: connect: connection refused", "count": 2}]
    assert summary["signature"]["id"] == "connection-refused"
    assert _usage_rows(app) == []  # free


def test_auto_summary_off_by_default_and_min_urgency(tmp_path, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    urgent = app.anomaly_store.get_anomaly(_anomaly(app))
    high = app.anomaly_store.get_anomaly(_anomaly(app, type_="error_rate_spike", namespace="shop", rule_key=""))
    assert app.summary_worker.enqueue([urgent, high]) == 0  # anomaly_auto_summary defaults to off
    assert app.insights.dispatch_pending() == 0 and calls == []
    app.ai_settings.update({"flags": {"anomaly_auto_summary": True}})
    assert app.summary_worker.enqueue([urgent, high]) == 1  # only urgent (the default minimum)
    assert app.summary_worker.enqueue([urgent]) == 0  # already queued


def test_worker_queue_never_blocks_detection(tmp_path, monkeypatch):
    gate = threading.Event()
    calls = _counting_openai(monkeypatch, delay=gate)
    app = _configured_app(tmp_path, monkeypatch)
    app.ai_settings.update({"flags": {"anomaly_auto_summary": True}})
    anomaly_id = _anomaly(app)
    job = InsightsJob(app.cfg, open_connection(app.cfg.webapp.db_path), app.anomaly_store,
                      dispatcher=app._dispatch_summaries)
    app.summary_worker.start()
    try:
        started = time.monotonic()
        counts = job.run_once(datetime(2026, 9, 7, 12, tzinfo=timezone.utc))
        assert time.monotonic() - started < 2 and counts["anomalies_queued"] == 1
        for _ in range(200):
            if calls:
                break
            time.sleep(0.01)
        assert len(calls) == 1  # the provider call is in progress on a worker thread...
        started = time.monotonic()
        job.run_once(datetime(2026, 9, 7, 12, tzinfo=timezone.utc))  # ...and detection still runs
        assert time.monotonic() - started < 2
        assert app.summary_worker.status()["in_progress"] == 1
        gate.set()
        for _ in range(300):
            if app.anomaly_store.get_anomaly(anomaly_id)["ai_summary"]:
                break
            time.sleep(0.01)
        saved = app.anomaly_store.get_anomaly(anomaly_id)
        assert saved["ai_summary"] == STEP_ANSWER["summary"] and saved["ai_meta"]["source"] == "ai"
    finally:
        gate.set()
        app.summary_worker.stop()


def test_worker_drops_batches_over_budget(tmp_path, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    app.ai_settings.update({"flags": {"anomaly_auto_summary": True},
                            "budgets": {"daily_calls": {"anomaly_auto_summary": 0}}})
    anomaly = app.anomaly_store.get_anomaly(_anomaly(app))
    app.summary_worker.enqueue([anomaly])
    app.summary_worker.process(app.summary_worker.take_batch(timeout=0))
    assert calls == [] and app.summary_worker.dropped == 1
    assert app.anomaly_store.get_anomaly(anomaly["id"])["ai_summary"] is None  # still pending
    assert [r["outcome"] for r in _usage_rows(app)] == ["budget_blocked"]


def test_batching_up_to_five_anomalies_in_one_call(tmp_path, monkeypatch):
    calls = []

    def urlopen(req, timeout=0):
        body = json.loads(req.data)
        calls.append(body)
        sent = json.loads(body["messages"][1]["content"])
        answer = {"summaries": [{"id": a["id"], "summary": f"Summary for {a['rule_key']}",
                                 "steps": [{"title": "t", "command": "kubectl -n shop get events",
                                            "explanation": "e", "risk": "read-only"}]} for a in sent["anomalies"]]}
        return _Resp({"choices": [{"message": {"content": json.dumps(answer)}}],
                      "usage": {"prompt_tokens": 900, "completion_tokens": 300}})

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", urlopen)
    app = _configured_app(tmp_path, monkeypatch)
    app.ai_settings.update({"flags": {"anomaly_auto_summary": True}})
    same_window = [_anomaly(app, rule_key=f"rule {name}", messages=(f"weird {name}",)) for name in "abcdef"]
    later = _anomaly(app, rule_key="rule z", messages=("weird z",), window="2026-09-07T14:00:00Z")
    worker = app.summary_worker
    assert worker.enqueue([app.anomaly_store.get_anomaly(i) for i in [*same_window, later]]) == 7
    first = worker.take_batch(timeout=0)
    assert [a["id"] for a in first] == same_window[:5]  # at most 5, same window
    worker.process(first)
    assert len(calls) == 1 and "summaries" in calls[0]["messages"][0]["content"]
    for anomaly_id, name in zip(same_window[:5], "abcde"):
        saved = app.anomaly_store.get_anomaly(anomaly_id)
        assert saved["ai_summary"] == f"Summary for rule {name}" and saved["ai_meta"]["tier"] == "fast"
    rest = worker.take_batch(timeout=0)
    assert [a["id"] for a in rest] == [same_window[5]]  # different window: not batched with "later"
    rows = _usage_rows(app)
    assert [(r["feature"], r["outcome"], r["tokens_in"]) for r in rows] == [("anomaly_auto_summary", "ok", 900)]


def test_manual_summary_is_cached_and_signature_first(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch)
    app = _configured_app(tmp_path, monkeypatch)
    plain = _anomaly(app, type_="message_frequency", namespace="shop", severity="", rule_key="cart rebuilt")
    known = _anomaly(app, type_="error_rate_spike", namespace="db", rule_key="",
                     messages=("ERROR:  deadlock detected",))
    server = served(app)
    summarize = lambda i, **o: _request(server, "POST", f"/api/anomalies/{i}/summarize",  # noqa: E731
                                        body=json.dumps(o), headers=JSON)[1]
    assert summarize(known)["source"] == "signature" and calls == []
    assert app.anomaly_store.get_anomaly(known)["ai_meta"]["source"] == "signature"
    assert summarize(plain)["source"] == "ai" and summarize(plain)["source"] == "cache" and len(calls) == 1
    deep = summarize(plain, tier="deep")
    assert deep["tier"] == "deep" and len(calls) == 2


# ─── Providers ───────────────────────────────────────────────────────────────


def test_local_openai_compatible_endpoint_needs_no_key(tmp_path, served, monkeypatch):
    calls = _counting_openai(monkeypatch, usage={"prompt_tokens": 120, "completion_tokens": 40})
    app = _app(tmp_path, model="llama3.1:8b", base_url="http://localhost:11434/v1")
    server = served(app)
    assert _request(server, "GET", "/api/status")[1]["ai_configured"] is True
    app.storage.insert_records([_record("lease lost on shard 1", i=1)])
    status, payload = _line(server, _ids(app)[0])
    assert status == 200 and payload["source"] == "ai"
    assert calls[0]["url"] == "http://localhost:11434/v1/chat/completions"
    assert calls[0]["model"] == "llama3.1:8b" and calls[0]["auth"] == "Bearer local"
    [row] = _usage_rows(app)
    assert (row["tokens_in"], row["tokens_out"], row["cost_usd_est"]) == (120, 40, None)
    _put(server, {"prices": {"llama3.1:8b": {"input": 0, "output": 0}}})
    assert app.ai_meter.record("explain_line", "ok", model="llama3.1:8b", tokens_in=10)["cost_usd_est"] == 0
    test = _request(server, "POST", "/api/settings/ai/test", headers={"Authorization": f"Bearer {ADMIN}"})[1]
    assert test["ok"] is True


def test_anthropic_system_block_is_cacheable_and_cached_tokens_recorded(monkeypatch):
    seen = []

    class Messages:
        def create(self, **kwargs):
            seen.append(kwargs)
            return types.SimpleNamespace(
                stop_reason="end_turn", content=[types.SimpleNamespace(type="text", text=json.dumps(ANSWER))],
                usage=types.SimpleNamespace(input_tokens=200, output_tokens=80, cache_read_input_tokens=1500,
                                            cache_creation_input_tokens=0))

    fake = types.ModuleType("anthropic")
    fake.APIStatusError = type("APIStatusError", (Exception,), {})
    fake.APIConnectionError = type("APIConnectionError", (Exception,), {})
    fake.Anthropic = lambda **kw: types.SimpleNamespace(messages=Messages(), beta=types.SimpleNamespace(
        messages=Messages()))
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    cfg = AiConfig(provider="anthropic", model="claude-opus-5-5", api_key_env="K", max_anomalies_per_tick=1,
                   reasoning_effort="", api_key="sk-ant-x")
    with ai_summary.capture_usage() as usage:
        ai_summary.explain_logs({"filters": {}, "templates": []}, cfg)
    [system] = seen[0]["system"]
    assert system["cache_control"] == {"type": "ephemeral"} and system["text"].startswith("You are")
    assert usage["tokens_in"] == 1700 and usage["cached_tokens"] == 1500 and usage["tokens_out"] == 80
