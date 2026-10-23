"""Signature KB: every command validates, matches are answered before any
AI call (metered as outcome=signature), operators can add validated rules."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_ai_settings import ANSWER, ENV_KEY, JSON, _app, _clean_env, _ids, _request, _usage_rows, served  # noqa: E402,F401

from webapp.api.actions import describe_action, resolve_action  # noqa: E402
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.signatures import (  # noqa: E402
    SAMPLE_VALUES,
    SignatureError,
    SignatureKB,
    fill_command,
    load_rules,
)

RULES = load_rules()
KB = SignatureKB(RULES)


def test_every_builtin_command_passes_the_actions_validator():
    assert len(RULES) >= 40
    commands = 0
    for rule in RULES:
        assert rule.steps, rule.id
        for step in rule.steps:
            filled = fill_command(step["command"], SAMPLE_VALUES)
            described = describe_action(resolve_action({"command": filled}))  # raises if unsupported
            assert described["risk"] == "read-only" and not described["is_mutating"], (rule.id, filled)
            commands += 1
    assert commands >= 60


@pytest.mark.parametrize("message,rule_id", [
    ("Last State: Terminated Reason: OOMKilled Exit Code: 137", "oom-killed"),
    ("container app exited with code 137", "oom-killed"),
    ("Back-off restarting failed container app in pod web-0", "crashloop-backoff"),
    ("Warning Failed kubelet Error: ImagePullBackOff", "image-pull"),
    ('Failed to pull image "x:1": ErrImagePull', "image-pull"),
    ("Liveness probe failed: HTTP probe failed with statuscode: 500", "liveness-probe"),
    ('Readiness probe failed: Get "http://10.0.0.1:8080/": context deadline exceeded', "readiness-probe"),
    ("dial tcp 10.43.12.7:5432: connect: connection refused", "connection-refused"),
    ("upstream request failed: i/o timeout", "connection-timeout"),
    ("lookup orders.shop.svc.cluster.local on 10.43.0.10:53: no such host", "dns-failure"),
    ("query returned NXDOMAIN for api.internal", "dns-failure"),
    ("x509: certificate has expired or is not yet valid", "tls-certificate"),
    ("write /data/x: no space left on device", "disk-full"),
    ("accept tcp [::]:8080: accept4: too many open files", "too-many-open-files"),
    ('FATAL:  password authentication failed for user "app"', "postgres-auth-failed"),
    ("FATAL:  sorry, too many clients already", "postgres-too-many-connections"),
    ('ERROR:  duplicate key value violates unique constraint "users_pkey"', "postgres-duplicate-key"),
    ("ERROR:  deadlock detected", "postgres-deadlock"),
    ('ERROR:  relation "orders" does not exist at character 15', "postgres-relation-missing"),
    ("panic: runtime error: invalid memory address or nil pointer dereference", "go-nil-pointer"),
    ("panic: assignment to entry in nil map", "go-panic"),
    ("Traceback (most recent call last):\n  File \"/app/x.py\", line 1", "python-traceback"),
    ('Exception in thread "main" java.lang.OutOfMemoryError: Java heap space', "java-oom"),
    ("open /var/run/app.sock: permission denied", "permission-denied"),
    ("all good, request served", None),
])
def test_known_messages_match(message, rule_id):
    rule = KB.match(message)
    assert (rule.id if rule else None) == rule_id


@pytest.mark.parametrize("falco_rule,rule_id", [
    ("Terminal shell in container", "falco-terminal-shell"),
    ("Read sensitive file untrusted", "falco-sensitive-file"),
    ("Write below etc", "falco-write-below-etc"),
    ("Write below binary dir", "falco-write-binary-dir"),
    ("Launch Privileged Container", "falco-privileged-container"),
    ("Contact K8S API Server From Container", "falco-k8s-api-contact"),
    ("Unexpected outbound connection destination", "falco-unexpected-connection"),
    ("Drop and execute new binary in container", "falco-drop-and-execute"),
    ("Redirect STDOUT/STDIN to Network Connection in Container", "falco-redirect-network"),
    ("Clear Log Activities", "falco-clear-logs"),
    ("Search Private Keys or Passwords", "falco-search-credentials"),
])
def test_top_falco_rules_match_by_rule_name(falco_rule, rule_id):
    record = {"is_falco": 1, "message": "(user=root)",
              "raw_line": json.dumps({"rule": falco_rule, "output": "x", "priority": "Warning"})}
    assert KB.match_record(record).id == rule_id


def test_answer_fills_the_records_identifiers_or_drops_the_command():
    rule = KB.match("OOMKilled")
    answer = KB.answer(rule, {"namespace": "shop", "pod": "api-0", "container": "app"})
    assert answer["source"] == "signature" and answer["signature"]["id"] == "oom-killed"
    assert answer["steps"][0]["command"] == "kubectl -n shop describe pod api-0"
    assert all(step["is_supported"] for step in answer["steps"])
    falco = KB.answer(rule, {"namespace": "", "pod": "", "container": ""})
    assert all(step["command"] == "" and "needs the pod" in step["explanation"] for step in falco["steps"])


USER_RULE = {"id": "shop-stock", "match": {"message": "failed to reserve stock"}, "severity": "warning",
             "title": "Stock service unavailable", "explanation": "The stock service did not answer.",
             "steps": [{"title": "Check stock pods", "command": "kubectl -n {namespace} get pods",
                        "explanation": "Is stock running?", "risk": "read-only"}]}


def _config_with(tmp_path, rules) -> Path:
    raw = yaml.safe_load((ROOT / "test" / "fixtures" / "config.test.yaml").read_text())
    raw.setdefault("webapp", {}).setdefault("ai", {})["signatures"] = rules
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_user_rules_load_after_builtins_and_are_validated(tmp_path):
    cfg = load_app_config(_config_with(tmp_path, [USER_RULE]))
    rules = load_rules(cfg.ai.signatures)
    assert rules[-1].id == "shop-stock" and not rules[-1].builtin and len(rules) == len(RULES) + 1
    # Built-ins first: a user rule cannot shadow one for the same message.
    shadow = {**USER_RULE, "id": "my-oom", "match": {"message": "OOMKilled"}}
    assert SignatureKB(load_rules([shadow])).match("OOMKilled").id == "oom-killed"

    for bad, needle in (
        ({**USER_RULE, "match": {"message": "("}}, "invalid regular expression"),
        ({**USER_RULE, "steps": [{**USER_RULE["steps"][0], "command": "kubectl -n x delete pod y"}]}, "not a supported"),
        ({**USER_RULE, "steps": [{**USER_RULE["steps"][0], "command": "kubectl -n x rollout restart deployment/y"}]},
         "not read-only"),
        ({**USER_RULE, "steps": [{**USER_RULE["steps"][0], "command": "kubectl -n {ns} get pods"}]}, "placeholder"),
        ({**USER_RULE, "id": "oom-killed"}, "Duplicate"),
        ({**USER_RULE, "extra": 1}, "unknown key"),
    ):
        with pytest.raises(ValueError, match=needle):
            load_app_config(_config_with(tmp_path, [bad]))
    with pytest.raises(SignatureError):
        load_rules([{**USER_RULE, "match": {}}])


def test_signature_answers_before_any_provider_call(tmp_path, served, monkeypatch):
    calls = []

    def urlopen(req, timeout=0):
        calls.append(json.loads(req.data))
        from test_ai_settings import _Resp

        return _Resp({"choices": [{"message": {"content": json.dumps(ANSWER)}}]})

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", urlopen)
    app = _app(tmp_path, model="m")
    monkeypatch.setenv("LS_TEST_AI_KEY", ENV_KEY)
    app.storage.insert_records([{
        "severity_bucket": "error", "scope": "namespaces/shop", "namespace": "shop", "pod": "api-0",
        "container": "app", "raw_line": "r", "source_etag": "e", "is_falco": 0, "timestamp": "2026-09-07T00:00:00Z",
        "message": "Back-off restarting failed container app", "source_key": "k", "line_number": 1}])
    server = served(app)
    record_id = _ids(app)[0]
    status, payload = _request(server, "POST", "/api/explain-line", body=json.dumps({"id": record_id}), headers=JSON)
    assert status == 200 and payload["source"] == "signature" and payload["can_ask_ai"] is True
    assert payload["signature"]["id"] == "crashloop-backoff" and payload["steps"][0]["command"].endswith("api-0")
    assert calls == []
    status, payload = _request(server, "POST", "/api/explain?namespace=shop")
    assert payload["source"] == "signature" and calls == []
    # "Ask AI anyway"
    status, payload = _request(server, "POST", "/api/explain-line",
                               body=json.dumps({"id": record_id, "skip_signature": True}), headers=JSON)
    assert status == 200 and payload["source"] == "ai" and len(calls) == 1
    outcomes = [(r["feature"], r["outcome"], r["tokens_in"]) for r in _usage_rows(app)]
    assert outcomes[:2] == [("explain_line", "signature", 0), ("explain_filtered", "signature", 0)]
    assert outcomes[2][:2] == ("explain_line", "ok")
    usage = app.ai_meter.summary(1)["today"]["by_feature"]["explain_line"]
    assert usage["signature_hits"] == 1 and usage["signature_hit_pct"] == 50.0


def test_signatures_work_without_an_ai_provider(tmp_path, served):
    app = _app(tmp_path)  # no model, no key
    app.storage.insert_records([{
        "severity_bucket": "error", "scope": "namespaces/db", "namespace": "db", "pod": "pg-0", "container": "pg",
        "raw_line": "r", "source_etag": "e", "is_falco": 0, "timestamp": "2026-09-07T00:00:00Z",
        "message": "ERROR:  deadlock detected", "source_key": "k", "line_number": 1}])
    server = served(app)
    status, payload = _request(server, "POST", "/api/explain-line", body=json.dumps({"id": _ids(app)[0]}), headers=JSON)
    assert status == 200 and payload["source"] == "signature"
    status, payload = _request(server, "POST", "/api/explain-line",
                               body=json.dumps({"id": _ids(app)[0], "skip_signature": True}), headers=JSON)
    assert status == 400 and "not configured" in payload["error"]
