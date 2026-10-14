"""OpenAI / Anthropic provider wiring, base_url overrides and key-env defaults."""

from __future__ import annotations

import json
import sys
import tempfile
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api import ai_summary  # noqa: E402
from webapp.api.ai_summary import explain_log_line  # noqa: E402
from webapp.api.config import AiConfig, load_app_config  # noqa: E402

RECORD = {"timestamp": "2026-09-07T00:00:00Z", "namespace": "app", "pod": "web-0",
          "container": "nginx", "severity_bucket": "error", "scope": "namespaces/app",
          "message": "upstream timed out"}
ANSWER = {"summary": "Upstream timeout in app/web-0.",
          "steps": [{"title": "Check pod", "command": "kubectl -n app get pod web-0",
                     "explanation": "Confirms pod state.", "risk": "read-only"}]}


def _cfg(provider, model, *, base_url="", effort="medium", key_env="AI_KEY"):
    return AiConfig(provider=provider, model=model, api_key_env=key_env,
                    max_anomalies_per_tick=5, reasoning_effort=effort, base_url=base_url)


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def test_openai_request_shape_and_base_url(monkeypatch):
    monkeypatch.setenv("AI_KEY", "sk-test-openai")
    captured = {}

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        captured["body"] = json.loads(req.data)
        return _Resp({"choices": [{"message": {"content": json.dumps(ANSWER)}}]})

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", fake_urlopen)
    result = explain_log_line(RECORD, _cfg("openai", "gpt-test", base_url="https://gw.example.internal/v1/"))

    assert result["summary"] == ANSWER["summary"]
    assert captured["url"] == "https://gw.example.internal/v1/chat/completions"
    assert captured["headers"]["authorization"] == "Bearer sk-test-openai"
    body = captured["body"]
    assert body["model"] == "gpt-test"
    assert body["response_format"] == {"type": "json_object"}
    assert "temperature" not in body and "reasoning_effort" not in body
    assert body["messages"][0]["role"] == "system"


def test_openai_default_endpoint(monkeypatch):
    monkeypatch.setenv("AI_KEY", "k")
    urls = []
    monkeypatch.setattr(
        "webapp.api.ai_summary.request.urlopen",
        lambda req, timeout=0: urls.append(req.full_url) or _Resp(
            {"choices": [{"message": {"content": json.dumps(ANSWER)}}]}),
    )
    explain_log_line(RECORD, _cfg("openai", "gpt-test"))
    assert urls == ["https://api.openai.com/v1/chat/completions"]


def test_gemini_base_url_override(monkeypatch):
    monkeypatch.setenv("AI_KEY", "k")
    urls = []
    monkeypatch.setattr(
        "webapp.api.ai_summary.request.urlopen",
        lambda req, timeout=0: urls.append(req.full_url) or _Resp(
            {"candidates": [{"content": {"parts": [{"text": json.dumps(ANSWER)}]}}]}),
    )
    explain_log_line(RECORD, _cfg("gemini", "gemini-test", base_url="https://proxy.example.internal"))
    assert urls == ["https://proxy.example.internal/v1beta/models/gemini-test:generateContent"]


class _FakeAnthropicModule(types.ModuleType):
    """Stands in for the anthropic SDK: records constructor and create() kwargs.
    `response` may be a callable(module) so errors use this module's classes."""

    def __init__(self, response):
        super().__init__("anthropic")
        self.calls = []
        module = self

        class APIStatusError(Exception):
            def __init__(self, message, status_code):
                super().__init__(message)
                self.message = message
                self.status_code = status_code

        class APIConnectionError(Exception):
            pass

        class _Messages:
            def __init__(self, kind):
                self.kind = kind

            def create(self, **kwargs):
                module.calls.append((self.kind, kwargs))
                result = response(module) if callable(response) else response
                if isinstance(result, Exception):
                    raise result
                return result

        class Anthropic:
            def __init__(self, **kwargs):
                module.client_kwargs = kwargs
                self.messages = _Messages("messages")
                self.beta = types.SimpleNamespace(messages=_Messages("beta"))

        self.APIStatusError = APIStatusError
        self.APIConnectionError = APIConnectionError
        self.Anthropic = Anthropic


def _claude_response(text, stop_reason="end_turn"):
    return types.SimpleNamespace(
        stop_reason=stop_reason,
        content=[types.SimpleNamespace(type="thinking", thinking=""),
                 types.SimpleNamespace(type="text", text=text)],
    )


def _install(monkeypatch, response):
    fake = _FakeAnthropicModule(response)
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setenv("AI_KEY", "sk-ant-test")
    return fake


def test_anthropic_current_model_uses_default_fallbacks_and_effort(monkeypatch):
    fake = _install(monkeypatch, _claude_response(json.dumps(ANSWER)))
    result = explain_log_line(RECORD, _cfg("anthropic", "claude-opus-5-5"))

    assert result["summary"] == ANSWER["summary"]
    kind, kwargs = fake.calls[0]
    assert kind == "beta"
    assert kwargs["fallbacks"] == "default"
    assert kwargs["betas"] == ["server-side-fallback-2026-07-01"]
    assert kwargs["model"] == "claude-opus-5-5"
    assert kwargs["output_config"] == {"effort": "medium"}
    assert kwargs["system"] and kwargs["messages"][0]["role"] == "user"
    for rejected in ("temperature", "top_p", "top_k", "thinking"):
        assert rejected not in kwargs
    assert fake.client_kwargs["api_key"] == "sk-ant-test"
    assert fake.client_kwargs["base_url"] is None
    # Bounded: one retry, 90 s per attempt.
    assert fake.client_kwargs["timeout"] == 90 and fake.client_kwargs["max_retries"] == 1


def test_anthropic_custom_endpoint_and_older_model_skip_fallbacks(monkeypatch):
    fake = _install(monkeypatch, _claude_response(json.dumps(ANSWER)))
    explain_log_line(RECORD, _cfg("anthropic", "claude-opus-5-5", base_url="https://llm-gw.example.internal"))
    explain_log_line(RECORD, _cfg("anthropic", "claude-haiku-5-5", effort=""))

    (k1, kw1), (k2, kw2) = fake.calls
    assert k1 == "messages" and "fallbacks" not in kw1
    assert k2 == "messages" and "output_config" not in kw2


def test_anthropic_refusal_and_errors_are_clean(monkeypatch):
    _install(monkeypatch, _claude_response("", stop_reason="refusal"))
    with pytest.raises(RuntimeError, match="declined"):
        explain_log_line(RECORD, _cfg("anthropic", "claude-opus-5-5"))

    _install(monkeypatch, lambda m: m.APIStatusError("invalid x-api-key sk-ant-test", 401))
    with pytest.raises(RuntimeError) as exc:
        explain_log_line(RECORD, _cfg("anthropic", "claude-opus-5-5"))
    assert "sk-ant-test" not in str(exc.value)


@pytest.mark.parametrize("provider,env", [
    ("anthropic", "ANTHROPIC_API_KEY"), ("openai", "OPENAI_API_KEY"),
    ("gemini", "GEMINI_API_KEY"), ("openrouter", "OPENROUTER_API_KEY"),
])
def test_default_key_env_per_provider(provider, env):
    base = (ROOT / "test" / "fixtures" / "config.test.yaml").read_text()
    base = base.replace("provider: openrouter", f"provider: {provider}", 1)
    base = "\n".join(line for line in base.splitlines() if "api_key_env:" not in line)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "config.yaml"
        p.write_text(base)
        cfg = load_app_config(p)
    assert cfg.ai.provider == provider
    assert cfg.ai.api_key_env == env
    assert provider in ai_summary.SUPPORTED_PROVIDERS


def test_openai_empty_answer_at_token_limit_is_explicit(monkeypatch):
    monkeypatch.setenv("AI_KEY", "k")
    monkeypatch.setattr(
        "webapp.api.ai_summary.request.urlopen",
        lambda req, timeout=0: _Resp({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}),
    )
    with pytest.raises(RuntimeError, match="max_completion_tokens"):
        explain_log_line(RECORD, _cfg("openai", "reasoning-model"))


def test_openrouter_model_index_is_cached(monkeypatch):
    ai_summary._openrouter_index_cache.clear()
    fetched = []

    def fake_urlopen(req, timeout=0):
        fetched.append(req.full_url)
        return _Resp({"data": [{"id": "vendor/m", "supported_parameters": ["response_format"]}]})

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", fake_urlopen)
    for _ in range(3):
        assert ai_summary._supported_parameters("vendor/m", "https://openrouter.example/api/v1") == {"response_format"}
    assert fetched == ["https://openrouter.example/api/v1/models"]
    ai_summary._openrouter_index_cache.clear()

