"""AI summarization stage for Logscope Insights.

Only ever called for already-detected anomalies — never over raw logs. The
provider is config-driven (webapp.ai.provider); 'none' performs no call and
returns None. OpenRouter uses the anomaly evidence payload as the only prompt
input and returns a short operator summary plus one suggested action.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any
from urllib import error, request

from .config import AiConfig


logger = logging.getLogger(__name__)
_OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
_warned_once: set[str] = set()
_warned_once_lock = threading.Lock()

_EXPLAIN_LINE_SYSTEM_PROMPT = (
    "Explain this single Kubernetes log line for an operator, using ONLY the provided fields. "
    "Do NOT invent context, root causes, or related services not stated in the line itself. "
    "If the line alone doesn't clarify what happened or why, say so explicitly. "
    "Return a short plain-language explanation and exactly one suggested action. "
    "If JSON output is requested/supported, return {\"summary\": ..., \"suggested_action\": ...}. "
    "Otherwise return plain text with lines beginning Summary: and Action:."
)


def explain_log_line(record: dict[str, Any], cfg: AiConfig) -> dict[str, str] | None:
    """Summarize a single already-fetched log record (re-derived server-side
    by id, never client-supplied text) for the per-row 'Explain this line' UI."""
    provider = str(cfg.provider or "").strip().lower()
    if provider not in ("openrouter", "gemini"):
        return None
    api_key = os.environ.get(cfg.api_key_env, "")
    model = str(cfg.model or "").strip()
    if not model:
        _warn_once(f"{provider}_missing_model", f"AI summarization is configured for {provider} but no model is set; skipping.")
        return None
    if not api_key:
        _warn_once(f"{provider}_missing_key", f"AI summarization is configured for {provider} but {cfg.api_key_env} is not set; skipping.")
        return None

    payload = {
        "timestamp": record.get("timestamp"),
        "namespace": record.get("namespace"),
        "pod": record.get("pod"),
        "container": record.get("container"),
        "severity": record.get("severity_bucket"),
        "scope": record.get("scope"),
        "message": record.get("message"),
    }

    if provider == "openrouter":
        return _summarize_openrouter(payload, model, api_key, cfg.reasoning_effort, system_prompt=_EXPLAIN_LINE_SYSTEM_PROMPT)
    elif provider == "gemini":
        return _summarize_gemini(payload, model, api_key, system_prompt=_EXPLAIN_LINE_SYSTEM_PROMPT)
    return None


def _warn_once(key: str, message: str) -> None:
    with _warned_once_lock:
        if key in _warned_once:
            return
        _warned_once.add(key)
    logger.warning(message)


def _openrouter_models_index() -> dict[str, dict[str, Any]]:
    try:
        req = request.Request(
            _OPENROUTER_MODELS_URL,
            headers={"Accept": "application/json", "User-Agent": "logscope-webapp/1.0"},
        )
        with request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except Exception:
        return {}
    models = data.get("data") or []
    if not isinstance(models, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for item in models:
        if isinstance(item, dict) and item.get("id"):
            out[str(item["id"])] = item
    return out


def _supported_parameters(model: str) -> set[str]:
    item = _openrouter_models_index().get(model) or {}
    params = item.get("supported_parameters") or []
    return {str(param) for param in params}


def _parse_summary_response(content: str) -> dict[str, str]:
    text = str(content or "").strip()
    if not text:
        return {"summary": "", "suggested_action": ""}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        summary = str(parsed.get("summary") or parsed.get("answer") or "").strip()
        action = str(
            parsed.get("suggested_action")
            or parsed.get("action")
            or parsed.get("next_action")
            or ""
        ).strip()
        return {"summary": summary, "suggested_action": action}

    summary = text
    action = ""
    for line in text.splitlines():
        lower = line.lower().strip()
        if lower.startswith("summary:"):
            summary = line.split(":", 1)[1].strip()
        elif lower.startswith("action:") or lower.startswith("suggested action:"):
            action = line.split(":", 1)[1].strip()
    if not action:
        action = "Review the provided evidence for further detail."
    return {"summary": summary, "suggested_action": action}


def build_prompt_payload(anomaly: dict[str, Any]) -> dict[str, Any]:
    """Evidence/cluster data only — no raw unrelated log lines."""
    return {
        "type": anomaly.get("type"),
        "namespace": anomaly.get("namespace"),
        "pod": anomaly.get("pod"),
        "rule_key": anomaly.get("rule_key"),
        "severity": anomaly.get("severity"),
        "evidence": anomaly.get("evidence"),
    }


_SYSTEM_PROMPT = (
    "Summarize the anomaly evidence for an operator using ONLY the provided evidence and sample log messages. "
    "Do NOT invent or hallucinate root causes or services not stated in the log data. "
    "If the log messages do not clarify the root cause, explicitly state 'insufficient detail to determine root cause'. "
    "Return a short summary and exactly one suggested action. "
    "If JSON output is requested/supported, return {\"summary\": ..., \"suggested_action\": ...}. "
    "Otherwise return plain text with lines beginning Summary: and Action:."
)

_EXPLAIN_SYSTEM_PROMPT = (
    "Summarize this filtered set of Kubernetes logs for an operator, using ONLY the provided log_sample "
    "and filters/sample_size/total_matching_exceeds_sample metadata. "
    "Do NOT invent or hallucinate root causes, services, or patterns not evidenced in the sample. "
    "If the sample does not clarify a root cause, explicitly state 'insufficient detail to determine root cause'. "
    "Return a short summary and exactly one suggested action. "
    "If JSON output is requested/supported, return {\"summary\": ..., \"suggested_action\": ...}. "
    "Otherwise return plain text with lines beginning Summary: and Action:."
)


def _summarize_openrouter(
    payload: dict[str, Any],
    model: str,
    api_key: str,
    reasoning_effort: str,
    system_prompt: str = _SYSTEM_PROMPT,
) -> dict[str, str]:
    params = _supported_parameters(model)
    messages = [
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
        },
    ]
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": 160,
    }
    if reasoning_effort and "reasoning_effort" in params:
        body["reasoning_effort"] = reasoning_effort
    if "response_format" in params or "structured_outputs" in params:
        body["response_format"] = {"type": "json_object"}
    req = request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "logscope-webapp/1.0",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except error.HTTPError as exc:
        raise RuntimeError(f"OpenRouter summarization failed with HTTP {exc.code}") from None
    except error.URLError as exc:
        raise RuntimeError(f"OpenRouter summarization failed: {exc.reason}") from None
    except TimeoutError:
        raise RuntimeError("OpenRouter summarization timed out") from None
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("OpenRouter summarization returned no choices")
    message = choices[0].get("message") or {}
    content = message.get("content") or ""
    result = _parse_summary_response(str(content))
    if not result["summary"]:
        raise RuntimeError("OpenRouter summarization returned an empty summary")
    return result


def _summarize_gemini(
    payload: dict[str, Any],
    model: str,
    api_key: str,
    system_prompt: str = _SYSTEM_PROMPT,
) -> dict[str, str]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body: dict[str, Any] = {
        "systemInstruction": {
            "parts": [{"text": system_prompt}]
        },
        "contents": [
            {
                "parts": [
                    {"text": json.dumps(payload, separators=(",", ":"), ensure_ascii=False)}
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json"
        },
    }
    req = request.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "logscope-webapp/1.0",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except error.HTTPError as exc:
        raise RuntimeError(f"Gemini summarization failed with HTTP {exc.code}") from None
    except error.URLError as exc:
        raise RuntimeError(f"Gemini summarization failed: {exc.reason}") from None
    except TimeoutError:
        raise RuntimeError("Gemini summarization timed out") from None

    candidates = data.get("candidates") or []
    if not candidates:
        raise RuntimeError("Gemini summarization returned no candidates")
    candidate_content = candidates[0].get("content") or {}
    parts = candidate_content.get("parts") or []
    if not parts:
        raise RuntimeError("Gemini summarization returned no parts")
    text = parts[0].get("text") or ""
    result = _parse_summary_response(str(text))
    if not result["summary"]:
        raise RuntimeError("Gemini summarization returned an empty summary")
    return result


def summarize_anomaly(anomaly: dict[str, Any], cfg: AiConfig) -> dict[str, str] | None:
    provider = str(cfg.provider or "").strip().lower()
    if provider not in ("openrouter", "gemini"):
        return None

    api_key = os.environ.get(cfg.api_key_env, "")
    model = str(cfg.model or "").strip()
    if not model:
        _warn_once(
            f"{provider}_missing_model",
            f"AI summarization is configured for {provider} but no model is set; skipping anomaly summaries.",
        )
        return None
    if not api_key:
        _warn_once(
            f"{provider}_missing_key",
            f"AI summarization is configured for {provider} but {cfg.api_key_env} is not set; skipping anomaly summaries.",
        )
        return None

    payload = build_prompt_payload(anomaly)

    if provider == "openrouter":
        return _summarize_openrouter(payload, model, api_key, cfg.reasoning_effort)
    elif provider == "gemini":
        return _summarize_gemini(payload, model, api_key)
    return None


def explain_logs(payload: dict[str, Any], cfg: AiConfig) -> dict[str, str] | None:
    """Summarize a filtered-log-sample payload for POST /api/explain.

    Unlike summarize_anomaly, this does NOT run the payload through
    build_prompt_payload (which only reads anomaly-shaped fields like
    'type'/'evidence' and would silently null out an explain payload's
    'log_sample'/'filters'/'sample_size' fields). The payload here — built
    by WebApp.api_explain from a server-side re-derived log sample — is
    sent to the provider as-is, under a prompt tailored to log samples
    rather than anomaly evidence.

    Same non-negotiables as summarize_anomaly: config-driven provider,
    key read from env only, missing key/model -> single warning + None
    (never raises for that case), provider failures raise RuntimeError so
    the caller can surface a clean error without crashing.
    """
    provider = str(cfg.provider or "").strip().lower()
    if provider not in ("openrouter", "gemini"):
        return None

    api_key = os.environ.get(cfg.api_key_env, "")
    model = str(cfg.model or "").strip()
    if not model:
        _warn_once(
            f"{provider}_missing_model",
            f"AI summarization is configured for {provider} but no model is set; skipping.",
        )
        return None
    if not api_key:
        _warn_once(
            f"{provider}_missing_key",
            f"AI summarization is configured for {provider} but {cfg.api_key_env} is not set; skipping.",
        )
        return None

    if provider == "openrouter":
        return _summarize_openrouter(
            payload, model, api_key, cfg.reasoning_effort, system_prompt=_EXPLAIN_SYSTEM_PROMPT
        )
    elif provider == "gemini":
        return _summarize_gemini(payload, model, api_key, system_prompt=_EXPLAIN_SYSTEM_PROMPT)
    return None