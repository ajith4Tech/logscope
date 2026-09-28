"""AI summarization and troubleshooting guidance for Logscope.

AI is only called for:
- already-detected anomalies, or
- a server-side re-derived sample of currently filtered logs, or
- one server-side re-derived log record.

The provider is config-driven (webapp.ai.provider).
The API key is read only from the configured environment variable.

AI responses are structured as:
{
    "summary": "...",
    "steps": [
        {
            "title": "...",
            "command": "...",
            "explanation": "...",
            "risk": "read-only|medium|high"
        }
    ],
    "suggested_action": "..."
}

The legacy `suggested_action` field is retained temporarily for compatibility
with existing code/tests. The first troubleshooting step is used to populate it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import Any
from urllib import error, request

from .actions import parse_command_to_action
from .config import AiConfig


logger = logging.getLogger(__name__)

_OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

# Retry transient provider/network failures only.
_TRANSIENT_HTTP_STATUS_CODES = {
    408,  # Request Timeout
    425,  # Too Early
    429,  # Too Many Requests
    500,  # Internal Server Error
    502,  # Bad Gateway
    503,  # Service Unavailable
    504,  # Gateway Timeout
}
_MAX_AI_ATTEMPTS = 4
_RETRY_BASE_SECONDS = 1.0
_MAX_RETRY_SECONDS = 8.0
_PROVIDER_TIMEOUT_SECONDS = 30

_warned_once: set[str] = set()
_warned_once_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Prompts
# ─────────────────────────────────────────────────────────────────────────────

_EXPLAIN_LINE_SYSTEM_PROMPT = (
    "You are a Kubernetes observability assistant for Logscope. "
    "Explain this single Kubernetes log record for an operator using ONLY the provided fields. "
    "First explain what the record explicitly shows: timestamp, severity, namespace, pod, "
    "container, scope, and important message details when present. "
    "Do not infer root causes, user intent, attacks, dependencies, or related services "
    "unless explicitly stated in the record. "
    "If the line alone cannot establish why the event happened, say so clearly. "
    "Then provide 2 to 3 ordered troubleshooting steps when the available fields support them. "
    "Each step must contain: title, command, explanation, and risk. "
    "The command must be a read-only diagnostic command and the explanation must say in one short line "
    "what the command checks and why that check is useful. "
    "Set risk to 'read-only' for diagnostic checks, or 'medium'/'high' if mutating. "
    "Prefer read-only diagnostic commands first. "
    "Only use namespace, pod, container, node, file path, process name, or other identifiers "
    "that are explicitly present in the provided record. "
    "Never invent identifiers or replace missing identifiers with fake placeholders such as "
    "<pod-name>, <namespace>, or <node>. "
    "Prefer safe diagnostic commands such as kubectl get, kubectl describe, kubectl logs, "
    "kubectl events. "
    "Do not suggest delete, restart, scale, patch, exec, configuration changes, permission changes, "
    "security-rule changes, allowlist changes, or disabling alerts from a single log record. "
    "Separate unrelated problems instead of forcing one root cause. "
    "State clearly when evidence is insufficient. "
    "If the record does not contain enough information to construct a safe command, "
    "leave command empty and use the explanation to state the exact additional evidence "
    "that should be collected. "
    "Return valid JSON only with this structure: "
    "{\"summary\":\"...\",\"steps\":["
    "{\"title\":\"...\",\"command\":\"...\",\"explanation\":\"...\",\"risk\":\"read-only|medium|high\"}"
    "]}"
)


_SYSTEM_PROMPT = (
    "You are a Kubernetes observability assistant for Logscope. "
    "Summarize the detected anomaly for an operator using ONLY the provided evidence "
    "and sample log messages. "
    "Do not invent root causes, services, infrastructure state, intent, dependencies, "
    "or facts not present in the evidence. "
    "Clearly distinguish what the logs show from what cannot yet be determined. "
    "The summary should state what happened, where it happened, the important evidence, "
    "and whether the available evidence is sufficient to establish a likely cause. "
    "If the evidence contains multiple unrelated event groups, explicitly separate them "
    "instead of forcing them into one explanation. "
    "Do not describe a security event as malicious unless the evidence explicitly establishes "
    "malicious activity. "
    "Then provide 2 to 5 ordered troubleshooting steps. "
    "Each step must contain: title, command, explanation, and risk. "
    "The command must be a read-only diagnostic command whenever the evidence provides "
    "the identifiers required to construct one. "
    "The explanation must state in one short line what that command checks and why that check helps. "
    "Set risk to 'read-only' for diagnostic checks, or 'medium'/'high' if mutating. "
    "Prefer read-only diagnostic commands first. "
    "Use only namespace names, pod names, container names, node names, rule names, process names, "
    "file paths, and other identifiers explicitly present in the evidence. "
    "Do not invent identifiers or use fake placeholders. "
    "Prefer commands such as kubectl get, kubectl describe, kubectl logs, kubectl events. "
    "The steps should progress from context gathering to evidence verification and correlation. "
    "Do not suggest commands that delete, restart, scale, patch, exec into, modify, disable, "
    "or otherwise change cluster state as the first response. "
    "Do not recommend changing Falco exceptions, allowlists, permissions, or production "
    "configuration as the first response. "
    "First inspect and verify the observed behavior. "
    "If a command cannot be safely constructed from the supplied evidence, leave command empty "
    "and explain exactly what additional evidence or identifier must be obtained. "
    "Do not invent commands simply to complete the list. "
    "Each step must add new diagnostic information; do not repeat the same command with minor changes. "
    "Avoid generic advice without specifying exactly what should be checked. "
    "Return valid JSON only with this structure: "
    "{\"summary\":\"...\",\"steps\":["
    "{\"title\":\"...\",\"command\":\"...\",\"explanation\":\"...\",\"risk\":\"read-only|medium|high\"}"
    "]}"
)


_EXPLAIN_SYSTEM_PROMPT = (
    "You are a Kubernetes observability assistant for Logscope. "
    "Summarize the currently filtered Kubernetes logs for an operator using ONLY the provided "
    "log_sample, filters, sample_size, and total_matching_exceeds_sample metadata. "
    "Do not invent root causes, services, dependencies, infrastructure state, intent, "
    "or patterns that are not evidenced in the sample. "
    "Identify the dominant or most important observed behavior, including severity, affected "
    "namespace/pod/container when supported, and notable repeated errors, warnings, failures, "
    "or security events. "
    "If the sample contains multiple unrelated event groups, clearly separate them. "
    "Do not force unrelated logs into a single incident or cause. "
    "Clearly state when the available sample is insufficient to determine a root cause. "
    "Then provide 2 to 5 ordered troubleshooting steps for the most important observed issue(s). "
    "Each step must contain: title, command, explanation, and risk. "
    "The command must be read-only whenever the provided evidence contains the identifiers "
    "required to build it. "
    "The explanation must say in one short line what the command checks and why that check is useful. "
    "Set risk to 'read-only' for diagnostic checks, or 'medium'/'high' if mutating. "
    "Prefer read-only diagnostic commands first. "
    "Use only identifiers explicitly present in the supplied filters and log sample. "
    "Do not invent namespace names, pod names, container names, node names, process names, "
    "rule names, deployment names, file paths, or other identifiers. "
    "Never use fake placeholders. "
    "Prefer diagnostic commands such as kubectl get, kubectl describe, kubectl logs, kubectl events. "
    "Order the steps logically: establish affected resource, inspect current state, "
    "inspect related logs/events, then correlate evidence. "
    "Do not suggest destructive or state-changing commands such as delete, restart, scale, patch, "
    "or rollout changes. "
    "Do not recommend weakening security rules, changing allowlists/exceptions, changing permissions, "
    "or modifying production configuration as the first response. "
    "If the sample does not provide enough information for a safe specific command, leave the command "
    "empty and state the exact evidence that should be collected next. "
    "Avoid generic advice without a concrete diagnostic target. "
    "Return valid JSON only with this structure: "
    "{\"summary\":\"...\",\"steps\":["
    "{\"title\":\"...\",\"command\":\"...\",\"explanation\":\"...\",\"risk\":\"read-only|medium|high\"}"
    "]}"
)


# ─────────────────────────────────────────────────────────────────────────────
# Public helpers
# ─────────────────────────────────────────────────────────────────────────────

def explain_log_line(
    record: dict[str, Any],
    cfg: AiConfig,
) -> dict[str, Any] | None:
    """Explain one already-fetched log record.

    The record is re-derived server-side by id before reaching this function.
    """

    provider = str(cfg.provider or "").strip().lower()
    if provider not in ("openrouter", "gemini"):
        return None

    api_key = os.environ.get(cfg.api_key_env, "")
    model = str(cfg.model or "").strip()

    if not model:
        _warn_once(
            f"{provider}_missing_model",
            f"AI summarization is configured for {provider} "
            "but no model is set; skipping.",
        )
        return None

    if not api_key:
        _warn_once(
            f"{provider}_missing_key",
            f"AI summarization is configured for {provider} "
            f"but {cfg.api_key_env} is not set; skipping.",
        )
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
        return _summarize_openrouter(
            payload,
            model,
            api_key,
            cfg.reasoning_effort,
            system_prompt=_EXPLAIN_LINE_SYSTEM_PROMPT,
        )

    if provider == "gemini":
        return _summarize_gemini(
            payload,
            model,
            api_key,
            system_prompt=_EXPLAIN_LINE_SYSTEM_PROMPT,
        )

    return None


def summarize_anomaly(
    anomaly: dict[str, Any],
    cfg: AiConfig,
) -> dict[str, Any] | None:
    """Summarize an already-detected anomaly and generate troubleshooting steps."""

    provider = str(cfg.provider or "").strip().lower()
    if provider not in ("openrouter", "gemini"):
        return None

    api_key = os.environ.get(cfg.api_key_env, "")
    model = str(cfg.model or "").strip()

    if not model:
        _warn_once(
            f"{provider}_missing_model",
            f"AI summarization is configured for {provider} "
            "but no model is set; skipping anomaly summaries.",
        )
        return None

    if not api_key:
        _warn_once(
            f"{provider}_missing_key",
            f"AI summarization is configured for {provider} "
            f"but {cfg.api_key_env} is not set; skipping anomaly summaries.",
        )
        return None

    payload = build_prompt_payload(anomaly)

    if provider == "openrouter":
        return _summarize_openrouter(
            payload,
            model,
            api_key,
            cfg.reasoning_effort,
            system_prompt=_SYSTEM_PROMPT,
        )

    if provider == "gemini":
        return _summarize_gemini(
            payload,
            model,
            api_key,
            system_prompt=_SYSTEM_PROMPT,
        )

    return None


def explain_logs(
    payload: dict[str, Any],
    cfg: AiConfig,
) -> dict[str, Any] | None:
    """Summarize a filtered-log-sample payload for POST /api/explain.

    The payload is already built server-side from the filtered records.
    It is deliberately not passed through build_prompt_payload(), because
    that helper is shaped for anomaly evidence rather than filtered logs.
    """

    provider = str(cfg.provider or "").strip().lower()
    if provider not in ("openrouter", "gemini"):
        return None

    api_key = os.environ.get(cfg.api_key_env, "")
    model = str(cfg.model or "").strip()

    if not model:
        _warn_once(
            f"{provider}_missing_model",
            f"AI summarization is configured for {provider} "
            "but no model is set; skipping.",
        )
        return None

    if not api_key:
        _warn_once(
            f"{provider}_missing_key",
            f"AI summarization is configured for {provider} "
            f"but {cfg.api_key_env} is not set; skipping.",
        )
        return None

    if provider == "openrouter":
        return _summarize_openrouter(
            payload,
            model,
            api_key,
            cfg.reasoning_effort,
            system_prompt=_EXPLAIN_SYSTEM_PROMPT,
        )

    if provider == "gemini":
        return _summarize_gemini(
            payload,
            model,
            api_key,
            system_prompt=_EXPLAIN_SYSTEM_PROMPT,
        )

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Configuration / payload helpers
# ─────────────────────────────────────────────────────────────────────────────

def _warn_once(key: str, message: str) -> None:
    with _warned_once_lock:
        if key in _warned_once:
            return
        _warned_once.add(key)

    logger.warning(message)


def build_prompt_payload(anomaly: dict[str, Any]) -> dict[str, Any]:
    """Build evidence-only input for anomaly summarization."""

    return {
        "type": anomaly.get("type"),
        "namespace": anomaly.get("namespace"),
        "pod": anomaly.get("pod"),
        "rule_key": anomaly.get("rule_key"),
        "severity": anomaly.get("severity"),
        "evidence": anomaly.get("evidence"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Response parsing
# ─────────────────────────────────────────────────────────────────────────────

def _strip_json_fence(content: str) -> str:
    text = str(content or "").strip()

    # If code fence present anywhere, try to extract inside of it
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            return match.group(1).strip()

    return text


def _format_step_action(step: dict[str, Any]) -> str:
    command = str(step.get("command") or "").strip()
    explanation = str(step.get("explanation") or "").strip()

    if command and explanation:
        return f"{command} — {explanation}"

    if command:
        return command

    return explanation


def _infer_risk(command: str, raw_risk: str | None) -> str:
    risk_clean = str(raw_risk or "").strip().lower()
    if risk_clean in ("read-only", "readonly", "low", "safe"):
        return "read-only"
    if risk_clean in ("medium", "modifying", "mutating"):
        return "medium"
    if risk_clean in ("high", "dangerous", "destructive"):
        return "high"

    cmd_lower = command.lower()
    if any(k in cmd_lower for k in ("delete", "drain", "cordon", "purge", "rm ")):
        return "high"
    if any(k in cmd_lower for k in ("restart", "undo", "scale", "patch", "apply", "set ", "rollout")):
        return "medium"

    return "read-only"


def _normalise_steps(value: Any, max_steps: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    steps: list[dict[str, Any]] = []

    for index, raw_step in enumerate(value[:max_steps], start=1):
        if isinstance(raw_step, dict):
            title = str(
                raw_step.get("title")
                or raw_step.get("name")
                or f"Step {index}"
            ).strip()

            command = str(
                raw_step.get("command")
                or raw_step.get("cmd")
                or ""
            ).strip()

            explanation = str(
                raw_step.get("explanation")
                or raw_step.get("what_it_checks")
                or raw_step.get("description")
                or ""
            ).strip()

            raw_risk = raw_step.get("risk")

        elif isinstance(raw_step, str):
            title = f"Step {index}"
            command = ""
            explanation = raw_step.strip()
            raw_risk = "read-only"

        else:
            continue

        if not title:
            title = f"Step {index}"

        if not command and not explanation:
            continue

        risk = _infer_risk(command, raw_risk)
        parsed_action = parse_command_to_action(command) if command else None

        steps.append(
            {
                "title": title,
                "command": command,
                "explanation": explanation,
                "risk": risk,
                "action": parsed_action,
                "is_supported": parsed_action is not None,
            }
        )

    return steps


def _parse_summary_response(content: str) -> dict[str, Any]:
    """Parse structured AI output with backwards-compatible fallback."""

    text = _strip_json_fence(content)

    if not text:
        return {
            "summary": "",
            "steps": [],
            "suggested_action": "",
        }

    parsed: Any = None

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # If text has leading/trailing characters around JSON, try substring
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            try:
                parsed = json.loads(text[first_brace : last_brace + 1])
            except json.JSONDecodeError:
                parsed = None

    if isinstance(parsed, dict):
        summary = str(
            parsed.get("summary")
            or parsed.get("answer")
            or ""
        ).strip()

        steps = _normalise_steps(
            parsed.get("steps")
            or parsed.get("troubleshooting_steps")
            or parsed.get("debug_steps")
            or parsed.get("actions"),
            max_steps=5,
        )

        legacy_action = str(
            parsed.get("suggested_action")
            or parsed.get("action")
            or parsed.get("next_action")
            or ""
        ).strip()

        if not steps and legacy_action:
            steps = [
                {
                    "title": "Suggested next step",
                    "command": "",
                    "explanation": legacy_action,
                    "risk": "read-only",
                    "action": None,
                    "is_supported": False,
                }
            ]

        suggested_action = legacy_action

        if not suggested_action and steps:
            suggested_action = _format_step_action(steps[0])

        return {
            "summary": summary,
            "steps": steps,
            "suggested_action": suggested_action,
        }

    # Plain-text compatibility fallback.
    summary = text
    suggested_action = ""
    parsed_steps: list[dict[str, Any]] = []

    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()

        if lower.startswith("summary:"):
            summary = stripped.split(":", 1)[1].strip()
            continue

        if lower.startswith("action:") or lower.startswith("suggested action:"):
            suggested_action = stripped.split(":", 1)[1].strip()
            continue

        # Basic support for numbered steps:
        # 1. COMMAND — explanation
        # 2. COMMAND - explanation
        if len(stripped) >= 3 and stripped[0].isdigit() and stripped[1:3] in {". ", ") "}:
            step_text = stripped[3:].strip()
            cmd = ""
            exp = step_text

            if " — " in step_text:
                cmd, exp = step_text.split(" — ", 1)
            elif " - " in step_text:
                cmd, exp = step_text.split(" - ", 1)

            parsed_steps.append(
                {
                    "title": f"Step {len(parsed_steps) + 1}",
                    "command": cmd.strip(),
                    "explanation": exp.strip(),
                    "risk": _infer_risk(cmd.strip(), None),
                    "action": parse_command_to_action(cmd.strip()) if cmd.strip() else None,
                    "is_supported": parse_command_to_action(cmd.strip()) is not None if cmd.strip() else False,
                }
            )

    steps = parsed_steps[:5]

    if not suggested_action and steps:
        suggested_action = _format_step_action(steps[0])

    if not suggested_action and not steps:
        suggested_action = (
            "No structured troubleshooting step was returned; inspect the supplied evidence."
        )

    return {
        "summary": summary,
        "steps": steps,
        "suggested_action": suggested_action,
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP / retry helpers
# ─────────────────────────────────────────────────────────────────────────────

def _retry_delay(exc: error.HTTPError, attempt: int) -> float:
    retry_after = ""

    try:
        retry_after = str(exc.headers.get("Retry-After") or "").strip()
    except Exception:
        retry_after = ""

    if retry_after:
        try:
            return min(float(retry_after), _MAX_RETRY_SECONDS)
        except ValueError:
            pass

    delay = _RETRY_BASE_SECONDS * (2 ** (attempt - 1))
    return min(delay, _MAX_RETRY_SECONDS)


def _clean_error_message(raw_text: str, *keys: str) -> str:
    text = str(raw_text or "").strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and "error" in parsed:
                err = parsed["error"]
                if isinstance(err, dict):
                    msg = err.get("message") or err.get("status") or ""
                    status = err.get("status") or ""
                    if msg:
                        text = f"{msg} ({status})" if status and status not in msg else msg
                elif isinstance(err, str):
                    text = err
        except Exception:
            pass

    for k in keys:
        if k and len(k) >= 4 and k in text:
            text = text.replace(k, "***REDACTED***")

    text = re.sub(r"key=[A-Za-z0-9_\-]+", "key=***REDACTED***", text)
    text = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer ***REDACTED***", text)

    if len(text) > 400:
        text = f"{text[:400]}..."

    return text


def _read_http_error_body(exc: error.HTTPError) -> str:
    try:
        raw = exc.read()
    except Exception:
        return ""

    if not raw:
        return ""

    try:
        body = raw.decode("utf-8", errors="replace")
    except Exception:
        body = str(raw)

    return body.strip()


def _post_json(
    *,
    provider: str,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    api_key_to_redact: str = "",
) -> dict[str, Any]:
    """POST JSON with bounded retries for transient failures (429, 5xx, network, timeouts).

    Permanent errors (400, 401, 403, 404) are NOT retried.
    API keys are strictly redacted from logs and error messages.
    """

    encoded_body = json.dumps(
        body,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    for attempt in range(1, _MAX_AI_ATTEMPTS + 1):
        req = request.Request(
            url,
            data=encoded_body,
            headers=headers,
            method="POST",
        )

        try:
            with request.urlopen(
                req,
                timeout=_PROVIDER_TIMEOUT_SECONDS,
            ) as resp:
                data = json.load(resp)

            if not isinstance(data, dict):
                raise RuntimeError(
                    f"{provider} summarization returned an invalid response"
                )

            return data

        except error.HTTPError as exc:
            code = int(exc.code)
            body_text = _read_http_error_body(exc)
            clean_detail = _clean_error_message(body_text, api_key_to_redact)

            if (
                code in _TRANSIENT_HTTP_STATUS_CODES
                and attempt < _MAX_AI_ATTEMPTS
            ):
                delay = _retry_delay(exc, attempt)

                logger.warning(
                    "%s summarization returned transient HTTP %s (%s); "
                    "retrying in %.1fs (attempt %s/%s)",
                    provider,
                    code,
                    clean_detail,
                    delay,
                    attempt,
                    _MAX_AI_ATTEMPTS,
                )

                time.sleep(delay)
                continue

            # Non-transient or attempts exhausted: clean error, no key exposure
            detail = f": {clean_detail}" if clean_detail else ""
            raise RuntimeError(
                f"{provider} summarization failed with HTTP {code}{detail}"
            ) from None

        except (error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", str(exc))
            clean_reason = _clean_error_message(str(reason), api_key_to_redact)

            if attempt < _MAX_AI_ATTEMPTS:
                delay = min(
                    _RETRY_BASE_SECONDS * (2 ** (attempt - 1)),
                    _MAX_RETRY_SECONDS,
                )

                logger.warning(
                    "%s summarization network error/timeout (%s); "
                    "retrying in %.1fs (attempt %s/%s)",
                    provider,
                    clean_reason,
                    delay,
                    attempt,
                    _MAX_AI_ATTEMPTS,
                )

                time.sleep(delay)
                continue

            raise RuntimeError(
                f"{provider} summarization network error: {clean_reason}"
            ) from None

    raise RuntimeError(f"{provider} summarization failed after {_MAX_AI_ATTEMPTS} attempts")


# ─────────────────────────────────────────────────────────────────────────────
# OpenRouter
# ─────────────────────────────────────────────────────────────────────────────

def _openrouter_models_index() -> dict[str, dict[str, Any]]:
    try:
        req = request.Request(
            _OPENROUTER_MODELS_URL,
            headers={
                "Accept": "application/json",
                "User-Agent": "logscope-webapp/1.0",
            },
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

    return {
        str(param)
        for param in params
    }


def _summarize_openrouter(
    payload: dict[str, Any],
    model: str,
    api_key: str,
    reasoning_effort: str,
    system_prompt: str = _SYSTEM_PROMPT,
) -> dict[str, Any]:
    params = _supported_parameters(model)

    messages = [
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": json.dumps(
                payload,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        },
    ]

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": 2048,
        "temperature": 0.2,
    }

    if reasoning_effort and "reasoning_effort" in params:
        body["reasoning_effort"] = reasoning_effort

    if "response_format" in params or "structured_outputs" in params:
        body["response_format"] = {
            "type": "json_object",
        }

    data = _post_json(
        provider="OpenRouter",
        url="https://openrouter.ai/api/v1/chat/completions",
        body=body,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "logscope-webapp/1.0",
        },
        api_key_to_redact=api_key,
    )

    choices = data.get("choices") or []

    if not choices:
        raise RuntimeError(
            "OpenRouter summarization returned no choices"
        )

    message = choices[0].get("message") or {}

    content = message.get("content") or ""

    result = _parse_summary_response(str(content))

    if not result["summary"]:
        raise RuntimeError(
            "OpenRouter summarization returned an empty summary"
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Gemini
# ─────────────────────────────────────────────────────────────────────────────

def _summarize_gemini(
    payload: dict[str, Any],
    model: str,
    api_key: str,
    system_prompt: str = _SYSTEM_PROMPT,
) -> dict[str, Any]:
    url = (
        "https://generativelanguage.googleapis.com/"
        f"v1beta/models/{model}:generateContent"
    )

    body: dict[str, Any] = {
        "systemInstruction": {
            "parts": [
                {
                    "text": system_prompt,
                }
            ],
        },
        "contents": [
            {
                "parts": [
                    {
                        "text": json.dumps(
                            payload,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "maxOutputTokens": 2048,
            "temperature": 0.2,
        },
    }

    data = _post_json(
        provider="Gemini",
        url=url,
        body=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "logscope-webapp/1.0",
            "x-goog-api-key": api_key,
        },
        api_key_to_redact=api_key,
    )

    candidates = data.get("candidates") or []

    if not candidates:
        raise RuntimeError(
            "Gemini summarization returned no candidates"
        )

    candidate_content = candidates[0].get("content") or {}

    parts = candidate_content.get("parts") or []

    if not parts:
        raise RuntimeError(
            "Gemini summarization returned no parts"
        )

    text = parts[0].get("text") or ""

    result = _parse_summary_response(str(text))

    if not result["summary"]:
        raise RuntimeError(
            "Gemini summarization returned an empty summary"
        )

    return result