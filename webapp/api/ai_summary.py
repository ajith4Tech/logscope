"""AI summarization stage for Logscope Insights.

Only ever called for already-detected anomalies — never over raw logs. The
provider is config-driven (webapp.ai.provider); 'none' (the current default,
per project decision) performs no call and returns None. Adding a real
provider later means adding one branch here that builds `prompt_payload`
into a request — no detection-code changes needed.
"""
from __future__ import annotations

import os
from typing import Any

from .config import AiConfig


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


def summarize_anomaly(anomaly: dict[str, Any], cfg: AiConfig) -> dict[str, str] | None:
    if cfg.provider == "none":
        return None
    api_key = os.environ.get(cfg.api_key_env, "")
    if not api_key:
        # No credentials configured: treat as a soft skip so the detection
        # pipeline keeps working without the AI stage.
        return None
    payload = build_prompt_payload(anomaly)
    if cfg.provider == "openai":
        raise NotImplementedError("openai provider not enabled yet")
    if cfg.provider == "anthropic":
        raise NotImplementedError("anthropic provider not enabled yet")
    raise ValueError(f"unknown ai provider: {cfg.provider}")