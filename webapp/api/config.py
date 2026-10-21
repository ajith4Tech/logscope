from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .state import STATE_DB_ENV, default_state_db_path


DEFAULT_BACKEND = {
    "poll_interval_secs": 30,
    "db_path": "/tmp/logscope-webapp.sqlite",
    # Durable state (saved views) in its own file; never in /tmp. None =
    # $XDG_DATA_HOME/logscope/state.sqlite (~/.local/share/logscope/...).
    "state_db_path": None,
    "page_size_default": 200,
    "page_size_max": 1000,
    # Re-list this much key time behind each prefix cursor to catch objects that
    # Vector flushes after a later-named object (see ingest.lookback_start_after).
    "s3_lookback_secs": 3600,
    # Records older than this are pruned from the local cache. None = follow
    # sinks.s3.retention_days (the source objects expire then anyway); 0 = keep forever.
    "retention_days": None,
}

DEFAULT_INSIGHTS = {
    "enabled": True,
    "detect_interval_secs": 300,
    "baseline_window_days": 7,
    "spike_multiplier": 3.0,
    "spike_min_count": 10,
    "shift_share_delta": 0.25,
    "shift_min_count": 20,
    "frequency_multiplier": 5.0,
    "frequency_min_count": 30,
    "detect_per_pod": False,
    "sample_timestamps_max": 10,
    "min_baseline_hours": 24,
    "min_partial_window_minutes": 15,
}

DEFAULT_AI = {
    "provider": "openrouter",
    "model": "",
    "api_key_env": "OPENROUTER_API_KEY",
    "max_anomalies_per_tick": 5,
    "reasoning_effort": "medium",
    "base_url": "",
    "deep_model": "",
    "prices": {},
    "features": {},
    "budgets": {},
    # AI answers are cached per log template for this long (0 = no cache).
    "cache_ttl_hours": 168,
    # With anomaly_auto_summary on, only anomalies at or above this urgency
    # (see notify.anomaly_urgency) are summarized automatically.
    "auto_summary_min_urgency": "urgent",
    # Extra signature rules (same format as webapp/api/signatures.yaml),
    # tried after the built-in ones.
    "signatures": [],
}

# Conventional key variable per provider when webapp.ai.api_key_env is not set.
_DEFAULT_KEY_ENV = {
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

DEFAULT_MATTERMOST = {
    "enabled": False,
    # The webhook URL is a credential: read from this env var only, never
    # from config files, and never logged or returned by the API.
    "webhook_url_env": "MATTERMOST_WEBHOOK_URL",
    "min_urgency": "high",
    # Public URL of the Logscope UI (e.g. https://logscope.example.com), used
    # for "open investigation" links in messages. Empty = no links.
    "link_base_url": "",
    # A recurrence of the same anomaly (type, namespace, pod, rule) is only
    # notified again once this long after the previous notification.
    "renotify_after_hours": 6,
    # Occurrences whose window started longer ago than this are never sent
    # (no backlog flood when notifications are first enabled).
    "max_age_hours": 6,
}

# Ordering used to compare an anomaly's urgency (see notify.anomaly_urgency)
# against min_urgency.
URGENCY_ORDER = {"low": 0, "medium": 1, "high": 2, "urgent": 3}


@dataclass(frozen=True)
class BackendConfig:
    poll_interval_secs: int
    db_path: Path
    page_size_default: int
    page_size_max: int
    s3_lookback_secs: int = 3600
    retention_days: int = 0
    state_db_path: Path | None = None  # None = state.default_state_db_path()


@dataclass(frozen=True)
class InsightsConfig:
    enabled: bool
    detect_interval_secs: int
    baseline_window_days: int
    spike_multiplier: float
    spike_min_count: int
    shift_share_delta: float
    shift_min_count: int
    frequency_multiplier: float
    frequency_min_count: int
    detect_per_pod: bool
    sample_timestamps_max: int
    # Hours of stored history needed before rate-based detectors may fire
    # (a new install has no baseline yet). Capped at the baseline window.
    min_baseline_hours: float = 24
    # The current, still-open hour is evaluated once this many minutes of it
    # have passed; the previous complete hour is always evaluated.
    min_partial_window_minutes: float = 15


@dataclass(frozen=True)
class AiConfig:
    provider: str
    model: str
    api_key_env: str
    max_anomalies_per_tick: int
    reasoning_effort: str
    base_url: str = ""
    # Model for anomaly summaries (deeper analysis); "" = model.
    deep_model: str = ""
    # Per-model prices in USD per million tokens: {model: {input, output, cached}}.
    prices: dict = field(default_factory=dict, compare=False)
    # Defaults for the Settings UI's feature flags and budgets (it overrides them).
    features: dict = field(default_factory=dict, compare=False)
    budgets: dict = field(default_factory=dict, compare=False)
    cache_ttl_hours: float = 168.0
    auto_summary_min_urgency: str = "urgent"
    signatures: tuple = field(default_factory=tuple, compare=False)
    # The resolved key (see ai_settings.AiSettings.effective); never from
    # config.yaml. Excluded from repr so it cannot reach a log line.
    api_key: str = field(default="", repr=False, compare=False)


@dataclass(frozen=True)
class MattermostConfig:
    enabled: bool
    webhook_url_env: str
    min_urgency: str  # low | medium | high | urgent — threshold, inclusive
    link_base_url: str = ""
    renotify_after_hours: float = 6
    max_age_hours: float = 6


@dataclass(frozen=True)
class AppConfig:
    root: Path
    s3_bucket: str
    s3_region: str
    s3_key_prefix: str
    s3_access_key_id: str | None
    s3_secret_access_key: str | None
    s3_session_token: str | None
    infra_namespaces: tuple[str, ...]
    severity_buckets: tuple[str, ...]
    falco_namespace: str | None
    webapp: BackendConfig
    insights: InsightsConfig
    ai: AiConfig
    mattermost: MattermostConfig


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def _load_secret_credentials(secret_path: Path) -> dict[str, str]:
    if not secret_path.exists():
        return {}
    raw = _load_yaml(secret_path)
    string_data = raw.get("stringData") or {}
    if not isinstance(string_data, dict):
        raise ValueError(f"{secret_path} stringData must be a mapping")
    out: dict[str, str] = {}
    access_key = string_data.get("AWS_ACCESS_KEY_ID")
    secret_key = string_data.get("AWS_SECRET_ACCESS_KEY")
    session_token = string_data.get("AWS_SESSION_TOKEN")
    if access_key:
        out["aws_access_key_id"] = str(access_key)
    if secret_key:
        out["aws_secret_access_key"] = str(secret_key)
    if session_token:
        out["aws_session_token"] = str(session_token)
    return out


def load_app_config(config_path: Path) -> AppConfig:
    raw = _load_yaml(config_path)
    s3 = raw.get("sinks") or {}
    s3_cfg = s3.get("s3") or {}
    routing = raw.get("routing") or {}
    severity = raw.get("severity") or {}
    falco = raw.get("falco") or {}
    webapp = raw.get("webapp") or {}
    backend = dict(DEFAULT_BACKEND)
    backend.update(webapp.get("backend") or {})
    insights = dict(DEFAULT_INSIGHTS)
    insights.update(webapp.get("insights") or {})
    ai = dict(DEFAULT_AI)
    ai_raw = webapp.get("ai") or {}
    if "api_key_env" not in ai_raw:
        ai["api_key_env"] = _DEFAULT_KEY_ENV.get(str(ai_raw.get("provider", "")).strip().lower(), DEFAULT_AI["api_key_env"])
    ai.update(ai_raw)
    mattermost = dict(DEFAULT_MATTERMOST)
    mattermost.update(webapp.get("mattermost") or {})
    # Container deployments mount persistent storage at a different path than
    # the local-dev default; same LOGSCOPE_* override style as scripts/render.py.
    if os.environ.get("LOGSCOPE_WEBAPP_DB_PATH"):
        backend["db_path"] = os.environ["LOGSCOPE_WEBAPP_DB_PATH"]
    if os.environ.get(STATE_DB_ENV):
        backend["state_db_path"] = os.environ[STATE_DB_ENV]
    retention_days = backend.get("retention_days")
    if retention_days is None:
        retention_days = s3_cfg.get("retention_days") or 0
    creds = _load_secret_credentials(config_path.parent / "deploy" / "k3s" / "s3-secret.yaml")

    if not s3_cfg.get("bucket"):
        raise ValueError("sinks.s3.bucket is required")
    if not s3_cfg.get("region"):
        raise ValueError("sinks.s3.region is required")
    if not s3_cfg.get("key_prefix"):
        raise ValueError("sinks.s3.key_prefix is required")

    buckets = tuple(str(item.get("name")) for item in (severity.get("buckets") or []) if item.get("name"))
    if not buckets:
        raise ValueError("severity.buckets must define at least one bucket")

    min_urgency = str(mattermost.get("min_urgency", "high")).strip().lower()
    if min_urgency not in URGENCY_ORDER:
        raise ValueError(
            f"webapp.mattermost.min_urgency must be one of {sorted(URGENCY_ORDER)}, got {min_urgency!r}"
        )

    # Values that would spin a loop, return nothing or never expire anything.
    for section, key, value, minimum in (
        ("backend", "poll_interval_secs", backend["poll_interval_secs"], 1),
        ("backend", "page_size_default", backend["page_size_default"], 1),
        ("backend", "page_size_max", backend["page_size_max"], 1),
        ("backend", "s3_lookback_secs", backend["s3_lookback_secs"], 0),
        ("backend", "retention_days", retention_days, 0),
        ("insights", "detect_interval_secs", insights["detect_interval_secs"], 10),
        ("insights", "baseline_window_days", insights["baseline_window_days"], 1),
        ("ai", "max_anomalies_per_tick", ai["max_anomalies_per_tick"], 0),
    ):
        if int(value) < minimum:
            raise ValueError(f"webapp.{section}.{key} must be >= {minimum}, got {value!r}")
    if int(backend["page_size_default"]) > int(backend["page_size_max"]):
        raise ValueError("webapp.backend.page_size_default must not exceed page_size_max")

    from .ai_settings import SettingsError, clean_budgets, clean_flags, clean_prices

    try:
        ai["prices"] = clean_prices(ai.get("prices") or {}, "webapp.ai.prices")
        ai["features"] = clean_flags(ai.get("features") or {}, "webapp.ai.features")
        ai["budgets"] = clean_budgets(ai.get("budgets") or {}, "webapp.ai.budgets")
    except SettingsError as exc:
        raise ValueError(str(exc)) from None
    if not isinstance(ai.get("signatures") or [], list):
        raise ValueError("webapp.ai.signatures must be a list of rules")
    from .signatures import SignatureError, load_rules

    try:
        load_rules(ai.get("signatures") or [])
    except SignatureError as exc:
        raise ValueError(f"webapp.ai.signatures: {exc}") from None
    auto_urgency = str(ai.get("auto_summary_min_urgency") or "urgent").strip().lower()
    if auto_urgency not in URGENCY_ORDER:
        raise ValueError(f"webapp.ai.auto_summary_min_urgency must be one of {sorted(URGENCY_ORDER)}")
    if float(ai.get("cache_ttl_hours") or 0) < 0:
        raise ValueError("webapp.ai.cache_ttl_hours must be >= 0")
    if "api_key" in ai_raw:
        raise ValueError("webapp.ai.api_key is not read from config files; set the variable named in api_key_env")

    link_base_url = str(mattermost.get("link_base_url") or "").strip().rstrip("/")
    if link_base_url and not link_base_url.lower().startswith(("https://", "http://")):
        raise ValueError("webapp.mattermost.link_base_url must start with https:// or http://")
    for key in ("renotify_after_hours", "max_age_hours"):
        if float(mattermost[key]) <= 0:
            raise ValueError(f"webapp.mattermost.{key} must be > 0, got {mattermost[key]!r}")

    return AppConfig(
        root=config_path.resolve().parent,
        s3_bucket=str(s3_cfg["bucket"]),
        s3_region=str(s3_cfg["region"]),
        s3_key_prefix=str(s3_cfg["key_prefix"]),
        s3_access_key_id=creds.get("aws_access_key_id"),
        s3_secret_access_key=creds.get("aws_secret_access_key"),
        s3_session_token=creds.get("aws_session_token"),
        infra_namespaces=tuple(str(x) for x in (routing.get("infra_namespaces") or [])),
        severity_buckets=buckets,
        falco_namespace=str(falco["namespace"]) if falco.get("enabled") and falco.get("namespace") else None,
        webapp=BackendConfig(
            poll_interval_secs=int(backend["poll_interval_secs"]),
            db_path=Path(str(backend["db_path"])).expanduser(),
            page_size_default=int(backend["page_size_default"]),
            page_size_max=int(backend["page_size_max"]),
            s3_lookback_secs=int(backend["s3_lookback_secs"]),
            retention_days=int(retention_days),
            state_db_path=Path(str(backend["state_db_path"] or default_state_db_path())).expanduser(),
        ),
        insights=InsightsConfig(
            enabled=bool(insights["enabled"]),
            detect_interval_secs=int(insights["detect_interval_secs"]),
            baseline_window_days=int(insights["baseline_window_days"]),
            spike_multiplier=float(insights["spike_multiplier"]),
            spike_min_count=int(insights["spike_min_count"]),
            shift_share_delta=float(insights["shift_share_delta"]),
            shift_min_count=int(insights["shift_min_count"]),
            frequency_multiplier=float(insights["frequency_multiplier"]),
            frequency_min_count=int(insights["frequency_min_count"]),
            detect_per_pod=bool(insights["detect_per_pod"]),
            sample_timestamps_max=int(insights["sample_timestamps_max"]),
            min_baseline_hours=float(insights["min_baseline_hours"]),
            min_partial_window_minutes=float(insights["min_partial_window_minutes"]),
        ),
        ai=AiConfig(
            provider=str(ai.get("provider", "openrouter")),
            model=str(ai["model"]),
            api_key_env=str(ai["api_key_env"]),
            max_anomalies_per_tick=int(ai["max_anomalies_per_tick"]),
            reasoning_effort=str(ai.get("reasoning_effort") or ""),
            base_url=str(ai.get("base_url") or ""),
            deep_model=str(ai.get("deep_model") or ""),
            prices=dict(ai.get("prices") or {}),
            features=dict(ai.get("features") or {}),
            budgets=dict(ai.get("budgets") or {}),
            cache_ttl_hours=float(ai.get("cache_ttl_hours") if ai.get("cache_ttl_hours") is not None else 168),
            auto_summary_min_urgency=auto_urgency,
            signatures=tuple(ai.get("signatures") or ()),
        ),
        mattermost=MattermostConfig(
            enabled=bool(mattermost["enabled"]),
            webhook_url_env=str(mattermost["webhook_url_env"]),
            min_urgency=min_urgency,
            link_base_url=link_base_url,
            renotify_after_hours=float(mattermost["renotify_after_hours"]),
            max_age_hours=float(mattermost["max_age_hours"]),
        ),
    )


def source_prefixes(cfg: AppConfig) -> list[dict[str, str]]:
    base = cfg.s3_key_prefix.split("{{ log_type }}", 1)[0]
    base = base.split("%Y", 1)[0]
    if not base.endswith("/"):
        base += "/"

    prefixes: list[dict[str, str]] = []
    for bucket in cfg.severity_buckets:
        prefixes.append({"bucket": bucket, "scope": "regular", "prefix": base + bucket + "/"})
        if cfg.falco_namespace:
            prefixes.append({"bucket": bucket, "scope": "security", "prefix": base + "security/" + bucket + "/"})
    return prefixes