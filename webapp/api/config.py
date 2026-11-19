from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .state import STATE_DB_ENV, default_state_db_path
from .storage import CACHE_DB_ENV, default_cache_db_path

DEFAULT_BACKEND = {
    "poll_interval_secs": 30,
    # The log cache (rebuildable from S3). None = $XDG_CACHE_HOME/logscope/
    # cache.sqlite (~/.cache/logscope/...); never /tmp. $LOGSCOPE_WEBAPP_DB_PATH wins.
    "db_path": None,
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
    # A namespace/pod's error_rate_spike and new_falco_rule are suppressed for
    # this many seconds after that namespace/pod's first observed record, so a
    # container's own start-up noise (DB-retry errors, entrypoint shells) is not
    # mistaken for an anomaly. Suppressed detections are still recorded.
    "cold_start_grace_s": 600,
    # Fewest baseline occurrences of a group before a rate ratio is computed.
    # Below it the baseline is "insufficient" rather than 0, so a first-ever
    # burst is not treated as an infinite spike.
    "min_baseline_samples": 5,
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
    # With the auto_triage feature on (default on), a rate/shift anomaly that
    # transitions to firing at or above this urgency is triaged automatically
    # (signatures -> cache -> AI), reusing the auto-summary worker. Falco
    # novelty (new_falco_rule) is never auto-triaged.
    "auto_triage_min_urgency": "high",
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

DEFAULT_ALERTS = {
    # Seconds subtracted from the ingest watermark (see alerts.watermark):
    # objects can land in S3 a little after the poll that should have seen them.
    "watermark_margin_secs": 120,
    # Vector's S3 batch timeout (batch.timeout_secs; scripts/render.py and the
    # chart use 600): an event is in S3 at most this long after it happened.
    "s3_batch_timeout_secs": 600,
    # How often the evaluator looks for due rules.
    "eval_tick_secs": 30,
}

DEFAULT_SECURITY = {
    # Web -> runtime correlation (security.py): a web-attack anomaly followed
    # by a Falco event in the same namespace becomes a security incident.
    "correlation_enabled": True,
    # Look this far past a web-attack anomaly's window end for a Falco event.
    "correlation_window_s": 900,
    # Falco events still inside the target pod's (or namespace's) cold-start
    # grace are never a correlation match. None = webapp.insights.cold_start_grace_s.
    "cold_start_grace_s": None,
    # Web-attack anomalies whose window ended longer ago than this (plus the
    # correlation window) are not correlated any more.
    "lookback_s": 86400,
    # Channels (ids from the Alerts tab) a new incident is sent to; empty =
    # the environment's Mattermost channel (id 0) when it is configured.
    "notify_channel_ids": [],
    # Per-source-IP behavior over access logs (behavioral.py); see DEFAULT_BEHAVIORAL.
    "behavioral": {},
    # Trivy Operator vulnerability view (vulnscan.py); see DEFAULT_VULNSCAN.
    "vulnscan": {},
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_VULNSCAN = {
    # Off unless enabled: it runs kubectl (fixed read-only commands) and
    # fetches CISA's KEV catalog over HTTPS.
    "enabled": False,
    # How often Trivy Operator's reports and the Ingresses are read.
    "poll_interval_s": 1800,
    # How often the CISA Known Exploited Vulnerabilities catalog is refreshed.
    "kev_refresh_s": 86400,
    "kev_url": KEV_URL,
    # Security incidents and attack-tagged anomalies this recent count as
    # an attack on a workload (risk scoring).
    "correlation_lookback_s": 86400,
    # "namespace/workload" or "namespace" entries treated as exposed even
    # without an Ingress (NodePort, an external load balancer).
    "exposed_workloads": [],
    # Upper bound for one kubectl call.
    "kubectl_timeout_s": 120,
}

DEFAULT_BEHAVIORAL = {
    "enabled": True,
    # Trailing window aggregated per (namespace, client_ip) on each insights run.
    "window_s": 300,
    # brute_force: one path requested at least this often, with this share of 401/403.
    "brute_force_min_repeats": 50,
    "brute_force_auth_fail_ratio": 0.7,
    # scanning: at least this many distinct paths, with this share of 404
    # (or a scanner signature already matched for this IP).
    "scanning_min_paths": 20,
    "scanning_not_found_ratio": 0.6,
    # flood: this many requests within window_s, whatever the status.
    "flood_requests": 300,
    # While the behavior continues the open anomaly is updated; after this
    # many quiet seconds a new occurrence opens a new anomaly.
    "cooldown_s": 1800,
    # Never evaluated: source IPs in these CIDRs, and requests whose
    # User-Agent contains one of these strings (case-insensitive).
    "trusted_cidrs": [],
    "trusted_user_agents": [],
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
    # See DEFAULT_INSIGHTS.
    cold_start_grace_s: float = 600
    min_baseline_samples: int = 5


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
    auto_triage_min_urgency: str = "high"
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
class AlertsConfig:
    # IANA zone for times in notifications (webapp.display_tz).
    display_tz: str = "UTC"
    # Public URL of the UI for deep links (webapp.public_url, else
    # webapp.mattermost.link_base_url). Empty = no links.
    public_url: str = ""
    watermark_margin_secs: int = 120
    s3_batch_timeout_secs: int = 600
    eval_tick_secs: float = 30


@dataclass(frozen=True)
class BehavioralConfig:
    """webapp.security.behavioral (see DEFAULT_BEHAVIORAL)."""

    enabled: bool = True
    window_s: float = 300
    brute_force_min_repeats: int = 50
    brute_force_auth_fail_ratio: float = 0.7
    scanning_min_paths: int = 20
    scanning_not_found_ratio: float = 0.6
    flood_requests: int = 300
    cooldown_s: float = 1800
    trusted_cidrs: tuple[str, ...] = ()
    trusted_user_agents: tuple[str, ...] = ()


@dataclass(frozen=True)
class VulnscanConfig:
    """webapp.security.vulnscan (see DEFAULT_VULNSCAN)."""

    enabled: bool = False
    poll_interval_s: float = 1800
    kev_refresh_s: float = 86400
    kev_url: str = KEV_URL
    correlation_lookback_s: float = 86400
    exposed_workloads: tuple[str, ...] = ()
    kubectl_timeout_s: float = 120


def load_vulnscan(raw: Any) -> VulnscanConfig:
    """webapp.security.vulnscan, validated (ValueError)."""
    if raw is not None and not isinstance(raw, dict):
        raise ValueError("webapp.security.vulnscan must be a mapping")
    values = {**DEFAULT_VULNSCAN, **(raw or {})}
    name = "webapp.security.vulnscan"
    unknown = sorted(set(values) - set(DEFAULT_VULNSCAN))
    if unknown:
        raise ValueError(f"{name}: unknown key {unknown[0]!r}")
    for key, minimum in (("poll_interval_s", 60), ("kev_refresh_s", 3600), ("correlation_lookback_s", 0),
                         ("kubectl_timeout_s", 5)):
        if float(values[key]) < minimum:
            raise ValueError(f"{name}.{key} must be >= {minimum}, got {values[key]!r}")
    url = str(values["kev_url"] or "")
    if not url.lower().startswith("https://"):
        raise ValueError(f"{name}.kev_url must be an https URL")
    exposed = values["exposed_workloads"] or []
    if not isinstance(exposed, list) or any(
            not isinstance(e, str) or not e.strip() or e.count("/") > 1 or e.strip().startswith("/")
            for e in exposed):
        raise ValueError(f"{name}.exposed_workloads must list \"namespace\" or \"namespace/workload\" strings")
    return VulnscanConfig(
        enabled=bool(values["enabled"]), poll_interval_s=float(values["poll_interval_s"]),
        kev_refresh_s=float(values["kev_refresh_s"]), kev_url=url,
        correlation_lookback_s=float(values["correlation_lookback_s"]),
        exposed_workloads=tuple(e.strip().strip("/") for e in exposed),
        kubectl_timeout_s=float(values["kubectl_timeout_s"]),
    )


@dataclass(frozen=True)
class SecurityConfig:
    """webapp.security (see DEFAULT_SECURITY)."""

    correlation_enabled: bool = True
    correlation_window_s: float = 900
    # None = InsightsConfig.cold_start_grace_s (the existing guard).
    cold_start_grace_s: float | None = None
    lookback_s: float = 86400
    notify_channel_ids: tuple[int, ...] = ()
    behavioral: BehavioralConfig = field(default_factory=BehavioralConfig)
    vulnscan: VulnscanConfig = field(default_factory=VulnscanConfig)


def load_behavioral(raw: Any) -> BehavioralConfig:
    """webapp.security.behavioral, validated (ValueError)."""
    if raw is not None and not isinstance(raw, dict):
        raise ValueError("webapp.security.behavioral must be a mapping")
    values = {**DEFAULT_BEHAVIORAL, **(raw or {})}
    unknown = sorted(set(values) - set(DEFAULT_BEHAVIORAL))
    if unknown:
        raise ValueError(f"webapp.security.behavioral: unknown key {unknown[0]!r}")
    name = "webapp.security.behavioral"
    for key, minimum in (("window_s", 30), ("brute_force_min_repeats", 1), ("scanning_min_paths", 1),
                         ("flood_requests", 1), ("cooldown_s", 0)):
        if float(values[key]) < minimum:
            raise ValueError(f"{name}.{key} must be >= {minimum}, got {values[key]!r}")
    for key in ("brute_force_auth_fail_ratio", "scanning_not_found_ratio"):
        if not 0 <= float(values[key]) <= 1:
            raise ValueError(f"{name}.{key} must be between 0 and 1, got {values[key]!r}")
    import ipaddress

    cidrs = values["trusted_cidrs"] or []
    agents = values["trusted_user_agents"] or []
    if not isinstance(cidrs, list) or not isinstance(agents, list):
        raise ValueError(f"{name}.trusted_cidrs and trusted_user_agents must be lists")
    for cidr in cidrs:
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            raise ValueError(f"{name}.trusted_cidrs: {cidr!r} is not an IP network") from None
    if any(not isinstance(a, str) or not a.strip() for a in agents):
        raise ValueError(f"{name}.trusted_user_agents must be non-empty strings")
    return BehavioralConfig(
        enabled=bool(values["enabled"]), window_s=float(values["window_s"]),
        brute_force_min_repeats=int(values["brute_force_min_repeats"]),
        brute_force_auth_fail_ratio=float(values["brute_force_auth_fail_ratio"]),
        scanning_min_paths=int(values["scanning_min_paths"]),
        scanning_not_found_ratio=float(values["scanning_not_found_ratio"]),
        flood_requests=int(values["flood_requests"]), cooldown_s=float(values["cooldown_s"]),
        trusted_cidrs=tuple(str(c) for c in cidrs), trusted_user_agents=tuple(a.strip() for a in agents),
    )


@dataclass(frozen=True)
class AppConfig:
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
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)


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
    if os.environ.get(CACHE_DB_ENV, "").strip():
        backend["db_path"] = os.environ[CACHE_DB_ENV].strip()
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
    triage_urgency = str(ai.get("auto_triage_min_urgency") or "high").strip().lower()
    if triage_urgency not in URGENCY_ORDER:
        raise ValueError(f"webapp.ai.auto_triage_min_urgency must be one of {sorted(URGENCY_ORDER)}")
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

    alerts = dict(DEFAULT_ALERTS)
    alerts.update(webapp.get("alerts") or {})
    for key, minimum in (("watermark_margin_secs", 0), ("s3_batch_timeout_secs", 1), ("eval_tick_secs", 1)):
        if float(alerts[key]) < minimum:
            raise ValueError(f"webapp.alerts.{key} must be >= {minimum}, got {alerts[key]!r}")
    display_tz = str(webapp.get("display_tz") or "UTC").strip()
    try:
        from zoneinfo import ZoneInfo

        if display_tz.upper() != "UTC":
            ZoneInfo(display_tz)
    except Exception:
        raise ValueError(f"webapp.display_tz must be an IANA time zone name, got {display_tz!r}") from None
    public_url = str(webapp.get("public_url") or "").strip().rstrip("/") or link_base_url
    security = dict(DEFAULT_SECURITY)
    security.update(webapp.get("security") or {})
    for key, minimum in (("correlation_window_s", 60), ("lookback_s", 3600)):
        if float(security[key]) < minimum:
            raise ValueError(f"webapp.security.{key} must be >= {minimum}, got {security[key]!r}")
    if security["cold_start_grace_s"] is not None and float(security["cold_start_grace_s"]) < 0:
        raise ValueError("webapp.security.cold_start_grace_s must be >= 0")
    notify_ids = security.get("notify_channel_ids") or []
    if not isinstance(notify_ids, list) or any(isinstance(i, bool) or not isinstance(i, int) or i < 0
                                               for i in notify_ids):
        raise ValueError("webapp.security.notify_channel_ids must be a list of channel ids")
    if public_url and not public_url.lower().startswith(("https://", "http://")):
        raise ValueError("webapp.public_url must start with https:// or http://")

    return AppConfig(
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
            db_path=Path(str(backend["db_path"] or default_cache_db_path())).expanduser(),
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
            cold_start_grace_s=float(insights["cold_start_grace_s"]),
            min_baseline_samples=int(insights["min_baseline_samples"]),
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
            auto_triage_min_urgency=triage_urgency,
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
        alerts=AlertsConfig(
            display_tz=display_tz,
            public_url=public_url,
            watermark_margin_secs=int(alerts["watermark_margin_secs"]),
            s3_batch_timeout_secs=int(alerts["s3_batch_timeout_secs"]),
            eval_tick_secs=float(alerts["eval_tick_secs"]),
        ),
        security=SecurityConfig(
            correlation_enabled=bool(security["correlation_enabled"]),
            correlation_window_s=float(security["correlation_window_s"]),
            cold_start_grace_s=(None if security["cold_start_grace_s"] is None
                                else float(security["cold_start_grace_s"])),
            lookback_s=float(security["lookback_s"]),
            notify_channel_ids=tuple(sorted(set(notify_ids))),
            behavioral=load_behavioral(security.get("behavioral")),
            vulnscan=load_vulnscan(security.get("vulnscan")),
        ),
    )


def prefix_root(cfg: AppConfig) -> str:
    """The key prefix up to the severity segment, e.g. "k3s-logs/logs/"."""
    base = cfg.s3_key_prefix.split("{{ log_type }}", 1)[0]
    base = base.split("%Y", 1)[0]
    return base if base.endswith("/") else base + "/"


def source_prefixes(cfg: AppConfig) -> list[dict[str, str]]:
    """Every prefix the web app lists. The security/ prefixes are always
    included, whatever this config's falco.enabled says: Vector decides
    whether Falco events are written (listing an empty prefix costs one
    request per poll), and a mismatch is reported by falco_warnings."""
    base = prefix_root(cfg)
    prefixes: list[dict[str, str]] = []
    for bucket in cfg.severity_buckets:
        prefixes.append({"bucket": bucket, "scope": "regular", "prefix": base + bucket + "/"})
        prefixes.append({"bucket": bucket, "scope": "security", "prefix": base + "security/" + bucket + "/"})
    return prefixes


def falco_warnings(*, falco_enabled: bool, security_objects: int, other_objects: int, root: str,
                   vector_falco: bool | None = None) -> list[str]:
    """Where this config's falco.enabled disagrees with what Vector does:
    the rendered Vector config (vector_falco, when known) or the objects
    ingested so far (security/ ones vs the rest)."""
    out: list[str] = []
    if vector_falco is not None and vector_falco != falco_enabled:
        out.append(f"falco.enabled is {str(falco_enabled).lower()} in this config but the rendered Vector config "
                   f"has Falco routing {'on' if vector_falco else 'off'}: re-render (logscope render) or fix the config")
    if not falco_enabled and security_objects:
        out.append(f"Vector writes Falco events ({security_objects} objects under {root}security/) but falco.enabled "
                   "is false in this config; they are ingested anyway. Set falco.enabled: true so both agree")
    elif falco_enabled and not security_objects and other_objects:
        out.append(f"falco.enabled is true but none of the {other_objects} objects ingested are under {root}security/:"
                   " Vector may run with falco.enabled: false (or Falco has not reported anything yet)")
    return out
