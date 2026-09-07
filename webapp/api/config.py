from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DEFAULT_BACKEND = {
    "poll_interval_secs": 30,
    "db_path": "/tmp/logscope-webapp.sqlite",
    "page_size_default": 200,
    "page_size_max": 1000,
}


@dataclass(frozen=True)
class BackendConfig:
    poll_interval_secs: int
    db_path: Path
    page_size_default: int
    page_size_max: int


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