#!/usr/bin/env python3
"""Apply Logscope S3 Lifecycle expiration from config.yaml.

Puts (or updates) a single deterministic rule ID ``logscope-retention`` on the
configured bucket. Other existing lifecycle rules are preserved. This is a
one-time AWS bucket operation — not part of render.py / Helm.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required: pip install -r requirements.txt\n")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "logscope-retention"
DEFAULT_RETENTION_DAYS = 30
DEFAULT_SECRET = ROOT / "deploy" / "k3s" / "s3-secret.yaml"

# Strip Vector ``{{ … }}`` and strftime ``%Y`` / ``%m`` / … templates from key_prefix.
_TEMPLATE_CUT = re.compile(r"(\{\{|%)")


def load_secret_credentials(path: Path) -> dict[str, str]:
    """Read AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from a K8s Secret YAML."""
    with path.open() as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        raise SystemExit(f"{path} did not parse as a mapping")
    data = doc.get("stringData") or doc.get("data") or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: stringData/data must be a mapping")
    # data: values are base64; stringData: plaintext
    if doc.get("stringData"):
        key_id = (data.get("AWS_ACCESS_KEY_ID") or "").strip()
        secret = (data.get("AWS_SECRET_ACCESS_KEY") or "").strip()
    else:
        import base64

        raw_id = data.get("AWS_ACCESS_KEY_ID") or ""
        raw_secret = data.get("AWS_SECRET_ACCESS_KEY") or ""
        try:
            key_id = base64.b64decode(raw_id).decode().strip() if raw_id else ""
            secret = base64.b64decode(raw_secret).decode().strip() if raw_secret else ""
        except Exception as e:
            raise SystemExit(f"{path}: failed to decode base64 Secret data: {e}") from e
    if not key_id or not secret:
        raise SystemExit(
            f"{path}: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required"
        )
    return {"aws_access_key_id": key_id, "aws_secret_access_key": secret}


def resolve_credentials(
    secret_path: Path | None,
    *,
    default_secret: Path = DEFAULT_SECRET,
) -> dict[str, str] | None:
    """Explicit --secret, else env keys, else deploy/k3s/s3-secret.yaml if present."""
    if secret_path is not None:
        if not secret_path.is_file():
            raise SystemExit(f"secret file not found: {secret_path}")
        return load_secret_credentials(secret_path)
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return None  # boto3 default chain
    if default_secret.is_file():
        return load_secret_credentials(default_secret)
    return None


def lifecycle_prefix(key_prefix: str) -> str:
    """Static Filter prefix: key_prefix root before Vector/date templates."""
    m = _TEMPLATE_CUT.search(key_prefix)
    prefix = key_prefix[: m.start()] if m else key_prefix
    return prefix


def resolve_retention_days(s3: dict, *, warn=sys.stderr.write) -> int:
    """Positive int from config; default 30 with a warning if unset."""
    raw = s3.get("retention_days", None)
    if raw is None:
        warn(
            f"warning: sinks.s3.retention_days unset; using default {DEFAULT_RETENTION_DAYS}\n"
        )
        return DEFAULT_RETENTION_DAYS
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise SystemExit("sinks.s3.retention_days must be a positive integer")
    return raw


def build_retention_rule(prefix: str, days: int) -> dict[str, Any]:
    return {
        "ID": RULE_ID,
        "Filter": {"Prefix": prefix},
        "Status": "Enabled",
        "Expiration": {"Days": days},
    }


def merge_lifecycle_rules(
    existing: list[dict[str, Any]], new_rule: dict[str, Any]
) -> list[dict[str, Any]]:
    """Replace rule by ID if present; otherwise append. Preserve all others."""
    out: list[dict[str, Any]] = []
    replaced = False
    for rule in existing:
        if rule.get("ID") == new_rule["ID"]:
            out.append(new_rule)
            replaced = True
        else:
            out.append(rule)
    if not replaced:
        out.append(new_rule)
    return out


def fetch_existing_rules(client: Any, bucket: str) -> list[dict[str, Any]]:
    try:
        resp = client.get_bucket_lifecycle_configuration(Bucket=bucket)
    except Exception as e:
        # botocore ClientError with Code NoSuchLifecycleConfiguration when unset.
        code = ""
        if getattr(e, "response", None):
            code = e.response.get("Error", {}).get("Code", "")
        if code == "NoSuchLifecycleConfiguration" or type(e).__name__ == (
            "NoSuchLifecycleConfiguration"
        ):
            return []
        raise
    return list(resp.get("Rules") or [])


def apply_lifecycle(
    client: Any,
    *,
    bucket: str,
    prefix: str,
    days: int,
) -> dict[str, Any]:
    """Merge logscope-retention into the bucket lifecycle and put it."""
    rule = build_retention_rule(prefix, days)
    existing = fetch_existing_rules(client, bucket)
    rules = merge_lifecycle_rules(existing, rule)
    client.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={"Rules": rules},
    )
    return rule


def load_config(path: Path) -> dict:
    with path.open() as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise SystemExit(f"{path} did not parse as a mapping")
    return cfg


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "-c",
        "--config",
        default=os.environ.get("LOGSCOPE_CONFIG", ""),
        help="config YAML (default: ./config.yaml if present, else config.example.yaml)",
    )
    p.add_argument(
        "--secret",
        default="",
        help=(
            "K8s Secret YAML with stringData AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY "
            f"(default: {DEFAULT_SECRET} if present, else AWS env / boto3 chain)"
        ),
    )
    args = p.parse_args()

    if args.config:
        cfg_path = Path(args.config)
    else:
        cfg_path = ROOT / "config.yaml"
        if not cfg_path.is_file():
            cfg_path = ROOT / "config.example.yaml"
    if not cfg_path.is_file():
        raise SystemExit(f"config not found: {cfg_path}")

    cfg = load_config(cfg_path)
    try:
        s3 = cfg["sinks"]["s3"]
    except (KeyError, TypeError) as e:
        raise SystemExit(f"config error: missing sinks.s3 ({e})") from e

    bucket = (s3.get("bucket") or "").strip()
    region = (s3.get("region") or "").strip()
    key_prefix = s3.get("key_prefix") or ""
    if not bucket:
        raise SystemExit("sinks.s3.bucket is required")
    if not region:
        raise SystemExit("sinks.s3.region is required")
    if not key_prefix:
        raise SystemExit("sinks.s3.key_prefix is required")

    days = resolve_retention_days(s3)
    prefix = lifecycle_prefix(key_prefix)
    if not prefix:
        raise SystemExit(
            "sinks.s3.key_prefix has no static root to scope the lifecycle Filter"
        )

    try:
        import boto3
        from botocore.exceptions import NoCredentialsError
    except ImportError:
        sys.stderr.write("boto3 is required: pip install -r requirements.txt\n")
        return 1

    secret_arg = Path(args.secret) if args.secret else None
    creds = resolve_credentials(secret_arg)
    client_kwargs: dict[str, Any] = {"region_name": region}
    if creds:
        client_kwargs.update(creds)
    client = boto3.client("s3", **client_kwargs)

    try:
        applied = apply_lifecycle(client, bucket=bucket, prefix=prefix, days=days)
    except NoCredentialsError:
        raise SystemExit(
            "Unable to locate AWS credentials. Set AWS_ACCESS_KEY_ID / "
            "AWS_SECRET_ACCESS_KEY, or use --secret deploy/k3s/s3-secret.yaml"
        ) from None

    print(f"Applied S3 lifecycle rule on s3://{bucket}/ (region={region})")
    print(f"  config: {cfg_path}")
    print(f"  filter prefix: {prefix!r}")
    print(f"  retention_days: {days}")
    print("  rule:")
    for line in yaml.safe_dump(applied, default_flow_style=False).splitlines():
        print(f"    {line}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError) as e:
        raise SystemExit(f"config error: {e}") from e
