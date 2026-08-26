#!/usr/bin/env python3
"""Tests for apply_s3_lifecycle (mocked boto3 — no real AWS)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import apply_s3_lifecycle as L  # noqa: E402


def test_lifecycle_prefix():
    assert (
        L.lifecycle_prefix("k3s-logs/logs/{{ log_type }}/%Y/%m/%d/%H_%M_%S_")
        == "k3s-logs/logs/"
    )
    assert L.lifecycle_prefix("cluster-logs/%Y/%m/") == "cluster-logs/"
    assert L.lifecycle_prefix("static-only/") == "static-only/"


def test_build_retention_rule():
    rule = L.build_retention_rule("k3s-logs/logs/", 30)
    assert rule == {
        "ID": "logscope-retention",
        "Filter": {"Prefix": "k3s-logs/logs/"},
        "Status": "Enabled",
        "Expiration": {"Days": 30},
    }


def test_resolve_retention_days_default():
    warnings: list[str] = []
    days = L.resolve_retention_days({}, warn=warnings.append)
    assert days == 30
    assert any("default 30" in w for w in warnings)


def test_resolve_retention_days_set():
    assert L.resolve_retention_days({"retention_days": 14}, warn=lambda _: None) == 14


def test_merge_replaces_not_duplicates():
    other = {
        "ID": "unrelated-archive",
        "Filter": {"Prefix": "other-app/"},
        "Status": "Enabled",
        "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}],
    }
    old = L.build_retention_rule("k3s-logs/logs/", 30)
    existing = [other, old]
    updated = L.build_retention_rule("k3s-logs/logs/", 14)
    merged = L.merge_lifecycle_rules(existing, updated)

    ids = [r["ID"] for r in merged]
    assert ids.count("logscope-retention") == 1
    assert "unrelated-archive" in ids
    assert next(r for r in merged if r["ID"] == "logscope-retention")["Expiration"][
        "Days"
    ] == 14
    # Unrelated rule object preserved (not dropped / rewritten).
    assert next(r for r in merged if r["ID"] == "unrelated-archive") is other


def test_merge_appends_when_missing():
    other = {
        "ID": "unrelated-archive",
        "Filter": {"Prefix": "other-app/"},
        "Status": "Enabled",
        "Expiration": {"Days": 365},
    }
    new = L.build_retention_rule("k3s-logs/logs/", 30)
    merged = L.merge_lifecycle_rules([other], new)
    assert len(merged) == 2
    assert merged[0] is other
    assert merged[1]["ID"] == "logscope-retention"


def test_apply_lifecycle_put_preserves_others():
    """Full apply path: get existing → merge → put; no duplicate; others kept."""
    other = {
        "ID": "unrelated-archive",
        "Filter": {"Prefix": "other-app/"},
        "Status": "Enabled",
        "Expiration": {"Days": 365},
    }
    prior = L.build_retention_rule("k3s-logs/logs/", 30)

    client = MagicMock()
    client.get_bucket_lifecycle_configuration.return_value = {"Rules": [other, prior]}
    # Simulate botocore ClientError attribute path unused here.
    client.exceptions.ClientError = type("ClientError", (Exception,), {})

    applied = L.apply_lifecycle(
        client, bucket="logscope", prefix="k3s-logs/logs/", days=14
    )
    assert applied["Expiration"]["Days"] == 14
    assert applied["ID"] == "logscope-retention"

    client.put_bucket_lifecycle_configuration.assert_called_once()
    kwargs = client.put_bucket_lifecycle_configuration.call_args.kwargs
    assert kwargs["Bucket"] == "logscope"
    rules: list[dict[str, Any]] = kwargs["LifecycleConfiguration"]["Rules"]
    assert [r["ID"] for r in rules].count("logscope-retention") == 1
    assert any(r["ID"] == "unrelated-archive" for r in rules)
    assert next(r for r in rules if r["ID"] == "logscope-retention")["Expiration"][
        "Days"
    ] == 14
    assert next(r for r in rules if r["ID"] == "unrelated-archive") == other


def test_apply_lifecycle_empty_bucket():
    client = MagicMock()

    class ClientError(Exception):
        def __init__(self):
            self.response = {"Error": {"Code": "NoSuchLifecycleConfiguration"}}

    client.exceptions.ClientError = ClientError
    client.get_bucket_lifecycle_configuration.side_effect = ClientError()

    L.apply_lifecycle(client, bucket="logscope", prefix="k3s-logs/logs/", days=30)
    rules = client.put_bucket_lifecycle_configuration.call_args.kwargs[
        "LifecycleConfiguration"
    ]["Rules"]
    assert len(rules) == 1
    assert rules[0]["ID"] == "logscope-retention"


def test_load_secret_credentials():
    import tempfile

    text = """\
apiVersion: v1
kind: Secret
metadata:
  name: logscope-s3-creds
stringData:
  AWS_ACCESS_KEY_ID: "AKIATEST"
  AWS_SECRET_ACCESS_KEY: "secretvalue"
"""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "s3-secret.yaml"
        path.write_text(text)
        creds = L.load_secret_credentials(path)
        assert creds["aws_access_key_id"] == "AKIATEST"
        assert creds["aws_secret_access_key"] == "secretvalue"


if __name__ == "__main__":
    test_lifecycle_prefix()
    test_build_retention_rule()
    test_resolve_retention_days_default()
    test_resolve_retention_days_set()
    test_merge_replaces_not_duplicates()
    test_merge_appends_when_missing()
    test_apply_lifecycle_put_preserves_others()
    test_apply_lifecycle_empty_bucket()
    test_load_secret_credentials()
    print("ok")
