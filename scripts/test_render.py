#!/usr/bin/env python3
"""Sanity checks for the renderer (no Vector binary required)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import render as R  # noqa: E402


def test_glob():
    assert R.glob_to_regex("kube-system") == r"^kube-system$"
    assert R.glob_to_regex("kube-*") == r"^kube-.*$"
    assert R.glob_to_regex("user-?") == r"^user-.$"


def test_line_format_default():
    expr = R.format_to_vrl("{timestamp} - {namespace} - {pod}/{container} - {message}")
    assert expr == 'ts + " - " + ns + " - " + pod + "/" + contnr + " - " + flat'


def test_example_config():
    cfg = R.load_config(ROOT / "config.example.yaml")
    R.validate_cfg(cfg)
    vrl = R.build_vrl(cfg)
    assert 'out = ts + " - " + ns + " - " + pod + "/" + contnr + " - " + flat' in vrl
    assert "match(ns, r'^kube-system$')" in vrl
    assert r"r'^E\d{4}\s'" in vrl
    assert r"r'^E\\d{4}\\s'" not in vrl
    assert "segmentation fault" in vrl
    assert 'bkt = "metrics"' in vrl
    assert cfg["sinks"]["s3"]["bucket"] == ""
    assert cfg["sinks"]["s3"]["region"] == ""
    assert cfg["format"]["line"] == cfg["format"]["metrics"]


if __name__ == "__main__":
    test_glob()
    test_line_format_default()
    test_example_config()
    print("ok")
