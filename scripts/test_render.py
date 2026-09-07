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
    assert R.falco_enabled(cfg)
    vrl_on = R.build_vrl(cfg)
    assert f'if ns == "{cfg["falco"]["namespace"]}"' in vrl_on
    assert 'scope = "security"' in vrl_on
    assert 'fpl == "informational"' in vrl_on
    assert 'fpl == "emergency"' in vrl_on
    assert '"falco": falco_hit' in vrl_on


def test_falco_priority_map_validation():
    from copy import deepcopy

    cfg = deepcopy(R.load_config(ROOT / "config.example.yaml"))
    R.validate_cfg(cfg)
    del cfg["falco"]["priority_map"]["informational"]
    try:
        R.validate_cfg(cfg)
    except SystemExit as e:
        msg = str(e)
        assert "informational" in msg
        assert "priority_map" in msg
    else:
        raise AssertionError("expected SystemExit for incomplete priority_map")
    cfg["falco"]["enabled"] = False
    R.validate_cfg(cfg)  # incomplete map is skipped when disabled


def test_falco_rendered_into_both_kits():
    cfg = R.load_config(ROOT / "config.yaml")
    R.validate_cfg(cfg)
    ns_needle = f'if ns == "{cfg["falco"]["namespace"]}"'
    for name in ("values-local.yaml", "values-agent.yaml"):
        text = (ROOT / "deploy" / name).read_text()
        assert ns_needle in text
        assert 'scope = "security"' in text
        assert 'fpl == "critical"' in text
        assert 'bkt = "error"' in text
    local = (ROOT / "deploy" / "values-local.yaml").read_text()
    assert "falco_security:" in local
    assert "type: filter" in local
    assert ".falco == true" in local
    assert "falco_security_log:" in local
    assert '{{`{{ scope }}`}}.log' in local
    # File dual-write is local-kit only; classify VRL is shared (agent still tags).
    agent = (ROOT / "deploy" / "values-agent.yaml").read_text()
    assert '"falco": falco_hit' in agent
    assert "falco_security:" in agent
    assert "falco_security_s3:" in agent
    assert '{{`{{ scope }}`}}/{{`{{ log_type }}`}}' in agent
    assert 'if falco_hit { out = out + " scope=" + scope }' in agent


def test_falco_pipeline_dual_write_not_exclusive():
    cfg = R.load_config(ROOT / "config.yaml")
    doc = R.vector_config_dict(cfg, include_file=True, include_s3=False)
    assert doc["sinks"]["log_files"]["inputs"] == ["classify_and_scope"]
    assert doc["transforms"]["falco_security"]["inputs"] == ["classify_and_scope"]
    assert doc["sinks"]["falco_security_log"]["inputs"] == ["falco_security"]
    assert doc["sinks"]["log_files"]["path"] == cfg["sinks"]["file"]["path"]
    assert doc["sinks"]["falco_security_log"]["path"] == R.falco_security_file_path(cfg)
    doc_s3 = R.vector_config_dict(cfg, include_file=False, include_s3=True)
    assert doc_s3["sinks"]["s3_logs"]["inputs"] == ["classify_and_scope"]
    assert doc_s3["transforms"]["falco_security"]["inputs"] == ["classify_and_scope"]
    assert doc_s3["sinks"]["falco_security_s3"]["inputs"] == ["falco_security"]
    assert doc_s3["sinks"]["s3_logs"]["key_prefix"] == cfg["sinks"]["s3"]["key_prefix"]
    assert doc_s3["sinks"]["falco_security_s3"]["key_prefix"] == R.falco_security_s3_prefix(cfg)
    assert "{{ scope }}/{{ log_type }}" in R.falco_security_s3_prefix(cfg)
    cfg_off = dict(cfg)
    cfg_off["falco"] = dict(cfg["falco"])
    cfg_off["falco"]["enabled"] = False
    doc_off = R.vector_config_dict(cfg_off, include_file=True, include_s3=True)
    assert "falco_security" not in doc_off["transforms"]
    assert "falco_security_log" not in doc_off["sinks"]
    assert "falco_security_s3" not in doc_off["sinks"]
    assert 'falco_hit' not in doc_off["transforms"]["classify_and_scope"]["source"]


if __name__ == "__main__":
    test_glob()
    test_line_format_default()
    test_example_config()
    test_falco_priority_map_validation()
    test_falco_rendered_into_both_kits()
    test_falco_pipeline_dual_write_not_exclusive()
    print("ok")
