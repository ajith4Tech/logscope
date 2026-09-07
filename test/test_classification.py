#!/usr/bin/env python3
"""Multiline reduce + starts_when coverage against test/fixtures."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import render as R  # noqa: E402

FIXTURES = ROOT / "test" / "fixtures"
GROUP_BY = (
    "kubernetes.pod_name",
    "kubernetes.container_name",
    "kubernetes.pod_namespace",
)


def _get_path(event: dict[str, Any], dotted: str) -> Any:
    cur: Any = event
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def reduce_multiline(
    events: list[dict[str, Any]],
    starts_when: str,
    group_by: tuple[str, ...] = GROUP_BY,
) -> list[dict[str, Any]]:
    """Python stand-in for Vector reduce + concat_newline + starts_when."""
    rx = re.compile(starts_when)
    buffers: dict[tuple, dict[str, Any]] = {}
    # Stable flush order: groups flush when a new start arrives for that key.
    out: list[dict[str, Any]] = []

    def flush(key: tuple) -> None:
        if key in buffers:
            out.append(buffers.pop(key))

    for ev in events:
        key = tuple(_get_path(ev, k) for k in group_by)
        msg = str(ev["message"])
        if key in buffers and rx.search(msg):
            flush(key)
        if key not in buffers:
            buffers[key] = {
                "message": msg,
                "kubernetes": dict(ev["kubernetes"]),
            }
        else:
            buffers[key]["message"] += "\n" + msg

    for key in list(buffers):
        flush(key)
    return out


def _lines(name: str) -> list[str]:
    text = (FIXTURES / name).read_text()
    return [ln for ln in text.splitlines() if ln != ""]


def _event(message: str, pod: str, container: str, namespace: str) -> dict[str, Any]:
    return {
        "message": message,
        "kubernetes": {
            "pod_name": pod,
            "container_name": container,
            "pod_namespace": namespace,
        },
    }


def test_starts_when_covers_fixture_formats():
    """Existing starts_when must match every first-line format in fixtures."""
    cfg = R.load_config(ROOT / "config.yaml")
    rx = re.compile(cfg["multiline"]["starts_when"])
    samples = {
        "plain_timestamp.txt": _lines("plain_timestamp.txt")[0],
        "json_lines.txt": _lines("json_lines.txt")[0],
        "logfmt.txt": _lines("logfmt.txt")[0],
        "klog.txt": _lines("klog.txt")[0],
        "single_lines.txt": _lines("single_lines.txt")[0],
        "stack_trace.txt": _lines("stack_trace.txt")[0],
        "falco_alerts.txt": _lines("falco_alerts.txt")[0],
    }
    missing = [name for name, line in samples.items() if not rx.search(line)]
    assert not missing, (
        f"starts_when {cfg['multiline']['starts_when']!r} does not match "
        f"fixture first lines: {missing}"
    )
    # klog severity letters each start an event
    for line in _lines("klog.txt"):
        assert rx.search(line), f"klog line should start an event: {line!r}"


def test_stack_trace_merges_to_one_event():
    cfg = R.load_config(ROOT / "config.yaml")
    lines = _lines("stack_trace.txt")
    assert len(lines) > 1, "stack_trace fixture must be multi-line"
    events = [
        _event(ln, "api-7d9f", "api", "app") for ln in lines
    ]
    # Trailing unrelated start forces flush of the open reduce buffer.
    events.append(_event("INFO: recovered", "api-7d9f", "api", "app"))
    out = reduce_multiline(events, cfg["multiline"]["starts_when"])
    assert len(out) == 2, f"expected 2 events (stack + info), got {len(out)}: {out!r}"
    merged = out[0]["message"]
    assert merged == "\n".join(lines)
    assert "File \"/app/worker.py\"" in merged
    assert out[1]["message"] == "INFO: recovered"


def test_postgres_multiline_merges_to_one_event():
    """Column-0 DETAIL/HINT/STATEMENT must not split a Postgres error block."""
    cfg = R.load_config(ROOT / "config.yaml")
    rx = re.compile(cfg["multiline"]["starts_when"])
    lines = _lines("postgres_multiline.txt")
    assert len(lines) > 1
    # Continuations must not look like starts under the tightened pattern.
    for ln in lines[1:]:
        assert not rx.search(ln), f"continuation unexpectedly matches starts_when: {ln!r}"
    events = [_event(ln, "pg-0", "postgres", "db") for ln in lines]
    # Known start-of-event after the block forces a flush boundary.
    events.append(
        _event(
            "2026-08-25T16:02:41Z connection authorized",
            "pg-0",
            "postgres",
            "db",
        )
    )
    out = reduce_multiline(events, cfg["multiline"]["starts_when"])
    assert len(out) == 2, f"expected 2 events (postgres block + next), got {len(out)}: {out!r}"
    assert out[0]["message"] == "\n".join(lines)
    assert "DETAIL:" in out[0]["message"]
    assert "HINT:" in out[0]["message"]
    assert "STATEMENT:" in out[0]["message"]
    assert out[1]["message"].startswith("2026-08-25T16:02:41Z")


def test_single_lines_not_merged():
    cfg = R.load_config(ROOT / "config.yaml")
    lines = _lines("single_lines.txt")
    events = [_event(ln, "api-7d9f", "api", "app") for ln in lines]
    out = reduce_multiline(events, cfg["multiline"]["starts_when"])
    assert len(out) == len(lines)
    assert [e["message"] for e in out] == lines


def test_format_fixtures_stay_separate_events():
    """Adjacent plain/JSON/logfmt/klog lines must not glue together."""
    cfg = R.load_config(ROOT / "config.yaml")
    bundles = [
        _lines("plain_timestamp.txt"),
        _lines("json_lines.txt"),
        _lines("logfmt.txt"),
        _lines("klog.txt"),
    ]
    for lines in bundles:
        events = [_event(ln, "svc-a", "c", "ns") for ln in lines]
        out = reduce_multiline(events, cfg["multiline"]["starts_when"])
        assert [e["message"] for e in out] == lines


def test_group_by_keeps_interleaved_pods_apart():
    cfg = R.load_config(ROOT / "config.yaml")
    # Interleaved: pod-a stack fragment, pod-b line, pod-a continuation.
    events = [
        _event("ERROR: pod-a failure", "pod-a", "c1", "ns1"),
        _event("ERROR: pod-b failure", "pod-b", "c1", "ns1"),
        _event("  at a.py:1", "pod-a", "c1", "ns1"),
        _event("  at b.py:1", "pod-b", "c1", "ns1"),
        _event("INFO: pod-a done", "pod-a", "c1", "ns1"),
        _event("INFO: pod-b done", "pod-b", "c1", "ns1"),
    ]
    out = reduce_multiline(events, cfg["multiline"]["starts_when"])
    by_pod = {e["kubernetes"]["pod_name"]: e["message"] for e in out if e["message"].startswith("ERROR")}
    # Each ERROR+continuation is one event per pod; INFO starts new events.
    assert len(out) == 4
    assert by_pod["pod-a"] == "ERROR: pod-a failure\n  at a.py:1"
    assert by_pod["pod-b"] == "ERROR: pod-b failure\n  at b.py:1"
    infos = [e for e in out if e["message"].startswith("INFO")]
    assert {e["kubernetes"]["pod_name"]: e["message"] for e in infos} == {
        "pod-a": "INFO: pod-a done",
        "pod-b": "INFO: pod-b done",
    }


def test_rendered_values_include_multiline_reduce():
    """Both kits must carry the same reduce transform (shared config)."""
    cfg = R.load_config(ROOT / "config.yaml")
    needle = (
        "match(string!(.message), r'"
        + R.vrl_escape_regex(cfg["multiline"]["starts_when"])
        + "')"
    )
    for name in ("values-local.yaml", "values-agent.yaml"):
        text = (ROOT / "deploy" / name).read_text()
        assert "multiline:" in text
        assert "type: reduce" in text
        assert "kubernetes.pod_name" in text
        assert "kubernetes.container_name" in text
        assert "kubernetes.pod_namespace" in text
        assert "concat_newline" in text
        assert needle in text
        assert "- multiline" in text


def _is_infra(cfg: dict[str, Any], ns: str) -> bool:
    for p in cfg["routing"]["infra_namespaces"] or []:
        if re.match(R.glob_to_regex(str(p)), ns):
            return True
    return False


def _bucket_from_level(cfg: dict[str, Any], lv: str) -> str:
    for b in cfg["severity"]["buckets"]:
        for e in b.get("level_equals") or []:
            if lv == str(e).lower():
                return b["name"]
        for c in b.get("level_contains") or []:
            if str(c).lower() in lv:
                return b["name"]
    return ""


def classify_event(cfg: dict[str, Any], message: str, namespace: str) -> dict[str, Any]:
    """Python stand-in for classify_and_scope + Falco overlay (tests)."""
    import json

    obj: dict[str, Any] = {}
    try:
        parsed = json.loads(message)
        if isinstance(parsed, dict):
            obj = parsed
    except json.JSONDecodeError:
        pass

    bkt = cfg["severity"]["default"]
    for field in cfg["severity"]["structured_fields"]:
        if field in obj and obj[field] is not None:
            mapped = _bucket_from_level(cfg, str(obj[field]).lower())
            if mapped:
                bkt = mapped
            break

    text = message
    for fname in cfg["severity"]["text_fields"]:
        if fname in obj and obj[fname]:
            text = str(obj[fname])
            break

    if _is_infra(cfg, namespace):
        scope = cfg["routing"]["infra_scope"]
    else:
        scope = cfg["routing"]["namespace_scope_prefix"] + namespace

    falco_hit = False
    if R.falco_enabled(cfg) and namespace == cfg["falco"]["namespace"]:
        falco_hit = True
        scope = "security"
        if obj.get("output"):
            text = str(obj["output"])
            rule = obj.get("rule")
            if rule and str(rule) not in text:
                text = f"{rule}: {text}"
        if obj.get("priority") is not None:
            pmap = R.falco_priority_map(cfg)
            key = str(obj["priority"]).lower()
            if key not in pmap:
                raise AssertionError(f"fixture priority {key!r} missing from priority_map")
            bkt = pmap[key]

    dests = [f"{scope}/{bkt}.log"]
    if falco_hit:
        dests.append(f"{scope}.log")
    return {
        "log_type": bkt,
        "scope": scope,
        "falco": falco_hit,
        "text": text,
        "dests": dests,
        "obj": obj,
    }


def test_falco_scope_security_overrides_infra():
    cfg = R.load_config(ROOT / "config.yaml")
    assert R.falco_enabled(cfg)
    ns = cfg["falco"]["namespace"]
    cfg["routing"]["infra_namespaces"] = list(cfg["routing"]["infra_namespaces"]) + [ns]
    line = _lines("falco_alerts.txt")[0]
    got = classify_event(cfg, line, ns)
    assert got["scope"] == "security"
    assert got["falco"] is True
    assert _is_infra(cfg, ns)


def test_falco_priority_map_and_dual_write():
    cfg = R.load_config(ROOT / "config.yaml")
    R.validate_cfg(cfg)
    pmap = R.falco_priority_map(cfg)
    ns = cfg["falco"]["namespace"]
    lines = _lines("falco_alerts.txt")
    priorities = set()
    nested = False
    for line in lines:
        got = classify_event(cfg, line, ns)
        pr = str(got["obj"]["priority"]).lower()
        priorities.add(pr)
        assert got["scope"] == "security"
        assert got["log_type"] == pmap[pr]
        assert got["obj"]["output"] in got["text"]
        assert f"security/{pmap[pr]}.log" in got["dests"]
        assert "security.log" in got["dests"]
        assert got["dests"].count("security.log") == 1
        if isinstance(got["obj"].get("output_fields"), dict):
            nested = True
    assert len(priorities) >= 4, f"need ≥4 fixture priorities, got {priorities}"
    assert nested, "fixture must include a nested output_fields object"


def test_non_falco_fixtures_no_security_leakage():
    cfg = R.load_config(ROOT / "config.yaml")
    samples = [
        ("json_lines.txt", "app"),
        ("klog.txt", "kube-system"),
        ("plain_timestamp.txt", "default"),
        ("logfmt.txt", "app"),
        ("single_lines.txt", "app"),
    ]
    for name, ns in samples:
        for line in _lines(name):
            got = classify_event(cfg, line, ns)
            assert got["falco"] is False
            assert got["scope"] != "security"
            assert "security.log" not in got["dests"]
            assert len(got["dests"]) == 1


def test_falco_disabled_falls_through():
    from copy import deepcopy

    cfg = deepcopy(R.load_config(ROOT / "config.yaml"))
    cfg["falco"]["enabled"] = False
    ns = cfg["falco"]["namespace"]
    line = _lines("falco_alerts.txt")[0]
    got = classify_event(cfg, line, ns)
    assert got["falco"] is False
    assert got["scope"] == cfg["routing"]["namespace_scope_prefix"] + ns
    assert "security.log" not in got["dests"]
    assert got["dests"] == [f"{got['scope']}/{got['log_type']}.log"]


def test_falco_json_starts_when():
    cfg = R.load_config(ROOT / "config.yaml")
    rx = re.compile(cfg["multiline"]["starts_when"])
    for line in _lines("falco_alerts.txt"):
        assert rx.search(line), f"Falco JSON should start an event: {line[:80]!r}"


if __name__ == "__main__":
    test_starts_when_covers_fixture_formats()
    test_stack_trace_merges_to_one_event()
    test_postgres_multiline_merges_to_one_event()
    test_single_lines_not_merged()
    test_format_fixtures_stay_separate_events()
    test_group_by_keeps_interleaved_pods_apart()
    test_rendered_values_include_multiline_reduce()
    test_falco_scope_security_overrides_infra()
    test_falco_priority_map_and_dual_write()
    test_non_falco_fixtures_no_security_leakage()
    test_falco_disabled_falls_through()
    test_falco_json_starts_when()
    print("ok")
