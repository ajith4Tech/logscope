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


if __name__ == "__main__":
    test_starts_when_covers_fixture_formats()
    test_stack_trace_merges_to_one_event()
    test_postgres_multiline_merges_to_one_event()
    test_single_lines_not_merged()
    test_format_fixtures_stay_separate_events()
    test_group_by_keeps_interleaved_pods_apart()
    test_rendered_values_include_multiline_reduce()
    print("ok")
