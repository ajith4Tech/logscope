"""The load test (scripts/loadtest.py): the synthetic data has the shape it
claims, and (marked slow, excluded by default) a small end-to-end run works.
Run the slow one with: pytest -m slow test/test_loadtest.py"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import loadtest  # noqa: E402

from webapp.api.parser import parse_flat_line  # noqa: E402
from webapp.api.storage import to_epoch  # noqa: E402


def test_synthetic_data_has_the_documented_shape():
    end = datetime(2026, 10, 21, 6, 0, tzinfo=timezone.utc)
    gen = loadtest.Generator(60_000, end)
    severities: Counter = Counter()
    namespaces, pods, templates = set(), set(), Counter()
    falco = 0
    epochs = []
    for _t0, regular, security in gen.windows_iter():
        for bucket, lines in regular.items():
            severities[bucket] += len(lines)
            for line in lines:
                parsed = parse_flat_line(line)
                namespaces.add(parsed.namespace)
                pods.add(parsed.pod)
                templates[parsed.message.split(" ")[0]] += 1
                epochs.append(to_epoch(parsed.timestamp))
        falco += sum(len(lines) for lines in security.values())
    total = sum(severities.values()) + falco
    assert abs(total - 60_000) <= 1
    assert len(namespaces) == 20 and sum(ns.startswith("user-") for ns in namespaces) == 15
    assert len(pods) == 200 and all(len(p.split("-")[-2]) == 10 for p in pods)   # replicaset hash
    share = {k: v / (total - falco) for k, v in severities.items()}
    for sev, want in loadtest.SEVERITY_MIX:
        if sev != "error":  # incidents add errors
            assert abs(share[sev] - want) < 0.02, (sev, share[sev])
    assert 0.03 < share["error"] < 0.08
    assert 0.002 < falco / total < 0.01
    assert None not in epochs and min(epochs) >= end.timestamp() - 7 * 86400 and max(epochs) <= end.timestamp() + 1
    assert sum(len(pool) for pool in gen.templates.values()) >= 500


@pytest.mark.slow
def test_loadtest_end_to_end_at_small_scale(tmp_path):
    out = tmp_path / "result.json"
    assert loadtest.main(["--rows", "30000", "--runs", "2", "--min-runs", "1", "--budget", "2",
                          "--concurrency-secs", "3", "--workdir", str(tmp_path / "work"), "--json", str(out)]) == 0
    result = json.loads(out.read_text())["results"]
    for name in ("histogram 24h", "fields 7d", "logs page 20 24h", "insights cycle", "alert evaluation 50 rules",
                 "backtest 7d", "dbtool backup", "prune (10 min of oldest data)"):
        assert "p95" in result[name], (name, result[name])
    assert result["concurrency"]["http_503"] == 0
    assert result["ingest_direct"]["lines"] == 30000 and result["ts_backfill_1m"]["rows"] >= 30000
