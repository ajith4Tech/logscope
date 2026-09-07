from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.insights import (  # noqa: E402
    AnomalyStore,
    InsightsDetector,
    InsightsJob,
    compute_baseline,
    is_spike,
    rule_key_of,
)
from webapp.api.storage import LogStorage  # noqa: E402

NOW = datetime(2026, 9, 7, 12, 30, 0, tzinfo=timezone.utc)
HOUR_START = NOW.replace(minute=0, second=0, microsecond=0)


def insert_record(conn, *, timestamp, namespace="app", pod="web-0", message="boom",
                  severity_bucket="info", scope="namespaces/app"):
    conn.execute(
        """
        INSERT INTO records (timestamp, severity_bucket, scope, namespace, pod, container,
                             message, raw_line, source_key, source_etag, line_number, is_falco)
        VALUES (?, ?, ?, ?, ?, 'c', ?, ?, 'k', 'e', 1, ?)
        """,
        (
            timestamp, severity_bucket, scope, namespace, pod, message,
            f"{timestamp} - {namespace} - {pod}/c - {message}",
            f"k/{timestamp}", "1" if scope == "security" else "0",
        ),
    )
    conn.commit()


@pytest.fixture()
def store(tmp_path):
    return AnomalyStore(tmp_path / "webapp.sqlite")


def make_job(store, summarizer=None, tmp_path=None, **overrides):
    defaults = dict(
        enabled=True,
        detect_interval_secs=300,
        baseline_window_days=7,
        spike_multiplier=3.0,
        spike_min_count=10,
        shift_share_delta=0.25,
        shift_min_count=20,
        frequency_multiplier=5.0,
        frequency_min_count=30,
        detect_per_pod=False,
        sample_timestamps_max=10,
    )
    defaults.update(overrides)
    from webapp.api.config import AiConfig, InsightsConfig, AppConfig
    from dataclasses import replace

    base = load_app_config(ROOT / "config.yaml")
    cfg = replace(
        base,
        webapp=replace(base.webapp, db_path=store._conn.execute("PRAGMA database_list").fetchall()[0][2] and Path(store._conn.execute("SELECT file FROM pragma_database_list").fetchone()[2])),
        insights=InsightsConfig(**defaults),
        ai=AiConfig(provider="none", model="", api_key_env="LOGSCOPE_AI_API_KEY", max_anomalies_per_tick=5),
    )
    # Rebuild a job against the store's own connection (same file).
    detector = InsightsDetector(store._conn, cfg.insights)
    job = InsightsJob.__new__(InsightsJob)
    job.cfg = cfg
    job.store = store
    job.detector = detector
    job._summarizer = summarizer
    job.last_run_at = None
    job.last_error = None
    return job


# --- Normalization parity with the UI dedupe feature -----------------------

def test_rule_key_of_matches_ui_rulekeyof():
    # PTRACE storm shape: embedded falco event time + trailing field dump
    ptrace = (
        "PTRACE attached to process: 15:50:11.473402755: Warning Detected ptrace "
        "PTRACE_ATTACH attempt | proc_pcmdline=systemd --user evt_type=ptrace"
    )
    assert rule_key_of(ptrace) == (
        "PTRACE attached to process: Warning Detected ptrace PTRACE_ATTACH attempt"
    )
    # Embedded timestamp without field dump
    assert rule_key_of("Find AWS Credentials: 09:55:44.837661594: Warning Detected AWS credentials search activity") == (
        "Find AWS Credentials: Warning Detected AWS credentials search activity"
    )
    # Plain message: unchanged
    assert rule_key_of("[WARNING] No files matching import glob pattern") == (
        "[WARNING] No files matching import glob pattern"
    )


# --- Baseline / threshold math (deterministic) ------------------------------

def test_compute_baseline():
    assert compute_baseline([]) == 0.0
    assert compute_baseline([4, 6]) == 5.0
    assert compute_baseline([3]) == 3.0


def test_is_spike_thresholds():
    assert not is_spike(5, 50.0, 3.0, 10)          # below multiplier
    assert not is_spike(9, 0.0, 3.0, 10)           # below min_count floor
    assert is_spike(150, 50.0, 3.0, 10)            # 3x baseline, above floor
    assert is_spike(12, 0.0, 3.0, 10)              # zero baseline, floor decides
    assert not is_spike(29, 10.0, 3.0, 10)         # under multiplier
