from __future__ import annotations

import json
import logging
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.ai_summary import summarize_anomaly  # noqa: E402
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


NOW = datetime(2026, 9, 7, 12, 30, 0, tzinfo=timezone.utc)
HOUR_START = NOW.replace(minute=0, second=0, microsecond=0)
BASELINE_START = HOUR_START - timedelta(days=7)


def _iso(dt: datetime) -> str:
    """ISO-8601 with trailing Z, matching the records.timestamp format."""
    return dt.isoformat().replace("+00:00", "Z")


def insert_record(conn, *, timestamp, namespace="app", pod="web-0", message="boom",
                  severity_bucket="info", scope="namespaces/app"):
    """Insert a single record.  source_key incorporates the timestamp so that
    INSERT OR IGNORE won't silently drop records that share a timestamp."""
    conn.execute(
        """
        INSERT OR IGNORE INTO records (timestamp, severity_bucket, scope, namespace, pod, container,
                             message, raw_line, source_key, source_etag, line_number, is_falco)
        VALUES (?, ?, ?, ?, ?, 'c', ?, ?, ?, 'e', 1, ?)
        """,
        (
            timestamp, severity_bucket, scope, namespace, pod, message,
            f"{timestamp} - {namespace} - {pod}/c - {message}",
            f"k/{timestamp}",
            "1" if scope == "security" else "0",
        ),
    )
    conn.commit()


@pytest.fixture()
def store(tmp_path):
    """AnomalyStore with a records table (LogStorage creates it first)."""
    db_path = tmp_path / "webapp.sqlite"
    LogStorage(db_path)  # side-effect: creates the ``records`` table
    return AnomalyStore(db_path)


def make_job(store, summarizer=None, **overrides):
    """Build an InsightsJob without starting its thread.

    The detector reads from ``store._conn`` directly, so the db_path in *cfg*
    is irrelevant — it only needs to satisfy the frozen-dataclass shape.
    """
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
    from webapp.api.config import AiConfig, InsightsConfig
    from dataclasses import replace

    base = load_app_config(ROOT / "config.yaml")
    cfg = replace(
        base,
        insights=InsightsConfig(**defaults),
        ai=AiConfig(
            provider="none",
            model="",
            api_key_env="LOGSCOPE_AI_API_KEY",
            max_anomalies_per_tick=5,
            reasoning_effort="medium",
        ),
    )
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


# --- Error-rate spike detection ----------------------------------------------

def _fill_baseline_errors(conn, count=168, namespace="app", pod="web-0"):
    """Insert *count* error records, one per hour, across the baseline window."""
    for i in range(count):
        ts = _iso(BASELINE_START + timedelta(hours=i))
        insert_record(conn, timestamp=ts, namespace=namespace, pod=pod,
                      severity_bucket="error", message="boom")


def _fill_current_errors(conn, count, namespace="app", pod="web-0"):
    """Insert *count* error records inside the current hour."""
    for i in range(count):
        ts = _iso(HOUR_START + timedelta(minutes=i))
        insert_record(conn, timestamp=ts, namespace=namespace, pod=pod,
                      severity_bucket="error", message="boom")


def test_error_rate_spike_detection(store):
    """20 current errors vs 1/hour baseline → spike anomaly."""
    conn = store._conn
    _fill_baseline_errors(conn, count=168)
    _fill_current_errors(conn, count=20)
    detector = InsightsDetector(conn, make_job(store).cfg.insights)
    anomalies = detector.detect_error_spikes(NOW)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a["type"] == "error_rate_spike"
    assert a["namespace"] == "app"
    assert a["pod"] == ""          # per-pod grouping is off by default
    assert a["evidence"]["current_count"] == 20
    assert a["evidence"]["baseline_avg_per_hour"] == 1.0
    assert a["evidence"]["multiplier"] == 3.0


def test_error_rate_spike_per_pod(store):
    """With detect_per_pod, the anomaly is keyed by pod."""
    conn = store._conn
    _fill_baseline_errors(conn, count=168)
    _fill_current_errors(conn, count=20)
    cfg = make_job(store, detect_per_pod=True).cfg.insights
    detector = InsightsDetector(conn, cfg)
    anomalies = detector.detect_error_spikes(NOW, per_pod=True)
    assert len(anomalies) == 1
    assert anomalies[0]["pod"] == "web-0"


def test_error_rate_no_spike_below_floor(store):
    """9 current errors is below the min_count floor of 10 → no anomaly."""
    conn = store._conn
    _fill_baseline_errors(conn, count=168)
    _fill_current_errors(conn, count=9)
    detector = InsightsDetector(conn, make_job(store).cfg.insights)
    assert detector.detect_error_spikes(NOW) == []


def test_error_rate_no_spike_when_baseline_high(store):
    """High baseline keeps current below multiplier × baseline → no anomaly."""
    conn = store._conn
    # 168 hours × 30 errors/hour = 5040 → baseline_avg = 30
    # Current = 80 → 80 < 3.0 * 30 = 90 → no spike
    for i in range(168):
        ts = _iso(BASELINE_START + timedelta(hours=i))
        for j in range(30):
            insert_record(conn, timestamp=f"{ts[:11]}{int(ts[11:13]):02d}.{j:02d}Z",
                          namespace="app", pod="web-0", severity_bucket="error",
                          message="boom")
    _fill_current_errors(conn, count=80)
    detector = InsightsDetector(conn, make_job(store).cfg.insights)
    assert detector.detect_error_spikes(NOW) == []


def test_openrouter_summarize_anomaly_uses_supported_parameters(monkeypatch, caplog):
    from webapp.api.config import AiConfig

    anomaly = {
        "type": "message_frequency",
        "namespace": "app",
        "pod": "",
        "rule_key": "boom",
        "severity": "error",
        "evidence": {"current_count": 42, "baseline_avg_per_hour": 4.2},
    }
    cfg = AiConfig(
        provider="openrouter",
        model="qwen/qwen3.5-plus:free",
        api_key_env="OPENROUTER_API_KEY",
        max_anomalies_per_tick=5,
        reasoning_effort="medium",
    )
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr("webapp.api.ai_summary._supported_parameters", lambda model: {"reasoning_effort", "response_format"})

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "summary": "Error spike concentrated in app namespace.",
                                    "suggested_action": "Inspect recent deploys and upstream dependencies.",
                                }
                            )
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", fake_urlopen)
    result = summarize_anomaly(anomaly, cfg)

    assert result == {
        "summary": "Error spike concentrated in app namespace.",
        "suggested_action": "Inspect recent deploys and upstream dependencies.",
    }
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["body"]["model"] == "qwen/qwen3.5-plus:free"
    assert captured["body"]["reasoning_effort"] == "medium"
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert captured["body"]["messages"][1]["content"] == json.dumps(
        {
            "type": "message_frequency",
            "namespace": "app",
            "pod": "",
            "rule_key": "boom",
            "severity": "error",
            "evidence": {"current_count": 42, "baseline_avg_per_hour": 4.2},
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def test_openrouter_missing_model_logs_once(monkeypatch, caplog):
    from webapp.api.config import AiConfig

    anomaly = {"type": "message_frequency", "namespace": "app", "pod": "", "rule_key": "boom", "severity": "error", "evidence": {}}
    cfg = AiConfig(
        provider="openrouter",
        model="",
        api_key_env="OPENROUTER_API_KEY",
        max_anomalies_per_tick=5,
        reasoning_effort="medium",
    )
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    caplog.set_level(logging.WARNING)

    assert summarize_anomaly(anomaly, cfg) is None
    assert summarize_anomaly(anomaly, cfg) is None
    warnings = [record.message for record in caplog.records if "no model is set" in record.message]
    assert len(warnings) == 1


def test_ai_failure_keeps_anomaly_retryable(store):
    conn = store._conn
    insert_record(conn, timestamp=_iso(HOUR_START), namespace="app", pod="web-0", severity_bucket="error", message="boom")
    job = make_job(store, summarizer=None)
    anomaly_id = store.upsert_anomaly(
        type="message_frequency",
        namespace="app",
        pod="",
        rule_key="boom",
        severity="error",
        evidence={"current_count": 1},
        detected_day="2026-09-07",
    )
    calls = []

    def flaky_summarizer(anomaly):
        calls.append(anomaly["id"])
        if len(calls) == 1:
            raise RuntimeError("temporary upstream outage")
        return {"summary": "retry succeeded", "suggested_action": "Proceed."}

    job._summarizer = flaky_summarizer

    assert job.summarize_pending() == 0
    row = conn.execute(
        "SELECT ai_summary, ai_suggested_action, ai_summarized_at FROM anomalies WHERE id=?",
        (anomaly_id,),
    ).fetchone()
    assert row["ai_summary"] is None
    assert row["ai_suggested_action"] is None
    assert row["ai_summarized_at"] is None

    assert job.summarize_pending() == 1
    row = conn.execute(
        "SELECT ai_summary, ai_suggested_action, ai_summarized_at FROM anomalies WHERE id=?",
        (anomaly_id,),
    ).fetchone()
    assert row["ai_summary"] == "retry succeeded"
    assert row["ai_suggested_action"] == "Proceed."
    assert row["ai_summarized_at"] is not None


def test_evidence_includes_sample_messages_for_spikes_and_frequency(store):
    conn = store._conn
    # Insert 15 error records with 3 distinct log messages
    msgs = ["Connection timeout to db-1", "HTTP 502 Bad Gateway", "Disk quota exceeded"]
    for i in range(15):
        ts = _iso(HOUR_START + timedelta(minutes=i))
        insert_record(
            conn,
            timestamp=ts,
            namespace="app",
            pod="web-0",
            severity_bucket="error",
            message=msgs[i % len(msgs)],
        )

    detector = InsightsDetector(conn, make_job(store).cfg.insights)
    spikes = detector.detect_error_spikes(NOW)
    assert len(spikes) == 1
    spike_evidence = spikes[0]["evidence"]
    assert "sample_messages" in spike_evidence
    assert isinstance(spike_evidence["sample_messages"], list)
    assert len(spike_evidence["sample_messages"]) == 3
    assert set(spike_evidence["sample_messages"]) == set(msgs)

    # Insert 35 records for a recurring message to cross frequency_min_count (30)
    for i in range(35):
        ts = _iso(HOUR_START + timedelta(seconds=i + 1))
        insert_record(
            conn,
            timestamp=ts,
            namespace="app",
            pod="web-0",
            severity_bucket="info",
            message="Recurring healthcheck failure",
        )

    freqs = detector.detect_message_frequency(NOW)
    assert len(freqs) >= 1
    freq_evidence = freqs[0]["evidence"]
    assert "sample_messages" in freq_evidence
    assert len(freq_evidence["sample_messages"]) >= 1
    assert "Recurring healthcheck failure" in freq_evidence["sample_messages"]


def test_gemini_summarize_anomaly_uses_correct_headers(monkeypatch):
    from webapp.api.config import AiConfig

    anomaly = {
        "type": "error_rate_spike",
        "namespace": "app",
        "pod": "web-0",
        "rule_key": "",
        "severity": "error",
        "evidence": {
            "current_count": 15,
            "sample_messages": ["Connection timeout to db-1"],
        },
    }
    cfg = AiConfig(
        provider="gemini",
        model="gemini-2.5-flash",
        api_key_env="GEMINI_API_KEY",
        max_anomalies_per_tick=5,
        reasoning_effort="medium",
    )
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": json.dumps(
                                            {
                                                "summary": "15 connection timeouts to db-1 detected in app namespace.",
                                                "suggested_action": "Check database db-1 health and network latency.",
                                            }
                                        )
                                    }
                                ]
                            }
                        }
                    ]
                }
            ).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr("webapp.api.ai_summary.request.urlopen", fake_urlopen)
    result = summarize_anomaly(anomaly, cfg)

    assert result == {
        "summary": "15 connection timeouts to db-1 detected in app namespace.",
        "suggested_action": "Check database db-1 health and network latency.",
    }
    assert captured["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    # Auth header must be x-goog-api-key, NOT Authorization Bearer
    assert captured["headers"]["X-goog-api-key"] == "test-gemini-key"
    assert "Authorization" not in captured["headers"]
    # Body must be Gemini format with systemInstruction and contents
    assert "systemInstruction" in captured["body"]
    assert "contents" in captured["body"]
    assert "generationConfig" in captured["body"]
    assert captured["body"]["generationConfig"]["responseMimeType"] == "application/json"
    # reasoning_effort must be dropped silently
    assert "reasoning_effort" not in captured["body"]


def test_anomaly_store_set_status(store):
    """set_status() updates status to reviewed/dismissed; rejects invalid values."""
    anomaly_id = store.upsert_anomaly(
        type="error_rate_spike",
        namespace="default",
        pod="",
        rule_key="",
        severity="error",
        evidence={"current_count": 5},
        detected_day="2026-09-07",
    )

    # Initial status is 'new'
    row = store._conn.execute("SELECT status FROM anomalies WHERE id=?", (anomaly_id,)).fetchone()
    assert row["status"] == "new"

    # Mark as reviewed
    updated = store.set_status(anomaly_id, "reviewed")
    assert updated is True
    row = store._conn.execute("SELECT status FROM anomalies WHERE id=?", (anomaly_id,)).fetchone()
    assert row["status"] == "reviewed"

    # Mark as dismissed
    updated = store.set_status(anomaly_id, "dismissed")
    assert updated is True
    row = store._conn.execute("SELECT status FROM anomalies WHERE id=?", (anomaly_id,)).fetchone()
    assert row["status"] == "dismissed"

    # Invalid status raises ValueError
    with pytest.raises(ValueError, match="Invalid status"):
        store.set_status(anomaly_id, "deleted")

    # Non-existent id returns False
    updated = store.set_status(999999, "reviewed")
    assert updated is False


def test_explain_cache_returns_cached_on_second_call(monkeypatch, tmp_path):
    """api_explain returns cached:True and skips AI on the second call with same filters."""
    from dataclasses import replace
    from webapp.api.config import AiConfig
    from webapp.api.server import WebApp
    from webapp.api.storage import LogStorage

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    db_path = tmp_path / "webapp.sqlite"
    # Create schema via LogStorage first
    storage = LogStorage(db_path)

    base = load_app_config(ROOT / "config.yaml")
    cfg = replace(
        base,
        ai=AiConfig(
            provider="gemini",
            model="gemini-2.5-flash",
            api_key_env="GEMINI_API_KEY",
            max_anomalies_per_tick=5,
            reasoning_effort="medium",
        ),
        webapp=replace(base.webapp, db_path=db_path),
    )

    app = WebApp(cfg)

    call_count = [0]

    def fake_summarize(payload, ai_cfg):
        call_count[0] += 1
        return {"summary": "Test summary.", "suggested_action": "Take action."}

    monkeypatch.setattr("webapp.api.server.summarize_anomaly", fake_summarize)

    # Insert one log record so the explain has something to sample
    app.storage.conn.execute(
        "INSERT OR IGNORE INTO records (timestamp, severity_bucket, scope, namespace, pod, container,"
        " message, raw_line, source_key, source_etag, line_number, is_falco)"
        " VALUES ('2026-09-07T12:00:00Z', 'error', 'namespaces/default', 'default', 'web-0', 'c',"
        " 'Connection timeout', 'raw', 'k/test', 'e', 1, 0)"
    )
    app.storage.conn.commit()

    params1: dict[str, list[str]] = {"namespace": ["default"]}
    result1 = app.api_explain(params1)
    assert result1["cached"] is False
    assert result1["summary"] == "Test summary."
    assert call_count[0] == 1

    # Second call with identical params — must use cache, not call AI again
    result2 = app.api_explain(params1)
    assert result2["cached"] is True
    assert result2["summary"] == "Test summary."
    assert call_count[0] == 1  # still 1 — AI was not called a second time
