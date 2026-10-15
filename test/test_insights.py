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

    base = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml")
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
    # The real constructor (the thread is created but never started), so state
    # added to __init__ is always present in tests.
    return InsightsJob(cfg, store._conn, store, summarizer=summarizer)


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
    monkeypatch.setattr("webapp.api.ai_summary._supported_parameters", lambda model, base_url=None: {"reasoning_effort", "response_format"})

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __init__(self, payload):
            self._payload = payload

        def read(self, *args):
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

    assert result["summary"] == "Error spike concentrated in app namespace."
    assert result["suggested_action"] == "Inspect recent deploys and upstream dependencies."
    assert len(result["steps"]) == 1
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


def test_persistent_ai_failure_is_recorded_after_bounded_retries(store):
    """A provider that keeps failing for one anomaly must not hold the per-tick
    quota forever: after the retry budget it is marked failed, and re-detection
    keeps the recorded error."""
    from webapp.api.insights import _MAX_AI_ATTEMPTS_PER_ANOMALY

    job = make_job(store, summarizer=None)
    upsert = dict(type="message_frequency", namespace="app", pod="", rule_key="boom",
                  severity="error", detected_day="2026-09-07")
    anomaly_id = store.upsert_anomaly(evidence={"current_count": 1}, **upsert)

    def always_failing(anomaly):
        raise RuntimeError("provider rejected the request")

    job._summarizer = always_failing
    for attempt in range(1, _MAX_AI_ATTEMPTS_PER_ANOMALY + 1):
        assert job.summarize_pending() == 0
        row = store._conn.execute("SELECT ai_summarized_at FROM anomalies WHERE id=?", (anomaly_id,)).fetchone()
        assert (row["ai_summarized_at"] is None) == (attempt < _MAX_AI_ATTEMPTS_PER_ANOMALY)

    assert store.pending_ai_anomalies(10) == []
    store.upsert_anomaly(evidence={"current_count": 2}, **upsert)  # next detection tick
    item = store.query_anomalies({}, limit=10)["items"][0]
    assert item["evidence"]["current_count"] == 2
    assert item["evidence"]["ai_error"] == "provider rejected the request"


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
    _history_marker(conn)  # detection needs min_baseline_hours of stored history
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

        def read(self, *args):
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

    assert result["summary"] == "15 connection timeouts to db-1 detected in app namespace."
    assert result["suggested_action"] == "Check database db-1 health and network latency."
    assert len(result["steps"]) == 1
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

    base = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml")
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
        return {
            "summary": "Test summary.",
            "suggested_action": "Take action.",
            "steps": [{"title": "Step 1", "command": "", "explanation": "Take action.", "risk": "read-only"}],
        }

    monkeypatch.setattr("webapp.api.server.explain_logs", fake_summarize)

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


# --- Audit P1 fixes ------------------------------------------------------------

import itertools  # noqa: E402

_seq = itertools.count()


def _bulk(conn, rows):
    """rows: iterable of (timestamp, namespace, severity_bucket, message[, scope]).
    Each row gets a unique source key (unlike insert_record, which keys on time)."""
    conn.executemany(
        """
        INSERT INTO records (timestamp, severity_bucket, scope, namespace, pod, container,
                             message, raw_line, source_key, source_etag, line_number, is_falco)
        VALUES (?, ?, ?, ?, 'web-0', 'c', ?, ?, ?, 'e', 1, ?)
        """,
        [
            (ts, sev, (rest[0] if rest else f"namespaces/{ns}"), ns, msg, f"{ts} - {ns} - web-0/c - {msg}",
             f"bulk/{next(_seq)}", 1 if rest and rest[0] == "security" else 0)
            for ts, ns, sev, msg, *rest in rows
        ],
    )
    conn.commit()


def _history_marker(conn):
    """One old record in an unrelated namespace: the store has history, so
    detection runs, while the baseline of the groups under test stays empty."""
    _bulk(conn, [(_iso(HOUR_START - timedelta(days=8)), "history-marker", "info", "old")])


def _spread(start, hours, count):
    """`count` timestamps spread over `hours` hours from `start`."""
    step = timedelta(hours=hours) / max(count, 1)
    return [_iso(start + step * i) for i in range(count)]


def test_severity_shift_compares_each_namespace_with_its_own_baseline(store):
    conn = store._conn
    job = make_job(store)
    # A busy namespace dominates total volume; a small one has a stable 50/50 mix.
    _bulk(conn, [(ts, "big", "info", "ok") for ts in _spread(BASELINE_START, 24 * 7 - 1, 5000)])
    small_baseline = _spread(BASELINE_START, 24 * 7 - 1, 40)
    _bulk(conn, [(ts, "small", "error" if i % 2 else "info", "m") for i, ts in enumerate(small_baseline)])
    current = _spread(HOUR_START, 0.5, 50)
    _bulk(conn, [(ts, "small", "error" if i % 2 else "info", "m") for i, ts in enumerate(current)])

    # Same mix as its own history: no shift. (Dividing by every namespace's
    # baseline made small's baseline share ~0 and flagged both buckets.)
    assert job.detector.detect_severity_shift(NOW) == []

    # A real shift in the small namespace is still detected.
    _bulk(conn, [(ts, "small", "error", "m") for ts in _spread(HOUR_START + timedelta(minutes=1), 0.45, 60)])
    shifts = {a["severity"]: a for a in job.detector.detect_severity_shift(NOW)}
    # Error share rose 0.5 -> 0.77 and info fell 0.5 -> 0.23; both moves are >= 0.25.
    assert {(a["namespace"], sev) for sev, a in shifts.items()} == {("small", "error"), ("small", "info")}
    evidence = shifts["error"]["evidence"]
    assert evidence["baseline_total"] == 40 and evidence["baseline_share"] == 0.5
    assert evidence["current_count"] == 85 and evidence["current_share"] == round(85 / 110, 3)


def test_severity_shift_skips_namespace_without_baseline(store):
    _bulk(store._conn, [(ts, "other", "info", "ok") for ts in _spread(BASELINE_START, 24, 30)])
    _bulk(store._conn, [(ts, "brand-new", "error", "x") for ts in _spread(HOUR_START, 0.5, 30)])
    assert make_job(store).detector.detect_severity_shift(NOW) == []


def test_evidence_counts_come_from_sql_not_from_the_sample(store):
    job = make_job(store, spike_min_count=10, sample_timestamps_max=10)
    _history_marker(store._conn)
    _bulk(store._conn, [(ts, "app", "error", f"failure {i % 7}") for i, ts in enumerate(_spread(HOUR_START, 0.5, 900))])
    [spike] = job.detector.detect_error_spikes(NOW)
    evidence = spike["evidence"]
    assert evidence["current_count"] == 900                     # more rows than the sample reads
    assert len(evidence["sample_timestamps"]) == 10
    assert evidence["sample_timestamps"] == sorted(evidence["sample_timestamps"])
    assert len(evidence["sample_messages"]) == 5


def test_new_falco_rule_lookback_is_bounded_by_the_baseline_window(store):
    job = make_job(store)
    rule = "Terminal shell in container"
    _bulk(store._conn, [(_iso(HOUR_START + timedelta(minutes=5)), "falco", "warning", rule, "security")])
    # Seen 10 days ago: outside the 7-day window, so it counts as new again.
    _bulk(store._conn, [(_iso(HOUR_START - timedelta(days=10)), "falco", "warning", rule, "security")])
    assert [a["rule_key"] for a in job.detector.detect_new_falco_rules(NOW)] == [rule]
    # Seen 2 days ago: not new.
    _bulk(store._conn, [(_iso(HOUR_START - timedelta(days=2)), "falco", "warning", rule, "security")])
    assert job.detector.detect_new_falco_rules(NOW) == []


def test_recurrence_clears_stale_ai_summary_and_counts_are_accurate(store):
    job = make_job(store, spike_min_count=10)
    _bulk(store._conn, [(ts, "app", "error", "boom") for ts in _spread(HOUR_START, 0.5, 20)])
    _history_marker(store._conn)

    first = job.run_once(NOW)
    assert first["anomalies_created"] >= 1 and first["anomalies_updated"] == 0
    second = job.run_once(NOW + timedelta(minutes=5))           # same hour, next tick
    assert second["anomalies_created"] == 0 and second["anomalies_updated"] == first["anomalies_created"]

    spike = next(a for a in store.query_anomalies({}, limit=10)["items"] if a["type"] == "error_rate_spike")
    store.save_ai_summary(spike["id"], "Errors at 12:00", "Check web", [{"title": "t", "command": "kubectl get pods"}])
    store.record_ai_failure(spike["id"], "old failure")

    # Same occurrence: the summary stays.
    _, outcome = store.record_detection(type="error_rate_spike", namespace="app", pod="", rule_key="",
                                        severity="error", evidence={**spike["evidence"], "current_count": 30},
                                        detected_day=spike["detected_day"])
    assert outcome == "updated"
    row = store.query_anomalies({}, limit=10)["items"][0]
    assert row["ai_summary"] == "Errors at 12:00" and row["evidence"]["ai_error"] == "old failure"

    # A later hour of the same day replaces the evidence: the old summary,
    # steps and AI error no longer describe it and are cleared for re-summary.
    later = {**spike["evidence"], "window_start": "2026-09-07T15:00:00Z", "window_end": "2026-09-07T16:00:00Z"}
    _, outcome = store.record_detection(type="error_rate_spike", namespace="app", pod="", rule_key="",
                                        severity="error", evidence=later, detected_day=spike["detected_day"])
    assert outcome == "recurred"
    row = next(a for a in store.query_anomalies({}, limit=10)["items"] if a["id"] == spike["id"])
    assert row["ai_summary"] is None and row["ai_steps"] == [] and row["ai_summarized_at"] is None
    assert "ai_error" not in row["evidence"] and row["evidence"]["window_start"] == "2026-09-07T15:00:00Z"
    assert spike["id"] in [a["id"] for a in store.pending_ai_anomalies(10)]


def test_stored_plan_risk_is_recomputed_and_never_lower_than_the_command(store):
    anomaly_id = store.upsert_anomaly(type="message_frequency", namespace="app", pod="", rule_key="x",
                                      severity="error", evidence={"current_count": 1}, detected_day="2026-09-07")
    store.save_ai_summary(anomaly_id, "s", "a", [
        {"title": "a", "command": "kubectl delete namespace prod", "risk": "read-only"},
        {"title": "b", "command": "kubectl rollout restart deployment/web -n app", "risk": "read-only"},
        {"title": "c", "command": "kubectl get pods -n app", "risk": "high"},
        {"title": "d", "command": "kubectl get pods -n app", "risk": "read-only"},
    ])
    steps = store.query_anomalies({}, limit=10)["items"][0]["ai_steps"]
    assert [s["risk"] for s in steps] == ["high", "medium", "high", "read-only"]


# --- C9: baseline history, partial hours, completed-hour re-check ------------

def _hourly(start, hours, per_hour, namespace="app", severity="error", message="boom"):
    """`per_hour` rows in each of `hours` consecutive hours from `start`."""
    rows = []
    for h in range(hours):
        base = start + timedelta(hours=h)
        rows += [(_iso(base + timedelta(minutes=m * 60 // per_hour)), namespace, severity, message)
                 for m in range(per_hour)]
    return rows


def test_new_install_is_learning_and_raises_nothing(store):
    job = make_job(store, spike_min_count=10)
    # 30 minutes of data in total, all of it errors: no baseline to compare with.
    _bulk(store._conn, [(ts, "app", "error", "boom") for ts in _spread(HOUR_START, 0.4, 50)])
    counts = job.run_once(NOW)
    assert counts["anomalies_created"] == 0
    status = job.status()
    assert status["learning"] is True and status["history_hours"] == 0.0
    # Once enough history exists, the same data is evaluated.
    _bulk(store._conn, [(_iso(HOUR_START - timedelta(hours=30)), "app", "info", "started")])
    assert job.run_once(NOW)["anomalies_created"] >= 1
    assert job.status()["learning"] is False and job.status()["history_hours"] == 30.0


def test_baseline_divides_by_available_history_not_the_full_window(store):
    """Two days of history at 10 errors/hour, then an hour with 20 (2x): not a
    3x spike. Dividing by 7 days would have made the baseline 2.9/hour and
    flagged it."""
    job = make_job(store, spike_min_count=10, spike_multiplier=3.0)
    first = HOUR_START - timedelta(hours=48)
    _bulk(store._conn, _hourly(first, 47, 10))                                  # 47 complete hours
    _bulk(store._conn, _hourly(HOUR_START - timedelta(hours=1), 1, 20))          # previous hour: 20
    at = HOUR_START + timedelta(minutes=10)                                     # open hour too young
    assert job.detector.detect_error_spikes(at) == []
    # 31 in the previous hour is a real 3x spike against the true 10/hour.
    _bulk(store._conn, _hourly(HOUR_START - timedelta(hours=1), 1, 11, message="boom2"))
    [spike] = job.detector.detect_error_spikes(at)
    ev = spike["evidence"]
    assert ev["window_start"] == _iso(HOUR_START - timedelta(hours=1)) and ev["window_complete"] is True
    assert ev["baseline_hours"] == 47.0 and ev["baseline_avg_per_hour"] == 10.0
    assert ev["current_count"] == 31 and ev["expected_count"] == 10.0


def test_open_hour_is_compared_with_the_same_duration_of_baseline(store):
    job = make_job(store, spike_min_count=10, spike_multiplier=3.0)
    _bulk(store._conn, _hourly(BASELINE_START, 24 * 7, 12))                     # 12/hour for a week
    # 12 errors in the first 20 minutes = 36/hour: three times the usual rate.
    _bulk(store._conn, [(_iso(HOUR_START + timedelta(minutes=m)), "app", "error", "burst") for m in range(12)])
    at = HOUR_START + timedelta(minutes=20)
    [spike] = job.detector.detect_error_spikes(at)
    ev = spike["evidence"]
    assert ev["window_complete"] is False and ev["observed_minutes"] == 20.0
    assert ev["current_count"] == 12 and ev["expected_count"] == 4.0
    # Before min_partial_window_minutes the open hour is not judged at all.
    assert job.detector.detect_error_spikes(HOUR_START + timedelta(minutes=10)) == []
    # Rows stamped after `now` (clock skew) are not counted yet.
    _bulk(store._conn, [(_iso(HOUR_START + timedelta(minutes=50)), "app", "error", "future")])
    assert job.detector.detect_error_spikes(at)[0]["evidence"]["current_count"] == 12


def test_completed_hour_is_rechecked_so_late_rows_are_not_missed(store):
    job = make_job(store, spike_min_count=10)
    _bulk(store._conn, _hourly(BASELINE_START, 24 * 7, 1))                      # 1/hour baseline
    _bulk(store._conn, [(_iso(HOUR_START + timedelta(minutes=m)), "app", "error", "x") for m in range(8)])
    late_tick = HOUR_START + timedelta(minutes=58)
    assert job.run_once(late_tick)["anomalies_created"] == 0                     # 8 < floor of 10
    # The rest of the hour's rows arrive after the hour ended (late S3 batch).
    _bulk(store._conn, [(_iso(HOUR_START + timedelta(minutes=50 + m)), "app", "error", "y") for m in range(8)])
    counts = job.run_once(HOUR_START + timedelta(hours=1, minutes=5))
    assert counts["anomalies_created"] == 1
    [anomaly] = store.query_anomalies({}, limit=10)["items"]
    assert anomaly["evidence"]["window_start"] == _iso(HOUR_START)
    assert anomaly["evidence"]["current_count"] == 16 and anomaly["evidence"]["window_complete"] is True


def test_previous_hour_after_midnight_belongs_to_the_previous_day(store):
    job = make_job(store, spike_min_count=10)
    day_start = HOUR_START.replace(hour=0)
    _bulk(store._conn, _hourly(day_start - timedelta(days=7), 24 * 7 - 1, 1))
    _bulk(store._conn, [(_iso(day_start - timedelta(minutes=50) + timedelta(minutes=m)), "app", "error", "x")
                        for m in range(20)])                                  # 23:10–23:29 the day before
    job.run_once(day_start + timedelta(minutes=5))
    [anomaly] = store.query_anomalies({}, limit=10)["items"]
    assert anomaly["detected_day"] == (day_start - timedelta(days=1)).strftime("%Y-%m-%d")


def test_newest_flagged_window_wins_and_evidence_never_moves_back(store):
    job = make_job(store, spike_min_count=10)
    _bulk(store._conn, _hourly(BASELINE_START, 24 * 7, 1))
    prev = HOUR_START - timedelta(hours=1)
    _bulk(store._conn, [(_iso(prev + timedelta(minutes=m)), "app", "error", "p") for m in range(30)])
    _bulk(store._conn, [(_iso(HOUR_START + timedelta(minutes=m)), "app", "error", "c") for m in range(30)])
    at = HOUR_START + timedelta(minutes=40)
    [spike] = job.detector.detect_error_spikes(at)                             # one per group
    assert spike["evidence"]["window_start"] == _iso(HOUR_START)
    job.run_once(at)
    # A later run where only the previous hour still qualifies does not
    # replace the newer occurrence (no flip-flop, no needless re-summary).
    _, outcome = store.record_detection(type="error_rate_spike", namespace="app", pod="", rule_key="",
                                        severity="error", evidence={"window_start": _iso(prev), "current_count": 31},
                                        detected_day=HOUR_START.strftime("%Y-%m-%d"))
    assert outcome == "unchanged"
    [anomaly] = store.query_anomalies({"type": "error_rate_spike"}, limit=10)["items"]
    assert anomaly["evidence"]["window_start"] == _iso(HOUR_START)


# --- Second hardening pass: gap visibility and future timestamps -------------

def test_evidence_reports_baseline_hours_without_data(store):
    job = make_job(store, spike_min_count=10, spike_multiplier=3.0)
    first = HOUR_START - timedelta(hours=48)
    _bulk(store._conn, _hourly(first, 10, 10))                                   # 10 hours of data...
    _bulk(store._conn, _hourly(first + timedelta(hours=40), 7, 10))              # ...a 30-hour gap, 7 more
    _bulk(store._conn, _hourly(HOUR_START - timedelta(hours=1), 1, 60))          # 60 in the previous hour
    [spike] = job.detector.detect_error_spikes(HOUR_START + timedelta(minutes=10))
    ev = spike["evidence"]
    assert ev["baseline_hours"] == 47.0 and ev["baseline_hours_with_data"] == 17


def test_future_dated_records_are_counted_not_evaluated(store):
    job = make_job(store, spike_min_count=1)
    _bulk(store._conn, _hourly(BASELINE_START, 24 * 7, 1, severity="info"))
    _bulk(store._conn, [(_iso(NOW + timedelta(hours=3)), "app", "error", "skewed clock")] * 1)
    _bulk(store._conn, [(_iso(NOW + timedelta(minutes=2)), "app", "info", "slight skew")])
    counts = job.run_once(NOW)
    assert job.status()["future_dated_records"] == 1                        # beyond the 5-minute tolerance
    assert all(a["evidence"]["current_count"] >= 0 for a in store.query_anomalies({}, limit=10)["items"])
    assert counts["anomalies_created"] == 0
