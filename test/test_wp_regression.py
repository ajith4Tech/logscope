"""End-to-end replay of the WordPress detection test (test-results/wp-detection.md)
against the Parts 1-4 fixes: ingest -> insights -> auto-triage.

Asserts the behaviour the straight measurement found missing:
  * Wave A/B now produce a message_frequency anomaly (before: none, because the
    detector grouped on raw text and 404s were info).
  * The start-up DB-retry burst and entrypoint shell do NOT alert (before: two
    false positives), but are still recorded (nothing silently lost).
  * The firing warning-severity anomaly is auto-triaged (carries ai_meta).
  * Wave C (CVE content-injection PoC) is still NOT auto-detected -- xfail, so
    the remaining gap stays visible in the test output.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.config import AiConfig, InsightsConfig, load_app_config  # noqa: E402
from webapp.api.explain import anomaly_cache_key, decorate  # noqa: E402
from webapp.api.insights import AnomalyStore, InsightsJob  # noqa: E402
from webapp.api.parser import make_record  # noqa: E402
from webapp.api.patterns import record_template  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402
from webapp.api.summary_worker import SummaryWorker  # noqa: E402

FIXTURE = ROOT / "test" / "fixtures" / "wp_attack_replay" / "waves.json"


# ── replay helpers ───────────────────────────────────────────────────────────

def _load_fixture() -> dict:
    with open(FIXTURE) as fh:
        return json.load(fh)


def _records_from_spec(spec: dict) -> list[dict]:
    """Expand one wave spec into records through the real ingest path
    (make_record), so Part 2's access-log re-classification is exercised."""
    start = datetime.fromisoformat(spec["start"].replace("Z", "+00:00"))
    scope = "security" if spec["scope"] == "security" else "namespace"
    out: list[dict] = []
    for i in range(spec["count"]):
        ts = start.timestamp() + i * spec["step_s"]
        ts_iso = datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")
        message = spec["message"].format(i=i, ip=(i % 250) + 1)
        raw = f"{ts_iso} - {spec['namespace']} - {spec['pod']}/{spec['container']} - {message}"
        record = make_record(
            raw_line=raw,
            source_bucket=spec["bucket"],
            source_scope=scope,
            source_key=f"wp/{spec['name']}",
            source_etag="e",
            line_number=i,
            infra_namespaces=(),
        )
        assert record is not None
        out.append(record)
    return out


def _replay(tmp_path) -> tuple[AnomalyStore, InsightsJob, datetime, dict]:
    fixture = _load_fixture()
    db = tmp_path / "webapp.sqlite"
    storage = LogStorage(db)
    all_records: dict[str, list[dict]] = {}
    for spec in fixture["specs"]:
        records = _records_from_spec(spec)
        all_records[spec["name"]] = records
        storage.insert_records(records)
    store = AnomalyStore(db)

    base = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml")
    # Production guard defaults: this is what the real deployment runs.
    insights = InsightsConfig(
        enabled=True, detect_interval_secs=300, baseline_window_days=7,
        spike_multiplier=3.0, spike_min_count=10, shift_share_delta=0.25, shift_min_count=20,
        frequency_multiplier=5.0, frequency_min_count=30, detect_per_pod=False,
        sample_timestamps_max=10, min_baseline_hours=24, min_partial_window_minutes=15,
        cold_start_grace_s=600, min_baseline_samples=5,
    )
    cfg = replace(
        base, insights=insights,
        ai=AiConfig(provider="none", model="", api_key_env="LOGSCOPE_AI_API_KEY",
                    max_anomalies_per_tick=5, reasoning_effort="medium"),
    )
    job = InsightsJob(cfg, storage._conn, store)
    now = datetime.fromisoformat(fixture["now"].replace("Z", "+00:00"))
    return store, job, now, all_records


def _anomalies(store: AnomalyStore, **filt) -> list[dict]:
    items = store.query_anomalies({}, limit=200)["items"]
    return [a for a in items if all(a.get(k) == v for k, v in filt.items())]


# ── a minimal explain double for the auto-triage worker ──────────────────────

class _FakeSettings:
    def __init__(self, flags: dict[str, bool]):
        self._flags = flags

    def enabled(self, feature: str) -> bool:
        return bool(self._flags.get(feature, False))


class _FakeService:
    def signature_hit(self, feature: str) -> None:
        pass


class _FakeExplainer:
    """Implements exactly what SummaryWorker.process touches: no signature, no
    cache, a configured provider that returns an AI-sourced summary (or a budget
    block when degraded=True)."""

    def __init__(self, flags: dict[str, bool], *, degraded: bool = False):
        self.settings = _FakeSettings(flags)
        self.service = _FakeService()
        self._degraded = degraded

    def anomaly_signature_answer(self, anomaly):
        return None

    def configured(self) -> bool:
        return True

    def _cached(self, key, feature, tier, *a, **k):
        return None

    def summarize_anomaly(self, anomaly, **kwargs):
        if self._degraded:
            return {"degraded": True}
        return decorate(
            {"summary": "Likely HTTP probing: a burst of 404s to /?author=N from many client IPs.",
             "suggested_action": "Check the source IPs and consider rate-limiting.", "steps": []},
            source="ai", tier="fast", cache_key=anomaly_cache_key("fast", anomaly),
        )

    def summarize_batch(self, anomalies, *, feature):
        return {int(a["id"]): self.summarize_anomaly(a) for a in anomalies}


def _triage_worker(store, *, degraded=False, triage=True):
    explainer = _FakeExplainer({"auto_triage": triage, "anomaly_auto_summary": False}, degraded=degraded)
    return SummaryWorker(explainer, store, min_urgency=lambda: "urgent",
                         triage_min_urgency=lambda: "high")


def _drain(worker: SummaryWorker, pending: list[dict]) -> int:
    queued = worker.enqueue(pending)
    while True:
        batch = worker.take_batch(timeout=0)
        if not batch:
            break
        worker.process(batch)
    return queued


# ── Part 1: template grouping ────────────────────────────────────────────────

def test_wave_b_collapses_to_one_template_count_400(tmp_path):
    _, _, _, records = _replay(tmp_path)
    wave_b = records["B_bruteforce"]
    assert len(wave_b) == 400
    template_ids = {record_template(r)[0] for r in wave_b}
    assert len(template_ids) == 1  # 400 near-identical lines -> one template


# ── Part 2: HTTP-aware severity ──────────────────────────────────────────────

def test_access_log_status_drives_severity(tmp_path):
    _, _, _, records = _replay(tmp_path)
    # 404 author-scan -> warning; 200 brute-force/baseline -> info (unchanged).
    assert {r["severity_bucket"] for r in records["A_enum"]} == {"warning"}
    assert {r["severity_bucket"] for r in records["B_bruteforce"]} == {"info"}
    assert {r["severity_bucket"] for r in records["idle_baseline"]} == {"info"}
    # Non-access lines are untouched.
    assert {r["severity_bucket"] for r in records["startup_db_errors"]} == {"error"}
    a = records["A_enum"][0]
    assert a["http_meta"] and json.loads(a["http_meta"])["status"] == 404


# ── Parts 1+3: detection outcome ─────────────────────────────────────────────

def test_waves_detected_and_startup_suppressed(tmp_path):
    store, job, now, _ = _replay(tmp_path)
    job.detect_once(now)

    freqs = _anomalies(store, type="message_frequency", namespace="sec-test", status="new")
    # Wave A (warning) and Wave B (info) both now surface (before: none).
    assert len(freqs) >= 2
    severities = {f["severity"] for f in freqs}
    assert "warning" in severities and "info" in severities
    # Wave B collapsed to one template counted as 400.
    b = [f for f in freqs if f["severity"] == "info"][0]
    assert b["evidence"]["current_count"] == 400

    # Start-up DB-retry errors: no firing error_rate_spike (insufficient baseline).
    assert _anomalies(store, type="error_rate_spike", status="new") == []

    # Entrypoint shell: recorded but suppressed as cold-start, never alerted.
    shells = _anomalies(store, type="new_falco_rule")
    assert shells, "the shell event should be recorded (nothing silently lost)"
    assert all(s["status"] == "suppressed_cold_start" for s in shells)
    assert _anomalies(store, type="new_falco_rule", status="new") == []


# ── Part 4: auto-triage ──────────────────────────────────────────────────────

def test_firing_anomaly_is_auto_triaged(tmp_path):
    store, job, now, _ = _replay(tmp_path)
    job.detect_once(now)
    worker = _triage_worker(store)

    pending = store.pending_ai_anomalies(50)
    queued = _drain(worker, pending)
    assert queued >= 1  # the warning-severity Wave A frequency spike (urgency high)

    triaged = [a for a in _anomalies(store, type="message_frequency", severity="warning")
               if a.get("ai_meta")]
    assert triaged, "the warning frequency spike should carry an ai_meta from auto-triage"
    assert triaged[0]["ai_meta"]["source"] == "ai"

    # An info-severity (medium) spike is NOT auto-triaged at the high threshold.
    info_freq = _anomalies(store, type="message_frequency", severity="info")
    assert info_freq and all(not a.get("ai_meta") for a in info_freq)


def test_auto_triage_only_on_transition_not_every_eval(tmp_path):
    store, job, now, _ = _replay(tmp_path)
    job.detect_once(now)
    worker = _triage_worker(store)
    assert _drain(worker, store.pending_ai_anomalies(50)) >= 1
    # Re-evaluating the same (still-firing) window is an "update", which keeps the
    # summary: nothing is pending, so auto-triage does not run again.
    job.detect_once(now)
    assert _drain(worker, store.pending_ai_anomalies(50)) == 0


def test_budget_blocked_leaves_anomaly_untriggered(tmp_path):
    store, job, now, _ = _replay(tmp_path)
    job.detect_once(now)
    worker = _triage_worker(store, degraded=True)  # provider over budget
    _drain(worker, store.pending_ai_anomalies(50))  # must not raise
    assert all(not a.get("ai_meta")
               for a in _anomalies(store, type="message_frequency", severity="warning"))


def test_new_falco_rule_is_never_auto_triaged(tmp_path):
    # A high-urgency new_falco_rule is still excluded from auto-triage.
    explainer = _FakeExplainer({"auto_triage": True, "anomaly_auto_summary": False})
    worker = SummaryWorker(explainer, object(), min_urgency=lambda: "urgent",
                           triage_min_urgency=lambda: "high")
    falco = {"id": 1, "type": "new_falco_rule", "severity": "error", "namespace": "",
             "pod": "", "rule_key": "x", "evidence": "{}"}
    assert worker.wants(falco) is False


# ── Part 5: the remaining gap stays visible ──────────────────────────────────

def test_wave_c_cve_identified_by_signature(tmp_path):
    # Wave C is only 3 requests (below the frequency floor), so no volume anomaly
    # fires -- that half of the gap remains (needs web->runtime correlation). But
    # the web-attack signature pack now correctly identifies the CVE shape, which
    # is what the real test showed the AI could already do manually.
    from webapp.api.signatures import SignatureKB, load_rules
    store, job, now, records = _replay(tmp_path)
    job.detect_once(now)
    kb = SignatureKB(load_rules())
    matches = [kb.match_record(r) for r in records["C_cve"]]
    assert matches and all(m is not None for m in matches)
    assert matches[0].id == "wp-rest-content-injection"
    assert matches[0].attack_type == "content-injection"
    assert matches[0].confidence == "high"
    # Still no volume anomaly for it (the remaining, documented gap).
    cve_anoms = [a for a in _anomalies(store, type="message_frequency", namespace="sec-test")
                 if "rest_route" in str(a.get("rule_key", ""))]
    assert cve_anoms == []


def test_firing_anomaly_carries_web_signature(tmp_path):
    # Part 2.2: a firing rate anomaly whose sample lines match a web-attack
    # signature surfaces it (and its attack_type) through the existing
    # anomaly_template_summary attach point -- no AI call, any urgency.
    from webapp.api.explain import anomaly_template_summary
    from webapp.api.signatures import SignatureKB, load_rules
    store, job, now, _ = _replay(tmp_path)
    job.detect_once(now)
    kb = SignatureKB(load_rules())

    warn = _anomalies(store, type="message_frequency", severity="warning")[0]  # Wave A: author 404s
    summ = anomaly_template_summary(kb, warn)
    assert summ["signature"] and summ["signature"]["id"] == "wp-author-enumeration"
    assert summ["attack_type"] == "enumeration"

    info = _anomalies(store, type="message_frequency", severity="info")[0]  # Wave B: wp-login flood
    assert anomaly_template_summary(kb, info)["attack_type"] == "brute-force"


# ── before/after scorecard (printed with -s) ─────────────────────────────────

def test_print_before_after_table(tmp_path):
    store, job, now, _ = _replay(tmp_path)
    job.detect_once(now)
    freq_warn = bool(_anomalies(store, type="message_frequency", severity="warning", status="new"))
    freq_info = bool(_anomalies(store, type="message_frequency", severity="info", status="new"))
    err_fp = bool(_anomalies(store, type="error_rate_spike", status="new"))
    falco_fp = bool(_anomalies(store, type="new_falco_rule", status="new"))
    rows = [
        ("Wave A (enum, 404 flood)", "no", "yes (message_frequency/warning)", "Part 1+2"),
        ("Wave B (brute force, 400x)", "no", "yes (message_frequency, 1 template x400)", "Part 1"),
        ("Wave C (CVE PoC)", "no", "signature match: wp-rest-content-injection", "Part 2 (sig pack)"),
        ("Start-up DB-retry errors", "FALSE POSITIVE", "suppressed", "Part 3"),
        ("Start-up entrypoint shell", "FALSE POSITIVE", "suppressed_cold_start", "Part 3"),
        ("Auto-triage of warning spike", "no", "ai_meta attached", "Part 4"),
    ]
    print("\n\n  mechanism                          | before          | after")
    print("  " + "-" * 78)
    for name, before, after, _part in rows:
        print(f"  {name:<34} | {before:<15} | {after}")
    # Sanity: the table reflects the asserted state.
    assert freq_warn and freq_info and not err_fp and not falco_fp
