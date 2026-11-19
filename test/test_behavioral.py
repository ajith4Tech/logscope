"""Per-source-IP web behavior (webapp/api/behavioral.py): brute force,
scanning and flood keyed on (namespace, client_ip) instead of a message
template. Fixture: test/fixtures/web_behavioral/traffic.json.

Covers each subtype (scanning that message_frequency cannot see; brute force
coexisting with message_frequency; flood on rate alone), trusted CIDRs and
User-Agents, the cold-start guard, cooldown (update vs new occurrence), the
anomalies UNIQUE/NOT NULL pod question, correlation into a security incident
with the correlator unchanged, isolation between namespaces and IPs, the
query plan, and config validation.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.behavioral import GROUP_SQL, BehavioralDetector  # noqa: E402
from webapp.api.config import (  # noqa: E402
    BehavioralConfig,
    InsightsConfig,
    SecurityConfig,
    load_app_config,
    load_behavioral,  # noqa: E402
)
from webapp.api.explain import anomaly_template_summary, classify_anomaly  # noqa: E402
from webapp.api.insights import AnomalyStore, InsightsJob  # noqa: E402
from webapp.api.notify import URGENCY_RANK_SQL, anomaly_urgency  # noqa: E402
from webapp.api.parser import make_record  # noqa: E402
from webapp.api.security import Correlator, IncidentStore  # noqa: E402
from webapp.api.signatures import SignatureKB, load_rules  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402

FIXTURE = ROOT / "test" / "fixtures" / "web_behavioral" / "traffic.json"
CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"
WP_POD = "wordpress-7d79967bc8-qjt4c"


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text())


NOW = datetime.fromisoformat(_fixture()["now"].replace("Z", "+00:00"))


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _expand(spec: dict, *, shift: timedelta = timedelta(0), key: str = "") -> list[dict]:
    """Fixture spec -> records through make_record (the real ingest path)."""
    start = _ts(spec["start"]) + shift
    out = []
    for i in range(spec["count"]):
        ts = datetime.fromtimestamp(start.timestamp() + i * spec["step_s"], timezone.utc)
        if "plain" in spec:
            message = spec["plain"]
        else:
            path = spec["paths"][i % len(spec["paths"])]
            status = spec["statuses"][i % len(spec["statuses"])]
            message = (f'{spec["ip"]} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                       f'"{spec["method"]} {path} HTTP/1.1" {status} 123 "-" "{spec["ua"]}"')
        raw = f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')} - {spec['namespace']} - {spec['pod']}/{spec.get('container', 'web')} - {message}"
        record = make_record(raw_line=raw, source_bucket="info",
                             source_scope="security" if spec.get("scope") == "security" else "namespace",
                             source_key=f"beh/{key or spec.get('name', spec.get('ip'))}/{shift.total_seconds()}",
                             source_etag="e", line_number=i, infra_namespaces=())
        assert record is not None
        out.append(record)
    return out


def _cfg(**behavioral):
    base = load_app_config(CONFIG)
    insights = InsightsConfig(
        enabled=True, detect_interval_secs=300, baseline_window_days=7,
        spike_multiplier=3.0, spike_min_count=10, shift_share_delta=0.25, shift_min_count=20,
        frequency_multiplier=5.0, frequency_min_count=30, detect_per_pod=False,
        sample_timestamps_max=10, min_baseline_hours=24, min_partial_window_minutes=15,
        cold_start_grace_s=600, min_baseline_samples=5,
    )
    return replace(base, insights=insights,
                   security=SecurityConfig(behavioral=replace(BehavioralConfig(), **behavioral)))


class Harness:
    def __init__(self, tmp_path: Path, *traffic: str, baseline: bool = True, **behavioral):
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.db = tmp_path / "cache.sqlite"
        self.storage = LogStorage(self.db)
        fixture = _fixture()
        if baseline:
            for spec in fixture["baseline"]:
                self.storage.insert_records(_expand(spec))
        for name in traffic:
            self.add(name)
        self.cfg = _cfg(**behavioral)
        self.store = AnomalyStore(self.db)
        self.kb = SignatureKB(load_rules())
        self.job = InsightsJob(self.cfg, self.storage._conn, self.store,
                               classifier=lambda a: classify_anomaly(self.kb, self.store, a))
        self.behavioral = BehavioralDetector(self.cfg, self.storage._conn, self.store)

    def add(self, name: str, shift: timedelta = timedelta(0), **override) -> None:
        spec = {**_fixture()["traffic"][name], **override}
        # A distinct source key per override, so ingest dedup keeps re-added traffic.
        key = name + (json.dumps(override, sort_keys=True) if override else "")
        self.storage.insert_records(_expand(spec, shift=shift, key=key))

    def run(self, now: datetime = NOW) -> dict:
        return self.behavioral.run_once(now)

    def anomalies(self, **filters) -> list[dict]:
        items = self.store.query_anomalies({}, limit=500)["items"]
        return [a for a in items if all(a.get(k) == v for k, v in filters.items())]

    def behavioral_rows(self) -> list[dict]:
        return self.anomalies(type="web_behavioral")


# ─── subtypes ────────────────────────────────────────────────────────────────


def test_scanning_fires_where_per_template_frequency_cannot(tmp_path):
    h = Harness(tmp_path, "scanning")
    h.job.detect_once(NOW)
    assert h.job.detector.learning is False  # the template detectors did run
    # 25 distinct paths at count 1 each: nothing per template.
    assert h.anomalies(type="message_frequency", namespace="shop") == []
    counts = h.run()
    assert counts["behavioral_created"] == 1
    [anomaly] = h.behavioral_rows()
    ev = anomaly["evidence"]
    assert anomaly["rule_key"] == "scanning:203.0.113.7" and anomaly["namespace"] == "shop"
    assert anomaly["attack_type"] == "scanning" and anomaly["attack_confidence"] == "medium"
    assert anomaly["pod"] == WP_POD and anomaly["status"] == "new"
    assert ev["client_ip"] == "203.0.113.7" and ev["distinct_paths"] == 25 and ev["total_requests"] == 25
    assert ev["status_counts"]["404"] == 25 and ev["not_found_ratio"] == 1.0
    assert ev["sample_messages"] == []  # no raw log lines in the evidence
    summary = anomaly_template_summary(h.kb, anomaly)
    assert summary["attack_type"] == "scanning" and "203.0.113.7" in summary["headline"]
    assert "25 requests to 25 path(s)" in summary["headline"] and "404: 25" in summary["headline"]
    assert anomaly_urgency(anomaly, ev) == "high"


def test_brute_force_fires_and_coexists_with_message_frequency(tmp_path):
    h = Harness(tmp_path, "brute_force")
    h.job.detect_once(NOW)
    h.run()
    [brute] = h.behavioral_rows()
    assert brute["rule_key"] == "brute_force:198.51.100.23" and brute["attack_type"] == "brute_force"
    ev = brute["evidence"]
    assert ev["max_path_repeat"] == 60 and ev["top_path"] == "/wp-login.php"
    assert ev["status_counts"]["401"] == 48 and ev["top_path_auth_fail_ratio"] == 0.8
    # The template detector also sees the 401 flood: a separate row of its own
    # type, its signature attack_type untouched by the behavioral one.
    [freq] = h.anomalies(type="message_frequency", namespace="shop")
    assert freq["id"] != brute["id"] and freq["evidence"]["current_count"] == 48
    # Its signature classification (401s on wp-login: auth-probe) is its own.
    signature_type = freq["attack_type"]
    assert signature_type and signature_type != "brute_force" and "wp-login" in freq["rule_key"]
    # Re-running both detectors changes neither the other's row nor the count.
    h.job.detect_once(NOW)
    h.run(NOW)
    assert len(h.behavioral_rows()) == 1 and len(h.anomalies(type="message_frequency", namespace="shop")) == 1
    assert h.anomalies(type="message_frequency", namespace="shop")[0]["attack_type"] == signature_type
    assert h.behavioral_rows()[0]["attack_type"] == "brute_force"


def test_flood_fires_on_rate_alone(tmp_path):
    h = Harness(tmp_path, "flood")
    h.run()
    [flood] = h.behavioral_rows()
    ev = flood["evidence"]
    assert flood["rule_key"] == "flood:192.0.2.50" and flood["attack_confidence"] == "low"
    assert ev["total_requests"] == 400 and ev["distinct_paths"] == 3
    assert ev["status_counts"] == {"401": 0, "403": 0, "404": 0, "5xx": 0, "other": 400}


def test_one_group_can_raise_several_subtypes(tmp_path):
    # 400 failed logins on one path: brute force and flood, two rows.
    h = Harness(tmp_path, "brute_force")
    h.add("brute_force", count=400, step_s=0.5, start="2026-11-02T10:55:30Z")
    h.run()
    assert sorted(a["rule_key"] for a in h.behavioral_rows()) == ["brute_force:198.51.100.23",
                                                                   "flood:198.51.100.23"]


def test_scanner_signature_already_matched_counts_as_scanning(tmp_path):
    h = Harness(tmp_path)
    h.add("scanning", count=3)  # 3 paths: far below scanning_min_paths
    assert h.run()["behavioral_created"] == 0
    # A web signature (attack_type scanner) was already matched on a template
    # anomaly whose sample lines carry this IP: no new matching here.
    anomaly_id, _ = h.store.record_detection(
        type="message_frequency", namespace="shop", pod=WP_POD, rule_key="GET /<N> 404", severity="warning",
        evidence={"window_start": "2026-11-02T10:00:00Z", "window_end": "2026-11-02T11:00:00Z",
                  "sample_messages": ['203.0.113.7 - - [x] "GET /a HTTP/1.1" 404 1 "-" "sqlmap/1.7"']},
        detected_day="2026-11-02")
    h.store.set_attack(anomaly_id, "scanner", "high")
    h.run()
    [scan] = h.behavioral_rows()
    assert scan["rule_key"] == "scanning:203.0.113.7" and scan["attack_confidence"] == "high"
    assert scan["evidence"]["signature_attack_types"] == ["scanner"]
    # Another IP that is a prefix of this one must not inherit the match.
    h2 = Harness(tmp_path / "prefix")
    h2.add("scanning", count=3, ip="203.0.113.70")
    h2.store.set_attack(h2.store.record_detection(
        type="message_frequency", namespace="shop", pod=WP_POD, rule_key="x", severity="warning",
        evidence={"window_end": "2026-11-02T11:00:00Z", "sample_messages": ["203.0.113.7 - - GET"]},
        detected_day="2026-11-02")[0], "scanner", "high")
    assert h2.run()["behavioral_created"] == 0


# ─── skips ───────────────────────────────────────────────────────────────────


def test_trusted_cidr_and_user_agent_are_skipped(tmp_path):
    assert Harness(tmp_path / "plain", "scanning").run()["behavioral_created"] == 1
    cidr = Harness(tmp_path / "cidr", "scanning", trusted_cidrs=("203.0.113.0/24",))
    assert cidr.run() == {"behavioral_created": 0, "behavioral_updated": 0, "behavioral_skipped": 1}
    assert cidr.behavioral_rows() == []
    ua = Harness(tmp_path / "ua", "scanning", trusted_user_agents=("COMPATIBLE; PROBE",))  # case-insensitive
    ua.run()
    assert ua.behavioral_rows() == []
    # A trusted UA only excludes its own requests: the same IP with an
    # untrusted UA is still evaluated.
    mixed = Harness(tmp_path / "mixed", "scanning", trusted_user_agents=("probe",))
    mixed.add("scanning", ua="curl/8.0")
    mixed.run()
    assert [a["rule_key"] for a in mixed.behavioral_rows()] == ["scanning:203.0.113.7"]


def test_cold_start_grace_suppresses_then_fires(tmp_path):
    # "fresh" has no history: its first record is the burst itself.
    h = Harness(tmp_path, baseline=False)
    h.add("flood", namespace="fresh", pod="app-0")
    h.run()
    assert h.behavioral_rows() == []
    assert h.behavioral.last_counts["behavioral_skipped"] == 1
    # The same traffic after the grace (600 s from the namespace's first record) fires.
    later = timedelta(minutes=15)
    h.add("flood", shift=later, namespace="fresh", pod="app-0")
    h.run(NOW + later)
    [flood] = h.behavioral_rows()
    assert flood["namespace"] == "fresh" and flood["rule_key"] == "flood:192.0.2.50"


# ─── cooldown and uniqueness ─────────────────────────────────────────────────


def test_continuing_behavior_updates_one_anomaly_then_cooldown_opens_a_new_one(tmp_path):
    h = Harness(tmp_path, "brute_force")
    h.run(NOW)
    [first] = h.behavioral_rows()
    h.store.set_status(first["id"], "reviewed")
    # Cycle 2: the attack goes on in the next window.
    h.add("brute_force", shift=timedelta(minutes=5))
    assert h.run(NOW + timedelta(minutes=5))["behavioral_updated"] == 1
    [same] = h.behavioral_rows()
    assert same["id"] == first["id"] and same["evidence"]["cycles"] == 2
    assert same["status"] == "reviewed"  # an operator's status survives the update
    assert same["evidence"]["window_start"] == first["evidence"]["window_start"]  # occurrence start kept
    assert same["evidence"]["last_seen"] > first["evidence"]["last_seen"]
    # Quiet windows: nothing is created or updated.
    assert h.run(NOW + timedelta(minutes=20)) == {"behavioral_created": 0, "behavioral_updated": 0,
                                                  "behavioral_skipped": 0}
    # Back after more than cooldown_s (1800) of quiet: a new occurrence, a new row.
    back = timedelta(minutes=45)
    h.add("brute_force", shift=back)
    assert h.run(NOW + back)["behavioral_created"] == 1
    rows = sorted(h.behavioral_rows(), key=lambda a: a["id"])
    assert len(rows) == 2 and rows[1]["status"] == "new" and rows[1]["evidence"]["cycles"] == 1
    assert rows[0]["detected_day"] != rows[1]["detected_day"]  # same UTC day, distinct occurrence keys


def test_back_within_cooldown_is_the_same_occurrence(tmp_path):
    h = Harness(tmp_path, "brute_force")
    h.run(NOW)
    back = timedelta(minutes=25)  # last request ~10:59, back at ~11:21: 22 min < 30 min
    h.add("brute_force", shift=back)
    assert h.run(NOW + back)["behavioral_updated"] == 1
    assert len(h.behavioral_rows()) == 1


def test_pod_cannot_be_null_and_ip_keyed_rows_do_not_duplicate(tmp_path):
    """The anomalies UNIQUE key includes pod. SQLite treats NULLs as distinct
    in UNIQUE, so NULL pods would duplicate silently; this proves they cannot
    occur (pod is NOT NULL) and that IP-keyed rows do not duplicate."""
    h = Harness(tmp_path)
    store = h.store
    columns = {r[1]: r for r in store._conn.execute("PRAGMA table_info(anomalies)")}
    assert columns["pod"][3] == 1  # notnull
    with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
        store._conn.execute(
            "INSERT INTO anomalies (type, namespace, pod, rule_key, severity, evidence, detected_at, detected_day, "
            "updated_at) VALUES ('web_behavioral', 'shop', NULL, 'flood:1.2.3.4', 'warning', '{}', 'x', 'd', 'x')")
    store._conn.rollback()
    # The UNIQUE constraint itself, with the "-" sentinel: two identical
    # detections are one row.
    for _ in range(2):
        store.record_detection(type="web_behavioral", namespace="shop", pod="-", rule_key="flood:1.2.3.4",
                               severity="warning", evidence={"window_start": "2026-11-02T10:55:00Z"},
                               detected_day="2026-11-02")
    assert len(h.anomalies(rule_key="flood:1.2.3.4")) == 1
    # The behavioral path (check-then-update, not insert-or-ignore): twice,
    # even with a different pod the second time, is one row.
    evidence = {"window_start": "2026-11-02T10:56:00Z", "last_seen": "2026-11-02T10:59:00Z", "total_requests": 400}
    for pod in ("-", "web-1"):
        store.record_behavioral(namespace="shop", pod=pod, rule_key="flood:5.6.7.8", severity="warning",
                                evidence=evidence, attack_type="flood", attack_confidence="low", now=NOW,
                                cooldown_s=1800)
    [row] = h.anomalies(rule_key="flood:5.6.7.8")
    assert row["pod"] == "-" and row["evidence"]["cycles"] == 2
    # An empty pod from the caller is stored as the sentinel, never NULL.
    store.record_behavioral(namespace="shop", pod="", rule_key="flood:9.9.9.9", severity="warning",
                            evidence=evidence, attack_type="flood", attack_confidence="low", now=NOW, cooldown_s=0)
    assert h.anomalies(rule_key="flood:9.9.9.9")[0]["pod"] == "-"


# ─── correlation (security.py unchanged) ─────────────────────────────────────


def test_behavioral_anomaly_followed_by_same_pod_falco_event_opens_an_incident(tmp_path):
    h = Harness(tmp_path, "brute_force")
    h.run(NOW)
    [brute] = h.behavioral_rows()
    h.storage.insert_records(_expand(_fixture()["falco_same_pod"], key="falco"))
    incidents = IncidentStore(h.db)
    correlator = Correlator(h.cfg, incidents, h.storage._conn)
    assert correlator.run_once(NOW + timedelta(minutes=5))["incidents_created"] == 1
    [incident] = incidents.list()
    assert incident["web_anomaly_id"] == brute["id"] and incident["attack_type"] == "brute_force"
    assert incident["attack_confidence"] == brute["attack_confidence"]
    assert incident["confidence"] == "high" and incident["severity"] == "critical" and incident["pod"] == WP_POD
    assert incident["web_started_at"] == "2026-11-02T10:56:00Z" and incident["falco_ts"] == "2026-11-02T11:03:00Z"
    assert incident["falco_rule"] == "Run shell untrusted"
    # A later behavioral update does not open a second incident.
    h.add("brute_force", shift=timedelta(minutes=5))
    h.run(NOW + timedelta(minutes=5))
    correlator.run_once(NOW + timedelta(minutes=10))
    assert len(incidents.list()) == 1


# ─── isolation ───────────────────────────────────────────────────────────────


def test_no_bleed_between_namespaces_or_ips(tmp_path):
    # One IP, 12 paths in each of two namespaces (24 in total), and a second
    # IP with 12 more in the first: every group is below 20 paths.
    h = Harness(tmp_path, "half_scan_shop", "half_scan_blog", "half_scan_shop_other_ip")
    assert h.run()["behavioral_created"] == 0
    # A real scanner in shop: only its own row, nothing for the others.
    h.add("scanning")
    h.run()
    assert [(a["namespace"], a["rule_key"]) for a in h.behavioral_rows()] == [("shop", "scanning:203.0.113.7")]
    assert h.behavioral_rows()[0]["evidence"]["total_requests"] == 25


# ─── query, index, config, notify parity ─────────────────────────────────────


def test_group_query_uses_the_access_log_index(tmp_path):
    h = Harness(tmp_path, "flood")
    sql, args = h.behavioral.query()
    plan = " ".join(str(r[3]) for r in h.storage._conn.execute(
        "EXPLAIN QUERY PLAN " + sql, (0.0, 1.0, *args, 10)))
    assert "idx_records_http_epoch" in plan
    assert "http_meta IS NOT NULL" in GROUP_SQL
    # Created idempotently at start.
    LogStorage(h.db)
    names = [r[0] for r in h.storage._conn.execute("SELECT name FROM sqlite_master WHERE name = 'idx_records_http_epoch'")]
    assert names == ["idx_records_http_epoch"]


def test_config_defaults_and_validation():
    cfg = load_app_config(CONFIG).security.behavioral
    assert (cfg.window_s, cfg.brute_force_min_repeats, cfg.scanning_min_paths, cfg.flood_requests,
            cfg.cooldown_s) == (300, 50, 20, 300, 1800)
    assert load_behavioral({"trusted_cidrs": ["10.0.0.0/8", "2001:db8::/32"]}).trusted_cidrs == (
        "10.0.0.0/8", "2001:db8::/32")
    for bad in ({"trusted_cidrs": ["not-a-cidr"]}, {"brute_force_auth_fail_ratio": 1.5}, {"window_s": 1},
                {"trusted_user_agents": [""]}, {"bogus": 1}):
        with pytest.raises(ValueError):
            load_behavioral(bad)


def test_urgency_sql_matches_python_for_behavioral(tmp_path):
    h = Harness(tmp_path, "flood")
    h.run()
    [row] = h.store._conn.execute(f"SELECT ({URGENCY_RANK_SQL}) FROM anomalies a WHERE type = 'web_behavioral'")
    assert row[0] == 2 and anomaly_urgency({"type": "web_behavioral"}, {}) == "high"


def test_malformed_client_ip_is_handled(tmp_path):
    h = Harness(tmp_path, trusted_cidrs=("10.0.0.0/8",))
    h.add("scanning", ip="<script>x</script>")
    h.run()
    [row] = h.behavioral_rows()
    assert row["evidence"]["client_ip"] == "<script>x</script>"  # stored as data; the UI escapes it


# ─── web app wiring ──────────────────────────────────────────────────────────


def test_web_app_runs_it_on_the_insights_cycle_and_lists_it(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "test"))
    from test_alerts import _app as alerts_app  # noqa: PLC0415

    monkeypatch.delenv("MATTERMOST_WEBHOOK_URL", raising=False)
    app = alerts_app(tmp_path)
    for spec in _fixture()["baseline"]:
        app.storage.insert_records(_expand(spec))
    app.storage.insert_records(_expand(_fixture()["traffic"]["scanning"], key="scan"))
    counts = app.insights.run_once(NOW)
    assert counts["behavioral_created"] == 1
    listed = app.api_anomalies({"type": ["web_behavioral"]})["items"]
    assert [a["rule_key"] for a in listed] == ["scanning:203.0.113.7"]
    assert listed[0]["template_summary"]["attack_type"] == "scanning"
    assert listed[0]["attack_type"] == "scanning"  # not overwritten by the signature write-back
    assert app.status()["security"]["behavioral"]["last_counts"]["behavioral_created"] == 1

