"""Vulnerability view (webapp/api/vulnscan.py): Trivy Operator reports, CISA
KEV, exposure, attack correlation and read-time risk. No cluster and no
network: kubectl and the KEV fetch are replaced by fixtures
(test/fixtures/vulnscan/)."""

from __future__ import annotations

import copy
import json
import logging
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from webapp.api import vulnscan  # noqa: E402
from webapp.api.config import VulnscanConfig, load_app_config, load_vulnscan  # noqa: E402
from webapp.api.insights import AnomalyStore  # noqa: E402
from webapp.api.security import IncidentStore  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402
from webapp.api.vulnscan import (  # noqa: E402
    CONFIG_AUDIT_ARGV,
    FIXED_COMMANDS,
    INGRESS_ARGV,
    VULN_ARGV,
    KubectlUnavailable,
    VulnScanner,
    VulnStore,
    parse_ingresses,
    parse_vulnerability_reports,
    pod_matches_workload,
    risk_tier,
    run_fixed,
    service_routes_to,
)

FIX = ROOT / "test" / "fixtures" / "vulnscan"
CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"
NOW = datetime(2026, 11, 19, 15, 0, tzinfo=timezone.utc)
WP_POD = "wordpress-7d79967bc8-qjt4c"


def _load(name: str) -> dict:
    return json.loads((FIX / f"{name}.json").read_text())


def _cfg(**vulnscan_values):
    base = load_app_config(CONFIG)
    vcfg = replace(VulnscanConfig(enabled=True), **vulnscan_values)
    return replace(base, security=replace(base.security, vulnscan=vcfg))


class FakeKubectl:
    """Answers the three fixed commands from fixtures (or raises)."""

    def __init__(self, reports: dict | None = None, *, fail: KubectlUnavailable | None = None):
        self.reports = reports if reports is not None else _load("vulnerabilityreports")
        self.fail = fail
        self.calls: list[tuple] = []

    def __call__(self, argv, *, timeout):
        self.calls.append(argv)
        if self.fail is not None:
            raise self.fail
        return {VULN_ARGV: self.reports, CONFIG_AUDIT_ARGV: _load("configauditreports"),
                INGRESS_ARGV: _load("ingresses")}[argv]


class FakeKev:
    def __init__(self, data=None, *, down: bool = False):
        self.data = data if data is not None else _load("kev_subset")
        self.down = down
        self.calls = 0

    def __call__(self, url):
        self.calls += 1
        if self.down:
            raise OSError("network unreachable")
        return copy.deepcopy(self.data)


def _scanner(tmp_path, *, runner=None, kev=None, **cfg) -> VulnScanner:
    db = tmp_path / "cache.sqlite"
    LogStorage(db)  # records schema, like the web app
    AnomalyStore(db)
    IncidentStore(db)
    return VulnScanner(_cfg(**cfg), VulnStore(db), runner=runner or FakeKubectl(), kev_fetch=kev or FakeKev(),
                       clock=lambda: NOW)


def _find(view, cve, workload=None):
    return next(i for i in view["items"] if i["cve_id"] == cve and (workload is None or i["workload"] == workload))


# ─── parsing ─────────────────────────────────────────────────────────────────


def test_reports_parse_into_findings():
    findings, scanned = parse_vulnerability_reports(_load("vulnerabilityreports"))
    assert scanned == {("shop", "Deployment", "wordpress", "wordpress"), ("db", "StatefulSet", "mysql", "mysql"),
                       ("logging", "DaemonSet", "vector", "vector"), ("logging", "CronJob", "backup", "backup")}
    by_cve = {(f["workload"], f["cve_id"]): f for f in findings}
    assert len(findings) == 8  # the duplicate zlib1g/CVE-2023-45853 entry is one finding
    php = by_cve[("wordpress", "CVE-2024-4577")]
    assert php["workload_kind"] == "Deployment"  # ReplicaSet wordpress-7d79967bc8 -> Deployment wordpress
    assert php["image"] == "index.docker.io/library/wordpress:6.4-php8.2-apache"
    assert (php["package"], php["installed_version"], php["fixed_version"], php["severity"]) == (
        "php8.2", "8.2.12-1", "8.2.20-1", "CRITICAL")
    assert by_cve[("wordpress", "CVE-2023-45853")]["severity"] == "HIGH"  # highest of the duplicates; "medium" normalized
    assert by_cve[("wordpress", "CVE-2005-2541")]["severity"] == "UNKNOWN"  # NEGLIGIBLE is not a tier
    assert by_cve[("wordpress", "CVE-2023-50387")]["fixed_version"] is None  # "" -> no fix
    assert by_cve[("mysql", "CVE-2021-44228")]["workload_kind"] == "StatefulSet"


def test_fresh_scan_resolves_reopens_and_leaves_unscanned_workloads(tmp_path):
    runner = FakeKubectl()
    scanner = _scanner(tmp_path, runner=runner)
    assert scanner.poll_once(NOW)["findings_new"] == 8
    first = {f["cve_id"] + f["workload"]: f for f in scanner.store.rows("SELECT * FROM vulnerability_findings")}
    # Next scan: wordpress no longer has CVE-2023-4039; mysql has no report at all (TTL gap).
    reports = _load("vulnerabilityreports")
    wp = reports["items"][0]["report"]["vulnerabilities"]
    reports["items"][0]["report"]["vulnerabilities"] = [v for v in wp if v["vulnerabilityID"] != "CVE-2023-4039"]
    reports["items"] = [r for r in reports["items"] if r["metadata"]["name"] != "statefulset-mysql-mysql"]
    runner.reports = reports
    later = NOW + timedelta(minutes=30)
    counts = scanner.poll_once(later)
    assert counts["findings_resolved"] == 1 and counts["findings_new"] == 0
    rows = {f["cve_id"] + f["workload"]: f for f in scanner.store.rows("SELECT * FROM vulnerability_findings")}
    assert rows["CVE-2023-4039wordpress"]["resolved_at"] == "2026-11-19T15:30:00Z"
    assert rows["CVE-2021-44228mysql"]["resolved_at"] is None  # not rescanned: not resolved
    assert rows["CVE-2024-4577wordpress"]["last_seen"] == "2026-11-19T15:30:00Z"
    assert rows["CVE-2024-4577wordpress"]["first_seen"] == first["CVE-2024-4577wordpress"]["first_seen"]
    # Listed again: reopened, same row.
    runner.reports = _load("vulnerabilityreports")
    scanner.poll_once(later + timedelta(minutes=30))
    again = {f["cve_id"] + f["workload"]: f for f in scanner.store.rows("SELECT * FROM vulnerability_findings")}
    assert again["CVE-2023-4039wordpress"]["resolved_at"] is None
    assert again["CVE-2023-4039wordpress"]["id"] == first["CVE-2023-4039wordpress"]["id"]
    # Open findings only by default; resolved on request.
    runner.reports = reports
    scanner.poll_once(later + timedelta(hours=1))
    assert all(i["cve_id"] != "CVE-2023-4039" for i in scanner.view(limit=100)["items"])
    assert any(i["cve_id"] == "CVE-2023-4039" for i in scanner.view(include_resolved=True, limit=100)["items"])


# ─── KEV ─────────────────────────────────────────────────────────────────────


def test_kev_join_and_flip_across_refreshes(tmp_path):
    kev = FakeKev()
    scanner = _scanner(tmp_path, kev=kev)
    scanner.poll_once(NOW)
    assert scanner.refresh_kev(NOW)
    view = scanner.view(limit=100)
    assert _find(view, "CVE-2024-4577")["is_kev"] and _find(view, "CVE-2021-44228")["is_kev"]
    assert not _find(view, "CVE-2026-13221")["is_kev"]
    assert _find(view, "CVE-2021-44228")["kev"]["date_added"] == "2021-12-10"
    # Next catalog: Log4Shell gone (hypothetically), the perl CVE added.
    data = _load("kev_subset")
    data["vulnerabilities"] = [v for v in data["vulnerabilities"] if v["cveID"] != "CVE-2021-44228"] + [
        {"cveID": "CVE-2026-13221", "dateAdded": "2026-11-18", "shortDescription": "perl heap overflow"}]
    kev.data = data
    assert scanner.refresh_kev(NOW + timedelta(days=1))
    view = scanner.view(limit=100)
    assert not _find(view, "CVE-2021-44228")["is_kev"] and _find(view, "CVE-2026-13221")["is_kev"]
    assert {i["cve_id"] for i in scanner.view(kev=True, limit=100)["items"]} == {"CVE-2024-4577", "CVE-2026-13221"}


def test_kev_unreachable_keeps_the_last_catalog_and_reports_staleness(tmp_path, caplog):
    kev = FakeKev()
    scanner = _scanner(tmp_path, kev=kev)
    scanner.poll_once(NOW)
    scanner.refresh_kev(NOW)
    kev.down = True
    with caplog.at_level(logging.WARNING):
        assert scanner.refresh_kev(NOW + timedelta(days=1)) is False
    status = scanner.kev_status(NOW + timedelta(days=1))
    assert status["entries"] == 3 and status["stale"] is False and "network unreachable" in status["last_error"]
    assert _find(scanner.view(limit=100), "CVE-2024-4577")["is_kev"]  # still in use
    assert scanner.kev_status(NOW + timedelta(days=2, seconds=1))["stale"] is True  # older than 2x refresh
    # A broken download never replaces the catalog either.
    kev.down, kev.data = False, {"unexpected": True}
    assert scanner.refresh_kev(NOW + timedelta(days=3)) is False
    assert scanner.kev_status()["entries"] == 3


def test_kev_unreachable_at_first_boot_means_not_kev_not_an_error(tmp_path):
    scanner = _scanner(tmp_path, kev=FakeKev(down=True))
    scanner.poll_once(NOW)
    assert scanner.refresh_kev(NOW) is False
    view = scanner.view(limit=100)
    assert view["total"] == 8 and not any(i["is_kev"] for i in view["items"])
    assert view["kev"]["entries"] == 0 and view["kev"]["last_success_at"] is None and view["kev"]["stale"] is True
    assert scanner.kev_due(NOW)  # tried again on the next KEV cycle


def test_kev_does_not_block_polling(tmp_path):
    """The KEV fetch runs on its own thread: a hanging fetch does not delay polls."""
    gate = threading.Event()
    scanner = _scanner(tmp_path, kev=lambda url: gate.wait(5) and {})
    scanner.start()
    try:
        deadline = time.monotonic() + 3
        while scanner.last_success_at is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert scanner.last_success_at is not None  # polled while the KEV fetch hangs
    finally:
        gate.set()
        scanner.stop()


# ─── exposure ────────────────────────────────────────────────────────────────


def test_exposure_by_ingress_allowlist_or_neither(tmp_path):
    scanner = _scanner(tmp_path, exposed_workloads=("db/mysql",))
    scanner.poll_once(NOW)
    view = scanner.view(limit=100)
    assert _find(view, "CVE-2024-4577")["exposure"] == "ingress shop-ingress"  # wordpress-service -> wordpress
    assert _find(view, "CVE-2021-44228")["exposure"] == "config"
    assert _find(view, "CVE-2026-13221")["exposure"] is None and not _find(view, "CVE-2026-13221")["exposed"]
    # A whole namespace in the allowlist.
    scanner.cfg = _cfg(exposed_workloads=("logging",))
    assert _find(scanner.view(limit=100), "CVE-2026-13221")["exposure"] == "config"


def test_service_name_matching():
    assert service_routes_to("wordpress-service", "wordpress")
    assert service_routes_to("user-ajith-pgadmin-service", "user-ajith-pgadmin-deployment")
    assert service_routes_to("user-postgres-pga", "user-postgres-pga")
    assert not service_routes_to("user-ajith-pgadmin-service", "user-ajith-deployment")
    assert not service_routes_to("web", "web-api")
    assert parse_ingresses(_load("ingresses")) == [("shop", "shop-ingress", "wordpress-service"),
                                                   ("user-ajith", "admin", "user-ajith-pgadmin-service")]


# ─── attack correlation ──────────────────────────────────────────────────────


def _incident(store: IncidentStore, *, namespace: str, pod: str, opened: datetime, anomaly_id: int) -> int:
    return store.create({
        "namespace": namespace, "pod": pod, "web_anomaly_id": anomaly_id, "falco_record_id": anomaly_id,
        "attack_type": "brute_force", "confidence": "high", "severity": "critical",
        "falco_ts": "2026-11-19T14:00:00Z", "falco_rule": "Terminal shell in container"},
        window_start=f"w{anomaly_id}", now=opened)


def test_recent_incident_correlates_and_the_lookback_boundary_holds(tmp_path):
    scanner = _scanner(tmp_path, correlation_lookback_s=3600)
    scanner.poll_once(NOW)
    incidents = IncidentStore(tmp_path / "cache.sqlite")
    inside = _incident(incidents, namespace="shop", pod=WP_POD, opened=NOW - timedelta(seconds=3600), anomaly_id=1)
    wp = _find(scanner.view(limit=100), "CVE-2024-4577")
    assert [i["id"] for i in wp["attacks"]["incidents"]] == [inside]  # exactly at the boundary: counted
    assert "recent attack" in wp["risk"]["reasons"]
    # Other workloads and namespaces are not attacked by it.
    assert _find(scanner.view(limit=100), "CVE-2021-44228")["attacks"] == {"incidents": [], "anomalies": []}
    # One second older than the lookback: not counted.
    scanner.cfg = _cfg(correlation_lookback_s=3599)
    assert _find(scanner.view(limit=100), "CVE-2024-4577")["attacks"]["incidents"] == []


def test_attack_tagged_anomaly_on_a_pod_of_the_workload_correlates(tmp_path):
    scanner = _scanner(tmp_path)
    scanner.poll_once(NOW)
    anomalies = AnomalyStore(tmp_path / "cache.sqlite")
    behavioral, _ = anomalies.record_behavioral(
        namespace="db", pod="mysql-0", rule_key="flood:192.0.2.9", severity="warning",
        evidence={"window_start": "2026-11-19T14:50:00Z", "last_seen": "2026-11-19T14:55:00Z"},
        attack_type="flood", attack_confidence="low", now=NOW, cooldown_s=1800)
    # Untagged anomaly on the same pod, and a tagged one on a different statefulset: ignored.
    anomalies.record_detection(type="error_rate_spike", namespace="db", pod="mysql-0", rule_key="", severity="error",
                               evidence={"window_start": "2026-11-19T14:00:00Z"}, detected_day="2026-11-19")
    other, _ = anomalies.record_behavioral(
        namespace="db", pod="mysql-backup-0", rule_key="flood:192.0.2.10", severity="warning",
        evidence={"window_start": "2026-11-19T14:50:00Z", "last_seen": "2026-11-19T14:55:00Z"},
        attack_type="flood", attack_confidence="low", now=NOW, cooldown_s=1800)
    log4j = _find(scanner.view(limit=100, now=datetime.now(timezone.utc)), "CVE-2021-44228")
    assert [a["id"] for a in log4j["attacks"]["anomalies"]] == [behavioral] and other != behavioral


def test_pod_names_per_workload_kind():
    assert pod_matches_workload(WP_POD, "Deployment", "wordpress")
    assert not pod_matches_workload("wordpress-api-7d79967bc8-qjt4c", "Deployment", "wordpress")
    assert pod_matches_workload("mysql-0", "StatefulSet", "mysql")
    assert not pod_matches_workload("mysql-backup-0", "StatefulSet", "mysql")
    assert pod_matches_workload("vector-x7k2p", "DaemonSet", "vector")
    assert not pod_matches_workload("-", "Deployment", "wordpress") and not pod_matches_workload(None, "Pod", "x")


# ─── risk tiers: each boundary, both ways ────────────────────────────────────

BASE_RISK = {"severity": "HIGH", "fixable": True, "is_kev": True, "exposed": True, "attacked": False}


@pytest.mark.parametrize("changes, tier", [
    ({}, "critical"),                                            # HIGH, fix, KEV, exposed
    ({"exposed": False, "attacked": True}, "critical"),          # attacked instead of exposed
    ({"severity": "CRITICAL"}, "critical"),
    ({"severity": "MEDIUM"}, "high"),                            # just below HIGH: KEV + exposed = 2 signals
    ({"fixable": False}, "high"),                                # no fix: not critical, 3 signals
    ({"is_kev": False}, "high"),                                 # not KEV: severe + exposed
    ({"exposed": False}, "high"),                                # neither exposed nor attacked: severe + KEV
    ({"is_kev": False, "exposed": False}, "medium"),             # severity alone
    ({"severity": "MEDIUM", "exposed": False}, "medium"),        # KEV alone
    ({"severity": "LOW", "is_kev": False}, "medium"),            # exposed alone
    ({"severity": "LOW", "is_kev": False, "exposed": False}, "low"),
    ({"severity": "UNKNOWN", "is_kev": False, "exposed": False, "fixable": False}, "low"),
])
def test_risk_tier_boundaries(changes, tier):
    assert risk_tier(**{**BASE_RISK, **changes})["tier"] == tier


def test_risk_in_the_view(tmp_path):
    scanner = _scanner(tmp_path)
    scanner.poll_once(NOW)
    scanner.refresh_kev(NOW)
    view = scanner.view(limit=100)
    assert _find(view, "CVE-2024-4577")["risk"]["tier"] == "critical"  # CRITICAL, fix, KEV, Ingress
    assert _find(view, "CVE-2021-44228")["risk"]["tier"] == "high"     # CRITICAL, fix, KEV, not exposed
    assert _find(view, "CVE-2023-50387")["risk"]["tier"] == "high"     # HIGH + exposed, no fix
    assert _find(view, "CVE-2023-4039")["risk"]["tier"] == "medium"    # LOW, exposed only
    assert _find(view, "CVE-2026-13221")["risk"]["tier"] == "medium"   # CRITICAL alone
    assert view["counts"] == {"critical": 1, "high": 3, "medium": 4, "low": 0}
    assert view["items"][0]["cve_id"] == "CVE-2024-4577"  # highest tier first


# ─── degraded states ─────────────────────────────────────────────────────────


def test_rbac_missing_is_logged_once_and_reported(tmp_path, caplog):
    runner = FakeKubectl(fail=KubectlUnavailable("rbac_missing", "vulnerabilityreports is forbidden"))
    scanner = _scanner(tmp_path, runner=runner)
    with caplog.at_level(logging.WARNING, logger="webapp.api.vulnscan"):
        assert scanner.poll_once(NOW) == {}
        assert scanner.poll_once(NOW + timedelta(minutes=30)) == {}
    assert len([r for r in caplog.records if "degraded" in r.getMessage()]) == 1
    status = scanner.status()
    assert status["state"] == "rbac_missing" and status["degraded"] and status["rbac_missing"]
    assert status["findings_open"] == 0 and "forbidden" in status["last_error"]
    # Recovery is picked up on the next poll.
    runner.fail = None
    scanner.poll_once(NOW + timedelta(hours=1))
    assert scanner.status()["state"] == "ok" and scanner.status()["findings_open"] == 8


def test_failed_polls_wait_the_full_interval(tmp_path):
    runner = FakeKubectl(fail=KubectlUnavailable("kubectl_missing", "no kubectl"))
    scanner = _scanner(tmp_path, runner=runner, poll_interval_s=60)
    scanner._kev_loop = lambda: None  # noqa: SLF001 - only the poll thread here
    scanner.start()
    time.sleep(0.5)
    scanner.stop()
    assert runner.calls == [VULN_ARGV]  # one attempt, then waiting 60 s: no tight retry loop


def test_run_fixed_states_without_a_cluster(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(KubectlUnavailable) as exc:
        run_fixed(VULN_ARGV)
    assert exc.value.state == "kubectl_missing"
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/kubectl")
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 1, b"", b'Error from server (Forbidden): vulnerabilityreports.'
                                           b'aquasecurity.github.io is forbidden: User "system:serviceaccount:x" '
                                           b"cannot list resource")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(KubectlUnavailable) as exc:
        run_fixed(VULN_ARGV)
    assert exc.value.state == "rbac_missing"
    assert seen["argv"] == ["/usr/bin/kubectl", "get", "vulnerabilityreports.aquasecurity.github.io", "-A", "-o",
                            "json"]
    assert seen["shell"] is False and seen["stdin"] == subprocess.DEVNULL
    assert set(seen["env"]) <= {"PATH", "HOME", "KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT"}

    def no_crd(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, b"", b'error: the server doesn\'t have a resource type '
                                           b'"vulnerabilityreports"')

    monkeypatch.setattr(subprocess, "run", no_crd)
    with pytest.raises(KubectlUnavailable) as exc:
        run_fixed(VULN_ARGV)
    assert exc.value.state == "crd_missing"


def test_only_the_fixed_commands_can_run():
    assert {VULN_ARGV, CONFIG_AUDIT_ARGV, INGRESS_ARGV} == FIXED_COMMANDS
    assert all(argv[:2] == ("kubectl", "get") and argv[-3:] == ("-A", "-o", "json") for argv in FIXED_COMMANDS)
    for argv in (("kubectl", "delete", "pods", "-A"), ("kubectl", "get", "secrets", "-A", "-o", "json"), ("sh",)):
        with pytest.raises(ValueError):
            run_fixed(argv)
    source = Path(vulnscan.__file__).read_text()
    assert "from .actions" not in source and "import actions" not in source  # separate from the action executor


def test_config_validation():
    assert load_app_config(CONFIG).security.vulnscan.enabled is False  # off unless enabled
    cfg = load_vulnscan({"enabled": True, "exposed_workloads": ["db/mysql", "logging"]})
    assert cfg.enabled and cfg.exposed_workloads == ("db/mysql", "logging")
    for bad in ({"kev_url": "http://insecure.example/kev.json"}, {"poll_interval_s": 5}, {"exposed_workloads": ["a/b/c"]},
                {"exposed_workloads": [""]}, {"nope": 1}):
        with pytest.raises(ValueError):
            load_vulnscan(bad)


# ─── API ─────────────────────────────────────────────────────────────────────


@pytest.fixture()
def vuln_app(tmp_path, monkeypatch):
    from test_alerts import _app as alerts_app  # noqa: PLC0415

    monkeypatch.delenv("MATTERMOST_WEBHOOK_URL", raising=False)
    app = alerts_app(tmp_path)
    app.cfg = _cfg()
    app.vulnscan.cfg = app.cfg
    app.vulnscan._runner = FakeKubectl()  # noqa: SLF001
    app.vulnscan._kev_fetch = FakeKev()  # noqa: SLF001
    app.vulnscan.poll_once(NOW)
    app.vulnscan.refresh_kev(NOW)
    return app


def test_api_filters_without_a_token(vuln_app):
    from test_production import _request, _serve  # noqa: PLC0415

    server = _serve(vuln_app)
    try:
        status, body = _request(server, "GET", "/api/security/vulnerabilities")
        assert status == 200 and body["enabled"] is True and body["total"] == 8
        assert body["counts"] == {"critical": 1, "high": 3, "medium": 4, "low": 0}
        crit = _request(server, "GET", "/api/security/vulnerabilities?tier=critical")[1]["items"]
        assert [i["cve_id"] for i in crit] == ["CVE-2024-4577"]
        db = _request(server, "GET", "/api/security/vulnerabilities?namespace=db")[1]["items"]
        assert {i["namespace"] for i in db} == {"db"} and len(db) == 2
        kev = _request(server, "GET", "/api/security/vulnerabilities?kev=true")[1]["items"]
        assert {i["cve_id"] for i in kev} == {"CVE-2024-4577", "CVE-2021-44228"}
        not_kev = _request(server, "GET", "/api/security/vulnerabilities?kev=false")[1]["items"]
        assert len(not_kev) == 6 and not any(i["is_kev"] for i in not_kev)
        for bad in ("tier=urgent", "kev=maybe", "namespace=Not_A_NS"):
            assert _request(server, "GET", f"/api/security/vulnerabilities?{bad}")[0] == 400
        assert _request(server, "POST", "/api/security/vulnerabilities", body="{}",
                        headers={"Content-Type": "application/json"})[0] == 405
        status_body = _request(server, "GET", "/api/status")[1]["security"]["vulnscan"]
        assert status_body["state"] == "ok" and status_body["findings_open"] == 8
        assert status_body["kev"]["entries"] == 3 and status_body["rbac_missing"] is False
    finally:
        server.shutdown()


def test_disabled_by_default_in_the_web_app(tmp_path, monkeypatch):
    from test_alerts import _app as alerts_app  # noqa: PLC0415

    monkeypatch.delenv("MATTERMOST_WEBHOOK_URL", raising=False)
    app = alerts_app(tmp_path)
    assert app.api_vulnerabilities({})["enabled"] is False
    app.vulnscan.start()  # no threads, no kubectl, no network
    assert app.vulnscan._threads == []  # noqa: SLF001
    assert app.status()["security"]["vulnscan"]["state"] == "never"

