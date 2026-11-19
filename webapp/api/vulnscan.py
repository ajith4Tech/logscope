"""Vulnerability view: Trivy Operator reports + CISA KEV + exposure + attacks.

Read path (separate from actions.py and its executor, by design): five fixed,
read-only kubectl commands with no input from requests, configuration or
data (FIXED_COMMANDS), run on a timer:

    kubectl get vulnerabilityreports.aquasecurity.github.io -A -o json
    kubectl get configauditreports.aquasecurity.github.io -A -o json
    kubectl get ingresses.networking.k8s.io -A -o json
    kubectl get services -A -o json
    kubectl get endpointslices.discovery.k8s.io -A -o json

(group/version as installed by trivy-operator chart 0.38.1: v1alpha1). In
the cluster the web app's ServiceAccount gets exactly get/list/watch on these
five resources (Helm chart, security.vulnerabilityScanning.enabled).

Without kubectl, RBAC or the CRDs the poller records the degraded state (shown
in /api/status), logs it once per change of state and tries again only on its
normal interval.

Cache tables in the cache database, rebuilt from the next poll if lost (what
Trivy last reported, never a source of truth):
  vulnerability_findings  one row per (workload, container, package, CVE);
                          resolved_at is set when a fresh report of that same
                          workload/container no longer lists it (a workload
                          whose report is absent is left as it was: Trivy
                          deletes and recreates reports on its own TTL)
  config_audit_summary    ConfigAuditReport counts per workload
  exposure_paths          Ingress -> Service -> backing pod, from the Services and
                          their EndpointSlices (targetRef pods)
  kev_catalog / kev_meta  CISA's KEV catalog, refreshed on its own thread
                          (never blocks the poller); on failure the last good
                          catalog stays in use and /api/status shows its age

Risk is computed at read time (risk_tier), joined with exposure and recent
attacks (security incidents and attack-tagged anomalies on a pod of the
workload). Exposure is a real path, never a guess from names: an Ingress
backend Service that exists, whose EndpointSlices list a pod of the workload
(pod_matches_workload). Without such a path the allowlist
webapp.security.vulnscan.exposed_workloads decides; when the Ingress/Service/
EndpointSlice data could not be read on the last poll and neither says
"exposed", exposure is "unknown" (counted as not exposed for the risk tier).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import request

from .storage import SQLITE_BUSY_TIMEOUT_SECS

logger = logging.getLogger(__name__)

TRIVY_GROUP = "aquasecurity.github.io"
VULN_ARGV = ("kubectl", "get", f"vulnerabilityreports.{TRIVY_GROUP}", "-A", "-o", "json")
CONFIG_AUDIT_ARGV = ("kubectl", "get", f"configauditreports.{TRIVY_GROUP}", "-A", "-o", "json")
INGRESS_ARGV = ("kubectl", "get", "ingresses.networking.k8s.io", "-A", "-o", "json")
SERVICES_ARGV = ("kubectl", "get", "services", "-A", "-o", "json")
ENDPOINTSLICES_ARGV = ("kubectl", "get", "endpointslices.discovery.k8s.io", "-A", "-o", "json")
FIXED_COMMANDS = frozenset({VULN_ARGV, CONFIG_AUDIT_ARGV, INGRESS_ARGV, SERVICES_ARGV, ENDPOINTSLICES_ARGV})
SERVICE_NAME_LABEL = "kubernetes.io/service-name"
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
KEV_MAX_BYTES = 64 * 1024 * 1024
KEV_TIMEOUT_S = 30
KEV_RETRY_S = 3600
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANK = {s: len(SEVERITIES) - 1 - i for i, s in enumerate(SEVERITIES)}  # CRITICAL 4 ... UNKNOWN 0
TIERS = ("critical", "high", "medium", "low")
RESOLVED_KEEP_DAYS = 30
_HASH_SUFFIX_RE = re.compile(r"-[a-z0-9]{6,10}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS vulnerability_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        namespace TEXT NOT NULL,
        workload_kind TEXT NOT NULL,
        workload TEXT NOT NULL,
        container TEXT NOT NULL DEFAULT '',
        image TEXT NOT NULL DEFAULT '',
        package TEXT NOT NULL DEFAULT '',
        installed_version TEXT NOT NULL DEFAULT '',
        cve_id TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
        fixed_version TEXT,
        title TEXT NOT NULL DEFAULT '',
        primary_link TEXT,
        score REAL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        resolved_at TEXT,
        UNIQUE (namespace, workload_kind, workload, container, package, cve_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_open ON vulnerability_findings(resolved_at, namespace, workload)",
    "CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerability_findings(cve_id)",
    """
    CREATE TABLE IF NOT EXISTS config_audit_summary (
        namespace TEXT NOT NULL,
        workload_kind TEXT NOT NULL,
        workload TEXT NOT NULL,
        critical INTEGER NOT NULL DEFAULT 0,
        high INTEGER NOT NULL DEFAULT 0,
        medium INTEGER NOT NULL DEFAULT 0,
        low INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (namespace, workload_kind, workload)
    )
    """,
    # Replaced by exposure_paths (the old table held name-matched Services).
    "DROP TABLE IF EXISTS ingress_backends",
    """
    CREATE TABLE IF NOT EXISTS exposure_paths (
        namespace TEXT NOT NULL,
        ingress TEXT NOT NULL,
        service TEXT NOT NULL,
        pod TEXT NOT NULL,
        PRIMARY KEY (namespace, ingress, service, pod)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kev_catalog (
        cve_id TEXT PRIMARY KEY,
        date_added TEXT,
        short_description TEXT NOT NULL DEFAULT '',
        vendor_project TEXT NOT NULL DEFAULT '',
        product TEXT NOT NULL DEFAULT '',
        known_ransomware TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE TABLE IF NOT EXISTS kev_meta (name TEXT PRIMARY KEY, value TEXT)",
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _text(value: Any, limit: int) -> str:
    """External text (Trivy, CISA) stored bounded and without control
    characters. It is still untrusted: the UI escapes it."""
    return _CONTROL_RE.sub(" ", str(value or ""))[:limit]


# ─── Fixed kubectl commands ──────────────────────────────────────────────────


class KubectlUnavailable(Exception):
    """kubectl cannot answer. state: kubectl_missing | rbac_missing |
    crd_missing | api_unreachable | error."""

    def __init__(self, state: str, message: str):
        super().__init__(message)
        self.state = state


def _kubectl_env() -> dict[str, str]:
    """Only what kubectl needs to find its configuration."""
    keep = ("PATH", "HOME", "KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT")
    return {k: os.environ[k] for k in keep if k in os.environ}


def run_fixed(argv: tuple[str, ...], *, timeout: float = 120) -> dict[str, Any]:
    """Run one of FIXED_COMMANDS and return its JSON. Nothing else can be run
    through here: there is no parameter that reaches the argv."""
    if argv not in FIXED_COMMANDS:
        raise ValueError("not a fixed vulnscan command")
    kubectl = shutil.which("kubectl")
    if not kubectl:
        raise KubectlUnavailable("kubectl_missing", "kubectl is not installed in this image or on PATH")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv (FIXED_COMMANDS), no shell
            [kubectl, *argv[1:]], shell=False, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=timeout, env=_kubectl_env(), check=False)
    except subprocess.TimeoutExpired:
        raise KubectlUnavailable("api_unreachable", f"kubectl did not answer within {timeout:g} s") from None
    except OSError as exc:
        raise KubectlUnavailable("kubectl_missing", f"kubectl could not be run ({type(exc).__name__})") from None
    stderr = proc.stderr.decode("utf-8", "replace")[:2000]
    if proc.returncode != 0:
        low = stderr.lower()
        if "forbidden" in low:
            state = "rbac_missing"
        elif "doesn't have a resource type" in low or "no matches for kind" in low:
            state = "crd_missing"
        elif any(s in low for s in ("unable to connect", "connection refused", "no such host", "i/o timeout",
                                    "the server could not find", "was refused")):
            state = "api_unreachable"
        else:
            state = "error"
        raise KubectlUnavailable(state, " ".join(stderr.split())[:300] or f"kubectl exited {proc.returncode}")
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        raise KubectlUnavailable("error", "kubectl output is larger than the limit")
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        raise KubectlUnavailable("error", "kubectl did not return JSON") from None
    if not isinstance(data, dict):
        raise KubectlUnavailable("error", "kubectl did not return a JSON object")
    return data


# ─── Parsing ─────────────────────────────────────────────────────────────────


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if text in SEVERITIES else "UNKNOWN"


def report_workload(report: dict[str, Any]) -> tuple[str, str, str, str]:
    """(namespace, workload kind, workload name, container) of a Trivy
    report: from its trivy-operator.* labels, else its owner reference. A
    ReplicaSet is reported as its Deployment (pod-template-hash removed)."""
    meta = report.get("metadata") or {}
    labels = meta.get("labels") or {}
    owners = meta.get("ownerReferences") or [{}]
    namespace = str(labels.get("trivy-operator.resource.namespace") or meta.get("namespace") or "")
    kind = str(labels.get("trivy-operator.resource.kind") or owners[0].get("kind") or "")
    name = str(labels.get("trivy-operator.resource.name") or owners[0].get("name") or meta.get("name") or "")
    container = str(labels.get("trivy-operator.container.name") or "")
    if kind == "ReplicaSet" and _HASH_SUFFIX_RE.search(name):
        kind, name = "Deployment", _HASH_SUFFIX_RE.sub("", name)
    return namespace, kind or "Unknown", name, container


def report_image(report: dict[str, Any]) -> str:
    body = report.get("report") or {}
    artifact = body.get("artifact") or {}
    server = str((body.get("registry") or {}).get("server") or "")
    repo = str(artifact.get("repository") or "")
    tag = str(artifact.get("tag") or "")
    image = f"{server}/{repo}" if server and repo else repo
    return _text(f"{image}:{tag}" if tag else image, 300)


def parse_vulnerability_reports(data: dict[str, Any]) -> tuple[list[dict[str, Any]], set[tuple]]:
    """(findings, workload/container keys that have a report in this scan)."""
    findings: dict[tuple, dict[str, Any]] = {}
    scanned: set[tuple] = set()
    for report in data.get("items") or []:
        if not isinstance(report, dict):
            continue
        namespace, kind, workload, container = report_workload(report)
        if not namespace or not workload:
            continue
        scanned.add((namespace, kind, workload, container))
        image = report_image(report)
        for vuln in (report.get("report") or {}).get("vulnerabilities") or []:
            cve = str(vuln.get("vulnerabilityID") or "").strip()
            if not cve:
                continue
            item = {
                "namespace": namespace, "workload_kind": kind, "workload": workload, "container": container,
                "image": image, "package": _text(vuln.get("resource"), 200),
                "installed_version": _text(vuln.get("installedVersion"), 100),
                "cve_id": _text(cve, 64), "severity": normalize_severity(vuln.get("severity")),
                "fixed_version": _text(vuln.get("fixedVersion"), 200) or None,
                "title": _text(vuln.get("title"), 500), "primary_link": _text(vuln.get("primaryLink"), 500) or None,
                "score": float(vuln["score"]) if isinstance(vuln.get("score"), (int, float)) else None,
            }
            key = (namespace, kind, workload, container, item["package"], item["cve_id"])
            previous = findings.get(key)
            if previous is None or SEVERITY_RANK[item["severity"]] > SEVERITY_RANK[previous["severity"]]:
                findings[key] = item
    return list(findings.values()), scanned


def parse_config_audit_reports(data: dict[str, Any]) -> list[dict[str, Any]]:
    out: dict[tuple, dict[str, Any]] = {}
    for report in data.get("items") or []:
        if not isinstance(report, dict):
            continue
        namespace, kind, workload, _ = report_workload(report)
        if not namespace or not workload:
            continue
        summary = (report.get("report") or {}).get("summary") or {}
        counts = {k: int(summary.get(f"{k}Count") or 0) for k in ("critical", "high", "medium", "low")}
        key = (namespace, kind, workload)
        prev = out.get(key)
        out[key] = {"namespace": namespace, "workload_kind": kind, "workload": workload,
                    **({k: prev[k] + v for k, v in counts.items()} if prev else counts)}
    return list(out.values())


def parse_ingresses(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(namespace, ingress, service) for every backend Service an Ingress
    routes to (rules and defaultBackend; the pre-v1 serviceName form too)."""
    out: set[tuple[str, str, str]] = set()
    for ing in data.get("items") or []:
        if not isinstance(ing, dict):
            continue
        meta = ing.get("metadata") or {}
        ns, name = str(meta.get("namespace") or ""), str(meta.get("name") or "")
        spec = ing.get("spec") or {}
        backends = [spec.get("defaultBackend") or spec.get("backend") or {}]
        for rule in spec.get("rules") or []:
            backends += [p.get("backend") or {} for p in ((rule or {}).get("http") or {}).get("paths") or []]
        for backend in backends:
            service = (backend.get("service") or {}).get("name") or backend.get("serviceName")
            if ns and name and service:
                out.add((ns, name, str(service)))
    return sorted(out)


def parse_services(data: dict[str, Any]) -> set[tuple[str, str]]:
    """(namespace, name) of every Service."""
    out: set[tuple[str, str]] = set()
    for svc in data.get("items") or []:
        meta = (svc or {}).get("metadata") or {}
        if meta.get("namespace") and meta.get("name"):
            out.add((str(meta["namespace"]), str(meta["name"])))
    return out


def parse_endpointslices(data: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    """{(namespace, service): pod names} from EndpointSlices: the slice's
    kubernetes.io/service-name label and its endpoints' Pod targetRefs
    (ready or not: a path exists either way)."""
    out: dict[tuple[str, str], set[str]] = {}
    for sl in data.get("items") or []:
        meta = (sl or {}).get("metadata") or {}
        ns = str(meta.get("namespace") or "")
        service = str((meta.get("labels") or {}).get(SERVICE_NAME_LABEL) or "")
        if not ns or not service:
            continue
        pods = out.setdefault((ns, service), set())
        for endpoint in sl.get("endpoints") or []:
            ref = (endpoint or {}).get("targetRef") or {}
            if ref.get("kind") == "Pod" and ref.get("name") and str(ref.get("namespace") or ns) == ns:
                pods.add(str(ref["name"]))
    return out


def exposure_chain(backends: list[tuple[str, str, str]], services: set[tuple[str, str]],
                   slices: dict[tuple[str, str], set[str]]) -> list[tuple[str, str, str, str]]:
    """(namespace, ingress, service, pod) for every Ingress backend Service
    that exists and has a pod behind it. A backend whose Service is missing,
    or has no EndpointSlice pods, yields nothing (no path)."""
    out: set[tuple[str, str, str, str]] = set()
    for ns, ingress, service in backends:
        if (ns, service) not in services:
            continue
        for pod in slices.get((ns, service), ()):
            out.add((ns, ingress, service, pod))
    return sorted(out)


# ─── Exposure, attack correlation, risk ──────────────────────────────────────

_GENERATED_SUFFIX_KINDS = ("Deployment", "ReplicaSet", "DaemonSet", "Job")


def pod_matches_workload(pod: str | None, kind: str, workload: str) -> bool:
    """A pod belongs to the workload, by its generated name: the identity
    used both for attack correlation and for exposure (EndpointSlice pods).

    Kubernetes cuts a generated pod name to 63 characters: the owner's
    generateName is truncated to 58 and 5 random characters follow, so a
    long Deployment's pods lose the hash (e.g. "...-pgadmin-deploymenzpnl").
    A 63-character name matches only what that cut can produce:
      * ReplicaSet/DaemonSet/Job pods ("<name>-"): its first 58 characters
        are exactly ("<workload>-")[:58];
      * Deployment pods ("<deployment>-<pod-template-hash>-"): the same, or
        "<workload>-" followed by the start of a 1-10 character hash (so a
        shorter workload that is merely a prefix does not match)."""
    if not pod or pod == "-" or not workload:
        return False
    if kind in _GENERATED_SUFFIX_KINDS and len(pod) == 63:
        head = pod[:58]
        if head == (workload + "-")[:58]:
            return True
        if kind == "Deployment" and head.startswith(workload + "-") and \
                re.fullmatch(r"[a-z0-9]{1,10}-?", head[len(workload) + 1:]):
            return True
    w = re.escape(workload)
    patterns = {
        "Deployment": rf"{w}-[a-z0-9]{{6,10}}-[a-z0-9]{{5}}",
        "ReplicaSet": rf"{w}-[a-z0-9]{{5}}",
        "StatefulSet": rf"{w}-\d+",
        "DaemonSet": rf"{w}-[a-z0-9]{{5}}",
        "Job": rf"{w}-[a-z0-9]{{5}}",
        "CronJob": rf"{w}-\d+-[a-z0-9]{{5}}",
        "Pod": w,
    }
    return re.fullmatch(patterns.get(kind, rf"{w}(-.+)?"), pod) is not None


def risk_tier(*, severity: str, fixable: bool, is_kev: bool, exposed: bool, attacked: bool) -> dict[str, Any]:
    """The risk tier of one finding, and why. The rule (tune here):

      critical  either path:
                  (A) severity CRITICAL or HIGH, AND a fix exists, AND in CISA
                      KEV, AND (exposed OR attacked recently)
                  (B) in CISA KEV AND (exposed OR attacked recently), whatever
                      the severity or fix: KEV listing already means real-world
                      exploitation, and reachability makes it urgent
                Today (B) contains (A): every finding (A) catches, (B) catches
                too. (A) stays written out because tightening (B) later (e.g.
                requiring a fix, or a severity floor) must not drop what (A)
                covers. The reason list says which path matched.
      high      at least two of: severity >= HIGH, in KEV, exposed, attacked
      medium    exactly one of those four
      low       none of them

    "exposed": a real Ingress -> Service -> EndpointSlice path to a pod of
    the workload, or the workload listed in exposed_workloads. "attacked": a
    security incident or attack-tagged anomaly on a pod of the workload
    within correlation_lookback_s.
    """
    severe = SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["HIGH"]
    signals = {"severity>=HIGH": severe, "known exploited (KEV)": is_kev, "exposed": exposed,
               "recent attack": attacked}
    reasons = [name for name, on in signals.items() if on]
    reachable = exposed or attacked
    path_a = severe and fixable and is_kev and reachable
    path_b = is_kev and reachable
    if path_a or path_b:
        tier = "critical"
        reasons.append("critical: fixable severe KEV, reachable" if path_a else "critical: KEV, reachable")
    elif len(reasons) >= 2:
        tier = "high"
    elif len(reasons) == 1:
        tier = "medium"
    else:
        tier = "low"
    if fixable:
        reasons.append("fix available")
    return {"tier": tier, "reasons": reasons}


# ─── Store + poller ──────────────────────────────────────────────────────────


class VulnStore:
    """The cache tables (own connection to the cache database)."""

    def __init__(self, db_path: Path):
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_SECS)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            for statement in _SCHEMA:
                self._conn.execute(statement)
            self._conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def apply_scan(self, findings: list[dict[str, Any]], scanned: set[tuple], now: datetime) -> dict[str, int]:
        """Upsert this scan's findings; resolve the open findings of every
        scanned workload/container that this scan no longer lists; reopen
        one that is listed again. Workloads without a report are untouched."""
        stamp = _iso(now)
        counts = {"findings_new": 0, "findings_resolved": 0, "findings_seen": len(findings)}
        with self._lock:
            try:
                seen_ids: set[int] = set()
                for f in findings:
                    key = (f["namespace"], f["workload_kind"], f["workload"], f["container"], f["package"],
                           f["cve_id"])
                    row = self._conn.execute(
                        "SELECT id FROM vulnerability_findings WHERE namespace = ? AND workload_kind = ? AND "
                        "workload = ? AND container = ? AND package = ? AND cve_id = ?", key).fetchone()
                    values = (f["image"], f["installed_version"], f["severity"], f["fixed_version"], f["title"],
                              f["primary_link"], f["score"])
                    if row is None:
                        cur = self._conn.execute(
                            "INSERT INTO vulnerability_findings (namespace, workload_kind, workload, container, "
                            "package, cve_id, image, installed_version, severity, fixed_version, title, "
                            "primary_link, score, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                            "?, ?, ?)", (*key, *values, stamp, stamp))
                        seen_ids.add(int(cur.lastrowid))
                        counts["findings_new"] += 1
                    else:
                        self._conn.execute(
                            "UPDATE vulnerability_findings SET image = ?, installed_version = ?, severity = ?, "
                            "fixed_version = ?, title = ?, primary_link = ?, score = ?, last_seen = ?, "
                            "resolved_at = NULL WHERE id = ?", (*values, stamp, row["id"]))
                        seen_ids.add(int(row["id"]))
                for namespace, kind, workload, container in scanned:
                    open_rows = self._conn.execute(
                        "SELECT id FROM vulnerability_findings WHERE resolved_at IS NULL AND namespace = ? AND "
                        "workload_kind = ? AND workload = ? AND container = ?",
                        (namespace, kind, workload, container)).fetchall()
                    gone = [int(r["id"]) for r in open_rows if int(r["id"]) not in seen_ids]
                    if gone:
                        self._conn.execute(
                            "UPDATE vulnerability_findings SET resolved_at = ? "
                            "WHERE id IN (SELECT value FROM json_each(?))", (stamp, json.dumps(gone)))
                        counts["findings_resolved"] += len(gone)
                self._conn.execute(
                    "DELETE FROM vulnerability_findings WHERE resolved_at IS NOT NULL AND resolved_at < ?",
                    (_iso(now - timedelta(days=RESOLVED_KEEP_DAYS)),))
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        return counts

    def replace_config_audits(self, items: list[dict[str, Any]], now: datetime) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM config_audit_summary")
            self._conn.executemany(
                "INSERT INTO config_audit_summary (namespace, workload_kind, workload, critical, high, medium, low, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(i["namespace"], i["workload_kind"], i["workload"], i["critical"], i["high"], i["medium"], i["low"],
                  _iso(now)) for i in items])
            self._conn.commit()

    def replace_exposure_paths(self, paths: list[tuple[str, str, str, str]]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM exposure_paths")
            self._conn.executemany(
                "INSERT INTO exposure_paths (namespace, ingress, service, pod) VALUES (?, ?, ?, ?)", paths)
            self._conn.commit()

    # -- KEV ----------------------------------------------------------------------

    def kev_meta(self) -> dict[str, str]:
        return {r["name"]: r["value"] for r in self.rows("SELECT name, value FROM kev_meta")}

    def set_kev_meta(self, **values: Any) -> None:
        with self._lock:
            self._conn.executemany("INSERT OR REPLACE INTO kev_meta (name, value) VALUES (?, ?)",
                                   [(k, None if v is None else str(v)) for k, v in values.items()])
            self._conn.commit()

    def replace_kev(self, entries: list[dict[str, Any]], meta: dict[str, Any]) -> None:
        with self._lock:
            try:
                self._conn.execute("DELETE FROM kev_catalog")
                self._conn.executemany(
                    "INSERT OR REPLACE INTO kev_catalog (cve_id, date_added, short_description, vendor_project, "
                    "product, known_ransomware) VALUES (?, ?, ?, ?, ?, ?)",
                    [(e["cve_id"], e["date_added"], e["short_description"], e["vendor_project"], e["product"],
                      e["known_ransomware"]) for e in entries])
                self._conn.executemany("INSERT OR REPLACE INTO kev_meta (name, value) VALUES (?, ?)",
                                       [(k, None if v is None else str(v)) for k, v in meta.items()])
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise


def parse_kev(data: Any) -> list[dict[str, Any]]:
    """CISA's KEV JSON (vulnerabilities[].cveID ...). ValueError when it does
    not look like the catalog, so a broken download never replaces it."""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("not a KEV catalog (no 'vulnerabilities' list)")
    out = []
    for item in data["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        out.append({"cve_id": cve, "date_added": _text(item.get("dateAdded"), 20) or None,
                    "short_description": _text(item.get("shortDescription"), 1000),
                    "vendor_project": _text(item.get("vendorProject"), 200), "product": _text(item.get("product"), 200),
                    "known_ransomware": _text(item.get("knownRansomwareCampaignUse"), 20)})
    if not out and data["vulnerabilities"]:
        raise ValueError("no usable entries in the KEV catalog")
    return out


def fetch_kev(url: str) -> Any:
    """GET the KEV JSON (generic client name, no credentials, bounded size)."""
    req = request.Request(url, headers={"User-Agent": "logscope-webapp/1.0", "Accept": "application/json"})  # noqa: S310 - https only (config)
    with request.urlopen(req, timeout=KEV_TIMEOUT_S) as resp:  # noqa: S310
        body = resp.read(KEV_MAX_BYTES + 1)
    if len(body) > KEV_MAX_BYTES:
        raise ValueError("KEV catalog larger than the limit")
    return json.loads(body)


class VulnScanner:
    """The poller (reports + Ingresses) and the KEV refresher, each on its
    own thread; read-time views for the API."""

    def __init__(self, cfg: Any, store: VulnStore, *, runner: Callable[..., dict[str, Any]] = run_fixed,
                 kev_fetch: Callable[[str], Any] = fetch_kev,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.cfg = cfg
        self.store = store
        self._runner = runner
        self._kev_fetch = kev_fetch
        self._clock = clock
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.state = "never"  # ok | kubectl_missing | rbac_missing | crd_missing | api_unreachable | error
        self.last_poll_at: str | None = None
        self.last_success_at: str | None = None
        self.last_error: str | None = None
        self.last_counts: dict[str, int] = {}
        # Ingress/Service/EndpointSlice chain: "ok" when all three were read on
        # the last poll, else the failure's state (exposure is then "unknown"
        # unless a path or the allowlist says exposed).
        self.exposure_state = "never"
        self._logged_state: str | None = None

    @property
    def vcfg(self) -> Any:
        return self.cfg.security.vulnscan

    # -- lifecycle -------------------------------------------------------------------

    def start(self) -> None:
        if not self.vcfg.enabled:
            return
        for target, name in ((self._poll_loop, "vulnscan-poll"), (self._kev_loop, "vulnscan-kev")):
            thread = threading.Thread(target=target, daemon=True, name=name)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=5)

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - never kills the loop; visible in /api/status
                self.last_error = type(exc).__name__
                logger.warning("Vulnerability poll failed (%s)", type(exc).__name__)
            # The normal interval even after a failure: no tight retry loop.
            self._stop.wait(float(self.vcfg.poll_interval_s))

    def _kev_loop(self) -> None:
        while not self._stop.is_set():
            wait = float(self.vcfg.kev_refresh_s)
            try:
                if self.kev_due():
                    if not self.refresh_kev():
                        wait = min(wait, KEV_RETRY_S)
                else:
                    wait = max(60.0, self.kev_due_in())
            except Exception as exc:  # noqa: BLE001
                logger.warning("KEV refresh failed (%s)", type(exc).__name__)
                wait = min(wait, KEV_RETRY_S)
            self._stop.wait(wait)

    # -- poll ----------------------------------------------------------------------

    def _set_state(self, state: str, message: str | None) -> None:
        self.state = state
        if state != self._logged_state:
            if state == "ok":
                if self._logged_state not in (None, "never"):
                    logger.info("Vulnerability reports are readable again")
            else:
                logger.warning("Vulnerability view degraded (%s): %s; next try in %g s", state, message,
                               float(self.vcfg.poll_interval_s))
            self._logged_state = state

    def poll_once(self, now: datetime | None = None) -> dict[str, int]:
        now = now or self._clock()
        self.last_poll_at = _iso(now)
        timeout = float(self.vcfg.kubectl_timeout_s)
        try:
            data = self._runner(VULN_ARGV, timeout=timeout)
        except KubectlUnavailable as exc:
            self.last_error = str(exc)[:300]
            self._set_state(exc.state, self.last_error)
            return {}
        findings, scanned = parse_vulnerability_reports(data)
        counts = self.store.apply_scan(findings, scanned, now)
        self.last_error = None
        self._set_state("ok", None)
        self.last_success_at = _iso(now)
        try:  # optional parts: their failure keeps the previous data
            self.store.replace_config_audits(parse_config_audit_reports(
                self._runner(CONFIG_AUDIT_ARGV, timeout=timeout)), now)
        except KubectlUnavailable as exc:
            logger.info("ConfigAuditReports not read (%s)", exc.state)
        try:
            backends = parse_ingresses(self._runner(INGRESS_ARGV, timeout=timeout))
            services = parse_services(self._runner(SERVICES_ARGV, timeout=timeout))
            slices = parse_endpointslices(self._runner(ENDPOINTSLICES_ARGV, timeout=timeout))
        except KubectlUnavailable as exc:
            # Keep the last paths (positive evidence); absence is now unknown.
            self.exposure_state = exc.state
            logger.info("Exposure chain not read (%s); exposure is unknown where no path is known", exc.state)
        else:
            self.store.replace_exposure_paths(exposure_chain(backends, services, slices))
            self.exposure_state = "ok"
        self.last_counts = counts
        return counts

    # -- KEV -----------------------------------------------------------------------

    def kev_due_in(self, now: datetime | None = None) -> float:
        last = _parse(self.store.kev_meta().get("last_success"))
        if last is None:
            return 0.0
        return float(self.vcfg.kev_refresh_s) - ((now or self._clock()) - last).total_seconds()

    def kev_due(self, now: datetime | None = None) -> bool:
        return self.kev_due_in(now) <= 0

    def refresh_kev(self, now: datetime | None = None) -> bool:
        """Fetch and replace the catalog; on any failure keep the last good
        one and record the error. True when refreshed."""
        now = now or self._clock()
        try:
            data = self._kev_fetch(self.vcfg.kev_url)
            entries = parse_kev(data)
        except Exception as exc:  # noqa: BLE001 - network, HTTP, JSON: all degrade the same way
            message = f"{type(exc).__name__}: {str(exc)[:200]}"
            self.store.set_kev_meta(last_attempt=_iso(now), last_error=message)
            logger.warning("KEV catalog refresh failed (%s); using the last good copy", type(exc).__name__)
            return False
        self.store.replace_kev(entries, {
            "last_success": _iso(now), "last_attempt": _iso(now), "last_error": None,
            "catalog_version": _text(data.get("catalogVersion"), 50), "date_released": _text(data.get("dateReleased"), 50),
            "count": len(entries)})
        return True

    def kev_status(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or self._clock()
        meta = self.store.kev_meta()
        last = _parse(meta.get("last_success"))
        age = (now - last).total_seconds() if last else None
        return {"entries": int(meta.get("count") or 0), "last_success_at": meta.get("last_success"),
                "age_s": int(age) if age is not None else None,
                "stale": last is None or age > 2 * float(self.vcfg.kev_refresh_s),
                "catalog_version": meta.get("catalog_version"), "last_attempt_at": meta.get("last_attempt"),
                "last_error": meta.get("last_error")}

    def status(self) -> dict[str, Any]:
        degraded = self.state not in ("ok", "never")
        try:
            open_count = int(self.store.rows(
                "SELECT COUNT(*) AS n FROM vulnerability_findings WHERE resolved_at IS NULL")[0]["n"])
            kev = self.kev_status()
        except sqlite3.Error as exc:
            return {"enabled": bool(self.vcfg.enabled), "status_error": type(exc).__name__}
        return {"enabled": bool(self.vcfg.enabled), "state": self.state, "degraded": degraded,
                "rbac_missing": self.state == "rbac_missing", "kubectl_missing": self.state == "kubectl_missing",
                "last_poll_at": self.last_poll_at, "last_success_at": self.last_success_at,
                "last_error": self.last_error, "exposure_state": self.exposure_state,
                "findings_open": open_count, "last_counts": dict(self.last_counts), "kev": kev}

    # -- read-time view ------------------------------------------------------------

    def exposure(self, namespace: str, kind: str, workload: str,
                 paths: dict[str, list[tuple[str, str, str]]]) -> dict[str, Any]:
        """{"state": exposed | not_exposed | unknown, "via": text or None}.
        A real Ingress -> Service -> pod path first, then the allowlist; with
        neither, "not_exposed" when the chain was read on the last poll, else
        "unknown". Never decided from names."""
        for ingress, service, pod in paths.get(namespace, []):
            if pod_matches_workload(pod, kind, workload):
                return {"state": "exposed", "via": f"ingress {ingress} -> service {service} -> pod {pod}"}
        for entry in self.vcfg.exposed_workloads:
            ns, _, wl = entry.partition("/")
            if ns == namespace and (not wl or wl == workload):
                return {"state": "exposed", "via": "config (exposed_workloads)"}
        return {"state": "not_exposed" if self.exposure_state == "ok" else "unknown", "via": None}

    def attacks(self, namespace: str, kind: str, workload: str, now: datetime) -> dict[str, list[dict[str, Any]]]:
        """Security incidents and attack-tagged anomalies on a pod of the
        workload within correlation_lookback_s (read-time; nothing written)."""
        cutoff = now - timedelta(seconds=float(self.vcfg.correlation_lookback_s))
        incidents, anomalies = [], []
        try:
            for row in self.store.rows(
                    "SELECT id, pod, opened_at, attack_type, severity, state FROM security_incidents "
                    "WHERE namespace = ? ORDER BY id DESC LIMIT 500", (namespace,)):
                opened = _parse(row["opened_at"])
                if opened and opened >= cutoff and pod_matches_workload(row["pod"], kind, workload):
                    incidents.append({"id": row["id"], "attack_type": row["attack_type"], "at": row["opened_at"],
                                      "severity": row["severity"], "state": row["state"]})
        except sqlite3.OperationalError:
            pass  # no security_incidents table yet
        try:
            for row in self.store.rows(
                    "SELECT id, type, pod, attack_type, updated_at FROM anomalies WHERE namespace = ? "
                    "AND attack_type IS NOT NULL AND attack_type != '' AND status != 'dismissed' "
                    "ORDER BY id DESC LIMIT 500", (namespace,)):
                seen = _parse(row["updated_at"])
                if seen and seen >= cutoff and pod_matches_workload(row["pod"], kind, workload):
                    anomalies.append({"id": row["id"], "type": row["type"], "attack_type": row["attack_type"],
                                      "at": row["updated_at"]})
        except sqlite3.OperationalError:
            pass
        return {"incidents": incidents, "anomalies": anomalies}

    def view(self, *, tier: str | None = None, namespace: str | None = None, kev: bool | None = None,
             include_resolved: bool = False, limit: int = 200, now: datetime | None = None) -> dict[str, Any]:
        now = now or self._clock()
        where, args = [], []
        if not include_resolved:
            where.append("f.resolved_at IS NULL")
        if namespace:
            where.append("f.namespace = ?")
            args.append(namespace)
        if kev is not None:
            where.append("k.cve_id IS NOT NULL" if kev else "k.cve_id IS NULL")
        rows = self.store.rows(
            "SELECT f.*, k.cve_id AS kev_cve, k.date_added AS kev_date_added, "
            "k.short_description AS kev_description, k.known_ransomware AS kev_ransomware "
            "FROM vulnerability_findings f LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id"
            + (" WHERE " + " AND ".join(where) if where else ""), tuple(args))
        paths: dict[str, list[tuple[str, str, str]]] = {}
        for p in self.store.rows("SELECT namespace, ingress, service, pod FROM exposure_paths ORDER BY ingress, pod"):
            paths.setdefault(p["namespace"], []).append((p["ingress"], p["service"], p["pod"]))
        audits = {(a["namespace"], a["workload_kind"], a["workload"]): a
                  for a in self.store.rows("SELECT * FROM config_audit_summary")}
        per_workload: dict[tuple, dict[str, Any]] = {}
        items, counts = [], dict.fromkeys(TIERS, 0)
        for row in rows:
            wkey = (row["namespace"], row["workload_kind"], row["workload"])
            if wkey not in per_workload:
                attacks = self.attacks(*wkey, now)
                audit = audits.get(wkey)
                per_workload[wkey] = {
                    "exposure": self.exposure(row["namespace"], row["workload_kind"], row["workload"], paths),
                    "attacks": attacks,
                    "config_audit": ({k: audit[k] for k in ("critical", "high", "medium", "low")} if audit else None)}
            context = per_workload[wkey]
            is_kev = row["kev_cve"] is not None
            attacked = bool(context["attacks"]["incidents"] or context["attacks"]["anomalies"])
            exposed = context["exposure"]["state"] == "exposed"
            risk = risk_tier(severity=row["severity"], fixable=bool(row["fixed_version"]), is_kev=is_kev,
                             exposed=exposed, attacked=attacked)
            counts[risk["tier"]] += 1
            if tier and risk["tier"] != tier:
                continue
            item = {k: row[k] for k in ("id", "namespace", "workload_kind", "workload", "container", "image",
                                        "package", "installed_version", "cve_id", "severity", "fixed_version",
                                        "title", "primary_link", "score", "first_seen", "last_seen", "resolved_at")}
            item.update({
                "is_kev": is_kev,
                "kev": ({"date_added": row["kev_date_added"], "short_description": row["kev_description"],
                         "known_ransomware": row["kev_ransomware"]} if is_kev else None),
                "exposed": exposed, "exposure": context["exposure"]["via"],
                "exposure_state": context["exposure"]["state"],
                "attacks": context["attacks"], "config_audit": context["config_audit"], "risk": risk,
            })
            items.append(item)
        tier_rank = {t: len(TIERS) - i for i, t in enumerate(TIERS)}
        items.sort(key=lambda i: (-tier_rank[i["risk"]["tier"]], -SEVERITY_RANK[i["severity"]], not i["is_kev"],
                                  i["namespace"], i["workload"], i["cve_id"]))
        return {"items": items[:limit], "total": len(items), "counts": counts, "kev": self.kev_status(now),
                "state": self.state}


__all__ = ["FIXED_COMMANDS", "KubectlUnavailable", "VulnScanner", "VulnStore", "parse_ingresses", "parse_kev",
           "parse_endpointslices", "parse_services", "parse_vulnerability_reports", "pod_matches_workload",
           "exposure_chain", "risk_tier", "run_fixed"]
