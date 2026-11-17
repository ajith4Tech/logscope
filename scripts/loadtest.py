#!/usr/bin/env python3
"""Load test for the web app's cache: synthetic Kubernetes logs at scale,
ingested through the S3 ingest code (minus the network), then timed reads,
detection, alert evaluation, maintenance and a mixed read/ingest load.

    python3 scripts/loadtest.py --rows 1000000            # or: make loadtest ROWS=1000000
    python3 scripts/loadtest.py --rows 5000000 --workdir /tmp/lt5m --reuse --json after.json
    python3 scripts/loadtest.py --compare before.json after.json

Data: 20 namespaces (5 infra, 15 user-*), 200 pods (40 deployments x 5
replicas, replicaset hashes, 3 containers per deployment), about 500 message
templates drawn with a Zipf distribution (s=1.2) with variable fields;
severity 70% info, 15% debug, 10% warning, 4% error, 1% metrics, plus 0.5%
Falco events (15 rules, written to security/ objects), flattened multiline
Postgres errors and Python tracebacks, and mixed timestamp formats (Z,
fractions, +05:30, no zone). Seven days with a diurnal shape and 3 incident
spikes, ending at the current 10-minute boundary. Objects are gzip, one per
severity per 10 minutes, keyed like Vector's.

Timings run each measurement up to --runs times (default 30) within a time
budget per measurement (--budget seconds, at least --min-runs runs), after
one untimed warm-up, and report p50 / p95 / max in milliseconds. Nothing here
touches S3, a cluster or the network: HTTP goes to 127.0.0.1, and the S3
throughput test uses moto (dev-only) when it is installed.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import http.client
import io
import json
import math
import multiprocessing
import os
import random
import shutil
import sqlite3
import statistics
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[1]
BUCKET = "loadtest-bucket"
REGION = "us-east-1"
KEY_PREFIX = "k3s-logs/logs/{{ log_type }}/%Y/%m/%d/%H_%M_%S_"
WINDOW_SECS = 600
DAYS = 7
SEVERITY_MIX = (("info", 0.70), ("debug", 0.15), ("warning", 0.10), ("error", 0.04), ("metrics", 0.01))
FALCO_SHARE = 0.005
ZIPF_S = 1.2
INFRA = ("kube-system", "kube-public", "kube-node-lease", "default", "ingress-nginx")
USERS = tuple(f"user-{n}" for n in ("payments", "orders", "search", "auth", "billing", "catalog", "cart", "ship",
                                    "notify", "report", "media", "chat", "profile", "ledger", "gateway"))
FALCO_RULES = (
    "Terminal shell in container", "Write below etc", "Read sensitive file untrusted", "Launch Privileged Container",
    "Contact K8S API Server From Container", "Unexpected outbound connection destination", "Modify binary dirs",
    "Create files below dev", "Change thread namespace", "Netcat Remote Code Execution in Container",
    "Find AWS Credentials", "PTRACE attached to process", "Drop and execute new binary in container",
    "Clear Log Activities", "Search Private Keys or Passwords",
)
FALCO_BUCKETS = ("warning", "warning", "error", "info")


# ─── synthetic data ──────────────────────────────────────────────────────────


def _hash(rng: random.Random, n: int, alphabet: str = "bcdfghjklmnpqrstvwxz2456789") -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _pods(rng: random.Random) -> list[tuple[str, str, tuple[str, ...]]]:
    """(namespace, pod, containers): 40 deployments x 5 replicas = 200 pods."""
    kinds = ("api", "web", "worker", "db", "cache", "proxy", "cron", "consumer")
    pods = []
    namespaces = INFRA + USERS
    for d in range(40):
        ns = namespaces[d % len(namespaces)]
        name = f"{kinds[d % len(kinds)]}-{d}"
        containers = (name.split("-")[0], "sidecar", "metrics-agent")
        rs = _hash(rng, 10)
        for _ in range(5):
            pods.append((ns, f"{name}-{rs}-{_hash(rng, 5)}", containers))
    return pods


_WORDS = ("user", "order", "invoice", "session", "cart", "payment", "token", "report", "upload", "index",
          "shard", "lease", "queue", "batch", "job", "cache", "replica", "volume", "secret", "config")
_VERBS = ("created", "updated", "deleted", "fetched", "processed", "scheduled", "retried", "synced", "flushed",
          "validated", "reconciled", "rotated")


def _templates(rng: random.Random) -> dict[str, list[str]]:
    """About 500 templates per severity pool; placeholders are filled per line."""
    out: dict[str, list[str]] = {"info": [], "debug": [], "warning": [], "error": [], "metrics": []}
    for i in range(300):
        w, v = _WORDS[i % len(_WORDS)], _VERBS[(i // len(_WORDS)) % len(_VERBS)]
        shape = i % 5
        out["info"].append(
            (f"GET /api/v1/{w}s/{{id}} 200 {{ms}}ms", f"{w} {{id}} {v} in {{ms}}ms",
             f"{v} {w} {{uuid}} for tenant {{n}}", f"request from {{ip}} {v} {w} batch size={{n}}",
             f"worker-{i} {v} {{n}} {w} records")[shape])
    for i in range(80):
        w = _WORDS[i % len(_WORDS)]
        out["debug"].append(f"debug: {w} cache lookup key={{uuid}} hit={{n}} probe-{i}")
    for i in range(70):
        w = _WORDS[i % len(_WORDS)]
        out["warning"].append((f"warn: slow query on {w} took {{ms}}ms (threshold 500ms) q{i}",
                               f"WARNING retrying {w} {{id}} after timeout attempt={{n}}",
                               f"deprecated API used by {{ip}} for {w} v{i}")[i % 3])
    for i in range(40):
        w = _WORDS[i % len(_WORDS)]
        out["error"].append((f"error: failed to process {w} {{id}}: connection refused to {{ip}}:5432",
                             f"ERROR upstream {w} returned 503 after {{ms}}ms e{i}",
                             f"exception while handling {w} {{uuid}}: timeout")[i % 3])
    out["error"].append("ERROR:  duplicate key value violates unique constraint \"users_email_key\" "
                        "DETAIL:  Key (email)=(user{n}@example.com) already exists. "
                        "HINT:  Use ON CONFLICT DO UPDATE to merge the row. "
                        "STATEMENT:  INSERT INTO users(email) VALUES ('user{n}@example.com')")
    out["error"].append("Traceback (most recent call last):   File \"/app/handlers.py\", line {n}, in handle     "
                        "result = process(payload)   File \"/app/core.py\", line 88, in process     "
                        "raise ValueError(\"bad payload {id}\") ValueError: bad payload {id}")
    out["error"].append("ERROR:  deadlock detected DETAIL:  Process {n} waits for ShareLock on transaction {id}; "
                        "blocked by process 4242. HINT:  See server log for query details.")
    out["error"].append("panic: runtime error: invalid memory address or nil pointer dereference "
                        "goroutine {n} [running]: main.handle(0x{id})")
    out["error"].append("java.lang.IllegalStateException: pool exhausted for {ip}   at com.example.Pool.get(Pool.java:{n})")
    for i in range(5):
        out["metrics"].append(f"# TYPE http_requests_total_{i} counter" if i == 0 else
                              f"http_requests_total{{{{code=\"200\",route=\"/r{i}\"}}}} {{n}}")
    return out


def _zipf(n: int) -> list[float]:
    acc, out = 0.0, []
    for k in range(1, n + 1):
        acc += 1.0 / k ** ZIPF_S
        out.append(acc)
    return out


class Generator:
    """Deterministic (seeded) synthetic lines, grouped into Vector-shaped objects."""

    def __init__(self, rows: int, end: datetime, seed: int = 7):
        self.rng = random.Random(seed)
        self.rows = rows
        self.end = end
        self.start = end - timedelta(days=DAYS)
        self.pods = _pods(self.rng)
        self.templates = _templates(self.rng)
        self.cum = {sev: _zipf(len(pool)) for sev, pool in self.templates.items()}
        self.windows = DAYS * 86400 // WINDOW_SECS
        weights = []
        for w in range(self.windows):
            t = self.start + timedelta(seconds=w * WINDOW_SECS)
            hour = t.hour + t.minute / 60
            weights.append(1.0 + 0.6 * math.sin(2 * math.pi * (hour - 8) / 24))  # busier in the afternoon
        total = sum(weights)
        self.per_window = [rows * w / total for w in weights]
        # Three 30-minute incidents: 10x errors in one namespace each.
        self.incidents = {}
        for day, ns in ((2, USERS[0]), (4, USERS[3]), (6, USERS[7])):
            first = (day * 86400 + 14 * 3600) // WINDOW_SECS
            for w in range(first, first + 3):
                self.incidents[w] = ns

    def _fill(self, template: str) -> str:
        r = self.rng
        return (template.replace("{id}", str(r.randrange(1, 10_000_000)))
                .replace("{ms}", str(r.randrange(1, 3000)))
                .replace("{uuid}", f"{r.getrandbits(32):08x}-{r.getrandbits(16):04x}")
                .replace("{ip}", f"10.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(256)}")
                .replace("{n}", str(r.randrange(1, 500))))

    def _timestamp(self, moment: datetime) -> str:
        roll = self.rng.random()
        if roll < 0.90:
            return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
        if roll < 0.94:
            return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if roll < 0.97:
            return (moment + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%dT%H:%M:%S+05:30")
        return moment.strftime("%Y-%m-%dT%H:%M:%S")  # no zone: UTC

    def windows_iter(self):
        """Yields (window start, {bucket: [lines]}, {bucket: [falco lines]})."""
        carry = 0.0
        for w in range(self.windows):
            t0 = self.start + timedelta(seconds=w * WINDOW_SECS)
            carry += self.per_window[w]
            n = int(carry)
            carry -= n
            regular: dict[str, list[str]] = {}
            security: dict[str, list[str]] = {}
            offsets = sorted(self.rng.random() * WINDOW_SECS for _ in range(n))
            sevs = self.rng.choices([s for s, _ in SEVERITY_MIX], [p for _, p in SEVERITY_MIX], k=n)
            incident_ns = self.incidents.get(w)
            for off, sev in zip(offsets, sevs, strict=True):
                moment = t0 + timedelta(seconds=off)
                ts = self._timestamp(moment)
                if self.rng.random() < FALCO_SHARE:
                    rule = FALCO_RULES[min(int(self.rng.paretovariate(1.2)) - 1, len(FALCO_RULES) - 1)]
                    bucket = self.rng.choice(FALCO_BUCKETS)
                    line = (f"{ts} - falco - falco-{_hash(self.rng, 5)}/falco - {rule}: "
                            f"{moment.strftime('%H:%M:%S')}.{self.rng.randrange(10**9):09d}: Warning {rule.lower()} "
                            f"| user=root container_id={_hash(self.rng, 12)} proc=sh scope=security")
                    security.setdefault(bucket, []).append(line)
                    continue
                if incident_ns and self.rng.random() < 0.3:
                    sev = "error"
                    ns, pod, ctrs = next(p for p in self.pods if p[0] == incident_ns)
                else:
                    ns, pod, ctrs = self.pods[self.rng.randrange(len(self.pods))]
                pool = self.templates[sev]
                template = self.rng.choices(pool, cum_weights=self.cum[sev], k=1)[0]
                regular.setdefault(sev, []).append(f"{ts} - {ns} - {pod}/{ctrs[self.rng.randrange(3)]} - "
                                                   f"{self._fill(template)}")
            yield t0, regular, security


class FakeS3:
    """get_object / list for in-memory gzip objects (the ingest code path minus the network)."""

    def __init__(self):
        self.bodies: dict[str, bytes] = {}

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3's names
        return {"Body": io.BytesIO(self.bodies.pop(Key)), "ETag": f'"{Key[-12:]}"'}

    def get_paginator(self, name):
        raise AssertionError("the load test feeds objects directly")


def _gz(lines: list[str]) -> bytes:
    return gzip.compress(("\n".join(lines) + "\n").encode("utf-8"), compresslevel=6)


def _key(root: str, bucket: str, t0: datetime, n: int, security: bool = False) -> str:
    return f"{root}{'security/' if security else ''}{bucket}/{t0.strftime('%Y/%m/%d/%H_%M_%S_')}{n:06d}.log.gz"


# ─── setup ───────────────────────────────────────────────────────────────────


def _write_config(workdir: Path) -> Path:
    import yaml

    raw = yaml.safe_load((REPO / "config.example.yaml").read_text())
    raw["routing"]["infra_namespaces"] = list(INFRA)
    raw["sinks"]["s3"].update(enabled=True, bucket=BUCKET, region=REGION, key_prefix=KEY_PREFIX, retention_days=30)
    raw["webapp"]["backend"].update(db_path=str(workdir / "cache.sqlite"),
                                    state_db_path=str(workdir / "state" / "state.sqlite"), retention_days=30)
    raw["webapp"]["mattermost"] = {"enabled": False}
    path = workdir / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def _ingest_objects(ingestor, specs, fake: FakeS3, objects: list[tuple[str, str, str, bytes]]) -> float:
    """objects: (prefix, key, last_modified, gzip body). Returns seconds spent in the ingest code."""
    from webapp.api.ingest import IngestResult

    result = IngestResult()
    elapsed = 0.0
    for prefix, key, last_modified, body in objects:
        fake.bodies[key] = body
        started = time.perf_counter()
        error = ingestor._try_object(result, specs[prefix], key, key[-12:], last_modified)
        elapsed += time.perf_counter() - started
        if error:
            raise RuntimeError(error)
    return elapsed


def generate(cfg, rows: int, end: datetime, log=print) -> dict[str, Any]:
    from webapp.api.config import source_prefixes
    from webapp.api.ingest import S3Ingestor
    from webapp.api.storage import LogStorage

    storage = LogStorage(cfg.webapp.db_path)
    ingestor = S3Ingestor(cfg, storage)
    fake = FakeS3()
    ingestor.client = fake
    specs = {p["prefix"]: p for p in source_prefixes(cfg)}
    root = KEY_PREFIX.split("{{", 1)[0]
    gen = Generator(rows, end)
    ingest_secs = 0.0
    lines = 0
    started = time.perf_counter()
    for i, (t0, regular, security) in enumerate(gen.windows_iter()):
        objects = []
        stamp = (t0 + timedelta(seconds=WINDOW_SECS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for bucket, batch in regular.items():
            objects.append((f"{root}{bucket}/", _key(root, bucket, t0, i), stamp, _gz(batch)))
            lines += len(batch)
        for bucket, batch in security.items():
            objects.append((f"{root}security/{bucket}/", _key(root, bucket, t0, i, True), stamp, _gz(batch)))
            lines += len(batch)
        ingest_secs += _ingest_objects(ingestor, specs, fake, objects)
        if i % 144 == 0:
            log(f"  day {i // 144 + 1}/{DAYS}: {lines:,} lines, {lines / max(ingest_secs, 1e-9):,.0f} lines/s ingest")
    storage.conn.close()
    return {"lines": lines, "ingest_secs": ingest_secs, "wall_secs": time.perf_counter() - started,
            "lines_per_sec": lines / max(ingest_secs, 1e-9)}


def seed_views_and_rules(app) -> None:
    if app.views.list():
        return
    views = []
    filters = ([{"ns": ns} for ns in USERS[:8]] + [{"ns": ns, "sev": "error"} for ns in USERS[:6]]
               + [{"sev": "error"}, {"sev": "warning"}, {"scope": "infra"}, {"scope": "security"},
                  {"ns": USERS[1], "q": "timeout"}, {"xns": ",".join(INFRA)}])
    for i, f in enumerate(filters[:20]):
        views.append(app.views.create({"name": f"view {i:02d}", "filters": f})["id"])
    metrics = ("count", "error_count", "distinct_pods")
    for i in range(50):
        metric = metrics[i % 3]
        app.alert_rules.create({
            "name": f"rule {i:02d}", "view_id": views[i % len(views)], "metric": metric,
            "op": "<" if i % 10 == 9 else ">", "threshold": {"count": 500, "error_count": 20, "distinct_pods": 3}[metric],
            "window_s": (300, 900, 3600)[i % 3], "interval_s": 60, "for_evals": 1,
            "group_by": "pod" if i % 3 == 0 else ("namespace" if i % 3 == 1 else "none"), "channel_ids": [],
        })


# ─── timing ──────────────────────────────────────────────────────────────────


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def measure(fn, *, runs: int, budget: float, min_runs: int, warmup: bool = True) -> dict[str, Any]:
    if warmup:
        fn()
    times: list[float] = []
    started = time.perf_counter()
    while len(times) < runs and (len(times) < min_runs or time.perf_counter() - started < budget):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return {"n": len(times), "p50": statistics.median(times), "p95": _pct(times, 0.95), "max": max(times)}


class Client:
    def __init__(self, port: int):
        self.port = port

    def get(self, path: str, params: dict | None = None) -> tuple[int, Any]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=600)
        try:
            conn.request("GET", path + ("?" + urlencode(params) if params else ""))
            res = conn.getresponse()
            body = res.read()
            return res.status, (json.loads(body) if body else None)
        finally:
            conn.close()

    def status(self, path: str, params: dict | None = None) -> int:
        """Status only (the body is read, not parsed): the load test's client cost."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=600)
        try:
            conn.request("GET", path + ("?" + urlencode(params) if params else ""))
            res = conn.getresponse()
            res.read()
            return res.status
        finally:
            conn.close()

    def ok(self, path: str, params: dict | None = None) -> Any:
        status, payload = self.get(path, params)
        if status != 200:
            raise RuntimeError(f"{path} {params}: HTTP {status} {str(payload)[:200]}")
        return payload


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _rss() -> dict[str, int]:
    out = {}
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith(("VmRSS:", "VmHWM:")):
                out[line.split(":")[0]] = int(line.split()[1]) * 1024
    return out


def _db_sizes(db: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"db_bytes": db.stat().st_size,
                           "wal_bytes": os.path.getsize(f"{db}-wal") if os.path.exists(f"{db}-wal") else 0}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name").fetchall()
        sizes = {name: int(size) for name, size in rows}
        out["fts_bytes"] = sum(v for k, v in sizes.items() if k.startswith("records_fts"))
        out["records_bytes"] = sizes.get("records", 0)
        out["index_bytes"] = sum(v for k, v in sizes.items() if k.startswith(("idx_", "sqlite_autoindex_records")))
        out["rollup_bytes"] = sum(v for k, v in sizes.items() if k.startswith("counts_hourly")
                                  or k.startswith("idx_counts"))
        out["rows"] = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    except sqlite3.Error as exc:
        out["dbstat_error"] = str(exc)
    finally:
        conn.close()
    return out


# ─── the run ─────────────────────────────────────────────────────────────────


def run(args) -> dict[str, Any]:
    if args.code:
        sys.path.insert(0, str(Path(args.code).resolve()))
    else:
        sys.path.insert(0, str(REPO))
    os.environ.setdefault("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", "0")
    if args.readers is not None:
        os.environ["LOGSCOPE_SQLITE_READERS"] = str(args.readers)
    os.environ.pop("LOGSCOPE_WEBAPP_DB_PATH", None)
    os.environ.pop("LOGSCOPE_WEBAPP_STATE_DB_PATH", None)
    from webapp.api import dbtool
    from webapp.api.config import load_app_config, source_prefixes
    from webapp.api.filters import iso_js
    from webapp.api.server import AppHTTPServer, LogscopeHandler, WebApp
    from webapp.api.storage import LogStorage

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    config = _write_config(workdir)
    cfg = load_app_config(config)
    meta_path = workdir / "dataset.json"
    report: dict[str, Any] = {"rows_requested": args.rows, "label": args.label, "code": str(args.code or REPO),
                              "results": {}}
    results = report["results"]
    groups = set((args.only or "endpoints,detect,concurrency,maintenance").split(","))
    want = groups.__contains__
    if args.switch_interval is not None:
        sys.setswitchinterval(args.switch_interval)
    report["switch_interval"] = sys.getswitchinterval()

    def log(msg: str) -> None:
        print(msg, flush=True)

    if args.reuse and meta_path.exists() and cfg.webapp.db_path.exists():
        meta = json.loads(meta_path.read_text())
        log(f"Reusing {cfg.webapp.db_path} ({meta['lines']:,} lines)")
    else:
        if cfg.webapp.db_path.exists():
            for suffix in ("", "-wal", "-shm"):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(f"{cfg.webapp.db_path}{suffix}")
        end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        end -= timedelta(minutes=end.minute % 10)
        log(f"Generating {args.rows:,} rows ending {end:%Y-%m-%d %H:%M} UTC into {cfg.webapp.db_path}")
        meta = generate(cfg, args.rows, end, log)
        meta["end"] = iso_js(end)
        meta_path.write_text(json.dumps(meta))
        results["ingest_direct"] = {"lines_per_sec": round(meta["lines_per_sec"]), "lines": meta["lines"],
                                    "ingest_secs": round(meta["ingest_secs"], 1)}
    report["dataset"] = meta
    end = datetime.fromisoformat(meta["end"].replace("Z", "+00:00"))

    app = WebApp(cfg)
    seed_views_and_rules(app)
    # Whatever background maintenance this version runs at start (index or
    # rollup migrations) is finished first, so the timings are steady state.
    started = time.perf_counter()
    for loop_name in ("_fts_migration_loop", "_ts_backfill_loop", "_rollup_rebuild_loop"):
        if hasattr(app, loop_name) and _pending(app, loop_name):
            getattr(app, loop_name)()
    if hasattr(app.storage, "optimize"):  # what WebApp.start() runs before serving
        app.storage.optimize(analyze=not app.storage._has_stats)
    if args.no_rollup and hasattr(app.storage, "use_rollup"):
        app.storage.use_rollup = False
        app.insights.detector.use_rollup = False
    results["startup_maintenance_secs"] = round(time.perf_counter() - started, 1)
    server = AppHTTPServer(("127.0.0.1", 0), LogscopeHandler, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = Client(server.server_address[1])
    m = {"runs": args.runs, "budget": args.budget, "min_runs": args.min_runs}

    def timed(name: str, fn, **kw) -> None:
        opts = {**m, **kw}
        try:
            results[name] = measure(fn, **opts)
        except Exception as exc:  # noqa: BLE001 - recorded, the run goes on
            results[name] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
        r = results[name]
        log(f"  {name:<34} " + (f"p50 {r['p50']:9.1f}  p95 {r['p95']:9.1f}  max {r['max']:9.1f} ms  (n={r['n']})"
                               if "p50" in r else r["error"]))

    ranges = {"1h": 3600, "24h": 86400, "7d": 7 * 86400}

    def rng(span: int) -> dict[str, str]:
        return {"start": _iso(end - timedelta(seconds=span)), "before": _iso(end)}

    log("Endpoints")
    for label, span in ranges.items():
        timed(f"dashboard {label}", lambda s=span: client.ok("/api/dashboard", rng(s)))
        timed(f"fields {label}", lambda s=span: client.ok("/api/fields", rng(s)))
        timed(f"histogram {label}", lambda s=span: client.ok("/api/histogram", rng(s)))
    day = rng(86400)
    first = client.ok("/api/logs", {**day, "limit": 200})
    timed("logs first page 24h", lambda: client.ok("/api/logs", {**day, "limit": 200}))
    cursor = first.get("next_cursor")
    for _ in range(18):
        cursor = client.ok("/api/logs", {**day, "limit": 200, "cursor": cursor}).get("next_cursor") or cursor
    timed("logs page 20 24h", lambda: client.ok("/api/logs", {**day, "limit": 200, "cursor": cursor}))
    pod = first["items"][0]["pod"]
    timed("logs narrow pod 7d", lambda: client.ok("/api/logs", {**rng(ranges["7d"]), "pod": pod, "limit": 200}))
    timed("search common 24h", lambda: client.ok("/api/logs", {**day, "q": "processed", "limit": 200}))
    timed("search rare 7d", lambda: client.ok("/api/logs", {**rng(ranges["7d"]), "q": "deadlock", "limit": 200}))
    timed("search phrase 24h", lambda: client.ok("/api/logs", {**day, "q": "\"connection refused\"",
                                                                "qmode": "raw", "limit": 200}))
    mid = first["items"][len(first["items"]) // 2]["id"]
    timed("logs context", lambda: client.ok("/api/logs/context", {"id": mid, "lines_before": 25,
                                                                   "lines_after": 25}))
    if hasattr(app.storage, "fts_merge_step"):  # the off-peak FTS merge, then search again
        started = time.perf_counter()
        steps = 0
        while app.storage.fts_merge_step():
            steps += 1
        results["fts_merge"] = {"secs": round(time.perf_counter() - started, 1), "steps": steps}
        log(f"  FTS merge: {results['fts_merge']}")
        timed("search common 24h (merged FTS)", lambda: client.ok("/api/logs", {**day, "q": "processed",
                                                                                 "limit": 200}))
        timed("search phrase 24h (merged FTS)", lambda: client.ok("/api/logs", {**day, "q": "\"connection refused\"",
                                                                                 "qmode": "raw", "limit": 200}))

    if want("detect"):
        log("Detection and alerts")
        timed("insights cycle", lambda: app.insights.run_once(end), budget=max(args.budget, 300), min_runs=3)
        timed("anomalies", lambda: client.ok("/api/anomalies", {"limit": 200}))
        for prefix in (p["prefix"] for p in source_prefixes(cfg)):
            app.storage.set_prefix_listed(prefix, iso_js(end))
        mark = app.alerts.watermark(end)
        at = datetime.fromisoformat(mark["at"].replace("Z", "+00:00"))
        rules = app.alert_rules.list()

        def evaluate_all() -> None:
            for rule in rules:
                app.alerts.evaluate(rule, at, end)

        timed("alert evaluation 50 rules", evaluate_all, budget=max(args.budget, 300), min_runs=3)
        view_id = next(v["id"] for v in app.views.list() if v["name"] == "view 00")
        body = {"view_id": view_id, "metric": "count", "op": ">", "threshold": 500, "window_s": 300, "interval_s": 60,
                "range": "7d"}
        timed("backtest 7d", lambda: app.api_alert_backtest(body))

    log("Sizes")
    results["sizes"] = _db_sizes(cfg.webapp.db_path)
    results["rss"] = _rss()
    log(f"  {results['sizes']}")

    if args.concurrency_secs > 0 and want("concurrency"):
        log(f"Concurrency: 10 readers + ingest at {args.ingest_rate} lines/s for {args.concurrency_secs}s")
        results["concurrency"] = concurrency(app, client, cfg, end, args, results)

    if want("maintenance"):
        log("Maintenance")
        backup = workdir / "backup.sqlite"

        def do_backup() -> None:
            with contextlib.suppress(FileNotFoundError):
                backup.unlink()
            dbtool.backup(cfg.webapp.db_path, backup)

        timed("dbtool backup", do_backup, runs=3, min_runs=1, warmup=False)
        with contextlib.suppress(FileNotFoundError):
            backup.unlink()
        results["ts_backfill_1m"] = backfill(cfg, workdir, LogStorage, log)
        oldest = app.storage.conn.execute("SELECT MIN(ts_epoch) FROM records").fetchone()[0]
        cutoff = {"t": float(oldest)}
        batch = 5000

        def prune_batch() -> None:  # one batch: what one locked step of pruning costs
            cutoff["t"] += 600
            app.storage.prune_records_before(cutoff["t"], batch=batch)

        timed("prune (10 min of oldest data)", prune_batch, runs=10, min_runs=3, warmup=False)
        if not args.skip_moto:
            results["ingest_moto"] = moto_ingest(cfg, workdir, log)
    server.shutdown()
    server.server_close()
    results["rss_end"] = _rss()
    return report


def _pending(app, loop_name: str) -> bool:
    storage = app.storage
    return {"_fts_migration_loop": lambda: storage.fts_layout == "migrating",
            "_ts_backfill_loop": lambda: storage.ts_backfill_pending,
            "_rollup_rebuild_loop": lambda: not getattr(storage, "rollup_ready", True)}[loop_name]()


def concurrency(app, client: Client, cfg, end: datetime, args, results) -> dict[str, Any]:
    from webapp.api.config import source_prefixes
    from webapp.api.ingest import S3Ingestor

    stop = threading.Event()
    day = {"start": _iso(end - timedelta(days=1)), "before": _iso(end)}
    first = client.ok("/api/logs", {**day, "limit": 200})
    mid = first["items"][len(first["items"]) // 2]["id"]
    mix = [
        ("logs first page 24h", "/api/logs", {**day, "limit": 200}),
        ("fields 24h", "/api/fields", day),
        ("histogram 24h", "/api/histogram", day),
        ("dashboard 24h", "/api/dashboard", day),
        ("search common 24h", "/api/logs", {**day, "q": "processed", "limit": 200}),
        ("logs context", "/api/logs/context", {"id": mid, "lines_before": 25, "lines_after": 25}),
    ]

    ingestor = S3Ingestor(cfg, app.storage)
    fake = FakeS3()
    ingestor.client = fake
    specs = {p["prefix"]: p for p in source_prefixes(cfg)}
    root = KEY_PREFIX.split("{{", 1)[0]
    written = {"lines": 0, "secs": 0.0}

    def writer() -> None:
        rng = random.Random(11)
        gen = Generator(10, end)
        n = 0
        per_tick = max(1, args.ingest_rate // 2)
        next_at = time.perf_counter()
        while not stop.is_set() and args.ingest_rate > 0:
            now = datetime.now(timezone.utc)
            lines = []
            for _ in range(per_tick):
                ns, pod, ctrs = gen.pods[rng.randrange(len(gen.pods))]
                lines.append(f"{now:%Y-%m-%dT%H:%M:%S}.{rng.randrange(1000):03d}Z - {ns} - {pod}/{ctrs[0]} - "
                             f"{gen._fill(gen.templates['info'][rng.randrange(50)])}")
            n += 1
            key = _key(root, "info", now, 900_000 + n)
            written["secs"] += _ingest_objects(ingestor, specs, fake,
                                               [(f"{root}info/", key, _iso(now), _gz(lines))])
            written["lines"] += len(lines)
            next_at += 0.5
            stop.wait(max(0.0, next_at - time.perf_counter()))

    # The readers run in their own process (like browsers): the server
    # process only serves requests and runs the ingest writer.
    ctx = multiprocessing.get_context("spawn")
    results_queue = ctx.Queue()
    readers = ctx.Process(target=_reader_process,
                          args=(client.port, mix, args.concurrency_secs, 10, results_queue), daemon=True)
    writer_thread = threading.Thread(target=writer, daemon=True)
    started = time.perf_counter()
    readers.start()
    writer_thread.start()
    lat, codes, errors = results_queue.get(timeout=args.concurrency_secs + 600)
    stop.set()
    writer_thread.join(timeout=120)
    readers.join(timeout=60)
    secs = time.perf_counter() - started
    out: dict[str, Any] = {"secs": round(secs, 1), "status_codes": codes, "errors": errors[:5],
                           "http_503": codes.get(503, 0),
                           "ingested_lines_per_sec": round(written["lines"] / secs), "endpoints": {}}
    for name, values in lat.items():
        unloaded = results.get(name, {}).get("p95")
        p95 = _pct(values, 0.95)
        out["endpoints"][name] = {"n": len(values), "p50": statistics.median(values), "p95": p95,
                                  "unloaded_p95": unloaded,
                                  "ratio": round(p95 / unloaded, 2) if unloaded else None}
        print(f"  {name:<24} p95 {p95:9.1f} ms under load (unloaded {unloaded or 0:9.1f}; "
              f"x{out['endpoints'][name]['ratio']}) n={len(values)}", flush=True)
    print(f"  status codes {codes}; ingest {out['ingested_lines_per_sec']} lines/s", flush=True)
    return out


def _reader_process(port: int, mix: list, secs: float, threads: int, out) -> None:
    """threads closed-loop readers for secs; puts (latencies by name, status counts, errors)."""
    client = Client(port)
    lat: dict[str, list[float]] = {}
    codes: dict[int, int] = {}
    errors: list[str] = []
    lock = threading.Lock()
    deadline = time.perf_counter() + secs

    def reader(i: int) -> None:
        k = i
        while time.perf_counter() < deadline:
            name, path, params = mix[k % len(mix)]
            k += 1
            t = time.perf_counter()
            try:
                status = client.status(path, params)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}"[:200])
                continue
            ms = (time.perf_counter() - t) * 1000
            with lock:
                codes[status] = codes.get(status, 0) + 1
                lat.setdefault(name, []).append(ms)

    pool = [threading.Thread(target=reader, args=(i,)) for i in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    out.put((lat, codes, errors))


def backfill(cfg, workdir: Path, LogStorage, log) -> dict[str, Any]:  # noqa: N803 - a class passed in
    """ts_epoch backfill of 1M rows: a legacy-schema copy of the first 1M records."""
    legacy = workdir / "legacy.sqlite"
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(f"{legacy}{suffix}")
    conn = sqlite3.connect(legacy)
    conn.execute("""CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        severity_bucket TEXT NOT NULL, scope TEXT NOT NULL, namespace TEXT NOT NULL, pod TEXT NOT NULL,
        container TEXT NOT NULL, message TEXT NOT NULL, raw_line TEXT NOT NULL, source_key TEXT NOT NULL,
        source_etag TEXT NOT NULL, line_number INTEGER NOT NULL, is_falco INTEGER NOT NULL DEFAULT 0,
        ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(source_key, source_etag, line_number))""")
    conn.execute("CREATE VIRTUAL TABLE records_fts USING fts5(message, raw_line)")  # a legacy index: no FTS backfill
    conn.execute("ATTACH DATABASE ? AS src", (str(cfg.webapp.db_path),))
    conn.execute("INSERT INTO records (id, timestamp, severity_bucket, scope, namespace, pod, container, message, "
                 "raw_line, source_key, source_etag, line_number, is_falco, ingested_at) SELECT id, timestamp, "
                 "severity_bucket, scope, namespace, pod, container, message, raw_line, source_key, source_etag, "
                 "line_number, is_falco, ingested_at FROM src.records ORDER BY id LIMIT 1000000")
    conn.commit()
    conn.execute("DETACH DATABASE src")
    rows = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    conn.close()
    t = time.perf_counter()
    storage = LogStorage(legacy)
    opened = time.perf_counter() - t
    steps = 0
    while storage.backfill_ts_step():
        steps += 1
    total = time.perf_counter() - t
    storage.conn.close()
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(f"{legacy}{suffix}")
    out = {"rows": rows, "secs": round(total, 1), "open_secs": round(opened, 1), "steps": steps,
           "rows_per_sec": round(rows / total)}
    log(f"  ts_epoch backfill: {out}")
    return out


def moto_ingest(cfg, workdir: Path, log, objects: int = 60, lines_per_object: int = 2500) -> dict[str, Any]:
    try:
        import boto3
        from moto import mock_aws
    except ImportError:
        log("  moto not installed (pip install '.[test]'): S3 ingest test skipped")
        return {"skipped": "moto not installed"}
    from webapp.api.ingest import S3Ingestor
    from webapp.api.storage import LogStorage

    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        os.environ[name] = "testing"
    db = workdir / "moto.sqlite"
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(f"{db}{suffix}")
    root = KEY_PREFIX.split("{{", 1)[0]
    gen = Generator(objects * lines_per_object, datetime.now(timezone.utc).replace(microsecond=0))
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET)
        put = 0
        lines = 0
        for t0, regular, _security in gen.windows_iter():
            for bucket, batch in regular.items():
                if put >= objects:
                    break
                if len(batch) < 50:
                    continue
                s3.put_object(Bucket=BUCKET, Key=_key(root, bucket, t0, put), Body=_gz(batch))
                put += 1
                lines += len(batch)
            if put >= objects:
                break
        storage = LogStorage(db)
        ingestor = S3Ingestor(replace(cfg, webapp=replace(cfg.webapp, db_path=db)), storage)
        t = time.perf_counter()
        result = ingestor.ingest_once()
        secs = time.perf_counter() - t
        storage.conn.close()
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(f"{db}{suffix}")
    out = {"objects": put, "lines": result.records_ingested, "secs": round(secs, 2),
           "lines_per_sec": round(result.records_ingested / secs), "error": result.error}
    log(f"  S3 ingest via moto: {out}")
    return out


# ─── report ──────────────────────────────────────────────────────────────────


def print_table(report: dict[str, Any]) -> None:
    res = report["results"]
    rows = report["dataset"]["lines"]
    print(f"\n== {report.get('label') or 'run'}: {rows:,} rows ==")
    print(f"{'measurement':<36}{'n':>4}{'p50 ms':>11}{'p95 ms':>11}{'max ms':>11}")
    for name, r in res.items():
        if isinstance(r, dict) and "p50" in r:
            print(f"{name:<36}{r['n']:>4}{r['p50']:>11.1f}{r['p95']:>11.1f}{r['max']:>11.1f}")
    for name in ("ingest_direct", "ingest_moto", "ts_backfill_1m", "fts_merge", "sizes", "rss", "rss_end",
                 "startup_maintenance_secs"):
        if name in res:
            print(f"{name}: {res[name]}")
    if "concurrency" in res:
        c = res["concurrency"]
        print(f"concurrency: 503s={c['http_503']} codes={c['status_codes']} ingest={c['ingested_lines_per_sec']} l/s")
        for name, e in c["endpoints"].items():
            print(f"  {name:<32} p95 {e['p95']:9.1f} ms  (unloaded {e['unloaded_p95'] or 0:9.1f}, x{e['ratio']})")


def compare(before: dict[str, Any], after: dict[str, Any]) -> None:
    b, a = before["results"], after["results"]
    print(f"\n== BEFORE vs AFTER: {after['dataset']['lines']:,} rows ==")
    print(f"{'measurement':<36}{'before p50':>12}{'before p95':>12}{'after p50':>11}{'after p95':>11}{'p95 x':>8}")
    for name in after["results"]:
        rb, ra = b.get(name), a.get(name)
        if isinstance(ra, dict) and "p95" in ra and isinstance(rb, dict) and "p95" in rb:
            print(f"{name:<36}{rb['p50']:>12.1f}{rb['p95']:>12.1f}{ra['p50']:>11.1f}{ra['p95']:>11.1f}"
                  f"{rb['p95'] / max(ra['p95'], 1e-9):>8.1f}")
    for key in ("ingest_direct", "ingest_moto", "ts_backfill_1m"):
        if key in a or key in b:
            print(f"{key}: before {b.get(key, {}).get('lines_per_sec', b.get(key, {}).get('rows_per_sec'))} "
                  f"after {a.get(key, {}).get('lines_per_sec', a.get(key, {}).get('rows_per_sec'))} per s")
    for key in ("db_bytes", "fts_bytes", "rollup_bytes"):
        print(f"{key}: before {b.get('sizes', {}).get(key)} after {a.get('sizes', {}).get(key)}")
    print(f"RSS peak: before {b.get('rss_end', {}).get('VmHWM')} after {a.get('rss_end', {}).get('VmHWM')}")
    if "concurrency" in a and "concurrency" in b:
        print(f"under load: 503s before {b['concurrency']['http_503']} after {a['concurrency']['http_503']}")
        for name, e in a["concurrency"]["endpoints"].items():
            eb = b["concurrency"]["endpoints"].get(name, {})
            print(f"  {name:<32} p95 before {eb.get('p95', 0):9.1f} (x{eb.get('ratio')})  "
                  f"after {e['p95']:9.1f} (x{e['ratio']})")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--rows", type=int, default=1_000_000)
    p.add_argument("--workdir", default=None, help="data directory (default: a temp dir, removed after)")
    p.add_argument("--reuse", action="store_true", help="reuse the database in --workdir if present")
    p.add_argument("--runs", type=int, default=30)
    p.add_argument("--min-runs", type=int, default=5)
    p.add_argument("--budget", type=float, default=90.0, help="seconds per measurement before stopping early")
    p.add_argument("--concurrency-secs", type=int, default=60)
    p.add_argument("--ingest-rate", type=int, default=2000, help="lines/s written during the concurrency test")
    p.add_argument("--skip-moto", action="store_true")
    p.add_argument("--no-rollup", action="store_true", help="serve counts from raw rows (comparison runs)")
    p.add_argument("--readers", type=int, default=None, help="LOGSCOPE_SQLITE_READERS for this run")
    p.add_argument("--switch-interval", type=float, default=None,
                   help="sys.setswitchinterval for the server process (default: what the server sets)")
    p.add_argument("--only", default=None, help="comma-separated measurement groups: endpoints,detect,concurrency,"
                                                "maintenance (default: all)")
    p.add_argument("--code", default=None, help="tree to import webapp/ from (default: this repository)")
    p.add_argument("--label", default="")
    p.add_argument("--json", default=None, help="write the results here")
    p.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="print a comparison of two JSON results")
    args = p.parse_args(argv)
    if args.compare:
        before, after = (json.loads(Path(f).read_text()) for f in args.compare)
        print_table(before)
        print_table(after)
        compare(before, after)
        return 0
    temp = None
    if not args.workdir:
        import tempfile

        temp = tempfile.mkdtemp(prefix="logscope-loadtest-")
        args.workdir = temp
    try:
        report = run(args)
    finally:
        if temp:
            shutil.rmtree(temp, ignore_errors=True)
    print_table(report)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
