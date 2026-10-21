"""Field sidebar (/api/fields), histogram (/api/histogram), exclusion
parameters and the default phrase search."""
from __future__ import annotations

import http.client
import json
import sys
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api import storage as storage_mod  # noqa: E402
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.server import AppHTTPServer, LogscopeHandler, WebApp  # noqa: E402
from webapp.api.storage import LogStorage, split_search_terms  # noqa: E402

CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"

# (minute offset from 10:00 UTC, namespace, pod, severity, message)
_FIXTURE = [
    (0, "kube-system", "coredns-1", "info", "kube-system dns ready"),
    (1, "kube-system", "coredns-1", "warning", "slow upstream 10.0.3.4"),
    (2, "kube-system", "traefik-0", "error", "error: backend down"),
    (7, "app", "web-0", "info", "GET /health 200"),
    (8, "app", "web-0", "error", 'parse failed near "quote" token'),
    (8, "app", "web-1", "error", "db timeout"),
    (16, "app", "web-1", "debug", "cache NEAR miss AND OR"),
    (31, "billing", "api-0", "info", "invoice 50% done_x"),
    (31, "billing", "api-0", "warning", "retrying 10.0.3.40"),
    (59, "billing", "api-1", "error", "card declined"),
]


def _records():
    out = []
    for i, (minute, ns, pod, sev, message) in enumerate(_FIXTURE):
        ts = f"2026-09-07T10:{minute:02d}:{i:02d}Z"
        out.append({
            "timestamp": ts, "severity_bucket": sev,
            "scope": "infra" if ns == "kube-system" else f"namespaces/{ns}",
            "namespace": ns, "pod": pod, "container": "main", "message": message,
            "raw_line": f"{ts} - {ns} - {pod}/main - {message}",
            "source_key": f"k/{i}", "source_etag": "e", "line_number": 1, "is_falco": 0,
        })
    return out


@pytest.fixture()
def storage(tmp_path):
    s = LogStorage(tmp_path / "webapp.sqlite")
    s.insert_records(_records())
    yield s
    s.conn.close()


def _messages(storage, **params):
    return sorted(r["message"] for r in storage.query_logs(params, limit=100)["items"])


# ─── Phrase search (default) ─────────────────────────────────────────────────

@pytest.mark.parametrize("q, expected", [
    # Search covers raw_line too, which holds the namespace and pod.
    ("kube-system", ["error: backend down", "kube-system dns ready", "slow upstream 10.0.3.4"]),
    ("10.0.3.4", ["slow upstream 10.0.3.4"]),
    ("error:", ["error: backend down"]),
    ('"quote"', ['parse failed near "quote" token']),
    ('failed "quote', ['parse failed near "quote" token']),
    ("NEAR AND OR", ["cache NEAR miss AND OR"]),
    ("near", ["cache NEAR miss AND OR", 'parse failed near "quote" token']),
    ("AND", ["cache NEAR miss AND OR"]),
    ("50%", ["invoice 50% done_x"]),
    ("done_x", ["invoice 50% done_x"]),
    ("web -db", ["GET /health 200", "cache NEAR miss AND OR", 'parse failed near "quote" token']),
    ("-error: backend", []),
    ("dns -upstream", ["kube-system dns ready"]),
])
def test_phrase_search_matches_words_as_written(storage, q, expected):
    assert _messages(storage, q=q) == expected


@pytest.mark.parametrize("q", [
    '") OR 1=1 --', "'; DROP TABLE records; --", "message : *", 'NEAR("a" "b")', "records_fts MATCH",
    '"', '""', "*", "^x", "a OR", "NOT", "(",
])
def test_phrase_search_never_raises_on_fts_syntax(storage, q):
    storage.query_logs({"q": q}, limit=10)  # no "Invalid search query"
    assert storage.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0] == len(_FIXTURE)


def test_exclusion_only_query_returns_everything_else(storage):
    got = _messages(storage, q="-error: -declined")
    assert "error: backend down" not in got and "card declined" not in got
    assert len(got) == len(_FIXTURE) - 2


def test_raw_mode_keeps_fts_syntax(storage):
    assert _messages(storage, q="cache OR card", qmode="raw") == ["cache NEAR miss AND OR", "card declined"]
    assert _messages(storage, q="inv*", qmode="raw") == ["invoice 50% done_x"]
    with pytest.raises(ValueError, match="Invalid search query"):
        storage.query_logs({"q": "kube-system", "qmode": "raw"}, limit=10)


def test_split_search_terms():
    assert split_search_terms('  a -b "c" - -  ') == (["a", '"c"', "-", "-"], ["b"])


def test_like_fallback_escapes_wildcards(storage):
    storage.fts_enabled = False  # substring matching, as without FTS5
    assert not storage.fts_search
    assert _messages(storage, q="%") == ["invoice 50% done_x"]
    assert _messages(storage, q="_") == ["invoice 50% done_x"]
    assert _messages(storage, q="50%_") == []
    assert _messages(storage, q="kube-system -upstream") == ["error: backend down", "kube-system dns ready"]
    assert _messages(storage, q="50%", qmode="raw") == ["invoice 50% done_x"]
    assert _messages(storage, q="5_%", qmode="raw") == []


# ─── Exclusions and indexes ──────────────────────────────────────────────────

def test_exclusion_params_filter_out_values(storage):
    assert all(r["namespace"] != "app" for r in storage.query_logs({"xns": ["app"]}, limit=100)["items"])
    got = storage.query_logs({"xns": ["app", "billing"], "xsev": ["info"]}, limit=100)["items"]
    assert sorted(r["message"] for r in got) == ["error: backend down", "slow upstream 10.0.3.4"]
    assert _messages(storage, xpod=["web-0", "web-1"], xctr=["main"]) == []
    assert len(_messages(storage, xscope=["infra"])) == 7


def test_records_indexes_are_created_by_storage(tmp_path):
    db = tmp_path / "w.sqlite"
    LogStorage(db).conn.close()
    storage = LogStorage(db)  # idempotent on reopen
    names = {r[0] for r in storage.conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"idx_records_ts_ns", "idx_records_ns_ts", "idx_records_sev_ts",
            "idx_records_scope_ts", "idx_records_pod_ts"} <= names
    plan = " ".join(str(r[3]) for r in storage.conn.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM records WHERE namespace = ? AND timestamp >= ?", ("a", "b")))
    assert "idx_records_ns_ts" in plan


# ─── /api/fields ─────────────────────────────────────────────────────────────

def test_fields_lists_top_values_and_ignores_own_filter(storage):
    out = storage.query_fields({"namespace": "app"})
    assert out["partial"] is False
    ns = out["fields"]["namespace"]
    # Other namespaces stay visible while namespace=app is applied.
    assert ns["values"] == [{"value": "app", "count": 4}, {"value": "billing", "count": 3},
                            {"value": "kube-system", "count": 3}]
    assert (ns["total"], ns["distinct"], ns["exclude_param"]) == (10, 3, "xns")
    # Every other field is computed under namespace=app.
    pods = out["fields"]["pod"]
    assert {v["value"] for v in pods["values"]} == {"web-0", "web-1"} and pods["total"] == 4
    sev = out["fields"]["severity_bucket"]
    assert sev["values"][0] == {"value": "error", "count": 2} and sev["distinct"] == 3


def test_fields_apply_exclusions_including_the_fields_own(storage):
    out = storage.query_fields({"xns": ["kube-system"], "severity_bucket": "error"})
    assert [v["value"] for v in out["fields"]["namespace"]["values"]] == ["app", "billing"]
    assert out["fields"]["namespace"]["total"] == 3          # errors outside kube-system
    assert out["fields"]["severity_bucket"]["total"] == 7    # own filter ignored, exclusion kept


def test_fields_top_values_are_capped(storage, monkeypatch):
    monkeypatch.setattr(storage_mod, "FIELD_TOP_VALUES", 2)
    pods = storage.query_fields({})["fields"]["pod"]
    assert len(pods["values"]) == 2 and pods["distinct"] == 6 and pods["total"] == 10


def test_fields_time_out_as_partial(storage, monkeypatch):
    monkeypatch.setattr(storage_mod, "_PROGRESS_OPS", 1)
    out = storage.query_fields({}, timeout_secs=-1)
    assert out["partial"] is True
    assert all(f["partial"] and f["values"] == [] and f["total"] is None for f in out["fields"].values())
    # The handler is removed afterwards: later queries run normally.
    assert len(storage.query_logs({}, limit=100)["items"]) == len(_FIXTURE)
    assert storage.query_fields({})["partial"] is False


# ─── /api/histogram ──────────────────────────────────────────────────────────

def test_histogram_zero_fills_every_bucket(storage):
    out = storage.query_histogram({"start": "2026-09-07T10:00:00Z", "before": "2026-09-07T11:00:00Z"})
    assert out["bucket_secs"] == 60 and len(out["buckets"]) == 60
    assert [b["t"] for b in out["buckets"][:3]] == ["2026-09-07T10:00:00Z", "2026-09-07T10:01:00Z",
                                                    "2026-09-07T10:02:00Z"]
    by_t = {b["t"]: b for b in out["buckets"]}
    assert by_t["2026-09-07T10:08:00Z"] == {"t": "2026-09-07T10:08:00Z", "total": 2, "error": 2,
                                            "warning": 0, "info": 0, "debug": 0}
    assert by_t["2026-09-07T10:30:00Z"]["total"] == 0           # empty bucket present
    assert sum(b["total"] for b in out["buckets"]) == len(_FIXTURE)
    assert sum(b["error"] for b in out["buckets"]) == 4


@pytest.mark.parametrize("hours, size", [(0.5, 60), (1, 60), (4, 300), (12, 900), (48, 3600), (14 * 24, 21600)])
def test_histogram_picks_bucket_size_from_range(storage, hours, size):
    start = datetime(2026, 9, 7, 10, tzinfo=timezone.utc).timestamp()
    before = datetime.fromtimestamp(start + hours * 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = storage.query_histogram({"start": "2026-09-07T10:00:00Z", "before": before})
    assert out["bucket_secs"] == size
    assert len(out["buckets"]) <= 60 + 1
    assert sum(b["total"] for b in out["buckets"]) == sum(1 for m, *_ in _FIXTURE if m < hours * 60)


def test_histogram_buckets_on_utc_epoch_not_strings(tmp_path):
    storage = LogStorage(tmp_path / "w.sqlite")
    base = {"severity_bucket": "info", "scope": "infra", "namespace": "n", "pod": "p", "container": "c",
            "raw_line": "r", "source_etag": "e", "line_number": 1, "is_falco": 0, "message": "m"}
    storage.insert_records([
        {**base, "timestamp": "2026-09-07T10:00:00.5Z", "source_key": "a"},     # sorts before ...:00Z as text
        {**base, "timestamp": "2026-09-07T15:31:00+05:30", "source_key": "b"},  # 10:01 UTC
    ])
    out = storage.query_histogram({"start": "2026-09-07T09:58:00Z", "before": "2026-09-07T10:03:00Z"})
    totals = {b["t"]: b["total"] for b in out["buckets"]}
    assert totals["2026-09-07T10:00:00Z"] == 1 and totals["2026-09-07T10:01:00Z"] == 1


def test_histogram_counts_only_the_requested_range(storage):
    # 10:01:01 starts mid-bucket; the 10:00 / 10:01:01 entries before it are not counted.
    out = storage.query_histogram({"start": "2026-09-07T10:01:30Z", "before": "2026-09-07T10:08:00Z"})
    assert out["buckets"][0]["t"] == "2026-09-07T10:01:00Z"
    assert sum(b["total"] for b in out["buckets"]) == 2        # 10:02:02 and 10:07:03


def test_histogram_without_start_begins_at_oldest_match(storage):
    out = storage.query_histogram({"namespace": "billing"},
                                  now=datetime(2026, 9, 7, 11, tzinfo=timezone.utc))
    assert out["buckets"][0]["t"] == "2026-09-07T10:31:00Z"
    assert sum(b["total"] for b in out["buckets"]) == 3
    assert storage.query_histogram({"namespace": "none"})["buckets"] == []


def test_histogram_applies_filters_and_exclusions(storage):
    params = {"start": "2026-09-07T10:00:00Z", "before": "2026-09-07T11:00:00Z", "xns": ["app"], "q": "10.0.3.4"}
    out = storage.query_histogram(params)
    assert sum(b["total"] for b in out["buckets"]) == 1 and sum(b["warning"] for b in out["buckets"]) == 1


def test_histogram_rejects_bad_times(storage):
    with pytest.raises(ValueError, match="Invalid time"):
        storage.query_histogram({"start": "yesterday"})


# ─── HTTP ────────────────────────────────────────────────────────────────────

@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSCOPE_ACTIONS_ENABLED", "false")
    cfg = load_app_config(CONFIG)
    app = WebApp(replace(cfg, webapp=replace(cfg.webapp, db_path=tmp_path / "webapp.sqlite")))
    app.storage.insert_records(_records())
    srv = AppHTTPServer(("127.0.0.1", 0), LogscopeHandler, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _get(server, path, params=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("GET", path + ("?" + urlencode(params, doseq=True) if params else ""))
    res = conn.getresponse()
    payload = json.loads(res.read() or b"{}")
    conn.close()
    return res.status, payload


_RANGE = {"start": "2026-09-07T10:00:00Z", "before": "2026-09-07T11:00:00Z"}


def test_http_fields_and_histogram(server):
    status, fields = _get(server, "/api/fields", {**_RANGE, "xns": "kube-system"})
    assert status == 200 and fields["partial"] is False
    assert [v["value"] for v in fields["fields"]["namespace"]["values"]] == ["app", "billing"]
    status, hist = _get(server, "/api/histogram", {**_RANGE, "severity_bucket": "error"})
    assert status == 200 and len(hist["buckets"]) == 60
    assert sum(b["total"] for b in hist["buckets"]) == 4


def test_http_exclusions_accept_repeated_and_comma_separated_values(server):
    for params in ({"xns": ["app", "billing"]}, {"xns": "app,billing"}, {"xns": ["app", " billing ,"]}):
        status, logs = _get(server, "/api/logs", {**params, "limit": 50})
        assert status == 200 and {r["namespace"] for r in logs["items"]} == {"kube-system"}, params
    status, tail = _get(server, "/api/tail", {"after_id": 0, "xsev": "error,info", "limit": 50})
    assert status == 200 and {r["severity_bucket"] for r in tail["items"]} == {"warning", "debug"}
    status, _ = _get(server, "/api/logs", {"xpod": ",".join(f"p{i}" for i in range(51))})
    assert status == 400


def test_http_search_modes(server):
    items = _get(server, "/api/logs", {"q": "kube-system dns"})[1]["items"]
    assert [r["message"] for r in items] == ["kube-system dns ready"]
    status, payload = _get(server, "/api/logs", {"q": "kube-system", "qmode": "raw"})
    assert status == 400 and "Invalid search query" in payload["error"]
    assert _get(server, "/api/logs", {"q": "x", "qmode": "regex"})[0] == 400


def test_http_explain_receives_exclusions(server, monkeypatch):
    from webapp.api import server as server_mod

    seen = {}

    def fake_explain(payload, _cfg):
        seen.update(payload)
        return {"summary": "ok", "steps": [], "suggested_action": ""}

    app = server.app
    monkeypatch.setattr(server_mod, "explain_logs", fake_explain)
    monkeypatch.setattr(type(app), "ai_configured", lambda self: True)
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("POST", "/api/explain?" + urlencode({"xns": "app,billing"}), body=b"{}",
                 headers={"Content-Type": "application/json"})
    res = conn.getresponse()
    res.read()
    conn.close()
    assert res.status == 200
    assert seen["filters"] == {"xns": ["app", "billing"]}
    assert {row["namespace"] for row in seen["log_sample"]} == {"kube-system"}
