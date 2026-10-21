"""Regression tests for the production-hardening behaviour: ingest resilience,
late-object lookback, cache retention, health endpoints and HTTP error handling."""

from __future__ import annotations

import gzip
import http.client
import io
import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dataclasses import replace  # noqa: E402

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.ingest import S3Ingestor, lookback_start_after  # noqa: E402
from webapp.api.server import AppHTTPServer, LogscopeHandler, WebApp  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402

CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"
FMT = "%Y/%m/%d/%H_%M_%S_"


class FakeS3:
    """Honours Prefix/StartAfter like list_objects_v2; objects may be appended between polls."""

    def __init__(self, objects, bodies):
        self._objects = objects
        self._bodies = bodies

    def get_paginator(self, name):
        objects = self._objects

        class _Paginator:
            def paginate(self, **kwargs):
                after = kwargs.get("StartAfter") or ""
                yield {"Contents": sorted(
                    (o for o in objects if o["Key"].startswith(kwargs["Prefix"]) and o["Key"] > after),
                    key=lambda o: o["Key"],
                )}

        return _Paginator()

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self._bodies[Key])}


def _gz(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))


def _make_webapp(db_path: Path) -> WebApp:
    cfg = load_app_config(CONFIG)
    return WebApp(replace(cfg, webapp=replace(cfg.webapp, db_path=db_path)))


def test_ingest_skips_bad_lines_and_corrupt_objects_without_stalling():
    cfg = load_app_config(CONFIG)
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        corrupt_key = "k3s-logs/logs/info/2026/09/07/00_00_00_a.gz"
        mixed_key = "k3s-logs/logs/info/2026/09/07/00_00_01_b.gz"
        objects = [
            {"Key": corrupt_key, "ETag": '"e1"', "LastModified": "2026-09-07T00:00:00Z"},
            {"Key": mixed_key, "ETag": '"e2"', "LastModified": "2026-09-07T00:00:01Z"},
        ]
        bodies = {
            corrupt_key: b"definitely not gzip",
            mixed_key: _gz(
                "not a logscope line\n"
                "2026-09-07T00:00:01Z - app - web-0/nginx - still ingested\n"
            ),
        }
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = FakeS3(objects, bodies)

        result = ingestor.ingest_once()

        assert result.error is None
        assert result.records_ingested == 1
        assert storage.object_seen(cfg.s3_bucket, corrupt_key, "e1")
        assert storage.get_prefix_cursor("k3s-logs/logs/info/") == mixed_key
        assert storage.get_status()["last_error"] is None


def test_lookback_start_after_moves_cursor_back_in_key_time():
    prefix = "k3s-logs/logs/info/"
    key = prefix + "2026/09/07/10_30_00_1788852736-uuid.log.gz"
    assert lookback_start_after(prefix, key, FMT, 3600) == prefix + "2026/09/07/09_30_00_"
    assert lookback_start_after(prefix, key, FMT, 0) == key
    assert lookback_start_after(prefix, None, FMT, 3600) is None
    assert lookback_start_after(prefix, prefix + "unexpected", FMT, 3600) == prefix + "unexpected"


def test_ingest_picks_up_object_that_lands_behind_the_cursor():
    cfg = load_app_config(CONFIG)
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        later_key = "k3s-logs/logs/info/2026/09/07/10_30_00_b.gz"
        late_key = "k3s-logs/logs/info/2026/09/07/10_20_00_a.gz"
        objects = [{"Key": later_key, "ETag": '"e2"', "LastModified": "2026-09-07T10:31:00Z"}]
        bodies = {
            later_key: _gz("2026-09-07T10:30:00Z - app - web-0/nginx - later"),
            late_key: _gz("2026-09-07T10:20:00Z - app - web-0/nginx - flushed late"),
        }
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = FakeS3(objects, bodies)
        assert ingestor.ingest_once().records_ingested == 1

        objects.append({"Key": late_key, "ETag": '"e1"', "LastModified": "2026-09-07T10:32:00Z"})
        second = ingestor.ingest_once()

        assert second.records_ingested == 1
        assert second.objects_ingested == 1  # later_key re-listed but not re-read
        assert storage.get_prefix_cursor("k3s-logs/logs/info/") == later_key


def test_retention_defaults_to_s3_retention_and_prunes_old_records():
    cfg = load_app_config(CONFIG)
    assert cfg.webapp.retention_days == 30
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        base = {"severity_bucket": "info", "scope": "infra", "namespace": "ns", "pod": "p",
                "container": "c", "raw_line": "r", "source_etag": "e", "line_number": 1, "is_falco": 0}
        storage.insert_records([
            {**base, "timestamp": "2026-01-01T00:00:00Z", "message": "old", "source_key": "k1"},
            {**base, "timestamp": "2026-09-01T00:00:00Z", "message": "new", "source_key": "k2"},
        ])
        storage.mark_object("b", "k1", "e", "2026-01-01T00:00:00Z", status="ok", record_count=1)

        assert storage.prune_records_before("2026-06-01T00:00:00Z") == 1

        assert [r["message"] for r in storage.query_logs({}, limit=10)["items"]] == ["new"]
        assert [r["message"] for r in storage.query_logs({"q": "old"}, limit=10)["items"]] == []
        assert not storage.object_seen("b", "k1", "e")


def _serve(app):
    server = AppHTTPServer(("127.0.0.1", 0), LogscopeHandler, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _request(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    res = conn.getresponse()
    payload = json.loads(res.read() or b"{}")
    conn.close()
    return res.status, payload


def test_http_health_errors_and_action_kill_switch(monkeypatch):
    monkeypatch.setenv("LOGSCOPE_ACTIONS_ENABLED", "false")
    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        server = _serve(app)
        try:
            assert _request(server, "GET", "/readyz") == (200, {"status": "ok"})
            # Ingest thread never started in this test, so liveness reports it.
            assert _request(server, "GET", "/healthz")[0] == 503

            status, payload = _request(server, "GET", "/api/logs?limit=abc")
            assert status == 400 and "error" in payload
            status, payload = _request(server, "GET", '/api/logs?qmode=raw&q=%22unterminated')
            assert status == 400 and payload["error"].startswith("Invalid request: Invalid search query")

            status, payload = _request(
                server, "POST", "/api/actions/execute",
                body=json.dumps({"command": "kubectl get pods"}),
                headers={"Content-Type": "application/json"},
            )
            assert status == 403
            assert _request(server, "GET", "/api/status")[1]["actions_enabled"] is False

            status, _ = _request(
                server, "POST", "/api/explain-line",
                body=b"{}", headers={"Content-Length": str(2 * 1024 * 1024)},
            )
            assert status == 413
        finally:
            server.shutdown()
            server.server_close()


def _raw(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    res = conn.getresponse()
    data = res.read()
    out = (res.status, {k.lower(): v for k, v in res.getheaders()}, data)
    conn.close()
    return out


JSON = {"Content-Type": "application/json"}


def test_csrf_origin_and_content_type_checks(monkeypatch):
    monkeypatch.setenv("LOGSCOPE_ALLOWED_ORIGINS", "https://logs.example.com")
    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        server = _serve(app)
        own = f"http://127.0.0.1:{server.server_address[1]}"
        body = json.dumps({"id": 1})
        try:
            # Cross-origin and opaque origins are rejected before any handler runs.
            for origin in ("https://evil.example", "null", f"http://localhost:{server.server_address[1]}"):
                status, payload = _request(server, "POST", "/api/explain-line", body=body,
                                           headers={**JSON, "Origin": origin})
                assert (status, payload) == (403, {"error": "Cross-origin request rejected"}), origin
            status, _ = _request(server, "PATCH", "/api/anomalies/1", body=json.dumps({"status": "reviewed"}),
                                 headers={**JSON, "Origin": "https://evil.example"})
            assert status == 403
            status, _ = _request(server, "POST", "/api/explain?namespace=x",
                                 headers={"Sec-Fetch-Site": "cross-site"})
            assert status == 403

            # Same origin, an allowed origin, and non-browser clients reach the handler
            # (which then reports that AI is not configured in this test).
            for headers in ({**JSON, "Origin": own}, {**JSON, "Origin": "https://logs.example.com"},
                            {**JSON, "Sec-Fetch-Site": "same-origin"}, JSON):
                status, payload = _request(server, "POST", "/api/explain-line", body=body, headers=headers)
                assert status == 400 and "not configured" in payload["error"], headers

            # JSON bodies need a JSON content type; malformed JSON keeps the old 400 path.
            status, payload = _request(server, "POST", "/api/explain-line", body=body,
                                       headers={"Content-Type": "text/plain"})
            assert (status, payload) == (415, {"error": "Content-Type must be application/json"})
            status, _ = _request(server, "PATCH", "/api/anomalies/1", body="{not json", headers=JSON)
            assert status == 400
        finally:
            server.shutdown()
            server.server_close()


def test_security_headers_and_head_without_filesystem_fallback():
    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        server = _serve(app)
        try:
            for path in ("/", "/api/status", "/does-not-exist"):
                status, headers, _ = _raw(server, "GET", path)
                assert headers["x-content-type-options"] == "nosniff", path
                assert headers["x-frame-options"] == "DENY"
                assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
                assert "frame-ancestors 'none'" in headers["content-security-policy"]
                assert "script-src 'self';" in headers["content-security-policy"]
            status, headers, data = _raw(server, "HEAD", "/")
            assert status == 200 and data == b"" and int(headers["content-length"]) > 0
            assert _raw(server, "HEAD", "/readyz")[0] == 200
            # Files under the working directory are no longer reachable via HEAD.
            assert _raw(server, "HEAD", "/webapp/api/config.py")[0] == 404
            assert _raw(server, "HEAD", "/README.md")[0] == 404
            assert _raw(server, "PUT", "/")[0] == 501
        finally:
            server.shutdown()
            server.server_close()


def test_ai_explain_rate_limit_returns_429(monkeypatch):
    monkeypatch.setenv("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("LS_TEST_AI_KEY", "not-a-real-key")
    calls = []
    monkeypatch.setattr(
        "webapp.api.server.explain_log_line",
        lambda record, cfg: calls.append(record["id"]) or {"summary": "s", "steps": [{"title": "t"}]},
    )
    with tempfile.TemporaryDirectory() as td:
        cfg = load_app_config(CONFIG)
        cfg = replace(cfg, webapp=replace(cfg.webapp, db_path=Path(td) / "webapp.sqlite"),
                      ai=replace(cfg.ai, provider="openai", model="m", api_key_env="LS_TEST_AI_KEY"))
        app = WebApp(cfg)
        base = {"severity_bucket": "error", "scope": "infra", "namespace": "ns", "pod": "p", "container": "c",
                "raw_line": "r", "source_etag": "e", "is_falco": 0, "timestamp": "2026-09-07T00:00:00Z"}
        app.storage.insert_records([{**base, "message": f"m{i}", "source_key": "k", "line_number": i} for i in (1, 2)])
        ids = [r["id"] for r in app.storage.query_logs({}, limit=10)["items"]]
        server = _serve(app)
        try:
            assert _request(server, "POST", "/api/explain-line", body=json.dumps({"id": ids[0]}), headers=JSON)[0] == 200
            # Cached answers are free and not limited.
            status, payload = _request(server, "POST", "/api/explain-line", body=json.dumps({"id": ids[0]}), headers=JSON)
            assert status == 200 and payload["cached"] is True
            status, headers, data = _raw(server, "POST", "/api/explain-line", body=json.dumps({"id": ids[1]}), headers=JSON)
            assert status == 429 and int(headers["retry-after"]) >= 1
            assert "rate limit" in json.loads(data)["error"]
            assert calls == [ids[0]]
        finally:
            server.shutdown()
            server.server_close()


def test_readyz_tolerates_busy_database_within_grace():
    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        server = _serve(app)
        app.storage.lock.acquire()
        try:
            assert _request(server, "GET", "/readyz") == (200, {"status": "ok", "db": "busy"})
            app._db_busy_since -= 3600  # busy far beyond the grace period
            assert _request(server, "GET", "/readyz")[0] == 503
        finally:
            app.storage.lock.release()
            server.shutdown()
            server.server_close()
        assert app.ready() == (True, False)


def _lines(n: int, start: int = 0) -> str:
    return "".join(f"2026-09-07T00:00:{i % 60:02d}Z - app - web-{i}/nginx - message number {i}\n"
                   for i in range(start, start + n))


def test_ingest_streams_in_bounded_batches(monkeypatch):
    cfg = load_app_config(CONFIG)
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        key = "k3s-logs/logs/info/2026/09/07/00_00_00_big.gz"
        bodies = {key: _gz(_lines(2500) + "garbage line\n" + _lines(1, start=2500))}
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = FakeS3([{"Key": key, "ETag": '"e"', "LastModified": "2026-09-07T00:00:00Z"}], bodies)
        sizes = []
        original = storage.insert_records
        monkeypatch.setattr(storage, "insert_records", lambda recs: sizes.append(len(recs)) or original(recs))

        result = ingestor.ingest_once()

        assert result.error is None and result.records_ingested == 2501
        assert max(sizes) <= 1000 and sum(sizes) == 2501
        assert storage.get_status()["total_records"] == 2501


def test_ingest_corrupt_deflate_marked_and_transport_error_retried_without_duplicates():
    cfg = load_app_config(CONFIG)
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        corrupt_key = "k3s-logs/logs/info/2026/09/07/00_00_00_a.gz"
        flaky_key = "k3s-logs/logs/info/2026/09/07/00_00_01_b.gz"
        good = _gz(_lines(5000))
        broken = bytearray(_gz(_lines(3000)))
        broken[len(broken) // 2: len(broken) // 2 + 64] = b"\xff" * 64
        objects = [{"Key": corrupt_key, "ETag": '"c"', "LastModified": "2026-09-07T00:00:00Z"},
                   {"Key": flaky_key, "ETag": '"f"', "LastModified": "2026-09-07T00:00:01Z"}]
        s3 = FakeS3(objects, {corrupt_key: bytes(broken), flaky_key: good})

        class _Flaky(io.BytesIO):
            def read(self, n=-1):
                if self.tell() >= len(good) // 2:
                    raise ConnectionResetError("connection reset by peer")
                n = len(good) // 2 - self.tell() if n is None or n < 0 else min(n, len(good) // 2 - self.tell())
                return super().read(n)

        real_get = s3.get_object
        s3.get_object = lambda Bucket, Key: {"Body": _Flaky(good)} if Key == flaky_key else real_get(Bucket, Key)
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = s3

        first = ingestor.ingest_once()
        assert first.error and "reset" in first.error            # transport failure surfaces
        assert storage.object_seen(cfg.s3_bucket, corrupt_key, "c")  # corrupt object recorded, not retried
        assert not storage.object_seen(cfg.s3_bucket, flaky_key, "f")
        assert storage.get_status()["last_error"]

        s3.get_object = real_get
        second = ingestor.ingest_once()
        assert second.error is None
        assert storage.get_status()["last_error"] is None         # success clears the old error
        rows = storage.conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT line_number) FROM records WHERE source_key = ?", (flaky_key,)
        ).fetchone()
        assert tuple(rows) == (5000, 5000)                          # complete, no duplicates


# --- Audit P1 fixes ------------------------------------------------------------

import base64  # noqa: E402
import logging  # noqa: E402
import sqlite3  # noqa: E402
import time  # noqa: E402
import types  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402

from webapp.api.storage import decode_cursor  # noqa: E402

_BASE_RECORD = {"severity_bucket": "info", "scope": "infra", "namespace": "ns", "pod": "p",
                "container": "c", "source_etag": "e", "line_number": 1, "is_falco": 0}


def _record(ts: str, message: str, key: str, **extra) -> dict:
    return {**_BASE_RECORD, "timestamp": ts, "message": message, "raw_line": f"{ts} - ns - p/c - {message}",
            "source_key": key, **extra}


def _b64(payload: str) -> str:
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def test_malformed_cursor_is_a_client_error():
    for bad in (_b64("{}"), _b64("[1, 2]"), _b64('{"ts": "x"}'), _b64('{"ts": "x", "id": true}'),
                _b64('{"ts": 5, "id": 1}'), "%%%not-base64", _b64("not json")):
        try:
            decode_cursor(bad)
        except ValueError as exc:
            assert str(exc) == "Invalid cursor", bad
        else:
            raise AssertionError(f"accepted {bad!r}")
    assert decode_cursor(_b64('{"ts": "2026-09-07T00:00:00Z", "id": 3}')) == ("2026-09-07T00:00:00Z", 3)

    with tempfile.TemporaryDirectory() as td:
        server = _serve(_make_webapp(Path(td) / "webapp.sqlite"))
        try:
            status, payload = _request(server, "GET", f"/api/logs?cursor={_b64('{}')}")
            assert status == 400 and payload["error"] == "Invalid request: Invalid cursor"
        finally:
            server.shutdown()
            server.server_close()


def test_tail_follows_ingest_order_so_late_records_are_not_missed():
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        storage.insert_records([_record("2026-09-07T10:00:00Z", "first", "k1"),
                                _record("2026-09-07T10:05:00Z", "second", "k2")])
        position = storage.query_logs({}, limit=10)["max_id"]
        assert storage.query_tail({}, after_id=None, limit=10) == {"items": [], "last_id": position, "truncated": False}

        # A late object: older event time than rows already shown, newer row id.
        storage.insert_records([_record("2026-09-07T09:00:00Z", "late", "k3"),
                                _record("2026-09-07T10:10:00Z", "newest", "k4", namespace="other")])
        tail = storage.query_tail({}, after_id=position, limit=10)
        assert [r["message"] for r in tail["items"]] == ["newest", "late"]   # newest ingested first
        assert tail["last_id"] == position + 2 and tail["truncated"] is False
        # Filters still apply, and the position advances past non-matching rows.
        filtered = storage.query_tail({"namespace": "ns"}, after_id=position, limit=10)
        assert [r["message"] for r in filtered["items"]] == ["late"] and filtered["last_id"] == position + 2
        # More new rows than the limit: the newest are kept and the response says so.
        capped = storage.query_tail({}, after_id=position, limit=1)
        assert [r["message"] for r in capped["items"]] == ["newest"] and capped["truncated"] is True
        assert storage.query_tail({}, after_id=tail["last_id"], limit=10)["items"] == []

    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        app.storage.insert_records([_record("2026-09-07T10:00:00Z", "a", "k1")])
        server = _serve(app)
        try:
            status, logs = _request(server, "GET", "/api/logs?limit=5")
            assert status == 200 and logs["max_id"] == 1
            app.storage.insert_records([_record("2026-09-07T08:00:00Z", "late", "k2")])
            status, tail = _request(server, "GET", f"/api/tail?after_id={logs['max_id']}")
            assert status == 200 and [r["message"] for r in tail["items"]] == ["late"] and tail["last_id"] == 2
            assert _request(server, "GET", "/api/tail?after_id=-1")[0] == 400
        finally:
            server.shutdown()
            server.server_close()


def test_writes_commit_promptly_and_database_uses_wal():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "webapp.sqlite"
        storage = LogStorage(db)
        assert storage.journal_mode == "wal"
        assert storage.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

        storage.set_prefix_cursor("p/", "p/k1")
        assert not storage.conn.in_transaction
        storage.mark_object("b", "p/k1", "e", "2026-09-07T00:00:00Z", status="ok", record_count=0)
        assert not storage.conn.in_transaction
        storage.record_object_failure("b", "p/k2", "e", prefix="p/", last_modified="x", error="boom")
        assert not storage.conn.in_transaction

        # Another connection (the anomaly writer) is not blocked by ingest state.
        other = sqlite3.connect(db, timeout=0.1)
        other.execute("CREATE TABLE IF NOT EXISTS probe (x)")
        other.execute("INSERT INTO probe VALUES (1)")
        other.commit()
        other.close()


class _S3WithFailures(FakeS3):
    """FakeS3 whose get_object raises for keys in `failing` and whose listing
    raises for prefixes in `failing_prefixes`."""

    def __init__(self, objects, bodies):
        super().__init__(objects, bodies)
        self.failing: dict[str, Exception] = {}
        self.failing_prefixes: set[str] = set()
        self.reads: list[str] = []

    def get_paginator(self, name):
        inner = super().get_paginator(name)
        failing_prefixes = self.failing_prefixes

        class _Paginator:
            def paginate(self, **kwargs):
                if kwargs["Prefix"] in failing_prefixes:
                    raise ConnectionError("listing timed out")
                yield from inner.paginate(**kwargs)

        return _Paginator()

    def get_object(self, Bucket, Key):
        self.reads.append(Key)
        if Key in self.failing:
            raise self.failing[Key]
        return super().get_object(Bucket, Key)


def test_failing_object_or_prefix_does_not_block_other_ingest_and_is_retried_with_backoff():
    cfg = load_app_config(CONFIG)
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        bad = "k3s-logs/logs/error/2026/09/07/00_00_00_bad.gz"
        after_bad = "k3s-logs/logs/error/2026/09/07/00_00_01_ok.gz"
        other_prefix = "k3s-logs/logs/info/2026/09/07/00_00_00_ok.gz"
        objects = [{"Key": k, "ETag": f'"{i}"', "LastModified": "2026-09-07T00:00:00Z"}
                   for i, k in enumerate((bad, after_bad, other_prefix))]
        bodies = {k: _gz(f"2026-09-07T00:00:00Z - app - web-0/nginx - from {k}") for k in (bad, after_bad, other_prefix)}
        s3 = _S3WithFailures(objects, bodies)
        s3.failing[bad] = PermissionError("AccessDenied (KMS)")
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = s3

        first = ingestor.ingest_once()
        assert first.records_ingested == 2 and first.objects_failed == 1        # others still ingested
        assert "AccessDenied" in first.error
        failure = storage.get_object_failure(cfg.s3_bucket, bad, "0")
        assert failure["attempts"] == 1
        status = storage.get_status()
        assert status["last_successful_ingest_at"] is not None                  # not a pipeline outage
        assert storage.get_prefix_cursor("k3s-logs/logs/error/") == after_bad    # cursor not pinned

        # First retry is on the next poll; after that the object backs off.
        assert ingestor.ingest_once().objects_failed == 1
        assert storage.get_object_failure(cfg.s3_bucket, bad, "0")["attempts"] == 2
        reads_before = len(s3.reads)
        third = ingestor.ingest_once()
        assert third.objects_failed == 0 and third.objects_deferred == 1
        assert bad not in s3.reads[reads_before:]                               # no retry storm

        # Once readable and due, the failure-table retry ingests it exactly once.
        del s3.failing[bad]
        storage.conn.execute("UPDATE object_failures SET next_attempt_at = '2000-01-01T00:00:00.000000Z'")
        storage.conn.commit()
        objects.clear()  # not listed any more (behind the cursor): only the retry pass can find it
        fourth = ingestor.ingest_once()
        assert fourth.records_ingested == 1 and fourth.error is None
        assert storage.get_object_failure(cfg.s3_bucket, bad, "0") is None
        assert storage.object_seen(cfg.s3_bucket, bad, "0")
        assert storage.get_status()["total_records"] == 3                       # no duplicates

        # A listing failure in one prefix leaves the others working and is reported.
        objects.append({"Key": "k3s-logs/logs/warning/2026/09/07/00_00_00_w.gz", "ETag": '"w"',
                        "LastModified": "2026-09-07T00:00:00Z"})
        bodies["k3s-logs/logs/warning/2026/09/07/00_00_00_w.gz"] = _gz("2026-09-07T00:00:00Z - app - w/c - w")
        s3.failing_prefixes.add("k3s-logs/logs/error/")
        last_success = storage.get_state("last_successful_ingest_at")
        time.sleep(0.01)
        fifth = ingestor.ingest_once()
        assert fifth.records_ingested == 1 and "listing timed out" in fifth.error
        assert storage.get_state("last_successful_ingest_at") == last_success  # prefix outage = not successful


def test_missing_object_is_dropped_from_retries():
    cfg = load_app_config(CONFIG)
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        key = "k3s-logs/logs/error/2026/09/07/00_00_00_gone.gz"
        s3 = _S3WithFailures([{"Key": key, "ETag": '"g"', "LastModified": "2026-09-07T00:00:00Z"}], {})
        s3.failing[key] = ClientError({"Error": {"Code": "NoSuchKey", "Message": "gone"}}, "GetObject")
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = s3
        result = ingestor.ingest_once()
        assert result.error is None and storage.get_object_failure(cfg.s3_bucket, key, "g") is None


def test_status_reports_ingest_staleness_and_insights_errors(caplog):
    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        assert app.status()["ingest"]["state"] == "stopped"          # loop never started

        app._thread = types.SimpleNamespace(is_alive=lambda: True)
        assert app.status()["ingest"]["state"] == "starting"
        app._last_poll_finished = time.monotonic()
        assert app.status()["ingest"]["state"] == "stale"            # never succeeded
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        app.storage.ingest_state(last_poll_at=now, last_successful_ingest_at=now,
                                 last_object_last_modified=None, last_error=None)
        assert app.status()["ingest"]["state"] == "ok"
        app.storage.record_object_failure(app.cfg.s3_bucket, "k", "e", prefix="p/", last_modified="x", error="boom")
        ingest = app.status()["ingest"]
        assert ingest["state"] == "degraded" and ingest["failing_objects"] == 1
        app._last_poll_finished = time.monotonic() - 10_000
        assert app.status()["ingest"]["state"] == "stalled"          # loop wedged; liveness unaffected

        # A failing insights run is logged and surfaced, and the loop survives.
        job = app.insights

        def boom(now):
            job._stop.set()
            raise RuntimeError("detector exploded")

        job.detector.detect_all = boom
        with caplog.at_level(logging.ERROR, logger="webapp.api.insights"):
            job._loop()
        insights = app.status()["insights"]
        assert insights["last_error"] == "detector exploded" and insights["consecutive_failures"] == 1
        assert any("Insights run failed" in r.getMessage() for r in caplog.records)
        # Detection reads through its own connection, not the shared one.
        assert job.detector._conn is not app.storage.conn


def test_trusted_host_policy_blocks_dns_rebinding(monkeypatch):
    monkeypatch.setenv("LOGSCOPE_TRUSTED_HOSTS", "logs.example.com,*.corp.example")
    with tempfile.TemporaryDirectory() as td:
        app = _make_webapp(Path(td) / "webapp.sqlite")
        server = _serve(app)
        port = server.server_address[1]
        try:
            for host in (f"evil.example:{port}", "attacker.test", "corp.example.evil.test", ""):
                status, payload = _request(server, "GET", "/api/status", headers={"Host": host})
                assert status == 421 and "LOGSCOPE_TRUSTED_HOSTS" in payload["error"], host
            # A rebinding POST matches Origin to Host, so only the Host check stops it.
            status, _ = _request(server, "POST", "/api/actions/execute", body=b"{}",
                                 headers={**JSON, "Host": f"evil.example:{port}", "Origin": f"http://evil.example:{port}"})
            assert status == 421
            for host in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}", "logs.example.com",
                         "a.corp.example", "10.42.0.7:8000"):
                assert _request(server, "GET", "/api/status", headers={"Host": host})[0] == 200, host
            # Probes are answered whatever the Host header says.
            assert _request(server, "GET", "/readyz", headers={"Host": "10.42.0.7:8000"})[0] == 200
            assert _request(server, "GET", "/readyz", headers={"Host": "anything.test"})[0] == 200
        finally:
            server.shutdown()
            server.server_close()

    monkeypatch.setenv("LOGSCOPE_TRUSTED_HOSTS", "*")
    with tempfile.TemporaryDirectory() as td:
        server = _serve(_make_webapp(Path(td) / "webapp.sqlite"))
        try:
            assert _request(server, "GET", "/api/status", headers={"Host": "anything.test"})[0] == 200
        finally:
            server.shutdown()
            server.server_close()


def test_actions_are_disabled_unless_explicitly_enabled(monkeypatch):
    monkeypatch.delenv("LOGSCOPE_ACTIONS_ENABLED", raising=False)
    with tempfile.TemporaryDirectory() as td:
        server = _serve(_make_webapp(Path(td) / "webapp.sqlite"))
        try:
            assert _request(server, "GET", "/api/status")[1]["actions_enabled"] is False
            status, _ = _request(server, "POST", "/api/actions/execute",
                                 body=json.dumps({"command": "kubectl get pods"}), headers=JSON)
            assert status == 403
        finally:
            server.shutdown()
            server.server_close()
    monkeypatch.setenv("LOGSCOPE_ACTIONS_ENABLED", "true")
    with tempfile.TemporaryDirectory() as td:
        assert _make_webapp(Path(td) / "webapp.sqlite").actions_enabled is True


def test_validate_endpoint_returns_the_exact_command_that_would_run():
    with tempfile.TemporaryDirectory() as td:
        server = _serve(_make_webapp(Path(td) / "webapp.sqlite"))
        try:
            status, payload = _request(server, "POST", "/api/actions/validate", headers=JSON, body=json.dumps(
                {"command": "kubectl logs web-0 -n app -c sidecar --previous --tail=50 -A"}))
            assert status == 200 and payload["valid"] is True
            assert payload["command"] == ("kubectl logs web-0 -n app -c sidecar --tail=50 "
                                          "--limit-bytes=262144 --previous")
            assert payload["ignored_args"] == ["-A"] and payload["risk"] == "read-only"
            status, payload = _request(server, "POST", "/api/actions/validate", headers=JSON, body=json.dumps(
                {"action": {"action": "rollout_restart", "namespace": "app", "resource": "web"}}))
            assert payload["is_mutating"] is True and payload["command"] == "kubectl rollout restart deployment/web -n app"
            status, payload = _request(server, "POST", "/api/actions/validate", headers=JSON,
                                       body=json.dumps({"command": "kubectl delete ns prod"}))
            assert status == 400 and payload["valid"] is False
        finally:
            server.shutdown()
            server.server_close()


def test_malformed_ai_provider_response_is_a_502_not_a_400(monkeypatch):
    from webapp.api import ai_summary

    monkeypatch.setenv("LOGSCOPE_AI_API_KEY", "sk-test")
    with tempfile.TemporaryDirectory() as td:
        cfg = load_app_config(CONFIG)
        cfg = replace(cfg, webapp=replace(cfg.webapp, db_path=Path(td) / "webapp.sqlite"),
                      ai=replace(cfg.ai, provider="openai", model="gpt-test", api_key_env="LOGSCOPE_AI_API_KEY"))
        app = WebApp(cfg)
        app.storage.insert_records([_record("2026-09-07T10:00:00Z", "boom", "k1")])

        class _Html:
            def __enter__(self):
                return io.BytesIO(b"<html>bad gateway</html>")

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr(ai_summary.request, "urlopen", lambda req, timeout=0: _Html())
        server = _serve(app)
        try:
            status, payload = _request(server, "POST", "/api/explain-line", body=json.dumps({"id": 1}), headers=JSON)
            assert status == 502 and "malformed response" in payload["error"]
        finally:
            server.shutdown()
            server.server_close()


def test_trusted_host_edge_cases(monkeypatch):
    monkeypatch.setenv("LOGSCOPE_TRUSTED_HOSTS", "Logs.Example.com,*.corp.example")
    with tempfile.TemporaryDirectory() as td:
        server = _serve(_make_webapp(Path(td) / "webapp.sqlite"))
        try:
            for host, expected in (("LOGS.EXAMPLE.COM.", 200), ("logs.example.com:443", 200),
                                   ("evilcorp.example", 421), ("corp.example.attacker.test", 421),
                                   ("logs.example.com@evil.test", 421)):
                assert _request(server, "GET", "/api/status", headers={"Host": host})[0] == expected, host
            # No Host header at all (HTTP/1.0 style) is refused outside the probes.
            assert _raw(server, "GET", "/api/status", headers={"Host": ""})[0] == 421
        finally:
            server.shutdown()
            server.server_close()
