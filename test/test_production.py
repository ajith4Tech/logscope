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
            status, payload = _request(server, "GET", '/api/logs?q=%22unterminated')
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
