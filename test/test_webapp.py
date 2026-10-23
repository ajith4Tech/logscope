from __future__ import annotations

import gzip
import io
import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.ingest import S3Ingestor  # noqa: E402
from webapp.api.parser import make_record  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.storage import LogStorage, decode_cursor  # noqa: E402


class FakePaginator:
    def __init__(self, objects):
        self.objects = objects

    def paginate(self, **kwargs):
        prefix = kwargs["Prefix"]
        start_after = kwargs.get("StartAfter") or ""
        contents = [obj for obj in self.objects if obj["Key"].startswith(prefix) and obj["Key"] > start_after]
        yield {"Contents": contents}


class FakeS3:
    def __init__(self, objects, bodies):
        self._objects = objects
        self._bodies = bodies

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return FakePaginator(self._objects)

    def get_object(self, Bucket, Key):
        return {"Body": self._bodies[Key]}


def _buffer(text: str):
    bio = io.BytesIO()
    with gzip.GzipFile(fileobj=bio, mode="wb") as fh:
        fh.write(text.encode("utf-8"))
    bio.seek(0)
    return bio


def test_parser_skips_regular_falco_duplicate_and_accepts_security_copy():
    cfg = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml")
    falco_fixture = json.loads((ROOT / "test" / "fixtures" / "falco_alerts.txt").read_text().splitlines()[0])
    falco_message = str(falco_fixture["output"])
    regular = make_record(
        raw_line=f"2026-09-07T00:00:00Z - falco - p/c - {falco_message} scope=security",
        source_bucket="error",
        source_scope="regular",
        source_key="k3s-logs/logs/error/obj.gz",
        source_etag="etag1",
        line_number=1,
        infra_namespaces=cfg.infra_namespaces,
    )
    assert regular is None
    security = make_record(
        raw_line=f"2026-09-07T00:00:00Z - falco - p/c - {falco_message} scope=security",
        source_bucket="error",
        source_scope="security",
        source_key="k3s-logs/logs/security/error/obj.gz",
        source_etag="etag2",
        line_number=1,
        infra_namespaces=cfg.infra_namespaces,
    )
    assert security is not None
    assert security["scope"] == "security"
    assert security["is_falco"] == 1


def test_storage_queries_and_facets():
    with tempfile.TemporaryDirectory() as td:
        storage = LogStorage(Path(td) / "webapp.sqlite")
        storage.insert_records(
            [
                {
                    "timestamp": "2026-08-25T16:02:39Z",
                    "severity_bucket": "info",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "web-0",
                    "container": "nginx",
                    "message": "application started",
                    "raw_line": "2026-08-25T16:02:39Z - app - web-0/nginx - application started",
                    "source_key": "k3s-logs/logs/info/obj1.gz",
                    "source_etag": "etag1",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-08-27T12:00:00Z",
                    "severity_bucket": "error",
                    "scope": "security",
                    "namespace": "falco",
                    "pod": "falco-0",
                    "container": "falco",
                    "message": "Terminal shell in container (user=root container=nginx proc=sh)",
                    "raw_line": "2026-08-27T12:00:00Z - falco - falco-0/falco - Terminal shell in container (user=root container=nginx proc=sh) scope=security",
                    "source_key": "k3s-logs/logs/security/error/obj2.gz",
                    "source_etag": "etag2",
                    "line_number": 1,
                    "is_falco": 1,
                },
            ]
        )
        result = storage.query_logs({}, limit=10)
        assert len(result["items"]) == 2
        facets = storage.query_facets({})
        assert any(item["value"] == "security" for item in facets["scope"])
        assert any(item["value"] == "app" for item in facets["namespace"])
        assert decode_cursor(result["next_cursor"])


def test_ingest_once_tracks_prefix_state_and_skips_duplicate_falco_copy():
    cfg = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml")
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "webapp.sqlite"
        storage = LogStorage(db)
        regular_key = "k3s-logs/logs/info/2026/09/07/00_00_00_a.gz"
        security_key = "k3s-logs/logs/security/error/2026/09/07/00_00_00_b.gz"
        objects = [
            {"Key": regular_key, "ETag": '"etag1"', "LastModified": "2026-09-07T00:00:00Z"},
            {"Key": security_key, "ETag": '"etag2"', "LastModified": "2026-09-07T00:00:01Z"},
        ]
        bodies = {
            regular_key: _buffer(
                "\n".join(
                    [
                        "2026-08-25T16:02:39Z - app - web-0/nginx - application started",
                        "2026-08-27T12:00:00Z - falco - falco-0/falco - Terminal shell in container (user=root container=nginx proc=sh) scope=security",
                    ]
                )
            ),
            security_key: _buffer(
                "2026-08-27T12:00:00Z - falco - falco-0/falco - Terminal shell in container (user=root container=nginx proc=sh) scope=security"
            ),
        }
        ingestor = S3Ingestor(cfg, storage)
        ingestor.client = FakeS3(objects, bodies)
        result = ingestor.ingest_once()
        assert result.objects_ingested == 2
        assert result.records_ingested == 2
        first = storage.query_logs({"scope": "security"}, limit=10)
        assert len(first["items"]) == 1


def _make_webapp(db_path: Path) -> WebApp:
    cfg = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml")
    cfg = replace(cfg, webapp=replace(cfg.webapp, db_path=db_path))
    return WebApp(cfg)


def test_dashboard_endpoint_aggregates_existing_logs():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "webapp.sqlite"
        storage = LogStorage(db)
        storage.insert_records(
            [
                {
                    "timestamp": "2026-09-07T00:00:00Z",
                    "severity_bucket": "info",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "web-0",
                    "container": "nginx",
                    "message": "application started",
                    "raw_line": "2026-09-07T00:00:00Z - app - web-0/nginx - application started",
                    "source_key": "k3s-logs/logs/info/obj1.gz",
                    "source_etag": "etag1",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-09-07T00:10:00Z",
                    "severity_bucket": "error",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "web-0",
                    "container": "nginx",
                    "message": "connection refused",
                    "raw_line": "2026-09-07T00:10:00Z - app - web-0/nginx - connection refused",
                    "source_key": "k3s-logs/logs/error/obj2.gz",
                    "source_etag": "etag2",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-09-07T00:20:00Z",
                    "severity_bucket": "error",
                    "scope": "security",
                    "namespace": "falco",
                    "pod": "falco-0",
                    "container": "falco",
                    "message": "Terminal shell in container",
                    "raw_line": "2026-09-07T00:20:00Z - falco - falco-0/falco - Terminal shell in container scope=security",
                    "source_key": "k3s-logs/logs/security/error/obj3.gz",
                    "source_etag": "etag3",
                    "line_number": 1,
                    "is_falco": 1,
                },
                {
                    "timestamp": "2026-09-07T01:00:00Z",
                    "severity_bucket": "warning",
                    "scope": "namespaces/ops",
                    "namespace": "ops",
                    "pod": "api-0",
                    "container": "worker",
                    "message": "disk nearing capacity",
                    "raw_line": "2026-09-07T01:00:00Z - ops - api-0/worker - disk nearing capacity",
                    "source_key": "k3s-logs/logs/warning/obj4.gz",
                    "source_etag": "etag4",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-09-07T02:00:00Z",
                    "severity_bucket": "debug",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "web-0",
                    "container": "nginx",
                    "message": "debug trace",
                    "raw_line": "2026-09-07T02:00:00Z - app - web-0/nginx - debug trace",
                    "source_key": "k3s-logs/logs/debug/obj5.gz",
                    "source_etag": "etag5",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-09-07T03:00:00Z",
                    "severity_bucket": "metrics",
                    "scope": "infra",
                    "namespace": "metrics",
                    "pod": "metrics-0",
                    "container": "collector",
                    "message": "scrape succeeded",
                    "raw_line": "2026-09-07T03:00:00Z - metrics - metrics-0/collector - scrape succeeded",
                    "source_key": "k3s-logs/logs/metrics/obj6.gz",
                    "source_etag": "etag6",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-09-07T00:30:00Z",
                    "severity_bucket": "error",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "api-0",
                    "container": "worker",
                    "message": "connection refused",
                    "raw_line": "2026-09-07T00:30:00Z - app - api-0/worker - connection refused",
                    "source_key": "k3s-logs/logs/error/obj7.gz",
                    "source_etag": "etag7",
                    "line_number": 1,
                    "is_falco": 0,
                },
            ]
        )

        app = _make_webapp(db)
        data = app.api_dashboard({})

        assert data["summary"] == {
            "total_logs": 7,
            "error_count": 3,
            "warning_count": 1,
            "info_count": 1,
            "debug_count": 1,
            "metrics_count": 1,
            "security_count": 1,
            "unique_namespaces": 4,
            "unique_pods": 4,
        }
        assert data["severity"] == [
            {"value": "error", "count": 3},
            {"value": "debug", "count": 1},
            {"value": "info", "count": 1},
            {"value": "metrics", "count": 1},
            {"value": "warning", "count": 1},
        ]
        assert {item["value"]: item["count"] for item in data["namespaces"]} == {
            "app": 4,
            "falco": 1,
            "metrics": 1,
            "ops": 1,
        }
        assert {item["value"]: item["count"] for item in data["error_namespaces"]} == {
            "app": 2,
            "falco": 1,
        }
        assert {item["value"]: item["count"] for item in data["error_pods"]} == {
            "api-0": 1,
            "falco-0": 1,
            "web-0": 1,
        }
        assert data["top_errors"][0] == {"value": "connection refused", "count": 2}
        assert [row["timestamp"] for row in data["timeline"]] == [
            "2026-09-07T00:00:00Z",
            "2026-09-07T01:00:00Z",
            "2026-09-07T02:00:00Z",
            "2026-09-07T03:00:00Z",
        ]
        assert data["timeline"][0] == {"timestamp": "2026-09-07T00:00:00Z", "total_logs": 4, "error_logs": 3}


def test_dashboard_endpoint_respects_time_filters():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "webapp.sqlite"
        storage = LogStorage(db)
        storage.insert_records(
            [
                {
                    "timestamp": "2026-09-07T00:00:00Z",
                    "severity_bucket": "info",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "web-0",
                    "container": "nginx",
                    "message": "application started",
                    "raw_line": "2026-09-07T00:00:00Z - app - web-0/nginx - application started",
                    "source_key": "k3s-logs/logs/info/obj1.gz",
                    "source_etag": "etag1",
                    "line_number": 1,
                    "is_falco": 0,
                },
                {
                    "timestamp": "2026-09-08T00:00:00Z",
                    "severity_bucket": "error",
                    "scope": "namespaces/app",
                    "namespace": "app",
                    "pod": "web-0",
                    "container": "nginx",
                    "message": "connection refused",
                    "raw_line": "2026-09-08T00:00:00Z - app - web-0/nginx - connection refused",
                    "source_key": "k3s-logs/logs/error/obj2.gz",
                    "source_etag": "etag2",
                    "line_number": 1,
                    "is_falco": 0,
                },
            ]
        )

        app = _make_webapp(db)
        data = app.api_dashboard({"start": ["2026-09-07T00:00:00Z"], "end": ["2026-09-07T23:59:59Z"]})

        assert data["summary"]["total_logs"] == 1
        assert data["summary"]["error_count"] == 0
        assert data["timeline"] == [{"timestamp": "2026-09-07T00:00:00Z", "total_logs": 1, "error_logs": 0}]
        assert data["top_errors"] == []


def test_dashboard_endpoint_handles_empty_dataset():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "webapp.sqlite"
        app = _make_webapp(db)
        data = app.api_dashboard({})

        assert data == {
            "summary": {
                "total_logs": 0,
                "error_count": 0,
                "warning_count": 0,
                "info_count": 0,
                "debug_count": 0,
                "metrics_count": 0,
                "security_count": 0,
                "unique_namespaces": 0,
                "unique_pods": 0,
            },
            "severity": [],
            "namespaces": [],
            "error_namespaces": [],
            "error_pods": [],
            "top_errors": [],
            "timeline": [],
        }
