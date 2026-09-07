from __future__ import annotations

import json
import gzip
import io
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.ingest import S3Ingestor  # noqa: E402
from webapp.api.parser import make_record, parse_flat_line  # noqa: E402
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
    cfg = load_app_config(ROOT / "config.yaml")
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
    cfg = load_app_config(ROOT / "config.yaml")
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
