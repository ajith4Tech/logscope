"""Part 2: HTTP-aware severity for access logs (additive, ingest-side)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.parser import (  # noqa: E402
    access_log_fields,
    access_log_severity,
    make_record,
)

TRAEFIK = ('{{"ClientHost":"10.0.0.7","RequestMethod":"{method}","RequestPath":"{path}",'
           '"DownstreamStatus":{status},"Duration":1200000,"request_User-Agent":"curl/8"}}')
COMMON = '203.0.113.5 - - [02/Nov/2026:10:00:00 +0000] "{method} {path} HTTP/1.1" {status} 1234 "-" "ua/1"'


@pytest.mark.parametrize("status,expected", [
    (200, None), (301, None), (204, None),
    (401, "warning"), (403, "warning"), (404, "warning"), (429, "warning"),
    (500, "error"), (502, "error"), (503, "error"),
])
def test_status_to_severity(status, expected):
    assert access_log_severity(status) == expected


@pytest.mark.parametrize("status", [200, 401, 403, 404, 429, 500])
def test_traefik_json_parsed(status):
    line = TRAEFIK.format(method="GET", path="/wp-login.php", status=status)
    fields = access_log_fields(line)
    assert fields == {"method": "GET", "path": "/wp-login.php", "status": status,
                      "client_ip": "10.0.0.7", "user_agent": "curl/8", "duration": 1200000}


@pytest.mark.parametrize("status", [200, 401, 403, 404, 429, 500])
def test_common_log_parsed(status):
    fields = access_log_fields(COMMON.format(method="POST", path="/x?author=1", status=status))
    assert fields["status"] == status and fields["method"] == "POST"
    assert fields["path"] == "/x?author=1" and fields["client_ip"] == "203.0.113.5"


@pytest.mark.parametrize("message", [
    "",
    "Starting up, listening on :8080",
    "level=info msg=\"request handled\" status=ok",   # no numeric status shape
    '{"msg":"hello","level":"info"}',                   # JSON without an HTTP status
    "E0102 10:00:00.1   1 controller.go:12] reconcile failed",
    "2026-11-02T10:00:00Z GET /health 200",            # not an access-log shape
])
def test_non_access_lines_are_ignored(message):
    assert access_log_fields(message) is None


def _record(message, bucket="info", scope="namespace"):
    raw = f"2026-11-02T10:00:00Z - sec-test - wordpress-abc/accesslog - {message}"
    return make_record(raw_line=raw, source_bucket=bucket, source_scope=scope,
                       source_key="k", source_etag="e", line_number=1, infra_namespaces=())


def test_make_record_overrides_severity_and_stores_http_meta():
    r = _record(COMMON.format(method="GET", path="/?author=1", status=404))
    assert r["severity_bucket"] == "warning"            # was info (prefix), now warning
    assert json.loads(r["http_meta"])["status"] == 404

    r = _record(COMMON.format(method="GET", path="/", status=500), bucket="info")
    assert r["severity_bucket"] == "error"

    r = _record(COMMON.format(method="GET", path="/", status=200), bucket="info")
    assert r["severity_bucket"] == "info"               # 2xx unchanged
    assert json.loads(r["http_meta"])["status"] == 200


def test_make_record_leaves_non_access_untouched():
    # A plain app error line keeps its prefix bucket and gets no http_meta.
    r = _record("Traceback: boom", bucket="error")
    assert r["severity_bucket"] == "error" and r["http_meta"] is None


def test_security_lines_are_not_reclassified():
    # Falco/security scope is never treated as an access log.
    r = _record(COMMON.format(method="GET", path="/", status=500), scope="security")
    assert r["scope"] == "security" and r["is_falco"] == 1
    assert r["http_meta"] is None and r["severity_bucket"] == "info"  # prefix bucket kept
