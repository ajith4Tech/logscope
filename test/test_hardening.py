"""Regression tests for the second hardening pass: action confirmation over
HTTP, stored-plan re-derivation, storage failure handling, ingest recovery,
redaction coverage and resource limits."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from test_production import JSON, _make_webapp, _request, _serve  # noqa: E402

from webapp.api.insights import AnomalyStore  # noqa: E402

_RESTART = {"action": {"action": "rollout_restart", "namespace": "app", "resource": "web"}}
_OK_RUN = (0, "deployment.apps/web restarted", "", False, False)


def _actions_server(monkeypatch, td):
    monkeypatch.setenv("LOGSCOPE_ACTIONS_ENABLED", "true")
    return _serve(_make_webapp(Path(td) / "webapp.sqlite"))


def test_mutating_action_needs_the_token_issued_for_that_exact_command(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        server = _actions_server(monkeypatch, td)
        try:
            with patch("webapp.api.actions._run_command", return_value=_OK_RUN) as run:
                # confirmed:true alone (a script, or a page that never showed the command) is not enough.
                status, res = _request(server, "POST", "/api/actions/execute", headers=JSON,
                                       body=json.dumps({**_RESTART, "confirmed": True}))
                assert status == 200 and res["requires_confirmation"] is True and res["confirm_token"]
                assert res["command"] == "kubectl rollout restart deployment/web -n app"
                assert not run.called

                # A token issued for another command does not authorise this one.
                _, other = _request(server, "POST", "/api/actions/validate", headers=JSON, body=json.dumps(
                    {"action": {"action": "rollout_restart", "namespace": "app", "resource": "api"}}))
                _, res = _request(server, "POST", "/api/actions/execute", headers=JSON, body=json.dumps(
                    {**_RESTART, "confirmed": True, "confirm_token": other["confirm_token"]}))
                assert res["requires_confirmation"] is True and not run.called

                # The token from validating this command runs it once.
                _, check = _request(server, "POST", "/api/actions/validate", headers=JSON, body=json.dumps(_RESTART))
                body = json.dumps({**_RESTART, "confirmed": True, "confirm_token": check["confirm_token"]})
                status, res = _request(server, "POST", "/api/actions/execute", headers=JSON, body=body)
                assert status == 200 and res["success"] is True
                assert run.call_args[0][0] == ["kubectl", "rollout", "restart", "deployment/web", "-n", "app"]

                # Replaying the same request (double submit, retry) does not run it again.
                _, res = _request(server, "POST", "/api/actions/execute", headers=JSON, body=body)
                assert res["requires_confirmation"] is True and run.call_count == 1

                # The token cannot be used without confirmed:true either.
                _, check = _request(server, "POST", "/api/actions/validate", headers=JSON, body=json.dumps(_RESTART))
                _, res = _request(server, "POST", "/api/actions/execute", headers=JSON, body=json.dumps(
                    {**_RESTART, "confirm_token": check["confirm_token"]}))
                assert res["requires_confirmation"] is True and run.call_count == 1

                # Read-only actions need no token.
                status, res = _request(server, "POST", "/api/actions/execute", headers=JSON,
                                       body=json.dumps({"command": "kubectl get pods -n app"}))
                assert status == 200 and res["success"] is True
        finally:
            server.shutdown()
            server.server_close()


def test_unsupported_and_concurrent_duplicate_actions_are_refused(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        server = _actions_server(monkeypatch, td)
        try:
            for command in ("kubectl rollout restart deployment/web --dry-run=client",
                            "kubectl get pods -n", "kubectl delete pod web-0"):
                status, res = _request(server, "POST", "/api/actions/execute", headers=JSON,
                                       body=json.dumps({"command": command, "confirmed": True}))
                assert status == 400 and "Unsupported" in res["error"], command
            app = server.app
            with app.action_gate.slot(["kubectl", "get", "pods", "-n", "app"]):
                status, res = _request(server, "POST", "/api/actions/execute", headers=JSON,
                                       body=json.dumps({"command": "kubectl get pods -n app"}))
                assert status == 409 and "already running" in res["error"]
        finally:
            server.shutdown()
            server.server_close()


def test_validate_issues_no_token_while_actions_are_disabled(monkeypatch):
    monkeypatch.delenv("LOGSCOPE_ACTIONS_ENABLED", raising=False)
    with tempfile.TemporaryDirectory() as td:
        server = _serve(_make_webapp(Path(td) / "webapp.sqlite"))
        try:
            status, res = _request(server, "POST", "/api/actions/validate", headers=JSON, body=json.dumps(_RESTART))
            assert status == 200 and res["is_mutating"] is True and "confirm_token" not in res
        finally:
            server.shutdown()
            server.server_close()


def test_stored_plans_are_rederived_with_the_current_parser():
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "webapp.sqlite"
        from webapp.api.storage import LogStorage

        LogStorage(db)
        store = AnomalyStore(db)
        anomaly_id = store.upsert_anomaly(type="error_rate_spike", namespace="app", pod="", rule_key="",
                                          severity="error", evidence={"window_start": "2026-09-07T10:00:00Z"},
                                          detected_day="2026-09-07")
        # Saved by an older parser: "deployment foo" became a restart of a
        # deployment literally named "deployment".
        stale = [
            {"title": "restart", "command": "kubectl rollout restart deployment web -n app", "risk": "read-only",
             "action": {"action": "rollout_restart", "resource": "deployment", "namespace": "app"},
             "is_supported": True, "exec_command": "kubectl rollout restart deployment/deployment -n app"},
            {"title": "dry run", "command": "kubectl rollout restart deployment/web --dry-run=client",
             "risk": "read-only", "action": {"action": "rollout_restart", "resource": "web"}, "is_supported": True},
        ]
        store.save_ai_summary(anomaly_id, "s", "a", stale)
        [item] = store.query_anomalies({}, limit=10)["items"]
        first, second = item["ai_steps"]
        assert first["action"]["resource"] == "web" and first["risk"] == "medium"
        assert first["exec_command"] == "kubectl rollout restart deployment/web -n app"
        assert second["is_supported"] is False and second["action"] is None and second["exec_command"] == ""
        assert second["risk"] == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# Ingest recovery
# ─────────────────────────────────────────────────────────────────────────────

import io  # noqa: E402
import sqlite3  # noqa: E402

import pytest  # noqa: E402

from test_production import CONFIG, FakeS3, _gz, _S3WithFailures  # noqa: E402

from webapp.api import ingest as ingest_mod  # noqa: E402
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.ingest import S3Ingestor  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402

_PREFIX = "k3s-logs/logs/info/"


class _VersionedS3(FakeS3):
    """GetObject returns the current body and its ETag, like S3 does."""

    def __init__(self, objects, bodies, etags):
        super().__init__(objects, bodies)
        self.etags = etags

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self._bodies[Key]), "ETag": f'"{self.etags[Key]}"'}


def _lines(*messages, ts="2026-09-07T10:00:00Z"):
    return "\n".join(f"{ts} - app - web-0/nginx - {m}" for m in messages) + "\n"


def _messages(storage):
    return sorted(r["message"] for r in storage.query_logs({}, limit=1000)["items"])


def test_object_replaced_after_listing_is_stored_once_under_the_version_read(tmp_path):
    cfg = load_app_config(CONFIG)
    storage = LogStorage(tmp_path / "db.sqlite")
    key = _PREFIX + "2026/09/07/10_00_00_a.gz"
    objects = [{"Key": key, "ETag": '"v1"', "LastModified": "2026-09-07T10:00:00Z"}]
    # Listed as v1, but replaced by v2 before the GET.
    s3 = _VersionedS3(objects, {key: _gz(_lines("second version"))}, {key: "v2"})
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = s3
    assert ingestor.ingest_once().records_ingested == 1
    assert storage.object_seen(cfg.s3_bucket, key, "v2")
    objects[0]["ETag"] = '"v2"'                     # the listing catches up
    storage.set_prefix_cursor(_PREFIX, "")          # e.g. within the lookback window
    assert ingestor.ingest_once().records_ingested == 0
    assert _messages(storage) == ["second version"]


def test_failed_object_retried_after_it_changed_is_not_ingested_twice(tmp_path):
    cfg = load_app_config(CONFIG)
    storage = LogStorage(tmp_path / "db.sqlite")
    key = _PREFIX + "2026/09/07/10_00_00_a.gz"
    objects = [{"Key": key, "ETag": '"v1"', "LastModified": "2026-09-07T10:00:00Z"}]
    s3 = _S3WithFailures(objects, {key: _gz(_lines("v1 line"))})
    s3.failing[key] = TimeoutError("read timed out")
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = s3
    assert ingestor.ingest_once().objects_failed == 1
    # The object is rewritten; the retry of (key, v1) reads the new content.
    ingestor.client = _VersionedS3(objects, {key: _gz(_lines("v2 line"))}, {key: "v2"})
    objects[0]["ETag"] = '"v2"'
    storage.conn.execute("UPDATE object_failures SET next_attempt_at = '2000-01-01T00:00:00.000000Z'")
    storage.conn.commit()
    storage.set_prefix_cursor(_PREFIX, "")
    ingestor.ingest_once()
    ingestor.ingest_once()
    assert _messages(storage) == ["v2 line"]
    assert storage.object_failure_summary()["failing_objects"] == 0


def test_local_database_failure_does_not_blame_the_object_or_move_the_cursor(tmp_path, monkeypatch):
    cfg = load_app_config(CONFIG)
    storage = LogStorage(tmp_path / "db.sqlite")
    keys = [_PREFIX + f"2026/09/07/10_00_0{i}_x.gz" for i in range(3)]
    objects = [{"Key": k, "ETag": f'"e{i}"', "LastModified": "2026-09-07T10:00:00Z"} for i, k in enumerate(keys)]
    bodies = {k: _gz(_lines(*(f"{k[-8:]} line {n}" for n in range(3)))) for k in keys}
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = FakeS3(objects, bodies)
    real_insert = storage.insert_records
    calls = {"n": 0}

    def disk_full_on_second(records):
        calls["n"] += 1
        if calls["n"] == 2:
            raise sqlite3.OperationalError("database or disk is full")
        return real_insert(records)

    monkeypatch.setattr(storage, "insert_records", disk_full_on_second)
    result = ingestor.ingest_once()
    assert "disk is full" in result.error
    assert storage.object_failure_summary()["failing_objects"] == 0     # no per-object backoff
    assert storage.get_prefix_cursor(_PREFIX) is None                     # cursor not advanced
    assert storage.get_status()["last_successful_ingest_at"] is None      # pipeline shows as failing
    monkeypatch.setattr(storage, "insert_records", real_insert)            # space freed
    ingestor.ingest_once()
    assert len(_messages(storage)) == 9 and len(set(_messages(storage))) == 9
    assert storage.get_prefix_cursor(_PREFIX) == keys[-1]


def test_overlong_lines_are_cut_without_shifting_line_numbers(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_mod, "_MAX_LINE_CHARS", 200)
    cfg = load_app_config(CONFIG)
    storage = LogStorage(tmp_path / "db.sqlite")
    key = _PREFIX + "2026/09/07/10_00_00_a.gz"
    text = _lines("before") + _lines("x" * 5000) + "\n" + _lines("after")
    objects = [{"Key": key, "ETag": '"e"', "LastModified": "2026-09-07T10:00:00Z"}]
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = FakeS3(objects, {key: _gz(text)})
    assert ingestor.ingest_once().records_ingested == 3
    rows = {r["line_number"]: r for r in storage.query_logs({}, limit=10)["items"]}
    assert sorted(rows) == [1, 2, 4]
    assert rows[4]["message"] == "after" and rows[2]["raw_line"].endswith("[line truncated by Logscope]")
    assert len(rows[2]["raw_line"]) < 300
    # Re-reading the same object (a retry) maps every line to the same key.
    assert storage.insert_records([dict(r, source_key=key, source_etag="e") for r in rows.values()]) == 0


@pytest.mark.parametrize("text,limit", [("a\nbb\n\nccc", 2), ("abc\n", 3), ("", 5), ("abcdef", 4)])
def test_bounded_lines_numbers_physical_lines(text, limit):
    got = list(ingest_mod._bounded_lines(io.StringIO(text), limit))
    assert [n for n, _, _ in got] == list(range(1, len(text.splitlines()) + 1))
    assert all(len(line) <= limit for _, line, _ in got)


def test_retries_survive_a_restart_and_are_bounded_per_poll(tmp_path, monkeypatch):
    cfg = load_app_config(CONFIG)
    db = tmp_path / "db.sqlite"
    storage = LogStorage(db)
    keys = [_PREFIX + f"2026/09/07/10_00_{i:02d}_x.gz" for i in range(60)]
    objects = [{"Key": k, "ETag": f'"e{i}"', "LastModified": "2026-09-07T10:00:00Z"} for i, k in enumerate(keys)]
    s3 = _S3WithFailures(objects, {k: _gz(_lines(f"from {k[-12:]}")) for k in keys})
    for k in keys:
        s3.failing[k] = TimeoutError("timeout")
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = s3
    assert ingestor.ingest_once().objects_failed == 60
    assert storage.get_prefix_cursor(_PREFIX) == keys[-1]   # recorded failures may be passed
    storage.conn.close()

    restarted = LogStorage(db)                               # pod restart: failures persist
    assert restarted.object_failure_summary()["failing_objects"] == 60
    restarted.conn.execute("UPDATE object_failures SET next_attempt_at = '2000-01-01T00:00:00.000000Z'")
    restarted.conn.commit()
    # Past the lookback window, so only the retry queue reads these objects.
    restarted.set_prefix_cursor(_PREFIX, _PREFIX + "2026/09/08/00_00_00_z.gz")
    s3.failing.clear()
    ingestor = S3Ingestor(cfg, restarted)
    ingestor.client = s3
    reads_before = len(s3.reads)
    first = ingestor.ingest_once()
    assert len(s3.reads) - reads_before == 50 and first.records_ingested == 50   # bounded batch
    ingestor.ingest_once()
    assert restarted.object_failure_summary()["failing_objects"] == 0
    assert len(_messages(restarted)) == 60


def test_listing_that_fails_part_way_keeps_the_cursor_and_does_not_duplicate(tmp_path):
    cfg = load_app_config(CONFIG)
    storage = LogStorage(tmp_path / "db.sqlite")
    keys = [_PREFIX + f"2026/09/07/10_00_0{i}_x.gz" for i in range(4)]
    objects = [{"Key": k, "ETag": f'"e{i}"', "LastModified": "2026-09-07T10:00:00Z"} for i, k in enumerate(keys)]
    bodies = {k: _gz(_lines(f"from {k[-10:]}")) for k in keys}

    class _BrokenSecondPage(FakeS3):
        broken = True

        def get_paginator(self, name):
            outer = self

            class _P:
                def paginate(self, **kwargs):
                    after = kwargs.get("StartAfter") or ""
                    page = sorted((o for o in objects if o["Key"] > after), key=lambda o: o["Key"])
                    yield {"Contents": page[:2]}
                    if outer.broken:
                        raise ConnectionError("connection reset while listing")
                    yield {"Contents": page[2:]}

            return _P()

    s3 = _BrokenSecondPage(objects, bodies)
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = s3
    result = ingestor.ingest_once()
    assert result.records_ingested == 2 and "connection reset" in result.error
    assert storage.get_prefix_cursor(_PREFIX) is None
    s3.broken = False
    assert ingestor.ingest_once().records_ingested == 2
    assert len(_messages(storage)) == 4 and storage.get_prefix_cursor(_PREFIX) == keys[-1]


# ─────────────────────────────────────────────────────────────────────────────
# AI privacy
# ─────────────────────────────────────────────────────────────────────────────

import http.client  # noqa: E402
import logging  # noqa: E402
from urllib import request as urlrequest  # noqa: E402

from webapp.api import ai_summary  # noqa: E402
from webapp.api.ai_summary import _call_provider, prepare_untrusted_payload, redact_text  # noqa: E402
from webapp.api.config import AiConfig  # noqa: E402


@pytest.mark.parametrize("text,secret", [
    (r'{\"password\":\"hunter2 two\"}', "hunter2"),              # JSON escaped inside a string field
    ('"password": "my secret pass"', "secret pass"),              # quoted value with spaces
    ("user=admin password='p@ss word' host=db", "p@ss"),
    ("Authorization: Token abcdef1234567890", "abcdef1234567890"),
    ('{"headers":{"Authorization":"Digest username=x, response=6629fae4"}}', "6629fae4"),
    ("Cookie: session=abc123; csrftoken=def456", "def456"),
    ("Set-Cookie: sid=xyz123; Path=/; HttpOnly", "xyz123"),
    ("GET /o?X-Amz-Signature=deadbeefcafe&X-Amz-Security-Token=FQoGZXIvYXdz", "deadbeefcafe"),
    ("GET /o?X-Amz-Signature=deadbeefcafe&X-Amz-Security-Token=FQoGZXIvYXdz", "FQoGZXIvYXdz"),
    ("charge with sk_live_51HabcdefghijklmnopQRST", "51Habcdefghijklmnop"),
    ("google ya29.a0AfH6SMBabcdefghijklmnopqrstuv", "a0AfH6SMB"),
    ("npm npm_abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123"),
    ("POST https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX"),
    ("POST https://chat.example.com/hooks/abcdefghij1234567890", "abcdefghij1234567890"),
    ("git clone https://abcdefghijklmnopqrstuvwxyz012345@github.com/x", "abcdefghijklmnopqrstuvwxyz012345"),
    ("DB_PASS=s3cr3t", "s3cr3t"),
    ("password:\n  multiline-secret", "multiline-secret"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKC\n-----END RSA PRIVATE KEY-----", "MIIEow"),
    ("postgres://app:hunter2@db:5432/x", "hunter2"),
    ("level=error client_secret=abc.def/ghi", "abc.def"),
])
def test_common_and_unusual_credential_formats_are_redacted(text, secret):
    assert secret not in redact_text(text)


def test_redaction_keeps_ordinary_troubleshooting_text():
    text = ("pod web-0 OOMKilled exit code 137 node 10.0.0.4 tests_passed=5 bypass=on "
            'msg="token refresh failed" status=503 path=/api/v1/orders')
    out = redact_text(text)
    for keep in ("web-0", "OOMKilled", "137", "10.0.0.4", "tests_passed=5", "bypass=on",
                 "token refresh failed", "status=503", "/api/v1/orders"):
        assert keep in out


def test_nested_oversized_evidence_is_redacted_everywhere_and_bounded():
    secret = "api_key=SUPERSECRET123"
    payload = {"evidence": {"sample_messages": [f"{i} {secret} " + "x" * 5000 for i in range(300)],
                            "nested": [{"deeper": {"k": secret}}], "big": "y" * 100_000 + secret}}
    out = json.dumps(prepare_untrusted_payload(payload))
    assert "SUPERSECRET123" not in out and len(out) <= 48_000 + 200


def _openai_cfg():
    return AiConfig(provider="openai", model="m", api_key_env="K", max_anomalies_per_tick=1,
                    reasoning_effort="")


def test_unexpected_transport_errors_never_carry_their_text(monkeypatch, caplog):
    def boom(req, timeout=0):
        raise http.client.IncompleteRead(b"password=leaked-from-echoed-request")

    monkeypatch.setattr(urlrequest, "urlopen", boom)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RuntimeError) as info:
            _call_provider("openai", {"m": "x"}, "m", "sk-key-123456789", _openai_cfg(), "system")
    assert str(info.value) == "openai request failed (IncompleteRead)"
    assert "leaked" not in caplog.text


def test_oversized_provider_response_is_refused(monkeypatch):
    class _Huge(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(ai_summary, "_MAX_RESPONSE_BYTES", 1000)
    monkeypatch.setattr(urlrequest, "urlopen", lambda req, timeout=0: _Huge(b"{" + b" " * 5000 + b"}"))
    with pytest.raises(RuntimeError, match="exceeded"):
        _call_provider("openai", {"m": "x"}, "m", "key", _openai_cfg(), "system")


def test_model_output_fields_are_bounded():
    content = json.dumps({"summary": "s" * 100_000, "steps": [
        {"title": "t" * 5000, "command": "kubectl get pods " + "-A " * 3000, "explanation": "e" * 9000}]})
    result = ai_summary._parse_summary_response(content)
    assert len(result["summary"]) == 20_000
    [step] = result["steps"]
    assert len(step["title"]) == 200 and len(step["command"]) <= 2000 and len(step["explanation"]) == 2000
    assert step["is_supported"] is False


def test_stored_ai_error_is_not_resent_as_evidence():
    payload = ai_summary.build_prompt_payload(
        {"type": "t", "evidence": json.dumps({"current_count": 3, "ai_error": "OpenAI failed with HTTP 500"})})
    assert payload["evidence"] == {"current_count": 3}


def test_insights_status_shows_provider_failures_without_failing_detection(tmp_path):
    from webapp.api.insights import InsightsJob

    cfg = load_app_config(CONFIG)
    db = tmp_path / "db.sqlite"
    LogStorage(db)
    store = AnomalyStore(db)
    store.upsert_anomaly(type="error_rate_spike", namespace="app", pod="", rule_key="", severity="error",
                         evidence={"window_start": "2026-09-07T10:00:00Z"}, detected_day="2026-09-07")

    def failing(_):
        raise RuntimeError("openai summarization failed with HTTP 503: Unavailable")

    from webapp.api.storage import open_connection
    job = InsightsJob(cfg, open_connection(db), store, summarizer=failing)
    job.run_once()
    status = job.status()
    assert status["last_error"] is None and status["consecutive_failures"] == 0   # detection is healthy
    assert "HTTP 503" in status["last_ai_error"] and status["last_ai_error_at"]


# ─────────────────────────────────────────────────────────────────────────────
# Observability and resource limits
# ─────────────────────────────────────────────────────────────────────────────

import socket  # noqa: E402
import time  # noqa: E402

from webapp.api import server as server_mod  # noqa: E402
from webapp.api.server import AppHTTPServer, LogscopeHandler  # noqa: E402


def test_status_survives_a_failing_database(tmp_path, monkeypatch):
    app = _make_webapp(tmp_path / "webapp.sqlite")
    server = _serve(app)
    try:
        def locked():
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(app.storage, "get_status", locked)
        status, payload = _request(server, "GET", "/api/status")
        assert status == 200 and "database is locked" in payload["database_error"]
        assert payload["ingest"]["state"] == "unknown" and "insights" in payload
        assert _request(server, "GET", "/readyz")[0] == 200   # one failed query is not "unready"
    finally:
        server.shutdown()
        server.server_close()


def test_disk_low_marks_ingest_degraded(tmp_path, monkeypatch):
    app = _make_webapp(tmp_path / "webapp.sqlite")
    app._last_poll_finished = time.monotonic()
    app.storage.ingest_state(last_poll_at="2099-01-01T00:00:00Z", last_successful_ingest_at=None,
                             last_object_last_modified=None)
    app.storage._set_state("last_successful_ingest_at", server_mod.datetime.now(server_mod.timezone.utc).isoformat())
    app.storage.conn.commit()
    monkeypatch.setattr(app._thread, "is_alive", lambda: True)
    assert app.status()["ingest"]["state"] == "ok"
    import shutil as _shutil
    monkeypatch.setattr("webapp.api.storage.shutil.disk_usage",
                        lambda p: _shutil._ntuple_diskusage(10 * 2**30, 10 * 2**30 - 2**20, 2**20))
    status = app.status()
    assert status["storage"]["disk_low"] is True and status["ingest"]["state"] == "degraded"


def test_oversized_and_out_of_range_inputs_are_client_errors(tmp_path):
    server = _serve(_make_webapp(tmp_path / "webapp.sqlite"))
    try:
        assert _request(server, "GET", "/api/logs?q=" + "a" * 1001)[0] == 400
        assert _request(server, "GET", "/api/tail?after_id=99999999999999999999999")[0] == 400
        assert _request(server, "GET", "/api/tail?after_id=-1")[0] == 400
        big_cursor = __import__("base64").urlsafe_b64encode(
            json.dumps({"ts": "2026", "id": 2**70}).encode()).decode().rstrip("=")
        assert _request(server, "GET", f"/api/logs?cursor={big_cursor}")[0] == 400
        assert _request(server, "PATCH", "/api/anomalies/99999999999999999999999", headers=JSON,
                        body=json.dumps({"status": "reviewed"}))[0] == 400
    finally:
        server.shutdown()
        server.server_close()


def test_explain_cache_front_is_bounded(monkeypatch, tmp_path):
    # The AI answer cache is persistent (state DB); its in-memory front is an LRU.
    from webapp.api import ai_cache
    from webapp.api.state import StateDB

    monkeypatch.setattr(ai_cache, "FRONT_MAX_ENTRIES", 5)
    cache = ai_cache.AiCache(StateDB(tmp_path / "s.sqlite"))
    for i in range(20):
        cache._front_put(str(i), {"i": i})
    assert list(cache._front) == ["15", "16", "17", "18", "19"]


def test_requests_beyond_the_concurrency_cap_get_a_quick_503(tmp_path):
    app = _make_webapp(tmp_path / "webapp.sqlite")
    server = AppHTTPServer(("127.0.0.1", 0), LogscopeHandler, app, max_concurrent=1)
    import threading as _threading
    _threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    hog = socket.create_connection(("127.0.0.1", port))   # holds the only slot (no request sent yet)
    try:
        time.sleep(0.2)
        status, _ = _request(server, "GET", "/api/status")
        assert status == 503
        hog.close()
        time.sleep(0.3)
        assert _request(server, "GET", "/api/status")[0] == 200   # slot released
    finally:
        hog.close()
        server.shutdown()
        server.server_close()


def test_fts_migration_retries_after_a_failure_and_reports_it(tmp_path, monkeypatch):
    from test_storage_maintenance import _make_legacy_db, _row

    db = tmp_path / "webapp.sqlite"
    _make_legacy_db(db, [_row(i) for i in range(50)])
    app = _make_webapp(db)
    assert app.storage.fts_layout == "migrating"
    monkeypatch.setattr(server_mod, "_FTS_MIGRATION_RETRY_SECS", 0.05)
    real_step = app.storage.migrate_fts_step
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise sqlite3.OperationalError("database or disk is full")
        return real_step(*a, **kw)

    monkeypatch.setattr(app.storage, "migrate_fts_step", flaky)
    seen_errors = []
    original_wait = app._stop.wait

    def watching_wait(t):
        if app.storage.fts_migration_error:
            seen_errors.append(app.storage.fts_migration_error)
        return original_wait(min(t, 0.05))

    monkeypatch.setattr(app._stop, "wait", watching_wait)
    app._fts_migration_loop()                          # returns once the swap is done
    assert app.storage.fts_layout == "external" and app.storage.fts_migration_error is None
    assert seen_errors and "disk is full" in seen_errors[0]
