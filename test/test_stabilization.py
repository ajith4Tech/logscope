"""Small fixes: /readyz on a database error, an anomaly whose stored evidence
is not JSON, and the log cache's default location (never /tmp)."""

from __future__ import annotations

import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from helpers import upsert_anomaly  # noqa: E402
from test_production import CONFIG, _make_webapp, _request, _serve  # noqa: E402

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.storage import default_cache_db_path  # noqa: E402


def test_readyz_is_503_when_the_database_fails(tmp_path):
    app = _make_webapp(tmp_path / "webapp.sqlite")
    server = _serve(app)
    try:
        assert _request(server, "GET", "/readyz") == (200, {"status": "ok"})
        app.storage.conn.close()  # e.g. the file was removed or the volume went away
        status, payload = _request(server, "GET", "/readyz")
        assert status == 503 and payload == {"status": "database unavailable"}
    finally:
        server.shutdown()
        server.server_close()


def test_corrupt_anomaly_evidence_is_reported_per_row(tmp_path):
    app = _make_webapp(tmp_path / "webapp.sqlite")
    common = {"pod": "", "rule_key": "", "severity": "error", "detected_day": "2026-09-07"}
    good = upsert_anomaly(app.anomaly_store, type="error_rate_spike", namespace="good",
                          evidence={"window_start": "2026-09-07T10:00:00Z", "current_count": 12}, **common)
    bad = upsert_anomaly(app.anomaly_store, type="error_rate_spike", namespace="bad",
                         evidence={"window_start": "2026-09-07T10:00:00Z"}, **common)
    listy = upsert_anomaly(app.anomaly_store, type="error_rate_spike", namespace="listy", evidence={}, **common)
    conn = app.anomaly_store._conn
    conn.execute("UPDATE anomalies SET evidence = '{\"window_start\": \"2026-09-07T1' WHERE id = ?", (bad,))
    conn.execute("UPDATE anomalies SET evidence = '[1, 2]' WHERE id = ?", (listy,))
    conn.commit()
    server = _serve(app)
    try:
        status, payload = _request(server, "GET", "/api/anomalies")
        assert status == 200
        by_id = {item["id"]: item for item in payload["items"]}
        assert by_id[good]["evidence"]["current_count"] == 12 and "evidence_error" not in by_id[good]
        assert by_id[bad]["evidence"] == {} and "not valid JSON" in by_id[bad]["evidence_error"]
        assert by_id[listy]["evidence"] == {} and "not a JSON object" in by_id[listy]["evidence_error"]
        assert by_id[bad]["template_summary"]["headline"]  # the free summary still renders
    finally:
        server.shutdown()
        server.server_close()


def test_cache_db_defaults_to_xdg_cache_never_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_db_path() == tmp_path / "xdg" / "logscope" / "cache.sqlite"
    assert load_app_config(CONFIG).webapp.db_path == tmp_path / "xdg" / "logscope" / "cache.sqlite"

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for value in ("", "relative/cache"):  # unset or relative (ignored, as the XDG spec says)
        monkeypatch.setenv("XDG_CACHE_HOME", value)
        assert default_cache_db_path() == tmp_path / "home" / ".cache" / "logscope" / "cache.sqlite"

    raw = yaml.safe_load(CONFIG.read_text())
    raw["webapp"]["backend"]["db_path"] = str(tmp_path / "configured.sqlite")
    configured = tmp_path / "config.yaml"
    configured.write_text(yaml.safe_dump(raw))
    assert load_app_config(configured).webapp.db_path == tmp_path / "configured.sqlite"
    monkeypatch.setenv("LOGSCOPE_WEBAPP_DB_PATH", str(tmp_path / "env.sqlite"))   # the environment wins
    assert load_app_config(configured).webapp.db_path == tmp_path / "env.sqlite"

    # The directory is created owner-only on first start.
    monkeypatch.delenv("LOGSCOPE_WEBAPP_DB_PATH")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "fresh"))
    cfg = load_app_config(CONFIG)
    app = WebApp(replace(cfg, webapp=replace(cfg.webapp, state_db_path=tmp_path / "state" / "s.sqlite")))
    assert app.storage.db_path == tmp_path / "fresh" / "logscope" / "cache.sqlite"
    assert (tmp_path / "fresh" / "logscope").stat().st_mode & 0o077 == 0
    example = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    assert "/tmp" not in str(example["webapp"]["backend"].get("db_path") or "")


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_chart_keeps_the_cache_on_the_pvc():
    from test_helm_chart import BASE, _find, _helm

    docs, _ = _helm(BASE)
    pod = _find(docs, "Deployment", "logscope-webapp")["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {e["name"]: e.get("value") for e in container["env"]}
    mounts = {m["mountPath"]: m["name"] for m in container["volumeMounts"]}
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert env["LOGSCOPE_WEBAPP_DB_PATH"] == "/data/logscope.sqlite"
    assert "persistentVolumeClaim" in volumes[mounts["/data"]]
