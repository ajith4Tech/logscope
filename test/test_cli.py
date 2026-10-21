"""The `logscope` CLI, bundled-asset lookup (source and PyInstaller layouts)
and the version reported by the server."""

from __future__ import annotations

import http.client
import os
import sys
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logscope import cli, resources, s3_lifecycle  # noqa: E402
from logscope.version import __version__  # noqa: E402
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.server import AppHTTPServer, LogscopeHandler, WebApp  # noqa: E402

CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"


def _config_with_paths(tmp_path: Path, db: Path, state: Path) -> Path:
    raw = yaml.safe_load(CONFIG.read_text())
    raw["webapp"]["backend"]["db_path"] = str(db)
    raw["webapp"]["backend"]["state_db_path"] = str(state)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_version_command(capsys):
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.startswith(f"logscope {__version__}")


def test_unknown_or_missing_command():
    with pytest.raises(SystemExit):
        cli.main(["no-such-command"])
    assert cli.main([]) == 2


def test_delegated_commands_use_their_own_parsers(capsys):
    for command, option in (("serve", "--port"), ("render", "--out"), ("s3-lifecycle", "--secret"), ("db", "--db")):
        with pytest.raises(SystemExit) as exc:
            cli.main([command, "--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert f"usage: logscope {command}" in out and option in out


class _Status(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):  # noqa: N802
        self.send_response(self.status if self.path == "/healthz" else 404)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("status,expected", [(200, 0), (503, 1)])
def test_healthcheck(status, expected, monkeypatch):
    # Must not go through a proxy even when one is configured.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    handler = type("H", (_Status,), {"status": status})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert cli.main(["healthcheck", "--port", str(server.server_address[1])]) == expected
    finally:
        server.shutdown()
        server.server_close()


def test_healthcheck_port_from_env_and_refused(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), _Status)
    port = server.server_address[1]
    server.server_close()  # nothing listens there now
    monkeypatch.setenv("PORT", str(port))
    assert cli.main(["healthcheck", "--timeout", "2"]) == 1


def test_selfcheck_passes_with_writable_paths(tmp_path, capsys):
    cfg = _config_with_paths(tmp_path, tmp_path / "data" / "logscope.sqlite", tmp_path / "state" / "s.sqlite")
    assert cli.main(["selfcheck", "--config", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "FTS5" in out and "selfcheck: passed" in out
    assert not list(tmp_path.rglob(".logscope-selfcheck-*"))  # probe files are removed


def test_selfcheck_fails_on_bad_config(tmp_path, capsys):
    bad = tmp_path / "config.yaml"
    bad.write_text("sinks: {}\n")
    assert cli.main(["selfcheck", "--config", str(bad)]) == 1
    assert "FAIL  config" in capsys.readouterr().out


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anywhere")
def test_selfcheck_fails_on_read_only_db_dir(tmp_path, capsys):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        cfg = _config_with_paths(tmp_path, ro / "logscope.sqlite", tmp_path / "s.sqlite")
        assert cli.main(["selfcheck", "--config", str(cfg)]) == 1
        assert "FAIL  db" in capsys.readouterr().out
    finally:
        ro.chmod(0o700)


def test_selfcheck_reports_ai_without_failing(tmp_path, monkeypatch, capsys):
    cfg = _config_with_paths(tmp_path, tmp_path / "l.sqlite", tmp_path / "s.sqlite")
    raw = yaml.safe_load(cfg.read_text())
    raw["webapp"]["ai"] = {"provider": "openai", "model": "m", "api_key_env": "LOGSCOPE_TEST_AI_KEY"}
    cfg.write_text(yaml.safe_dump(raw))
    monkeypatch.delenv("LOGSCOPE_TEST_AI_KEY", raising=False)
    assert cli.main(["selfcheck", "--config", str(cfg)]) == 0
    assert "WARN  ai" in capsys.readouterr().out


def test_s3_lifecycle_honours_logscope_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSCOPE_S3_BUCKET", "override-bucket")
    monkeypatch.setenv("LOGSCOPE_S3_RETENTION_DAYS", "7")
    cfg = s3_lifecycle.load_config(CONFIG)
    assert cfg["sinks"]["s3"]["bucket"] == "override-bucket"
    assert s3_lifecycle.resolve_retention_days(cfg["sinks"]["s3"]) == 7


def test_scripts_wrappers_are_the_package_modules():
    sys.path.insert(0, str(ROOT / "scripts"))
    import apply_s3_lifecycle
    import render

    from logscope import render as render_impl

    assert render is render_impl and apply_s3_lifecycle is s3_lifecycle


def test_ui_assets_resolve_in_source_mode():
    for name in resources.UI_FILES:
        assert resources.ui_asset(name).read_bytes()
    with pytest.raises(ValueError):
        resources.ui_asset("../config.yaml")


def test_assets_resolve_in_pyinstaller_layout(tmp_path, monkeypatch):
    bundle = tmp_path / "_internal"
    (bundle / "webapp" / "ui").mkdir(parents=True)
    (bundle / "webapp" / "ui" / "app.js").write_text("// bundled")
    (bundle / "config.example.yaml").write_text("bundled: true\n")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    monkeypatch.chdir(tmp_path)
    assert resources.ui_asset("app.js").read_text() == "// bundled"
    assert resources.example_config().read_text() == "bundled: true\n"
    assert resources.default_server_config() == Path("/etc/logscope/config.yaml")
    assert resources.project_dir() == tmp_path


def test_server_reports_version_in_status_and_header(tmp_path):
    cfg = load_app_config(CONFIG)
    app = WebApp(replace(cfg, webapp=replace(cfg.webapp, db_path=tmp_path / "w.sqlite")))
    server = AppHTTPServer(("127.0.0.1", 0), LogscopeHandler, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for path in ("/api/status", "/app.js"):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            conn.request("GET", path)
            res = conn.getresponse()
            body = res.read()
            conn.close()
            assert res.status == 200
            assert res.getheader("X-Logscope-Version") == __version__
            if path == "/api/status":
                assert b'"version":"' + __version__.encode() + b'"' in body
    finally:
        server.shutdown()
        server.server_close()

