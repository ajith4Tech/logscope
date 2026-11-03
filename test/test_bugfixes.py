"""Reported bugs: Falco's security/ prefix is always ingested (with a warning
when the web app's and Vector's falco settings disagree), whitespace-free
timestamps enforced by render and shared with the parser, and dbtool's
default database path."""

from __future__ import annotations

import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))
sys.path.insert(0, str(ROOT / "scripts"))

import render as R  # noqa: E402
from test_webapp import FakeS3, _buffer  # noqa: E402

from logscope import cli  # noqa: E402
from logscope.lineformat import TIMESTAMP_PATTERN, line_format_problem, timestamp_format_problem  # noqa: E402
from webapp.api import dbtool  # noqa: E402
from webapp.api.config import falco_warnings, load_app_config, source_prefixes  # noqa: E402
from webapp.api.ingest import S3Ingestor  # noqa: E402
from webapp.api.parser import LINE_RE  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402

CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"
SECURITY_LINE = ("2026-08-27T12:00:00Z - falco - falco-0/falco - Terminal shell in container "
                 "(user=root container=nginx proc=sh) scope=security")


def _config(tmp_path: Path, *, falco: bool) -> Path:
    raw = yaml.safe_load(CONFIG.read_text())
    raw["falco"]["enabled"] = falco
    raw["webapp"]["backend"]["db_path"] = str(tmp_path / "cache.sqlite")
    raw["webapp"]["backend"]["state_db_path"] = str(tmp_path / "state.sqlite")
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


# ─── security/ is always ingested ────────────────────────────────────────────


def test_security_prefix_is_ingested_even_with_falco_disabled(tmp_path):
    cfg = load_app_config(_config(tmp_path, falco=False))
    assert cfg.falco_namespace is None
    assert {p["prefix"] for p in source_prefixes(cfg) if p["scope"] == "security"} == {
        f"k3s-logs/logs/security/{b}/" for b in cfg.severity_buckets}
    storage = LogStorage(tmp_path / "cache.sqlite")
    key = "k3s-logs/logs/security/error/2026/08/27/12_00_00_b.gz"
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = FakeS3([{"Key": key, "ETag": '"e"', "LastModified": "2026-08-27T12:00:01Z"}],
                             {key: _buffer(SECURITY_LINE)})
    assert ingestor.ingest_once().records_ingested == 1
    assert storage.query_logs({"scope": "security"}, limit=5)["items"][0]["is_falco"] == 1


def test_falco_warnings_both_ways():
    root = "k3s-logs/logs/"
    assert falco_warnings(falco_enabled=True, security_objects=3, other_objects=10, root=root) == []
    assert falco_warnings(falco_enabled=False, security_objects=0, other_objects=10, root=root) == []
    assert falco_warnings(falco_enabled=True, security_objects=0, other_objects=0, root=root) == []  # nothing yet
    off = falco_warnings(falco_enabled=False, security_objects=3, other_objects=10, root=root)
    assert len(off) == 1 and "falco.enabled is false" in off[0] and "ingested anyway" in off[0]
    on = falco_warnings(falco_enabled=True, security_objects=0, other_objects=10, root=root)
    assert len(on) == 1 and "falco.enabled: false" in on[0]
    rendered = falco_warnings(falco_enabled=True, security_objects=3, other_objects=10, root=root, vector_falco=False)
    assert len(rendered) == 1 and "rendered Vector config has Falco routing off" in rendered[0]


def test_status_warns_when_falco_settings_disagree(tmp_path):
    cfg = load_app_config(_config(tmp_path, falco=False))
    app = WebApp(cfg)
    assert app.status()["config_warnings"] == []
    app.storage.mark_object(cfg.s3_bucket, "k3s-logs/logs/info/2026/08/27/a.gz", "e1", "2026-08-27T12:00:00Z",
                            status="ok", record_count=1)
    app.storage.mark_object(cfg.s3_bucket, "k3s-logs/logs/security/error/2026/08/27/b.gz", "e2",
                            "2026-08-27T12:00:00Z", status="ok", record_count=1)
    [warning] = app.status()["config_warnings"]
    assert "Vector writes Falco events (1 objects under k3s-logs/logs/security/)" in warning
    on = WebApp(replace(cfg, falco_namespace="falco"))
    assert on.status()["config_warnings"] == []


def test_selfcheck_warns_when_rendered_vector_config_disagrees(tmp_path, capsys):
    config = _config(tmp_path, falco=True)
    rendered = R.load_config(config)
    rendered["falco"]["enabled"] = False
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "vector.yaml").write_text(R.dump_vector_yaml(R.vector_config_dict(rendered)))
    assert cli.main(["selfcheck", "--config", str(config)]) == 0      # a warning, not a failure
    out = capsys.readouterr().out
    assert "WARN  falco" in out and "Falco routing off" in out
    (tmp_path / "deploy" / "vector.yaml").write_text(R.dump_vector_yaml(R.vector_config_dict(R.load_config(config))))
    assert cli.main(["selfcheck", "--config", str(config)]) == 0
    assert "WARN  falco" not in capsys.readouterr().out


# ─── one whitespace-free timestamp token ─────────────────────────────────────


@pytest.mark.parametrize("fmt", ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S\tZ", "%c", "%e-%b-%Y", "%_H:%M",
                                 "%Y-%m-%dT%k:%M", "%r", "%v"])
def test_render_rejects_timestamps_with_whitespace(fmt):
    cfg = deepcopy(R.load_config(CONFIG))
    cfg["format"]["timestamp"] = fmt
    with pytest.raises(SystemExit, match="format.timestamp"):
        R.validate_cfg(cfg)


@pytest.mark.parametrize("fmt", ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%.3f%:z", "%+", "%s", "%Y-%m-%-eT%H"])
def test_render_accepts_one_token_timestamps(fmt):
    assert timestamp_format_problem(fmt) is None


def test_render_rejects_a_line_format_that_glues_the_message_to_the_timestamp():
    cfg = deepcopy(R.load_config(CONFIG))
    cfg["format"]["line"] = "{timestamp}|{message}"
    with pytest.raises(SystemExit, match=r"format.line .* joins \{timestamp\} and \{message\}"):
        R.validate_cfg(cfg)
    assert line_format_problem("{timestamp} - {namespace} - {pod}/{container} - {message}") is None
    assert line_format_problem("[{timestamp}] {message}") is None


def test_parser_timestamp_group_is_the_shared_constant():
    assert f"(?P<timestamp>{TIMESTAMP_PATTERN})" in LINE_RE.pattern
    assert LINE_RE.match("2026-10-21T06:00:00Z - ns - p/c - a b c").group("message") == "a b c"
    assert LINE_RE.match("2026-10-21 06:00:00 - ns - p/c - m") is None     # what render now refuses


# ─── dbtool default path ─────────────────────────────────────────────────────


def test_dbtool_falls_back_to_config_then_default(tmp_path, monkeypatch):
    monkeypatch.delenv("LOGSCOPE_WEBAPP_DB_PATH", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    config = _config(tmp_path, falco=True)
    LogStorage(tmp_path / "cache.sqlite").conn.close()
    assert dbtool.main(["--config", str(config), "backup", str(tmp_path / "b1.sqlite")]) == 0
    assert dbtool.main(["verify", str(tmp_path / "b1.sqlite")]) == 0
    # No config: the default cache location, like the server.
    default = tmp_path / "xdg" / "logscope" / "cache.sqlite"
    LogStorage(default).conn.close()
    assert dbtool.main(["--config", str(tmp_path / "missing.yaml"), "backup", str(tmp_path / "b2.sqlite")]) == 0
    assert dbtool._default_db(False, None) == default
    # The environment still wins; --state reads state_db_path from the config.
    monkeypatch.setenv("LOGSCOPE_WEBAPP_DB_PATH", str(tmp_path / "env.sqlite"))
    assert dbtool._default_db(False, config) == tmp_path / "env.sqlite"
    assert dbtool._default_db(True, config) == tmp_path / "state.sqlite"
