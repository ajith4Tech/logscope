"""Saved views: the durable state database (separate from the log cache),
its migrations, the /api/views endpoints and dbtool --state."""

from __future__ import annotations

import json
import shutil
import sqlite3
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from test_production import CONFIG, JSON, _request, _serve  # noqa: E402

from webapp.api import dbtool  # noqa: E402
from webapp.api import state as state_mod
from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.server import WebApp  # noqa: E402
from webapp.api.state import (  # noqa: E402
    MIGRATIONS,
    VIEWS_MAX,
    SavedViews,
    StateDB,
    ViewConflict,
    ViewError,
    default_state_db_path,
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _app(tmp_path: Path, *, cache: str = "cache.sqlite", state_db: str = "state/views.sqlite") -> WebApp:
    cfg = load_app_config(CONFIG)
    return WebApp(replace(cfg, webapp=replace(
        cfg.webapp, db_path=tmp_path / cache, state_db_path=tmp_path / state_db,
    )))


@pytest.fixture
def server(tmp_path):
    srv = _serve(_app(tmp_path))
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def store(tmp_path):
    db = StateDB(tmp_path / "state.sqlite")
    yield SavedViews(db)
    db.close()


def _call(server, method, path, body=None, headers=None):
    data = None if body is None else json.dumps(body)
    return _request(server, method, path, body=data, headers={**JSON, **(headers or {})})


# ─── State database ──────────────────────────────────────────────────────────


def test_state_db_is_created_private_in_wal_mode(tmp_path):
    path = tmp_path / "new-dir" / "state.sqlite"
    db = StateDB(path)
    db.conn.execute("INSERT INTO saved_views (name, created_at, updated_at) VALUES ('a', 'x', 'x')")
    assert _mode(path.parent) == 0o700
    assert _mode(path) == 0o600
    wal = Path(f"{path}-wal")
    assert wal.exists() and _mode(wal) == 0o600  # SQLite copies the database file's mode
    assert db.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.schema_version() == MIGRATIONS[-1][0]
    db.close()


def test_migrations_are_idempotent_and_forward_only(tmp_path):
    path = tmp_path / "state.sqlite"
    db = StateDB(path)
    SavedViews(db).create({"name": "Errors"})
    assert db.migrate() == MIGRATIONS[-1][0]  # second run: nothing to do
    db.close()
    db = StateDB(path)  # and again on reopen
    rows = db.conn.execute("SELECT version FROM schema_version").fetchall()
    assert [r[0] for r in rows] == [m[0] for m in MIGRATIONS]
    assert [v["name"] for v in SavedViews(db).list()] == ["Errors"]
    # A database written by a newer version is refused, not modified.
    db.conn.execute("INSERT INTO schema_version VALUES (999, 'x')")
    db.close()
    with pytest.raises(ValueError, match="newer"):
        StateDB(path)


def test_default_path_follows_xdg_and_never_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_state_db_path() == tmp_path / "xdg" / "logscope" / "state.sqlite"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for xdg in ("", "relative/dir"):  # unset or relative: ~/.local/share
        monkeypatch.setenv("XDG_DATA_HOME", xdg)
        assert default_state_db_path() == tmp_path / "home" / ".local" / "share" / "logscope" / "state.sqlite"
    cfg = load_app_config(CONFIG)
    assert cfg.webapp.state_db_path == default_state_db_path()
    assert cfg.webapp.state_db_path != cfg.webapp.db_path
    monkeypatch.setenv("LOGSCOPE_WEBAPP_STATE_DB_PATH", str(tmp_path / "env.sqlite"))
    assert load_app_config(CONFIG).webapp.state_db_path == tmp_path / "env.sqlite"


def test_state_db_path_from_config_file(tmp_path, monkeypatch):
    raw = CONFIG.read_text(encoding="utf-8")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(raw + f"\nwebapp:\n  backend:\n    state_db_path: {tmp_path / 'cfg.sqlite'}\n", encoding="utf-8")
    assert load_app_config(cfg_file).webapp.state_db_path == tmp_path / "cfg.sqlite"
    monkeypatch.setenv("LOGSCOPE_WEBAPP_STATE_DB_PATH", str(tmp_path / "env.sqlite"))
    assert load_app_config(cfg_file).webapp.state_db_path == tmp_path / "env.sqlite"


# ─── API ─────────────────────────────────────────────────────────────────────


def test_crud_and_ordering(server):
    assert _call(server, "GET", "/api/views") == (200, {"views": []})
    status, body = _call(server, "POST", "/api/views", {
        "name": "  Payments errors ", "description": "5xx in payments",
        "filters": {"ns": "payments", "sev": "error", "range": "1h"},
    })
    assert status == 201
    view = body["view"]
    assert view["name"] == "Payments errors" and view["pinned"] is False
    assert view["filters"] == {"ns": "payments", "sev": "error", "range": "1h"}
    assert view["created_at"] == view["updated_at"] and view["last_used_at"] is None
    vid = view["id"]

    _call(server, "POST", "/api/views", {"name": "beta"})
    _call(server, "POST", "/api/views", {"name": "Alpha", "pinned": True})
    names = [v["name"] for v in _call(server, "GET", "/api/views")[1]["views"]]
    assert names == ["Alpha", "Payments errors", "beta"]  # pinned first, then sort_order

    status, body = _call(server, "PATCH", f"/api/views/{vid}", {
        "name": "Payments 5xx", "description": "", "filters": {"ns": "payments"}, "pinned": True, "sort_order": -1,
    })
    assert status == 200
    assert body["view"]["filters"] == {"ns": "payments"} and body["view"]["description"] == ""
    assert body["view"]["updated_at"] >= view["updated_at"]
    names = [v["name"] for v in _call(server, "GET", "/api/views")[1]["views"]]
    assert names == ["Payments 5xx", "Alpha", "beta"]

    status, body = _call(server, "POST", f"/api/views/{vid}/use")
    assert status == 200 and body["view"]["last_used_at"]
    assert _call(server, "GET", f"/api/views/{vid}")[1]["view"]["last_used_at"] == body["view"]["last_used_at"]

    assert _call(server, "DELETE", f"/api/views/{vid}") == (200, {"ok": True, "id": vid})
    for method, path in (("DELETE", f"/api/views/{vid}"), ("PATCH", f"/api/views/{vid}"),
                         ("POST", f"/api/views/{vid}/use"), ("GET", f"/api/views/{vid}"),
                         ("GET", "/api/views/abc"), ("DELETE", "/api/views/99999999999999999999999"),
                         ("POST", f"/api/views/{vid}/nope")):
        status, payload = _call(server, method, path, {"name": "x"} if method == "PATCH" else None)
        assert status == 404, (method, path, payload)


def test_duplicate_names_are_compared_case_insensitively(server):
    assert _call(server, "POST", "/api/views", {"name": "Errors"})[0] == 201
    for name in ("errors", "ERRORS", " Errors "):
        status, body = _call(server, "POST", "/api/views", {"name": name})
        assert status == 409 and body["field"] == "name", name
    assert _call(server, "POST", "/api/views", {"name": "Ärger"})[0] == 201
    assert _call(server, "POST", "/api/views", {"name": "äRGER"})[0] == 409  # beyond SQLite's ASCII NOCASE
    status, body = _call(server, "POST", "/api/views", {"name": "Other"})
    other = body["view"]["id"]
    assert _call(server, "PATCH", f"/api/views/{other}", {"name": "eRRORS"})[0] == 409
    assert _call(server, "PATCH", f"/api/views/{other}", {"name": "OTHER"})[0] == 200  # its own name, recased


@pytest.mark.parametrize("filters, field", [
    ({"namespace": "x"}, "filters.namespace"),            # API name, not the URL key
    ({"tab": "logs"}, "filters.tab"),
    ({"view": "1"}, "filters.view"),
    ({"ns": ""}, "filters.ns"),
    ({"ns": "a" * 254}, "filters.ns"),
    ({"sev": "x" * 65}, "filters.sev"),
    ({"q": "x" * 501}, "filters.q"),
    ({"pod": "web\n0"}, "filters.pod"),
    ({"ctr": 5}, "filters.ctr"),
    ({"qmode": "regex"}, "filters.qmode"),
    ({"range": "2h"}, "filters.range"),
    ({"range": "1h", "from": "2026-10-01T00:00:00Z"}, "filters.range"),
    ({"from": "yesterday"}, "filters.from"),
    ({"from": "1999-12-31T00:00:00Z"}, "filters.from"),
    ({"from": "2026-10-02T00:00:00Z", "to": "2026-10-01T00:00:00Z"}, "filters.to"),
    ({"xns": "a,,b"}, "filters.xns"),
    ({"xpod": ",".join(f"p{i}" for i in range(51))}, "filters.xpod"),
    ({"xsev": ["error", 3]}, "filters.xsev"),
    ("ns=x", "filters"),
])
def test_unknown_filter_keys_and_bad_values_are_rejected(store, filters, field):
    with pytest.raises(ViewError) as exc:
        store.create({"name": "v", "filters": filters})
    assert exc.value.status == 422 and exc.value.field == field, exc.value
    assert store.list() == []


@pytest.mark.parametrize("body, field", [
    ({}, "name"),
    ({"name": ""}, "name"),
    ({"name": "   "}, "name"),
    ({"name": "x" * 81}, "name"),
    ({"name": 7}, "name"),
    ({"name": "v", "description": "d" * 501}, "description"),
    ({"name": "v", "pinned": "yes"}, "pinned"),
    ({"name": "v", "sort_order": 1.5}, "sort_order"),
    ({"name": "v", "sort_order": 2**40}, "sort_order"),
    ({"name": "v", "id": 3}, "id"),
    ({"name": "v", "created_at": "x"}, "created_at"),
])
def test_field_validation_and_limits(store, body, field):
    with pytest.raises(ViewError) as exc:
        store.create(body)
    assert exc.value.status == 422 and exc.value.field == field, exc.value


def test_validation_errors_are_422_with_the_field(server):
    status, body = _call(server, "POST", "/api/views", {"name": "v", "filters": {"bogus": "1"}})
    assert (status, body["field"]) == (422, "filters.bogus")
    vid = _call(server, "POST", "/api/views", {"name": "v"})[1]["view"]["id"]
    status, body = _call(server, "PATCH", f"/api/views/{vid}", {"filters": {"range": "2h"}})
    assert (status, body["field"]) == (422, "filters.range")
    status, body = _call(server, "PATCH", f"/api/views/{vid}", {"name": "x" * 81})
    assert (status, body["field"]) == (422, "name")
    assert _call(server, "GET", f"/api/views/{vid}")[1]["view"]["name"] == "v"


def test_size_and_count_limits(store):
    views = store
    assert views.create({"name": "n" * 80, "description": "d" * 500})["name"] == "n" * 80
    # 50 exclusions x 253 chars per key stays under the URL limits but not 8 KB.
    big = {key: ",".join(f"{i:02d}" + "x" * 251 for i in range(50)) for key in ("xns",)}
    assert len(big["xns"]) < 20000
    with pytest.raises(ViewError) as exc:
        views.create({"name": "big", "filters": big})
    assert exc.value.field == "filters" and "8192" in str(exc.value)
    views.create({"name": "fits", "filters": {"xns": ",".join(f"ns{i}" for i in range(50))}})
    for i in range(VIEWS_MAX - 2):
        views.create({"name": f"view {i}"})
    with pytest.raises(ViewError, match=f"At most {VIEWS_MAX}"):
        views.create({"name": "one too many"})
    assert len(views.list()) == VIEWS_MAX


def test_relative_and_absolute_ranges_round_trip(server):
    status, body = _call(server, "POST", "/api/views", {"name": "rel", "filters": {"range": "24h", "ns": "a"}})
    assert body["view"]["filters"] == {"range": "24h", "ns": "a"}  # stays relative: no from/to
    status, body = _call(server, "POST", "/api/views", {"name": "abs", "filters": {
        "from": "2026-10-01T12:00:00+02:00", "to": "2026-10-01T11:30:00.5Z",
    }})
    # Absolute bounds normalised to UTC, as the UI's URL carries them (toISOString).
    assert body["view"]["filters"] == {"from": "2026-10-01T10:00:00.000Z", "to": "2026-10-01T11:30:00.500Z"}
    status, body = _call(server, "POST", "/api/views", {"name": "open", "filters": {"from": "2026-10-01T10:00:00.000Z"}})
    assert body["view"]["filters"] == {"from": "2026-10-01T10:00:00.000Z"}
    # Defaults are left out like in the URL: today's range, phrase search.
    status, body = _call(server, "POST", "/api/views", {"name": "dflt", "filters": {
        "range": "today", "qmode": "phrase", "q": "timeout", "xns": "kube-system, monitoring,kube-system",
    }})
    assert body["view"]["filters"] == {"q": "timeout", "xns": "kube-system,monitoring"}
    stored = {v["name"]: v["filters"] for v in _call(server, "GET", "/api/views")[1]["views"]}
    assert stored["rel"] == {"range": "24h", "ns": "a"}
    assert stored["abs"]["from"] == "2026-10-01T10:00:00.000Z"


def test_origin_check_guards_every_write(monkeypatch, server):
    port = server.server_address[1]
    vid = _call(server, "POST", "/api/views", {"name": "mine"})[1]["view"]["id"]
    for method, path, body in (("POST", "/api/views", {"name": "evil"}),
                               ("PATCH", f"/api/views/{vid}", {"name": "evil"}),
                               ("DELETE", f"/api/views/{vid}", None),
                               ("POST", f"/api/views/{vid}/use", None)):
        for headers in ({"Origin": "https://evil.example"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}):
            assert _call(server, method, path, body, headers) == (403, {"error": "Cross-origin request rejected"})
    views = _call(server, "GET", "/api/views")[1]["views"]
    assert [(v["name"], v["last_used_at"]) for v in views] == [("mine", None)]
    # Same origin is accepted.
    status, _ = _call(server, "DELETE", f"/api/views/{vid}", headers={"Origin": f"http://127.0.0.1:{port}"})
    assert status == 200


def test_bodies_use_the_existing_request_limits(server, monkeypatch):
    from webapp.api import server as server_mod
    monkeypatch.setattr(server_mod, "_MAX_BODY_BYTES", 64)
    status, _ = _call(server, "POST", "/api/views", {"name": "x", "description": "d" * 100})
    assert status == 413
    status, _ = _request(server, "POST", "/api/views", body='{"name": "x"}', headers={"Content-Type": "text/plain"})
    assert status == 415


def test_wiping_the_cache_db_keeps_views(tmp_path):
    app = _app(tmp_path)
    srv = _serve(app)
    try:
        _call(srv, "POST", "/api/views", {"name": "keep me", "filters": {"ns": "a"}})
    finally:
        srv.shutdown()
        srv.server_close()
    app.storage.conn.close()
    for path in tmp_path.glob("cache.sqlite*"):
        path.unlink()
    srv = _serve(_app(tmp_path))
    try:
        views = _call(srv, "GET", "/api/views")[1]["views"]
        assert [(v["name"], v["filters"]) for v in views] == [("keep me", {"ns": "a"})]
        assert _call(srv, "GET", "/api/logs")[1]["items"] == []  # the cache really is new
    finally:
        srv.shutdown()
        srv.server_close()


# ─── dbtool --state ──────────────────────────────────────────────────────────


def test_dbtool_state_backup_verify_restore(tmp_path, monkeypatch, capsys):
    db = tmp_path / "live" / "state.sqlite"
    views = SavedViews(StateDB(db))
    views.create({"name": "before backup", "pinned": True})
    monkeypatch.setenv("LOGSCOPE_WEBAPP_STATE_DB_PATH", str(db))

    backup = tmp_path / "state-backup.sqlite"
    assert dbtool.main(["backup", "--state", str(backup)]) == 0  # --db from the env var
    assert _mode(backup) == 0o600
    assert dbtool.main(["verify", "--state", str(backup)]) == 0
    out = capsys.readouterr().out
    assert "'saved_views': 1" in out and f"'schema_version': {MIGRATIONS[-1][0]}" in out
    # The two kinds of database are not interchangeable.
    assert dbtool.main(["verify", str(backup)]) == 1
    assert "not a Logscope database" in capsys.readouterr().err

    views.create({"name": "after backup"})
    views._db.close()
    assert dbtool.main(["restore", "--state", str(backup), "--app-stopped"]) == 0
    assert _mode(db) == 0o600
    restored = SavedViews(StateDB(db))
    assert [v["name"] for v in restored.list()] == ["before backup"]
    kept = list(db.parent.glob("state.sqlite.pre-restore-*"))
    assert len(kept) == 1 and dbtool.verify(kept[0], state=True)["counts"]["saved_views"] == 2


def test_dbtool_state_refuses_a_cache_backup(tmp_path):
    app = _app(tmp_path)
    cache_backup = tmp_path / "cache-backup.sqlite"
    dbtool.backup(app.cfg.webapp.db_path, cache_backup)
    with pytest.raises(ValueError, match="not a Logscope state database"):
        dbtool.restore(app.cfg.webapp.state_db_path, cache_backup, state=True)
    assert dbtool.verify(app.cfg.webapp.state_db_path, state=True)["counts"]["saved_views"] == 0


def test_dbtool_state_defaults_to_the_xdg_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    StateDB(default_state_db_path()).close()
    assert dbtool.main(["backup", "--state", str(tmp_path / "b.sqlite")]) == 0
    assert str(tmp_path / "b.sqlite") in capsys.readouterr().out


# ─── Helm chart ──────────────────────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_chart_mounts_state_under_its_own_subpath():
    from test_helm_chart import BASE, _find, _helm, _merge

    docs, _ = _helm(BASE)
    pod = _find(docs, "Deployment", "logscope-webapp")["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["LOGSCOPE_WEBAPP_STATE_DB_PATH"] == "/state/state.sqlite"
    mounts = {m["mountPath"]: m for m in container["volumeMounts"]}
    assert mounts["/state"]["name"] == mounts["/data"]["name"] == "data"  # the existing PVC
    assert mounts["/state"]["subPath"] == "state" and "subPath" not in mounts["/data"]
    _, err = _helm(_merge(BASE, {"webapp": {"extraEnv": [{"name": "LOGSCOPE_WEBAPP_STATE_DB_PATH", "value": "x"}]}}),
                   expect_ok=False)
    assert "webapp.extraEnv must not set LOGSCOPE_WEBAPP_STATE_DB_PATH" in err


def test_conflict_and_not_found_are_distinct_errors(tmp_path):
    views = SavedViews(StateDB(tmp_path / "s.sqlite"))
    views.create({"name": "a"})
    with pytest.raises(ViewConflict):
        views.create({"name": "A"})
    assert issubclass(state_mod.ViewNotFound, ViewError)
    with pytest.raises(state_mod.ViewNotFound):
        views.update(12345, {"name": "b"})
    assert sqlite3.connect(tmp_path / "s.sqlite").execute("SELECT COUNT(*) FROM saved_views").fetchone()[0] == 1
