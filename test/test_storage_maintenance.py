"""Storage layout, full-text index migration from the legacy layout, and the
dbtool backup / restore / compact commands."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api import dbtool  # noqa: E402
from webapp.api.storage import LogStorage  # noqa: E402

# The records table exactly as created by the release before this change.
_LEGACY_RECORDS_DDL = """
CREATE TABLE records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity_bucket TEXT NOT NULL,
    scope TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod TEXT NOT NULL,
    container TEXT NOT NULL,
    message TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    source_key TEXT NOT NULL,
    source_etag TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    is_falco INTEGER NOT NULL DEFAULT 0,
    ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_key, source_etag, line_number)
)
"""

_WORDS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel")


def _row(i: int, day: int = 7) -> dict:
    ts = f"2026-09-{day:02d}T{i % 24:02d}:{i % 60:02d}:00Z"
    message = f"request {i} {_WORDS[i % len(_WORDS)]} status={500 if i % 5 == 0 else 200} payload={'x' * (i % 40)}"
    return {
        "timestamp": ts, "severity_bucket": "error" if i % 5 == 0 else "info", "scope": "infra",
        "namespace": f"ns{i % 3}", "pod": f"pod-{i % 4}", "container": "c", "message": message,
        "raw_line": f"{ts} - ns{i % 3} - pod-{i % 4}/c - {message}", "source_key": f"k/{day}/{i}",
        "source_etag": "e", "line_number": 1, "is_falco": 0,
    }


def _make_legacy_db(path: Path, rows: list[dict]) -> None:
    conn = sqlite3.connect(path)
    conn.execute(_LEGACY_RECORDS_DDL)
    conn.execute("CREATE VIRTUAL TABLE records_fts USING fts5(message, raw_line)")
    for r in rows:
        cur = conn.execute(
            "INSERT INTO records(timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,"
            " source_key, source_etag, line_number, is_falco) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["timestamp"], r["severity_bucket"], r["scope"], r["namespace"], r["pod"], r["container"],
             r["message"], r["raw_line"], r["source_key"], r["source_etag"], r["line_number"], r["is_falco"]),
        )
        conn.execute("INSERT INTO records_fts(rowid, message, raw_line) VALUES (?,?,?)",
                     (cur.lastrowid, r["message"], r["raw_line"]))
    conn.commit()
    conn.close()


def _search(storage: LogStorage, q: str) -> list[int]:
    return sorted(int(r["id"]) for r in storage.query_logs({"q": q}, limit=10_000)["items"])


def _used_bytes(conn: sqlite3.Connection) -> int:
    page = conn.execute("PRAGMA page_size").fetchone()[0]
    return (conn.execute("PRAGMA page_count").fetchone()[0] - conn.execute("PRAGMA freelist_count").fetchone()[0]) * page


def _fts_integrity(storage: LogStorage) -> None:
    # Raises if the index disagrees with the records table (external content).
    storage.conn.execute("INSERT INTO records_fts(records_fts) VALUES('integrity-check')")


QUERIES = ("bravo", "\"status=500\"", '"request 12"', "ns1", '"pod-3" AND golf', "echo OR hotel", "deltA", "fox*",
           "message : bravo", "raw_line : ns2")


def test_new_database_uses_external_content_index_wal_and_incremental_vacuum(tmp_path):
    storage = LogStorage(tmp_path / "new.sqlite")
    assert storage.fts_layout == "external" and storage.journal_mode == "wal"
    assert storage.conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
    storage.insert_records([_row(i) for i in range(200)])
    storage.insert_records([_row(i, day=1) for i in range(50)])
    before = _search(storage, "bravo")
    assert before and _search(storage, "ns2 AND hotel")
    _fts_integrity(storage)

    assert storage.prune_records_before("2026-09-05T00:00:00Z") == 50
    _fts_integrity(storage)                               # deletes kept the index consistent
    assert all(storage.get_record_by_id(i)["timestamp"].startswith("2026-09-07") for i in _search(storage, "bravo"))
    assert len(_search(storage, "bravo")) == len([i for i in range(200) if i % 8 == 1])


def test_legacy_index_is_migrated_in_the_background_without_losing_search(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _make_legacy_db(db, [_row(i) for i in range(3000)] + [_row(i, day=1) for i in range(500)])
    probe = sqlite3.connect(db)
    used_before = _used_bytes(probe)
    probe.close()

    storage = LogStorage(db)
    assert storage.fts_layout == "migrating"
    expected = {q: _search(storage, q) for q in QUERIES}     # served by the legacy index
    assert all(expected[q] for q in ("bravo", "\"status=500\"", "fox*"))

    # Partial progress survives a restart.
    assert storage.migrate_fts_step(batch=700) is False
    storage.conn.close()
    storage = LogStorage(db)
    assert storage.fts_layout == "migrating"
    assert int(storage.get_state("fts_migration_done")) > 0

    # Ingest and pruning keep working while the migration is half done.
    new_rows = [_row(i, day=8) for i in range(100)]
    storage.insert_records(new_rows)
    assert storage.prune_records_before("2026-09-05T00:00:00Z") == 500
    storage.migrate_fts_step(batch=700)

    used_peak = 0
    while not storage.migrate_fts_step(batch=700):
        used_peak = max(used_peak, _used_bytes(storage.conn))
    assert storage.fts_layout == "external"
    assert storage.get_state("fts_migration_done") is None
    assert "content=" in storage._table_sql("records_fts").replace(" ", "")
    assert storage._table_sql("records_fts_ext") is None
    _fts_integrity(storage)

    # Same answers as a brute-force scan of what is now in the table.
    for q in QUERIES:
        got = _search(storage, q)
        assert set(got) >= {i for i in expected[q] if storage.get_record_by_id(i)}, q
    all_ids = [r["id"] for r in storage.query_logs({}, limit=100_000)["items"]]
    bravo = [i for i in all_ids if "bravo" in storage.get_record_by_id(i)["raw_line"]]
    assert _search(storage, "bravo") == sorted(bravo)
    assert _search(storage, "request") == sorted(all_ids)       # pruned rows gone, new rows present

    # The migrated database stores each line's text once less.
    used_after = _used_bytes(storage.conn)
    print(f"\nused bytes: legacy={used_before} peak-during-migration={used_peak} migrated={used_after}")
    assert used_after < used_before * 0.8
    storage.conn.close()
    assert LogStorage(db).fts_layout == "external"


def test_backup_verify_restore_and_compact(tmp_path):
    db = tmp_path / "app.sqlite"
    storage = LogStorage(db)
    storage.insert_records([_row(i) for i in range(300)])
    storage.conn.execute("CREATE TABLE anomalies (id INTEGER PRIMARY KEY, status TEXT)")
    storage.conn.execute("INSERT INTO anomalies(status) VALUES ('reviewed')")
    storage.conn.commit()

    # Online backup while the app's connection stays open.
    report = dbtool.backup(db, tmp_path / "backup.sqlite")
    assert report["counts"] == {"records": 300, "ingested_objects": 0, "anomalies": 1}
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("backup")) == ["backup.sqlite"]
    with pytest.raises(ValueError, match="already exists"):
        dbtool.backup(db, tmp_path / "backup.sqlite")

    # Restore refuses while another connection is writing.
    storage.conn.execute("INSERT INTO anomalies(status) VALUES ('new')")
    assert storage.conn.in_transaction
    with pytest.raises(ValueError, match="in use"):
        dbtool.restore(db, tmp_path / "backup.sqlite")
    storage.conn.commit()
    storage.conn.close()

    restored = dbtool.restore(db, tmp_path / "backup.sqlite")
    assert restored["counts"]["anomalies"] == 1                 # back to the backup's state
    [kept] = [p for p in restored["previous_database_kept_as"] if p.endswith(".sqlite") or "pre-restore" in p][:1]
    assert dbtool.verify(Path(kept))["counts"]["anomalies"] == 2  # nothing deleted
    reopened = LogStorage(db)
    assert reopened.journal_mode == "wal" and _search(reopened, "bravo")
    reopened.conn.close()

    with pytest.raises(ValueError, match="Logscope database"):
        bad = tmp_path / "other.sqlite"
        sqlite3.connect(bad).execute("CREATE TABLE t (x)").connection.commit()
        dbtool.verify(bad)

    # compact: rebuilds an old (auto_vacuum=NONE) file with incremental auto-vacuum.
    old = tmp_path / "old.sqlite"
    _make_legacy_db(old, [_row(i) for i in range(500)])
    conn = sqlite3.connect(old)
    conn.execute(_LEGACY_RECORDS_DDL.replace("records", "app_state_dummy", 1))
    conn.execute("CREATE TABLE ingested_objects (x)")
    conn.execute("CREATE TABLE app_state (name TEXT PRIMARY KEY, value TEXT)")
    conn.execute("DELETE FROM records WHERE id > 100")
    conn.commit()
    conn.close()
    result = dbtool.compact(old)
    assert result["bytes_after"] < result["bytes_before"]
    assert sqlite3.connect(old).execute("PRAGMA auto_vacuum").fetchone()[0] == 2


def test_dbtool_cli_requires_explicit_confirmation_for_offline_commands(tmp_path, capsys):
    db = tmp_path / "app.sqlite"
    LogStorage(db).conn.close()
    with pytest.raises(SystemExit):
        dbtool.main(["--db", str(db), "compact"])                   # missing --app-stopped
    assert dbtool.main(["--db", str(db), "backup", str(tmp_path / "b.sqlite")]) == 0
    assert "integrity: ok" in capsys.readouterr().out
    assert dbtool.main(["verify", str(tmp_path / "missing.sqlite")]) == 1


class _FailOn:
    """Connection proxy that raises when a statement contains `needle`."""

    def __init__(self, conn, needle):
        self._conn, self._needle = conn, needle

    def execute(self, sql, *args):
        if self._needle in sql:
            raise sqlite3.OperationalError("simulated crash")
        return self._conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_index_swap_is_atomic_and_resumes_after_a_failure(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _make_legacy_db(db, [_row(i) for i in range(300)])
    storage = LogStorage(db)
    while storage.migrate_fts_step(batch=100) is False and storage.get_state("fts_migration_done") != "300":
        pass
    real = storage._conn
    storage._conn = _FailOn(real, "RENAME")
    with pytest.raises(sqlite3.OperationalError):
        storage.migrate_fts_step()                       # DROP ran, RENAME failed
    storage._conn = real
    # Rolled back: the legacy index is still there and still answers searches.
    assert storage._table_sql("records_fts") is not None and "content=" not in storage._table_sql("records_fts")
    assert storage._table_sql("records_fts_ext") is not None
    assert storage.fts_layout == "migrating" and _search(storage, "bravo")
    real.close()
    reopened = LogStorage(db)
    assert reopened.fts_layout == "migrating"
    while not reopened.migrate_fts_step():
        pass
    assert reopened.fts_layout == "external"
    _fts_integrity(reopened)
    assert len(_search(reopened, "bravo")) == len([i for i in range(300) if i % 8 == 1])


def test_migration_restarts_when_an_older_version_wrote_in_between(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _make_legacy_db(db, [_row(i) for i in range(200)])
    storage = LogStorage(db)
    storage.migrate_fts_step(batch=50)
    storage.conn.close()
    # Downgrade: the previous release inserts into the records table and its
    # own index only (no dual-write into the half-built one).
    conn = sqlite3.connect(db)
    r = _row(999, day=9)
    cur = conn.execute(
        "INSERT INTO records(timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,"
        " source_key, source_etag, line_number, is_falco) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (r["timestamp"], r["severity_bucket"], r["scope"], r["namespace"], r["pod"], r["container"],
         r["message"], r["raw_line"], r["source_key"], r["source_etag"], 1, 0))
    conn.execute("INSERT INTO records_fts(rowid, message, raw_line) VALUES (?,?,?)",
                 (cur.lastrowid, r["message"], r["raw_line"]))
    conn.commit()
    conn.close()

    upgraded = LogStorage(db)                            # detects the gap and starts over
    assert upgraded.get_state("fts_migration_done") == "0"
    assert int(upgraded.get_state("fts_migration_upper")) == 201
    while not upgraded.migrate_fts_step(batch=64):
        pass
    _fts_integrity(upgraded)
    assert _search(upgraded, "request") == list(range(1, 202))


def test_records_without_any_index_are_backfilled_and_searchable_meanwhile(tmp_path):
    db = tmp_path / "noindex.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(_LEGACY_RECORDS_DDL)
    for i in range(120):
        r = _row(i)
        conn.execute(
            "INSERT INTO records(timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,"
            " source_key, source_etag, line_number, is_falco) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["timestamp"], r["severity_bucket"], r["scope"], r["namespace"], r["pod"], r["container"],
             r["message"], r["raw_line"], r["source_key"], r["source_etag"], 1, 0))
    conn.commit()
    conn.close()

    storage = LogStorage(db)
    assert storage.fts_layout == "migrating" and storage.fts_search is False
    expected = [i + 1 for i in range(120) if i % 8 == 1]
    assert _search(storage, "bravo") == expected          # substring fallback, nothing missed
    storage.insert_records([_row(500, day=8)])
    while not storage.migrate_fts_step(batch=50):
        pass
    assert storage.fts_layout == "external" and storage.fts_search is True
    _fts_integrity(storage)
    assert _search(storage, "bravo") == expected
    assert len(_search(storage, "request")) == 121


# ─────────────────────────────────────────────────────────────────────────────
# Failure injection, batched pruning, downgrade and dbtool safety
# ─────────────────────────────────────────────────────────────────────────────

import json  # noqa: E402
import shutil  # noqa: E402
import threading  # noqa: E402


class _FailNth:
    """Connection proxy that raises on the nth statement containing `needle`."""

    def __init__(self, conn, needle, nth=1, error=sqlite3.OperationalError("database or disk is full")):
        self._conn, self._needle, self._left, self._error = conn, needle, nth, error

    def _check(self, sql):
        if self._needle in sql:
            self._left -= 1
            if self._left == 0:
                raise self._error

    def execute(self, sql, *args):
        self._check(sql)
        return self._conn.execute(sql, *args)

    def cursor(self):
        parent, real = self, self._conn.cursor()

        class _Cursor:
            def execute(self, sql, *args):
                parent._check(sql)
                return real.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(real, name)

        return _Cursor()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _insert_raw(conn, rows):
    for r in rows:
        conn.execute(
            "INSERT INTO records(timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,"
            " source_key, source_etag, line_number, is_falco) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["timestamp"], r["severity_bucket"], r["scope"], r["namespace"], r["pod"], r["container"],
             r["message"], r["raw_line"], r["source_key"], r["source_etag"], r["line_number"], r["is_falco"]))


def _make_unindexed_db(path, rows):
    conn = sqlite3.connect(path)
    conn.execute(_LEGACY_RECORDS_DDL)
    _insert_raw(conn, rows)
    conn.commit()
    conn.close()


def _check_all_indexes(storage):
    for name in ("records_fts", "records_fts_ext"):
        if storage._table_sql(name) is not None:
            storage.conn.execute(f"INSERT INTO {name}({name}) VALUES('integrity-check')")


def _oracle(storage, q):
    """What a correct, complete index answers for q over the current records."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE VIRTUAL TABLE o USING fts5(message, raw_line)")
    conn.executemany("INSERT INTO o(rowid, message, raw_line) VALUES (?,?,?)",
                     storage.conn.execute("SELECT id, message, raw_line FROM records").fetchall())
    ids = sorted(int(r[0]) for r in conn.execute("SELECT rowid FROM o WHERE o MATCH ?", (q,)))
    conn.close()
    return ids


def _layout_db(kind, path, rows):
    if kind == "external":
        storage = LogStorage(path)
        storage.insert_records(rows)
        return storage
    (_make_legacy_db if kind == "legacy" else _make_unindexed_db)(path, rows)
    storage = LogStorage(path)
    storage.migrate_fts_step(batch=len(rows) // 3)  # part-way through the backfill
    return storage


@pytest.mark.parametrize("kind", ["external", "legacy", "unindexed"])
def test_failed_insert_batch_is_rolled_back_in_every_layout(tmp_path, kind):
    storage = _layout_db(kind, tmp_path / "db.sqlite", [_row(i) for i in range(90)])
    before = storage.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    real = storage._conn
    needle = "INSERT INTO records_fts" if kind != "unindexed" else "INSERT INTO records_fts_ext"
    storage._conn = _FailNth(real, needle, nth=3)     # disk fills after two rows of the batch
    with pytest.raises(sqlite3.OperationalError):
        storage.insert_records([_row(i, day=2) for i in range(10)])
    storage._conn = real
    storage.set_prefix_cursor("p/", "k")               # an unrelated commit must not persist half a batch
    assert storage.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0] == before
    _check_all_indexes(storage)
    assert storage.insert_records([_row(i, day=2) for i in range(10)]) == 10   # retry inserts everything
    while not storage.migrate_fts_step(batch=40):
        pass
    _check_all_indexes(storage)
    for q in QUERIES:
        assert _search(storage, q) == _oracle(storage, q), q


@pytest.mark.parametrize("kind", ["external", "legacy", "unindexed"])
def test_batched_prune_keeps_every_layout_consistent(tmp_path, kind):
    storage = _layout_db(kind, tmp_path / "db.sqlite", [_row(i, day=1 + i % 9) for i in range(300)])
    storage.insert_records([_row(i, day=1 + i % 9) for i in range(300, 360)])   # dual-written rows
    removed = storage.prune_records_before("2026-09-05T00:00:00Z", batch=7)
    assert removed == sum(1 for i in range(360) if 1 + i % 9 < 5)
    assert storage.conn.execute("SELECT COUNT(*) FROM records WHERE timestamp < '2026-09-05'").fetchone()[0] == 0
    _check_all_indexes(storage)
    while not storage.migrate_fts_step(batch=50):
        pass
    assert storage.fts_layout == "external"
    _check_all_indexes(storage)
    for q in QUERIES:
        assert _search(storage, q) == _oracle(storage, q), q


def test_prune_failure_part_way_keeps_committed_batches_and_index_consistent(tmp_path):
    storage = LogStorage(tmp_path / "db.sqlite")
    storage.insert_records([_row(i, day=1 + i % 2) for i in range(100)])
    real = storage._conn
    storage._conn = _FailNth(real, "DELETE FROM records WHERE id IN", nth=2)
    with pytest.raises(sqlite3.OperationalError):
        storage.prune_records_before("2026-09-02T00:00:00Z", batch=10)
    storage._conn = real
    _check_all_indexes(storage)
    assert storage.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 90   # first batch only
    assert storage.prune_records_before("2026-09-02T00:00:00Z", batch=10) == 40
    _check_all_indexes(storage)


def test_search_matches_a_complete_index_at_every_migration_step(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _make_legacy_db(db, [_row(i, day=1 + i % 9) for i in range(900)])
    storage = LogStorage(db)
    expected_before = {q: _oracle(storage, q) for q in QUERIES}
    assert {q: _search(storage, q) for q in QUERIES} == expected_before
    step = 0
    while not storage.migrate_fts_step(batch=97):
        step += 1
        # Ingest and retention keep running during the backfill.
        storage.insert_records([_row(1000 + step * 10 + j, day=9) for j in range(10)])
        if step == 4:
            storage.prune_records_before("2026-09-02T00:00:00Z", batch=13)
        for q in QUERIES:
            assert _search(storage, q) == _oracle(storage, q), (step, q)
    assert storage.fts_layout == "external"
    _check_all_indexes(storage)
    for q in QUERIES:
        assert _search(storage, q) == _oracle(storage, q), q


def test_interrupted_backfill_step_resumes_without_gaps(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _make_legacy_db(db, [_row(i) for i in range(250)])
    storage = LogStorage(db)
    storage.migrate_fts_step(batch=100)
    real = storage._conn
    storage._conn = _FailNth(real, "INSERT INTO app_state")   # batch copied, progress not recorded
    with pytest.raises(sqlite3.OperationalError):
        storage.migrate_fts_step(batch=100)
    storage._conn = real
    assert storage.get_state("fts_migration_done") == "100"     # the copied batch was rolled back too
    real.close()
    reopened = LogStorage(db)                                   # restart
    assert reopened.fts_layout == "migrating" and reopened.get_state("fts_migration_done") == "100"
    while not reopened.migrate_fts_step(batch=100):
        pass
    _check_all_indexes(reopened)
    assert _search(reopened, "request") == list(range(1, 251))


def test_older_version_writing_after_the_swap_keeps_the_index_consistent(tmp_path):
    """Downgrade after a completed migration: the previous release inserts
    into records_fts by rowid and deletes from it before deleting records,
    which an external-content index handles correctly."""
    db = tmp_path / "app.sqlite"
    storage = LogStorage(db)
    storage.insert_records([_row(i) for i in range(100)])
    storage.conn.close()
    conn = sqlite3.connect(db)
    _insert_raw(conn, [_row(500 + i, day=9) for i in range(20)])
    conn.execute("INSERT INTO records_fts(rowid, message, raw_line) "
                 "SELECT id, message, raw_line FROM records WHERE id > 100")
    conn.execute("DELETE FROM records_fts WHERE rowid IN (SELECT id FROM records WHERE id <= 10)")
    conn.execute("DELETE FROM records WHERE id <= 10")
    conn.commit()
    conn.close()
    upgraded = LogStorage(db)
    assert upgraded.fts_layout == "external"
    _check_all_indexes(upgraded)
    for q in QUERIES:
        assert _search(upgraded, q) == _oracle(upgraded, q), q


def test_tail_restarts_from_the_end_when_the_database_was_replaced(tmp_path):
    storage = LogStorage(tmp_path / "db.sqlite")
    storage.insert_records([_row(i) for i in range(5)])
    res = storage.query_tail({}, after_id=10_000, limit=10)       # cursor from before a restore
    assert res == {"items": [], "last_id": 5, "truncated": False, "reset": True}
    storage.insert_records([_row(i, day=8) for i in range(2)])
    assert [r["id"] for r in storage.query_tail({}, after_id=res["last_id"], limit=10)["items"]] == [7, 6]


def test_status_reports_size_disk_and_migration_progress(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _make_legacy_db(db, [_row(i) for i in range(120)])
    storage = LogStorage(db)
    storage.migrate_fts_step(batch=50)
    info = storage.get_status()["storage"]
    assert info["fts_layout"] == "migrating" and info["fts_migration"]["rows_remaining"] == 70
    assert info["db_bytes"] > 0 and info["disk_free_bytes"] > 0 and info["disk_low"] in (True, False)
    assert "request" not in json.dumps(info)                      # sizes only, never row contents


def _populate_app_db(db):
    from webapp.api.insights import AnomalyStore

    storage = LogStorage(db)
    storage.insert_records([_row(i) for i in range(50)])
    storage.set_prefix_cursor("k3s-logs/logs/info/", "k3s-logs/logs/info/2026/09/07/x.gz")
    storage.mark_object("b", "k1", "e1", "2026-09-07T00:00:00Z", status="ok", record_count=3)
    storage.record_object_failure("b", "k2", "e2", prefix="k3s-logs/logs/info/",
                                  last_modified="2026-09-07T00:00:00Z", error="timeout")
    storage.ingest_state(last_poll_at="2026-09-07T00:00:00Z", last_successful_ingest_at="2026-09-07T00:00:00Z",
                         last_object_last_modified=None)
    store = AnomalyStore(db)
    anomaly_id = store.upsert_anomaly(type="error_rate_spike", namespace="app", pod="", rule_key="",
                                      severity="error", evidence={"window_start": "2026-09-07T10:00:00Z"},
                                      detected_day="2026-09-07")
    store.save_ai_summary(anomaly_id, "summary", "action", [{"title": "t", "command": "kubectl get pods"}])
    store.set_status(anomaly_id, "reviewed")
    return storage, store


_STATE_TABLES = ("records", "ingested_objects", "prefix_state", "app_state", "object_failures", "anomalies")


def _snapshot(db):
    conn = sqlite3.connect(db)
    try:
        return {t: conn.execute(f"SELECT * FROM {t} ORDER BY 1, 2").fetchall() for t in _STATE_TABLES}
    finally:
        conn.close()


def test_backup_and_restore_preserve_all_state_tables(tmp_path):
    db = tmp_path / "app.sqlite"
    storage, store = _populate_app_db(db)
    dbtool.backup(db, tmp_path / "b.sqlite")
    expected = _snapshot(tmp_path / "b.sqlite")
    assert expected == _snapshot(db) and all(expected[t] for t in _STATE_TABLES)
    storage.insert_records([_row(i, day=8) for i in range(5)])
    store.set_status(1, "dismissed")
    storage.conn.close()
    store._conn.close()
    dbtool.restore(db, tmp_path / "b.sqlite")
    assert _snapshot(db) == expected
    reopened = LogStorage(db)                                       # the app opens it as usual
    assert reopened.fts_layout == "external"
    _check_all_indexes(reopened)


def test_backup_never_replaces_a_file_that_appears_during_the_copy(tmp_path, monkeypatch):
    db = tmp_path / "app.sqlite"
    LogStorage(db).insert_records([_row(i) for i in range(10)])
    dest = tmp_path / "b.sqlite"
    real_copy = dbtool._copy_database

    def copy_then_race(src, out):
        real_copy(src, out)
        dest.write_bytes(b"someone else's backup")

    monkeypatch.setattr(dbtool, "_copy_database", copy_then_race)
    with pytest.raises(ValueError, match="already exists"):
        dbtool.backup(db, dest)
    assert dest.read_bytes() == b"someone else's backup"
    assert not (tmp_path / "b.sqlite.partial").exists()


def test_failed_restore_leaves_the_current_database_untouched(tmp_path, monkeypatch):
    db = tmp_path / "app.sqlite"
    storage, store = _populate_app_db(db)
    dbtool.backup(db, tmp_path / "b.sqlite")
    storage.insert_records([_row(i, day=8) for i in range(5)])
    storage.conn.close()
    store._conn.close()
    before = _snapshot(db)

    def disk_full(src, out):
        out.write_bytes(b"partial")
        out.unlink()
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(dbtool, "_copy_database", disk_full)
    with pytest.raises(sqlite3.OperationalError):
        dbtool.restore(db, tmp_path / "b.sqlite")
    monkeypatch.undo()
    assert _snapshot(db) == before
    assert sorted(p.name for p in tmp_path.iterdir() if "pre-restore" in p.name or "partial" in p.name) == []

    monkeypatch.setattr(dbtool.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10**9, 10**9, 1024))
    with pytest.raises(ValueError, match="not enough free space"):
        dbtool.restore(db, tmp_path / "b.sqlite")
    with pytest.raises(ValueError, match="not enough free space"):
        dbtool.backup(db, tmp_path / "c.sqlite")
    assert _snapshot(db) == before and not (tmp_path / "c.sqlite").exists()


def test_repeated_restores_keep_every_previous_database(tmp_path):
    db = tmp_path / "app.sqlite"
    LogStorage(db).insert_records([_row(i) for i in range(10)]) or None
    dbtool.backup(db, tmp_path / "b.sqlite")
    first = dbtool.restore(db, tmp_path / "b.sqlite")["previous_database_kept_as"]
    second = dbtool.restore(db, tmp_path / "b.sqlite")["previous_database_kept_as"]
    third = dbtool.restore(db, tmp_path / "b.sqlite")["previous_database_kept_as"]
    names = [p for kept in (first, second, third) for p in kept if not p.endswith(("-wal", "-shm"))]
    assert len(set(names)) == 3 and all(Path(p).is_file() for p in names)
    for p in names:
        assert dbtool.verify(Path(p))["counts"]["records"] == 10
    assert not any(Path(f"{db}{s}").exists() for s in ("-wal", "-shm"))


def test_online_backup_while_ingest_writes_is_consistent(tmp_path):
    db = tmp_path / "app.sqlite"
    storage = LogStorage(db)
    storage.insert_records([_row(i) for i in range(200)])
    stop = threading.Event()

    def writer():
        n = 0
        while not stop.is_set():
            storage.insert_records([_row(10_000 + n, day=8)])
            n += 1

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        report = dbtool.backup(db, tmp_path / "b.sqlite")
    finally:
        stop.set()
        thread.join()
    assert report["integrity"] == "ok" and report["counts"]["records"] >= 200
    copy = LogStorage(tmp_path / "b.sqlite")
    _check_all_indexes(copy)
