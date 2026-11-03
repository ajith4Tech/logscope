"""The hourly rollup (counts_hourly) and the read pool.

Property: after any sequence of ingests, prunes, ts_epoch backfills and a
resumable rebuild, the rollup equals the counts of the raw rows.
Equivalence: every endpoint the rollup serves returns exactly what the raw
path returns, over aligned and unaligned ranges, filters and exclusions."""

from __future__ import annotations

import random
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp.api.storage import LogStorage, iso_from_epoch  # noqa: E402

T0 = datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc).timestamp()
NAMESPACES = ("app", "billing", "kube-system", "user-a")
PODS = ("web-0", "web-1", "db-0", "api-x")
SEVERITIES = ("error", "warning", "info", "debug", "metrics")
_seq = {"n": 0}


def _record(rng: random.Random, epoch: float) -> dict:
    _seq["n"] += 1
    ns = rng.choice(NAMESPACES)
    fmt = rng.random()
    moment = datetime.fromtimestamp(epoch, timezone.utc)
    if fmt < 0.7:
        ts = moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    elif fmt < 0.85:
        ts = (moment + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.%f+05:30")
    else:
        ts = moment.strftime("%Y-%m-%dT%H:%M:%S.%f")  # no zone
    return {"timestamp": ts, "severity_bucket": rng.choice(SEVERITIES),
            "scope": "infra" if ns == "kube-system" else f"namespaces/{ns}", "namespace": ns,
            "pod": rng.choice(PODS), "container": rng.choice(("main", "sidecar")),
            "message": f"m{rng.randrange(20)} request failed", "raw_line": "r", "source_key": f"k{_seq['n']}",
            "source_etag": "e", "line_number": 1, "is_falco": 0}


def _raw_counts(storage: LogStorage) -> dict:
    rows = storage.conn.execute(
        "SELECT CAST(ts_epoch / 3600 AS INTEGER) * 3600, scope, namespace, pod, container, severity_bucket, COUNT(*) "
        "FROM records WHERE ts_epoch IS NOT NULL GROUP BY 1, 2, 3, 4, 5, 6").fetchall()
    return {tuple(r[:6]): r[6] for r in rows}


def _rollup(storage: LogStorage) -> dict:
    rows = storage.conn.execute("SELECT hour_epoch, scope, namespace, pod, container, severity, n "
                                "FROM counts_hourly").fetchall()
    return {tuple(r[:6]): r[6] for r in rows}


def _ingest(storage: LogStorage, rng: random.Random, n: int, span_hours: float = 60) -> None:
    storage.insert_records([_record(rng, T0 + rng.random() * span_hours * 3600) for _ in range(n)])


@pytest.mark.parametrize("seed", range(8))
def test_rollup_equals_raw_counts_after_random_operations(tmp_path, seed):
    rng = random.Random(seed)
    db = tmp_path / "w.sqlite"
    storage = LogStorage(db)
    _ingest(storage, rng, 300)
    # Half the runs start from a database written before the rollup existed,
    # with some rows also still waiting for their ts_epoch.
    if seed % 2:
        storage.conn.execute("DROP TABLE counts_hourly")
        storage.conn.execute("UPDATE records SET ts_epoch = NULL WHERE id % 7 = 0")
        storage.conn.commit()
        storage.close()
        storage = LogStorage(db)
        assert not storage.rollup_ready and storage.ts_backfill_pending
    cutoff = T0
    for _ in range(40):
        op = rng.random()
        if op < 0.35:
            _ingest(storage, rng, rng.randrange(1, 80))
        elif op < 0.55:
            cutoff += rng.random() * 4 * 3600
            storage.prune_records_before(cutoff, batch=rng.choice((7, 50, 5000)))
        elif op < 0.75:
            storage.backfill_ts_step(batch=rng.choice((3, 20, 100)))
        else:
            storage.rebuild_rollup_step(batch=rng.choice((5, 40, 200)))
        if storage.rollup_ready:
            assert _rollup(storage) == _raw_counts(storage)
    while storage.backfill_ts_step(batch=50):
        pass
    while not storage.rebuild_rollup_step(batch=50):
        pass
    assert storage.rollup_ready and _rollup(storage) == _raw_counts(storage)
    assert all(n > 0 for n in _rollup(storage).values())
    # Reopening checks the totals and keeps a consistent rollup as it is.
    storage.close()
    storage = LogStorage(db)
    assert storage.rollup_ready and _rollup(storage) == _raw_counts(storage)


def test_rows_written_without_the_rollup_trigger_a_rebuild(tmp_path):
    """A downgrade writes rows without updating counts_hourly: the next start
    notices the totals differ and rebuilds."""
    rng = random.Random(3)
    db = tmp_path / "w.sqlite"
    storage = LogStorage(db)
    _ingest(storage, rng, 100)
    storage.close()
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO records (timestamp, ts_epoch, severity_bucket, scope, namespace, pod, container, "
                 "message, raw_line, source_key, source_etag, line_number) VALUES "
                 "('2026-10-18T05:00:00Z', ?, 'info', 'infra', 'kube-system', 'p', 'c', 'm', 'r', 'old', 'e', 1)",
                 (T0 + 5 * 3600,))
    conn.commit()
    conn.close()
    storage = LogStorage(db)
    assert not storage.rollup_ready
    while not storage.rebuild_rollup_step(batch=30):
        pass
    assert _rollup(storage) == _raw_counts(storage)


# ─── equivalence with the raw path ───────────────────────────────────────────


@pytest.fixture(scope="module")
def fixture_storage(tmp_path_factory):
    rng = random.Random(42)
    storage = LogStorage(tmp_path_factory.mktemp("rollup") / "w.sqlite")
    for _ in range(10):
        _ingest(storage, rng, 400, span_hours=72)
    assert storage.rollup_ready
    return storage


def _both(storage: LogStorage, fn):
    storage.use_rollup = False
    try:
        raw = fn()
    finally:
        storage.use_rollup = True
    return raw, fn()


def _ranges(rng: random.Random):
    yield {}
    yield {"start": iso_from_epoch(T0 + 3600 * 5), "before": iso_from_epoch(T0 + 3600 * 29)}   # aligned
    yield {"start": iso_from_epoch(T0 + 3600 * 5), "end": iso_from_epoch(T0 + 3600 * 29)}      # inclusive end
    yield {"start": iso_from_epoch(T0 + 1234.5)}                                                # open end
    yield {"before": iso_from_epoch(T0 + 3600 * 40 + 17)}                                       # open start
    for _ in range(12):
        a = T0 + rng.random() * 72 * 3600
        b = a + rng.random() * 72 * 3600
        key = rng.choice(("before", "end"))
        yield {"start": iso_from_epoch(a), key: iso_from_epoch(b)}


def _filters(rng: random.Random):
    yield {}
    yield {"namespace": "app"}
    yield {"severity_bucket": "error", "xns": ["billing"]}
    yield {"pod": "web-0", "container": "main"}
    yield {"xsev": ["info", "debug"], "xpod": ["db-0"]}
    yield {"scope": "infra"}
    yield {"namespace": rng.choice(NAMESPACES), "q": "failed"}   # a search: raw path on both sides


def test_histogram_fields_dashboard_alerts_and_backtest_match_the_raw_path(fixture_storage):
    storage = fixture_storage
    rng = random.Random(7)
    now = datetime.fromtimestamp(T0 + 80 * 3600, timezone.utc)
    checked = 0
    for time_range in _ranges(rng):
        for filters in _filters(rng):
            params = {**time_range, **filters}
            raw, rolled = _both(storage, lambda p=params: storage.query_histogram(p, now=now))
            assert raw == rolled, params
            raw, rolled = _both(storage, lambda p=params: storage.query_fields(p))
            assert raw == rolled, params
            raw, rolled = _both(storage, lambda p=params: storage.query_dashboard(p))
            assert raw == rolled, params
            for metric in ("count", "error_count", "distinct_pods"):
                for group_by in ("none", "namespace", "pod"):
                    for lowest in (False, True):
                        raw, rolled = _both(storage, lambda p=params, m=metric, g=group_by, lo=lowest:
                                            storage.alert_metric(p, metric=m, group_by=g, max_groups=3,
                                                                 lowest_first=lo))
                        assert raw == rolled, (params, metric, group_by, lowest)
            checked += 1
    assert checked >= 100
    for filters in _filters(rng):
        for start, end, size in ((T0, T0 + 72 * 3600, 3600), (T0 + 7200, T0 + 50 * 3600, 21600),
                                 (T0 + 600, T0 + 30 * 3600, 3600), (T0, T0 + 24 * 3600, 60)):
            for pods in (False, True):
                raw, rolled = _both(storage, lambda f=filters, a=int(start), b=int(end), s=size, p=pods:
                                    storage.metric_series(f, start_epoch=a, end_epoch=b, bucket_secs=s, pods=p))
                assert raw == rolled, (filters, start, end, size, pods)


def test_rollup_is_used_for_whole_hours_only(fixture_storage):
    storage = fixture_storage
    hour = {"start": iso_from_epoch(T0 + 3600), "before": iso_from_epoch(T0 + 3 * 3600)}
    assert storage._grouped_counts(hour, ["namespace"]) is not None
    inside = {"start": iso_from_epoch(T0 + 3700), "before": iso_from_epoch(T0 + 7100)}
    assert storage._grouped_counts(inside, ["namespace"]) is None          # no whole hour: raw
    assert storage._grouped_counts({**hour, "q": "x"}, ["namespace"]) is None
    storage.use_rollup = False
    assert storage._grouped_counts(hour, ["namespace"]) is None
    storage.use_rollup = True


def test_read_pool_serves_reads_while_a_write_holds_the_lock(tmp_path):
    storage = LogStorage(tmp_path / "w.sqlite")
    _ingest(storage, random.Random(1), 50)
    assert storage._pool is not None and storage._pool.qsize() == 4
    storage.optimize(analyze=True)  # new statistics: pooled connections are replaced as they return
    assert storage.query_logs({}, limit=1)["items"] and storage._pool.qsize() == 4
    got = {}
    with storage._lock:  # e.g. a long ingest batch on the writer connection
        thread = threading.Thread(target=lambda: got.update(storage.query_logs({}, limit=5)))
        thread.start()
        thread.join(timeout=10)
    assert not thread.is_alive() and len(got["items"]) == 5
    # One snapshot per call: max_id and items agree even while rows are added.
    assert storage.query_logs({}, limit=1000)["max_id"] == max(r["id"] for r in storage.query_logs({}, limit=1000)["items"])


def test_without_a_pool_reads_use_the_shared_connection(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSCOPE_SQLITE_READERS", "0")
    storage = LogStorage(tmp_path / "w.sqlite")
    assert storage._pool is None
    _ingest(storage, random.Random(2), 20)
    assert len(storage.query_logs({}, limit=50)["items"]) == 20
    delete_mode = LogStorage(tmp_path / "d.sqlite", journal_mode="delete")
    monkeypatch.delenv("LOGSCOPE_SQLITE_READERS")
    assert LogStorage(tmp_path / "d2.sqlite", journal_mode="delete")._pool is None and delete_mode._pool is None


def test_insights_detection_is_identical_with_and_without_the_rollup(tmp_path):
    from webapp.api.config import load_app_config
    from webapp.api.insights import InsightsDetector
    from webapp.api.storage import open_connection

    rng = random.Random(9)
    storage = LogStorage(tmp_path / "w.sqlite")
    now = datetime(2026, 10, 26, 12, 40, tzinfo=timezone.utc)
    start = now.timestamp() - 8 * 86400
    batch = []
    for _ in range(6000):
        batch.append(_record(rng, start + rng.random() * (8 * 86400 - 1800)))
    for i in range(400):  # a spike of one message in the last hour and the current one
        rec = _record(rng, now.timestamp() - rng.random() * 5000)
        rec.update(severity_bucket="error", namespace="billing", scope="namespaces/billing",
                   message=f"payment gateway timeout after {i} ms")
        batch.append(rec)
    for _ in range(30):  # a new Falco rule
        rec = _record(rng, now.timestamp() - rng.random() * 3000)
        rec.update(scope="security", namespace="falco", is_falco=1,
                   message="Terminal shell in container: 12:00:00.123456789: Warning shell | user=root")
        batch.append(rec)
    storage.insert_records(batch)
    storage.conn.execute("DELETE FROM records WHERE id % 97 = 0 AND ts_epoch < ?", (start + 86400 * 3,))
    storage.conn.commit()  # a gap: hours with no data in the baseline
    cfg = load_app_config(ROOT / "test" / "fixtures" / "config.test.yaml").insights
    results = {}
    for use in (False, True):
        storage2 = LogStorage(tmp_path / "w.sqlite")  # reopen: rollup totals are re-checked (the delete above)
        while not storage2.rebuild_rollup_step():
            pass
        detector = InsightsDetector(open_connection(tmp_path / "w.sqlite"), cfg)
        detector.use_rollup = use
        found = detector.detect_all(now)
        assert detector._rollup is use
        results[use] = (sorted(found, key=lambda a: (a["type"], a["namespace"], a["pod"], a["rule_key"])),
                        detector._hours_with_data(datetime.fromtimestamp(start + 1234, timezone.utc), now))
    assert results[True] == results[False]
    assert {a["type"] for a in results[True][0]} >= {"error_rate_spike", "new_falco_rule"}
