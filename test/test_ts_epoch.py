"""records.ts_epoch: every time filter, ordering, bucket, window and prune
works on UTC epoch seconds, whatever format or zone the line's timestamp
has. Covers fractional seconds, +05:30 offsets, mixed formats at hour
boundaries, pruning of non-UTC timestamps, the S3-object-time fallback (and
its /api/status count) and the resumable backfill of older databases."""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from test_webapp import FakeS3, _buffer  # noqa: E402

from webapp.api.config import load_app_config  # noqa: E402
from webapp.api.ingest import S3Ingestor  # noqa: E402
from webapp.api.insights import InsightsDetector  # noqa: E402
from webapp.api.storage import LogStorage, decode_cursor, to_epoch  # noqa: E402

CONFIG = ROOT / "test" / "fixtures" / "config.test.yaml"


def _epoch(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def _store(tmp_path, timestamps: list[str], **extra) -> LogStorage:
    storage = LogStorage(tmp_path / "w.sqlite")
    storage.insert_records([
        {"timestamp": ts, "severity_bucket": "info", "scope": "infra", "namespace": "ns", "pod": "p",
         "container": "c", "message": f"m{i}", "raw_line": f"{ts} - ns - p/c - m{i}", "source_key": "k",
         "source_etag": "e", "line_number": i + 1, "is_falco": 0, **extra}
        for i, ts in enumerate(timestamps)
    ])
    return storage


def _messages(storage: LogStorage, **params) -> list[str]:
    return [r["message"] for r in storage.query_logs(params, limit=100, direction="asc")["items"]]


@pytest.mark.parametrize("text, expected", [
    ("2026-10-21T06:00:00Z", _epoch(2026, 10, 21, 6)),
    ("2026-10-21T06:00:00.250Z", _epoch(2026, 10, 21, 6) + 0.25),
    ("2026-10-21T06:00:00.123456789Z", _epoch(2026, 10, 21, 6, 0, 0, 123456)),   # Vector nanoseconds
    ("2026-10-21T06:00:00,5Z", _epoch(2026, 10, 21, 6) + 0.5),
    ("2026-10-21T11:30:00+05:30", _epoch(2026, 10, 21, 6)),
    ("2026-10-21T11:30:00.75+0530", _epoch(2026, 10, 21, 6) + 0.75),
    ("2026-10-21T01:00:00-05:00", _epoch(2026, 10, 21, 6)),
    ("2026-10-21T08:00:00+02", _epoch(2026, 10, 21, 6)),
    ("2026-10-21 06:00:00", _epoch(2026, 10, 21, 6)),                            # no zone: UTC
    ("2026-10-21T06:00", _epoch(2026, 10, 21, 6)),
    ("2026-10-21", _epoch(2026, 10, 21)),
    ("2026-10-21T06:00:00 UTC", _epoch(2026, 10, 21, 6)),
    ("not a time", None),
    ("2026-13-01T00:00:00Z", None),
    ("2026-10-21T06:00:60Z", None),
    ("2026-10-21T06:00:00+25:00", None),
    ("", None),
])
def test_to_epoch(text, expected):
    assert to_epoch(text) == expected


def test_fractional_seconds_order_and_filter_by_instant(tmp_path):
    # As text, "06:00:00Z" sorts after "06:00:00.5Z" ('Z' > '.'); in time it is first.
    storage = _store(tmp_path, ["2026-10-21T06:00:00.5Z", "2026-10-21T06:00:00Z", "2026-10-21T06:00:00.123456789Z"])
    assert _messages(storage) == ["m1", "m2", "m0"]
    assert _messages(storage, start="2026-10-21T06:00:00.200Z") == ["m0"]
    assert _messages(storage, before="2026-10-21T06:00:00.200Z") == ["m1", "m2"]
    assert _messages(storage, end="2026-10-21T06:00:00.123456Z") == ["m1", "m2"]   # inclusive end
    # Paging steps through equal-second records by instant, then id.
    page = storage.query_logs({}, limit=1)
    assert [r["message"] for r in page["items"]] == ["m0"]
    rest = storage.query_logs({}, limit=10, cursor=decode_cursor(page["next_cursor"]))
    assert [r["message"] for r in rest["items"]] == ["m2", "m1"]


def test_offsets_are_compared_as_instants(tmp_path):
    storage = _store(tmp_path, [
        "2026-10-21T11:29:59+05:30",   # 05:59:59Z: inside [05:45, 06:00) although its text says 11:29
        "2026-10-21T05:30:00Z",
        "2026-10-21T00:50:00-05:00",   # 05:50Z
        "2026-10-21T11:30:00+05:30",   # 06:00Z: outside
    ])
    assert _messages(storage, start="2026-10-21T05:45:00Z", before="2026-10-21T06:00:00Z") == ["m2", "m0"]
    assert _messages(storage, start="2026-10-21T11:15:00+05:30", before="2026-10-21T11:30:00+05:30") == ["m2", "m0"]
    hist = storage.query_histogram({"start": "2026-10-21T05:00:00Z", "before": "2026-10-21T07:00:00Z"})
    by_time = {b["t"]: b["total"] for b in hist["buckets"] if b["total"]}
    assert hist["bucket_secs"] == 300
    assert by_time == {"2026-10-21T05:30:00Z": 1, "2026-10-21T05:50:00Z": 1, "2026-10-21T05:55:00Z": 1,
                       "2026-10-21T06:00:00Z": 1}
    record_id = storage.query_logs({"start": "2026-10-21T05:59:00Z", "before": "2026-10-21T06:00:00Z"},
                                   limit=1)["items"][0]["id"]
    context = storage.query_context(record_id, lines_before=5, lines_after=5)
    assert [r["message"] for r in context["before"]] == ["m1", "m2"]
    assert [r["message"] for r in context["after"]] == ["m3"]
    assert context["bounds"]["from"] == "2026-10-20T23:59:59.000Z"   # 6 h before 05:59:59Z


def test_mixed_formats_at_hour_boundaries(tmp_path):
    storage = _store(tmp_path, [
        "2026-10-21T05:59:59.999Z",
        "2026-10-21 06:00:00",                  # no zone: UTC
        "2026-10-21T07:00:00+01:00",            # 06:00Z
        "2026-10-21T06:59:59.999999999Z",
        "2026-10-21T02:00:00-05:00",            # 07:00Z
        "2026-10-21T12:29:59.5+05:30",          # 06:59:59.5Z
    ], severity_bucket="error")
    hour = {"start": "2026-10-21T06:00:00Z", "before": "2026-10-21T07:00:00Z"}
    assert sorted(_messages(storage, **hour)) == ["m1", "m2", "m3", "m5"]
    timeline = {t["timestamp"]: t["total_logs"] for t in storage.query_dashboard({})["timeline"]}
    assert timeline == {"2026-10-21T05:00:00Z": 1, "2026-10-21T06:00:00Z": 4, "2026-10-21T07:00:00Z": 1}
    alert = storage.alert_metric({**hour, "end": "2026-10-21T06:59:59.999Z"}, metric="error_count")
    assert alert["groups"] == {"": 3.0}                     # inclusive end at .999: the .999999 one is past it
    assert storage.metric_series({}, start_epoch=int(_epoch(2026, 10, 21, 5)),
                                 end_epoch=int(_epoch(2026, 10, 21, 8)), bucket_secs=3600) == {
        0: (1, 1), 1: (4, 4), 2: (1, 1)}
    # Insights windows and baselines count by instant too.
    detector = InsightsDetector(storage.conn, load_app_config(CONFIG).insights)
    counts = detector._counts(datetime(2026, 10, 21, 6, tzinfo=timezone.utc),
                              datetime(2026, 10, 21, 7, tzinfo=timezone.utc), ("namespace",))
    assert counts == {("ns",): 4}
    assert detector._first_record_time() == datetime(2026, 10, 21, 5, 59, 59, 999000, tzinfo=timezone.utc)
    assert detector.future_record_count(datetime(2026, 10, 21, 6, 50, tzinfo=timezone.utc)) == 3   # after 06:55


def test_pruning_non_utc_timestamps(tmp_path):
    storage = _store(tmp_path, [
        "2026-09-05T01:00:00+05:30",    # 2026-09-04T19:30Z: older than the cutoff (text says the 5th, 01:00)
        "2026-09-04T20:00:00-05:00",    # 2026-09-05T01:00Z: newer (text says the 4th)
        "2026-09-04T23:59:59.999Z",
        "2026-09-05T00:00:00Z",         # at the cutoff: kept
    ])
    assert storage.prune_records_before("2026-09-05T00:00:00Z", batch=1) == 2
    assert _messages(storage) == ["m3", "m1"]
    assert storage.prune_records_before(_epoch(2026, 9, 5, 0, 30)) == 1     # epoch cutoffs work too
    assert _messages(storage) == ["m1"]


def test_unparseable_timestamp_uses_the_object_time_and_is_counted(tmp_path):
    cfg = load_app_config(CONFIG)
    storage = LogStorage(tmp_path / "w.sqlite")
    key = "k3s-logs/logs/info/2026/09/07/00_00_00_a.gz"
    body = "\n".join([
        "2026-09-06T23:00:00+02:00 - app - web-0/nginx - zoned",
        "yesterday-ish - app - web-0/nginx - no usable time",
    ])
    ingestor = S3Ingestor(cfg, storage)
    ingestor.client = FakeS3([{"Key": key, "ETag": '"e1"', "LastModified": "2026-09-07T00:05:00Z"}], {key: _buffer(body)})
    assert ingestor.ingest_once().records_ingested == 2
    rows = {r["message"]: r for r in storage.query_logs({}, limit=10)["items"]}
    assert rows["zoned"]["ts_epoch"] == _epoch(2026, 9, 6, 21)
    assert rows["no usable time"]["ts_epoch"] == _epoch(2026, 9, 7, 0, 5)
    assert rows["no usable time"]["timestamp"] == "yesterday-ish"            # the text is kept as written
    assert storage.get_status()["timestamp_fallbacks"] == 1
    ingestor.ingest_once()                                                  # nothing new: not counted again
    assert storage.get_status()["timestamp_fallbacks"] == 1


def _legacy_db(path: Path, rows: list[tuple[str, str]]) -> None:
    """A cache written before ts_epoch existed (with the old text indexes)."""
    storage = LogStorage(path)
    storage.insert_records([
        {"timestamp": ts, "severity_bucket": "info", "scope": "infra", "namespace": "ns", "pod": "p",
         "container": "c", "message": msg, "raw_line": msg, "source_key": "k", "source_etag": "e",
         "line_number": i + 1, "is_falco": 0}
        for i, (ts, msg) in enumerate(rows)
    ])
    storage.mark_object("bucket", "k", "e", "2026-09-07T00:05:00Z", status="ok", record_count=len(rows))
    storage.conn.execute("UPDATE records SET ts_epoch = NULL")
    storage.conn.execute("DELETE FROM app_state WHERE name = 'ts_fallback_count'")
    storage.conn.execute("CREATE INDEX idx_records_ts_ns ON records(timestamp, namespace)")
    storage.conn.commit()
    storage.conn.close()


def test_backfill_runs_in_resumable_batches(tmp_path):
    db = tmp_path / "legacy.sqlite"
    rows = [(f"2026-09-07T{i:02d}:00:00+05:30", f"m{i}") for i in range(12)] + [("garbage", "bad")]
    _legacy_db(db, rows)
    storage = LogStorage(db)
    assert storage.ts_backfill_pending
    assert "idx_records_ts_ns" not in {r[0] for r in storage.conn.execute("SELECT name FROM sqlite_master")}
    assert storage.get_status()["storage"]["ts_backfill"]["rows_remaining"] == 13
    assert _messages(storage, start="2026-09-06T00:00:00Z") == []          # not visible to time filters yet
    assert storage.backfill_ts_step(batch=5) == 5
    storage.conn.close()

    storage = LogStorage(db)                                                # restart: resumes, not restarts
    assert storage.ts_backfill_remaining() == 8
    assert storage.backfill_ts_step(batch=5) == 5
    assert storage.backfill_ts_step(batch=5) == 3
    assert storage.backfill_ts_step(batch=5) == 0 and not storage.ts_backfill_pending
    assert "ts_backfill" not in storage.get_status()["storage"]
    epochs = {r["message"]: r["ts_epoch"] for r in storage.query_logs({}, limit=100)["items"]}
    assert epochs["m6"] == _epoch(2026, 9, 7, 0, 30)
    assert epochs["bad"] == _epoch(2026, 9, 7, 0, 5)                        # its S3 object's time
    assert storage.get_status()["timestamp_fallbacks"] == 1
    assert len(_messages(storage, start="2026-09-06T00:00:00Z")) == 13


def test_prune_finishes_a_pending_backfill_first(tmp_path):
    db = tmp_path / "legacy.sqlite"
    _legacy_db(db, [("2026-09-01T00:00:00Z", "old"), ("2026-09-09T00:00:00Z", "new")])
    storage = LogStorage(db)
    assert storage.prune_records_before("2026-09-05T00:00:00Z") == 1
    assert _messages(storage) == ["new"] and not storage.ts_backfill_pending


def test_legacy_rows_written_without_ts_epoch_by_an_older_version(tmp_path):
    db = tmp_path / "w.sqlite"
    LogStorage(db).conn.close()
    conn = sqlite3.connect(db)  # a downgraded release writes rows without the column
    conn.execute("INSERT INTO records(timestamp, severity_bucket, scope, namespace, pod, container, message, raw_line,"
                 " source_key, source_etag, line_number) VALUES ('2026-09-07T12:00:00Z','info','infra','ns','p','c',"
                 "'x','x','k','e',1)")
    conn.commit()
    conn.close()
    storage = LogStorage(db)
    assert storage.ts_backfill_pending and storage.backfill_ts_step() == 1
    assert storage.query_logs({}, limit=1)["items"][0]["ts_epoch"] == _epoch(2026, 9, 7, 12)
