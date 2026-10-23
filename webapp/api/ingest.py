from __future__ import annotations

import gzip
import io
import logging
import sqlite3
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from .config import AppConfig, source_prefixes
from .parser import make_record
from .storage import LogStorage, to_epoch, utc_stamp

logger = logging.getLogger(__name__)

# Records parsed per SQLite insert. Bounds memory per object (Vector batches can
# reach tens of MB uncompressed) and releases the DB lock between batches.
_INSERT_BATCH_SIZE = 1000
# Characters kept from one log line. A line without newlines (or a crafted
# object) would otherwise be read into memory whole; the rest is dropped and
# the stored line is marked as cut.
_MAX_LINE_CHARS = 1_000_000
_TRUNCATED_MARK = " …[line truncated by Logscope]"


def _bounded_lines(stream, limit: int):
    """(physical line number, text, truncated) for each "\n"-separated line,
    holding at most `limit` characters of a line in memory. Numbering matches
    plain iteration, so retries map lines to the same UNIQUE keys."""
    line_number = 0
    while True:
        chunk = stream.readline(limit)
        if not chunk:
            return
        line_number += 1
        if chunk.endswith("\n") or len(chunk) < limit:
            yield line_number, chunk, False
            continue
        while True:  # skip the remainder of this line
            rest = stream.readline(limit)
            if not rest or rest.endswith("\n"):
                break
        yield line_number, chunk, True


def _dt_to_iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _strip_quotes(etag: str) -> str:
    return etag.strip('"')


def _key_time_format(key_prefix: str) -> str:
    """strftime layout that follows the log-type segment of sinks.s3.key_prefix,
    e.g. "%Y/%m/%d/%H_%M_%S_". Empty when the prefix has no usable time part."""
    if "{{ log_type }}" not in key_prefix:
        return ""
    tail = key_prefix.split("{{ log_type }}", 1)[1].lstrip("/")
    if "{{" in tail or "%" not in tail:
        return ""
    return tail


def lookback_start_after(prefix: str, last_key: str | None, time_format: str, lookback_secs: int) -> str | None:
    """Move the StartAfter cursor back by lookback_secs of key time.

    Vector names objects by event time but flushes batches later, so an object
    can land after a lexicographically later key was already listed. Re-listing
    a short window catches those; object_seen() keeps re-listed keys from being
    ingested twice. Falls back to the exact cursor if the key does not parse.
    """
    if not last_key or lookback_secs <= 0 or not time_format or not last_key.startswith(prefix):
        return last_key
    width = len(datetime(2000, 1, 1).strftime(time_format))
    try:
        key_time = datetime.strptime(last_key[len(prefix):len(prefix) + width], time_format)
    except ValueError:
        return last_key
    return prefix + (key_time - timedelta(seconds=lookback_secs)).strftime(time_format)


@dataclass
class IngestResult:
    objects_ingested: int = 0
    records_ingested: int = 0
    objects_failed: int = 0
    objects_deferred: int = 0  # failed earlier and still backing off
    last_object_last_modified: str | None = None
    error: str | None = None


def _missing_object(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    code = str(exc.response.get("Error", {}).get("Code", ""))
    return code in ("NoSuchKey", "404", "NotFound")


class S3Ingestor:
    def __init__(self, cfg: AppConfig, storage: LogStorage):
        self.cfg = cfg
        self.storage = storage
        client_kwargs: dict[str, Any] = {"region_name": cfg.s3_region}
        if cfg.s3_access_key_id and cfg.s3_secret_access_key:
            client_kwargs["aws_access_key_id"] = cfg.s3_access_key_id
            client_kwargs["aws_secret_access_key"] = cfg.s3_secret_access_key
            if cfg.s3_session_token:
                client_kwargs["aws_session_token"] = cfg.s3_session_token
        self.client = boto3.client("s3", **client_kwargs)
        self._time_format = _key_time_format(cfg.s3_key_prefix)

    def _list_objects(self, prefix: str, start_after: str | None):
        kwargs: dict[str, Any] = {"Bucket": self.cfg.s3_bucket, "Prefix": prefix}
        if start_after:
            kwargs["StartAfter"] = start_after
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(**kwargs):
            yield from page.get("Contents", [])

    def _ingest_object(self, spec: dict[str, str], key: str, etag: str, last_modified: str) -> tuple[int | None, str]:
        """Stream one gzip object into storage in bounded batches.

        Returns (records inserted, ETag of the content read). The count is
        None when the object is corrupt (recorded as status="error" so it does
        not block later objects on every poll; lines parsed before the
        corruption are kept). The ETag is the one GetObject returned: if the
        object was replaced since it was listed (or since a failed attempt was
        recorded), rows are stored under the version actually read, so the
        new version is not ingested a second time under its own ETag.
        Transport errors propagate: the caller records the failure and retries
        the object with backoff, and the UNIQUE (key, etag, line) constraint
        drops rows already stored.
        Lines are split on "\n" only (Vector writes newline-delimited text).
        """
        response = self.client.get_object(Bucket=self.cfg.s3_bucket, Key=key)
        body = response["Body"]
        etag = _strip_quotes(str(response.get("ETag") or "")) or etag
        # Lines whose timestamp does not parse are placed at the object's time.
        object_epoch = to_epoch(last_modified)
        inserted = 0
        skipped_lines = 0
        truncated_lines = 0
        batch: list[dict[str, Any]] = []
        try:
            with io.TextIOWrapper(
                gzip.GzipFile(fileobj=body, mode="rb"), encoding="utf-8", errors="replace", newline="\n"
            ) as lines:
                for line_number, line, truncated in _bounded_lines(lines, _MAX_LINE_CHARS):
                    raw_line = line.rstrip("\r\n")
                    if not raw_line.strip():
                        continue
                    if truncated:
                        truncated_lines += 1
                        raw_line += _TRUNCATED_MARK
                    try:
                        record = make_record(
                            raw_line=raw_line,
                            source_bucket=spec["bucket"],
                            source_scope=spec["scope"],
                            source_key=key,
                            source_etag=etag,
                            line_number=line_number,
                            infra_namespaces=self.cfg.infra_namespaces,
                            fallback_epoch=object_epoch,
                        )
                    except ValueError:
                        skipped_lines += 1
                        continue
                    if record is not None:
                        batch.append(record)
                        if len(batch) >= _INSERT_BATCH_SIZE:
                            inserted += self.storage.insert_records(batch)
                            batch = []
        except (gzip.BadGzipFile, EOFError, zlib.error) as exc:
            inserted += self.storage.insert_records(batch)
            logger.warning("Skipping unreadable S3 object %s after %d record(s): %s", key, inserted, exc)
            self.storage.mark_object(self.cfg.s3_bucket, key, etag, last_modified, status="error", record_count=inserted)
            return None, etag
        finally:
            body.close()
        inserted += self.storage.insert_records(batch)
        if skipped_lines:
            logger.warning("Skipped %d unparseable line(s) in S3 object %s", skipped_lines, key)
        if truncated_lines:
            logger.warning("Cut %d line(s) longer than %d characters in S3 object %s",
                           truncated_lines, _MAX_LINE_CHARS, key)
        return inserted, etag

    def _try_object(self, result: IngestResult, spec: dict[str, str], key: str, etag: str, last_modified: str) -> str | None:
        """Ingest one object; on failure record it for a later retry instead of
        aborting the poll. Returns the error text, or None on success."""
        bucket = self.cfg.s3_bucket
        try:
            inserted, read_etag = self._ingest_object(spec, key, etag, last_modified)
        except sqlite3.Error:
            # The local database failed (disk full, locked), not the object:
            # no per-object backoff. The poll for this prefix stops without
            # moving its cursor, so the object is listed again next time.
            raise
        except Exception as exc:
            if _missing_object(exc):
                # Expired by the lifecycle rule or deleted: nothing left to read.
                logger.info("S3 object %s no longer exists; dropping it from the retry list", key)
                self.storage.clear_object_failure(bucket, key, etag)
                return None
            attempts = self.storage.record_object_failure(
                bucket, key, etag, prefix=spec["prefix"], last_modified=last_modified, error=str(exc)
            )
            result.objects_failed += 1
            logger.warning("Reading S3 object %s failed (attempt %d), will retry: %s", key, attempts, exc)
            return f"{key}: {exc}"
        self.storage.clear_object_failure(bucket, key, etag)
        if read_etag != etag:
            logger.info("S3 object %s changed since it was listed; stored the version read (%s)", key, read_etag)
            self.storage.clear_object_failure(bucket, key, read_etag)
        if inserted is None:  # corrupt; already marked status="error"
            return None
        self.storage.mark_object(bucket, key, read_etag, last_modified, status="ok", record_count=inserted)
        result.objects_ingested += 1
        result.records_ingested += inserted
        result.last_object_last_modified = last_modified
        return None

    def ingest_once(self) -> IngestResult:
        """One poll. A prefix whose listing fails, or an object that cannot be
        read, is reported and retried later without stopping the others."""
        result = IngestResult()
        last_polled_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        bucket = self.cfg.s3_bucket
        prefix_errors: list[str] = []
        errors_by_prefix: dict[str, str] = {}  # for the status page
        object_errors: list[str] = []
        attempted: set[tuple[str, str]] = set()
        specs: dict[str, dict[str, str]] = {}
        try:
            for spec in source_prefixes(self.cfg):
                prefix = spec["prefix"]
                specs[prefix] = spec
                try:
                    start_after = self.storage.get_prefix_cursor(prefix)
                    max_key = start_after or ""
                    list_after = lookback_start_after(
                        prefix, start_after, self._time_format, self.cfg.webapp.s3_lookback_secs
                    )
                    for obj in self._list_objects(prefix, list_after):
                        key = str(obj.get("Key") or "")
                        if not key or key.endswith("/"):
                            continue
                        etag = _strip_quotes(str(obj.get("ETag") or ""))
                        last_modified = _dt_to_iso(obj.get("LastModified"))
                        # The cursor may pass a failed object: the failure table
                        # retries it by key, so it is not lost behind the cursor.
                        max_key = max(max_key, key)
                        if self.storage.object_seen(bucket, key, etag):
                            continue
                        failure = self.storage.get_object_failure(bucket, key, etag)
                        if failure and failure["next_attempt_at"] > utc_stamp():
                            result.objects_deferred += 1
                            continue
                        attempted.add((key, etag))
                        error = self._try_object(result, spec, key, etag, last_modified)
                        if error:
                            object_errors.append(error)
                    if max_key and max_key != (start_after or ""):
                        self.storage.set_prefix_cursor(prefix, max_key)
                    # Everything in S3 at the start of this poll is now read or
                    # in the failure table: the alert watermark's input.
                    self.storage.set_prefix_listed(prefix, last_polled_at)
                except Exception as exc:
                    # Listing failed: keep the cursor so the next poll re-lists.
                    logger.warning("S3 listing for prefix %s failed: %s", prefix, exc)
                    prefix_errors.append(f"{prefix}: {exc}")
                    errors_by_prefix[prefix] = str(exc)

            # Retry earlier failures that are due and were not listed this poll.
            for failure in self.storage.due_object_failures(bucket):
                ident = (failure["key"], failure["etag"])
                if ident in attempted:
                    continue
                if self.storage.object_seen(bucket, *ident):
                    self.storage.clear_object_failure(bucket, *ident)
                    continue
                spec = specs.get(failure["prefix"])
                if spec is None:  # prefix no longer configured
                    self.storage.clear_object_failure(bucket, *ident)
                    continue
                error = self._try_object(result, spec, failure["key"], failure["etag"], failure["last_modified"])
                if error:
                    object_errors.append(error)
        except Exception as exc:  # storage failure: surfaced to the status endpoint
            prefix_errors.append(str(exc))
            errors_by_prefix["*"] = str(exc)  # not tied to one prefix
            logger.warning("S3 ingest poll failed: %s", exc)

        errors = prefix_errors + object_errors
        result.error = "; ".join(errors) if errors else None
        try:
            self.storage.ingest_state(
                last_poll_at=last_polled_at,
                # Unreadable objects are retried on their own schedule and shown
                # as failing objects; they do not make the whole pipeline stale.
                last_successful_ingest_at=(
                    self.storage.get_state("last_successful_ingest_at") if prefix_errors else last_polled_at
                ),
                last_object_last_modified=result.last_object_last_modified,
                last_error=result.error[:2000] if result.error else None,
                prefix_errors=errors_by_prefix,
            )
        except Exception:
            logger.exception("Could not record ingest state")
        return result
