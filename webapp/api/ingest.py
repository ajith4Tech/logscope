from __future__ import annotations

import gzip
import io
import logging
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from .config import AppConfig, source_prefixes
from .parser import make_record
from .storage import LogStorage

logger = logging.getLogger(__name__)

# Records parsed per SQLite insert. Bounds memory per object (Vector batches can
# reach tens of MB uncompressed) and releases the DB lock between batches.
_INSERT_BATCH_SIZE = 1000


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
    objects_scanned: int = 0
    objects_ingested: int = 0
    records_ingested: int = 0
    last_object_last_modified: str | None = None
    error: str | None = None


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
            for obj in page.get("Contents", []):
                yield obj

    def _ingest_object(self, spec: dict[str, str], key: str, etag: str, last_modified: str) -> int | None:
        """Stream one gzip object into storage in bounded batches.

        Returns the number of records inserted, or None when the object is
        corrupt (recorded as status="error" so it does not block later objects
        on every poll; lines parsed before the corruption are kept). Transport
        errors propagate: the object stays unmarked and is re-read next poll,
        and the UNIQUE (key, etag, line) constraint drops rows already stored.
        Lines are split on "\n" only (Vector writes newline-delimited text).
        """
        body = self.client.get_object(Bucket=self.cfg.s3_bucket, Key=key)["Body"]
        inserted = 0
        skipped_lines = 0
        batch: list[dict[str, Any]] = []
        try:
            with io.TextIOWrapper(
                gzip.GzipFile(fileobj=body, mode="rb"), encoding="utf-8", errors="replace", newline="\n"
            ) as lines:
                for line_number, line in enumerate(lines, start=1):
                    raw_line = line.rstrip("\r\n")
                    if not raw_line.strip():
                        continue
                    try:
                        record = make_record(
                            raw_line=raw_line,
                            source_bucket=spec["bucket"],
                            source_scope=spec["scope"],
                            source_key=key,
                            source_etag=etag,
                            line_number=line_number,
                            infra_namespaces=self.cfg.infra_namespaces,
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
            return None
        finally:
            body.close()
        inserted += self.storage.insert_records(batch)
        if skipped_lines:
            logger.warning("Skipped %d unparseable line(s) in S3 object %s", skipped_lines, key)
        return inserted

    def ingest_once(self) -> IngestResult:
        result = IngestResult()
        last_polled_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            for spec in source_prefixes(self.cfg):
                prefix = spec["prefix"]
                start_after = self.storage.get_prefix_cursor(prefix)
                max_key = start_after or ""
                list_after = lookback_start_after(
                    prefix, start_after, self._time_format, self.cfg.webapp.s3_lookback_secs
                )
                for obj in self._list_objects(prefix, list_after):
                    key = str(obj.get("Key") or "")
                    if not key or key.endswith("/"):
                        continue
                    result.objects_scanned += 1
                    etag = _strip_quotes(str(obj.get("ETag") or ""))
                    last_modified = _dt_to_iso(obj.get("LastModified"))
                    max_key = max(max_key, key)
                    if self.storage.object_seen(self.cfg.s3_bucket, key, etag):
                        continue
                    inserted = self._ingest_object(spec, key, etag, last_modified)
                    if inserted is None:
                        continue
                    self.storage.mark_object(self.cfg.s3_bucket, key, etag, last_modified, status="ok", record_count=inserted)
                    result.objects_ingested += 1
                    result.records_ingested += inserted
                    result.last_object_last_modified = last_modified
                if max_key and max_key != (start_after or ""):
                    self.storage.set_prefix_cursor(prefix, max_key)
            self.storage.ingest_state(
                last_poll_at=last_polled_at,
                last_successful_ingest_at=last_polled_at,
                last_object_last_modified=result.last_object_last_modified,
                last_error=None,
            )
        except Exception as exc:  # pragma: no cover - surfaced to status endpoint
            result.error = str(exc)
            logger.warning("S3 ingest poll failed: %s", exc)
            self.storage.ingest_state(
                last_poll_at=last_polled_at,
                last_successful_ingest_at=self.storage.get_state("last_successful_ingest_at"),
                last_object_last_modified=result.last_object_last_modified,
                last_error=str(exc),
            )
        return result