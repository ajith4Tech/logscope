from __future__ import annotations

import gzip
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import boto3

from .config import AppConfig, source_prefixes
from .parser import make_record
from .storage import LogStorage


def _dt_to_iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _strip_quotes(etag: str) -> str:
    return etag.strip('"')


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

    def _list_objects(self, prefix: str, start_after: str | None):
        kwargs: dict[str, Any] = {"Bucket": self.cfg.s3_bucket, "Prefix": prefix}
        if start_after:
            kwargs["StartAfter"] = start_after
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                yield obj

    def ingest_once(self) -> IngestResult:
        result = IngestResult()
        last_polled_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            for spec in source_prefixes(self.cfg):
                prefix = spec["prefix"]
                start_after = self.storage.get_prefix_cursor(prefix)
                max_key = start_after or ""
                for obj in self._list_objects(prefix, start_after):
                    key = str(obj.get("Key") or "")
                    if not key or key.endswith("/"):
                        continue
                    result.objects_scanned += 1
                    etag = _strip_quotes(str(obj.get("ETag") or ""))
                    last_modified = _dt_to_iso(obj.get("LastModified"))
                    max_key = max(max_key, key)
                    if self.storage.object_seen(self.cfg.s3_bucket, key, etag):
                        continue
                    body = self.client.get_object(Bucket=self.cfg.s3_bucket, Key=key)["Body"].read()
                    text = gzip.decompress(body).decode("utf-8", errors="replace")
                    records: list[dict[str, Any]] = []
                    for line_number, raw_line in enumerate(text.splitlines(), start=1):
                        if not raw_line.strip():
                            continue
                        record = make_record(
                            raw_line=raw_line,
                            source_bucket=spec["bucket"],
                            source_scope=spec["scope"],
                            source_key=key,
                            source_etag=etag,
                            line_number=line_number,
                            infra_namespaces=self.cfg.infra_namespaces,
                        )
                        if record is not None:
                            records.append(record)
                    inserted = self.storage.insert_records(records)
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
            self.storage.ingest_state(
                last_poll_at=last_polled_at,
                last_successful_ingest_at=self.storage.get_status().get("last_successful_ingest_at"),
                last_object_last_modified=result.last_object_last_modified,
                last_error=str(exc),
            )
        return result