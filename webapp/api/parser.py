from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .storage import to_epoch

LINE_RE = re.compile(
    r"^(?P<timestamp>[^ ]+) - (?P<namespace>[^ ]+) - (?P<pod>[^/]+)/(?P<container>[^ ]+) - (?P<message>.*)$"
)


@dataclass(frozen=True)
class ParsedLine:
    timestamp: str
    namespace: str
    pod: str
    container: str
    message: str
    is_security_suffix: bool


def parse_flat_line(raw_line: str) -> ParsedLine:
    match = LINE_RE.match(raw_line)
    if not match:
        raise ValueError(f"unrecognized log line: {raw_line!r}")
    message = match.group("message")
    is_security_suffix = message.endswith(" scope=security")
    if is_security_suffix:
        message = message[: -len(" scope=security")]
    return ParsedLine(
        timestamp=match.group("timestamp"),
        namespace=match.group("namespace") or "-",
        pod=match.group("pod") or "-",
        container=match.group("container") or "-",
        message=message,
        is_security_suffix=is_security_suffix,
    )


def route_scope(namespace: str, infra_namespaces: tuple[str, ...]) -> str:
    for pattern in infra_namespaces:
        if pattern == namespace:
            return "infra"
        if "*" in pattern or "?" in pattern:
            rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
            if re.match(rx, namespace):
                return "infra"
    return f"namespaces/{namespace}"


def make_record(
    *,
    raw_line: str,
    source_bucket: str,
    source_scope: str,
    source_key: str,
    source_etag: str,
    line_number: int,
    infra_namespaces: tuple[str, ...],
    fallback_epoch: float | None = None,
) -> dict[str, Any] | None:
    """One record from one line. ts_epoch is the line's timestamp in UTC
    epoch seconds (no zone = UTC); when it does not parse, fallback_epoch
    (the S3 object's time) is used and ts_fallback is set.

    Falco events are read from the security/ prefix only: a line tagged
    " scope=security" in a regular prefix (written there by versions that
    sent every Falco event to both sinks) is skipped."""
    parsed = parse_flat_line(raw_line)
    if source_scope != "security" and parsed.is_security_suffix:
        return None
    ts_epoch = to_epoch(parsed.timestamp)
    ts_fallback = ts_epoch is None
    if ts_fallback:
        ts_epoch = fallback_epoch

    scope = "security" if source_scope == "security" else route_scope(parsed.namespace, infra_namespaces)
    return {
        "timestamp": parsed.timestamp,
        "ts_epoch": ts_epoch,
        "ts_fallback": ts_fallback,
        "severity_bucket": source_bucket,
        "scope": scope,
        "namespace": parsed.namespace,
        "pod": parsed.pod,
        "container": parsed.container,
        "message": parsed.message,
        "raw_line": raw_line,
        "source_key": source_key,
        "source_etag": source_etag,
        "line_number": line_number,
        "is_falco": 1 if scope == "security" else 0,
    }
