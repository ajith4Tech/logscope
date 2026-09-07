from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


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
) -> dict[str, Any] | None:
    parsed = parse_flat_line(raw_line)
    if source_scope != "security" and parsed.is_security_suffix:
        return None

    scope = "security" if source_scope == "security" else route_scope(parsed.namespace, infra_namespaces)
    return {
        "timestamp": parsed.timestamp,
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