from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from logscope.lineformat import FIELD_SEPARATOR, TIMESTAMP_PATTERN

from .storage import to_epoch

# The timestamp group comes from the constant render validates format.* against.
_SEP = re.escape(FIELD_SEPARATOR)
LINE_RE = re.compile(
    rf"^(?P<timestamp>{TIMESTAMP_PATTERN}){_SEP}(?P<namespace>[^ ]+){_SEP}(?P<pod>[^/]+)/(?P<container>[^ ]+)"
    rf"{_SEP}(?P<message>.*)$"
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


# ── HTTP access-log classification (additive) ────────────────────────────────
# Access logs (Traefik JSON, nginx/Apache common/combined) carry an HTTP status
# but no "error"/"warn" keyword, so the keyword classifier files them as info and
# a 4xx/5xx flood is invisible. We re-derive severity from the status and attach
# the parsed fields; lines that do not match an access-log shape are untouched.

# nginx/Apache common & combined: IP ident user [time] "METHOD path proto" status size ...
_ACCESS_COMMON_RE = re.compile(
    r'^(?P<client_ip>\S+) \S+ \S+ \[[^\]]+\] '
    r'"(?P<method>[A-Z]{3,10}) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3})(?: (?P<size>\S+))?'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
# Traefik JSON access-log keys (and common aliases from nginx/Envoy JSON).
_JSON_STATUS_KEYS = ("DownstreamStatus", "OriginStatus", "status", "http.status_code", "status_code")
_JSON_METHOD_KEYS = ("RequestMethod", "method", "http.method")
_JSON_PATH_KEYS = ("RequestPath", "RequestURI", "path", "http.path", "uri")
_JSON_IP_KEYS = ("ClientHost", "ClientAddr", "client_ip", "remote_addr", "RemoteAddr")
_JSON_UA_KEYS = ("request_User-Agent", "RequestUserAgent", "user_agent", "http.user_agent")
_JSON_DURATION_KEYS = ("Duration", "duration", "request_time")
# Statuses that mean trouble even though the line holds no error keyword.
_WARNING_STATUSES = frozenset({401, 403, 404, 429})


def _first_key(obj: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def access_log_fields(message: str) -> dict[str, Any] | None:
    """Parse one access-log line (Traefik JSON or common/combined) into
    {method, path, status, client_ip, user_agent, duration}, or None when the
    line is not an access log. Only `status` is required."""
    text = str(message or "").strip()
    if not text:
        return None
    if text[0] == "{" and text[-1] == "}":
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict):
            raw_status = _first_key(obj, _JSON_STATUS_KEYS)
            try:
                status = int(raw_status)
            except (TypeError, ValueError):
                return None
            if not 100 <= status <= 599:
                return None
            return {
                "method": _first_key(obj, _JSON_METHOD_KEYS),
                "path": _first_key(obj, _JSON_PATH_KEYS),
                "status": status,
                "client_ip": _first_key(obj, _JSON_IP_KEYS),
                "user_agent": _first_key(obj, _JSON_UA_KEYS),
                "duration": _first_key(obj, _JSON_DURATION_KEYS),
            }
        return None
    match = _ACCESS_COMMON_RE.match(text)
    if not match:
        return None
    status = int(match.group("status"))
    if not 100 <= status <= 599:
        return None
    return {
        "method": match.group("method"),
        "path": match.group("path"),
        "status": status,
        "client_ip": match.group("client_ip"),
        "user_agent": match.groupdict().get("ua"),
        "duration": None,
    }


def access_log_severity(status: int) -> str | None:
    """Status-based severity override, or None to keep existing classification.
    >=500 -> error; 401/403/404/429 -> warning; everything else unchanged."""
    if status >= 500:
        return "error"
    if status in _WARNING_STATUSES:
        return "warning"
    return None


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
    severity_bucket = source_bucket
    http_meta: str | None = None
    # Access-log re-classification is additive and skips security (Falco) lines.
    if scope != "security":
        fields = access_log_fields(parsed.message)
        if fields is not None:
            http_meta = json.dumps(fields, separators=(",", ":"))
            override = access_log_severity(int(fields["status"]))
            if override is not None:
                severity_bucket = override
    return {
        "timestamp": parsed.timestamp,
        "ts_epoch": ts_epoch,
        "ts_fallback": ts_fallback,
        "severity_bucket": severity_bucket,
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
        "http_meta": http_meta,
    }
