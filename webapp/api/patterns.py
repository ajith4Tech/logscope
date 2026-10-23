"""Log message templates: the variable parts of a line (numbers, ids,
addresses, times, pod hashes, quoted values, paths with digits) become
placeholders, so lines that differ only in those parts share one template.

Pure functions, no I/O. Used for the AI cache keys (one answer per template
instead of per line) and for compact AI inputs (templates with counts instead
of raw rows).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from typing import Any

_DIGIT_RE = re.compile(r"\d")

# Order matters: a timestamp must go before its numbers, a UUID before hex
# ids, an address before its numbers.
_RULES: tuple[tuple[re.Pattern[str], Any], ...] = (
    # Falco's "12:00:00.123456789: " event-time prefix and klog's "I0907 12:00:00.123456   1 file.go:12]".
    (re.compile(r"\b[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+\s+\d+ [\w.-]+:\d+\]"), "<KLOG>"),
    # ISO-8601 / RFC 3339 and "2026-09-07 12:00:00,123" timestamps.
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2}|\s?UTC)?"), "<TS>"),
    # Syslog "Sep  7 12:00:00" and bare clock times.
    (re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}\d{1,2} \d{2}:\d{2}:\d{2}\b"), "<TS>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    # IPv4 (optionally :port) and IPv6 (at least two groups and a "::" or 7 colons).
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    (re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![\w:])"), "<IP>"),
    (re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?(?![\w:])"),
     "<IP>"),
    # Pod names: Deployment pods (<name>-<replicaset hash>-<5 chars>), then
    # the 5-character suffix alone (DaemonSet/Job pods) when it holds a digit.
    (re.compile(r"\b([a-z0-9]+(?:-[a-z0-9]+)*?)-[a-z0-9]{8,10}-[bcdfghjklmnpqrstvwxz2456789]{5}(?![A-Za-z0-9])"),
     r"\1-<HASH>"),
    (re.compile(r"\b([a-z][a-z0-9]*(?:-[a-z0-9]+)*)-(?=[bcdfghjklmnpqrstvwxz2456789]{5}(?![A-Za-z0-9]))(?=[a-z]*\d)[a-z0-9]{5}(?![A-Za-z0-9])"),
     r"\1-<HASH>"),
    # Quoted values containing digits (ids, URLs, versions), keeping the
    # quotes. Every quoted string is matched left to right (so quotes pair up
    # correctly); text without digits stays, as it is usually a message, a
    # JSON key or a name that tells two different events apart.
    (re.compile(r'"(?:[^"\\\n]|\\.){0,500}"'), lambda m: '"<STR>"' if _DIGIT_RE.search(m.group(0)) else m.group(0)),
    (re.compile(r"(?<![A-Za-z])'(?:[^'\\\n]|\\.){0,500}'"),
     lambda m: "'<STR>'" if _DIGIT_RE.search(m.group(0)) else m.group(0)),
    # Paths containing digits (/var/lib/pod/123/x, /proc/42/status).
    (re.compile(r"(?<![\w<])(?:/[\w.@-]+)*/[\w.@-]*\d[\w.@-]*(?:/[\w.@-]+)*"), "<PATH>"),
    # Hex ids (container ids, git shas, 0xc000123): 8+ hex chars with a digit.
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{8,}\b"), "<HEX>"),
    # Long random ids (base62/base64url request ids, tokens): 16+ characters
    # mixing letters and digits.
    (re.compile(r"(?<![\w<-])(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{16,}(?![\w>])"), "<ID>"),
    # Durations: 1.5s, 250ms, 3m20s, 2h.
    (re.compile(r"\b\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))*\b"), "<DUR>"),
    (re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])"), "<NUM>"),
)
_WS_RE = re.compile(r"\s+")
_NAMESPACE_NUMERIC_RE = re.compile(r"(?<=-)\d+(?=-|$)")
MAX_TEMPLATE_CHARS = 2000


def normalize_message(message: Any) -> str:
    """The template of one log message."""
    text = str(message or "")[: MAX_TEMPLATE_CHARS * 2]
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return _WS_RE.sub(" ", text).strip()[:MAX_TEMPLATE_CHARS]


def namespace_pattern(namespace: Any) -> str:
    """user-123 -> user-*, tenant-7-prod -> tenant-*-prod; other names unchanged."""
    return _NAMESPACE_NUMERIC_RE.sub("*", str(namespace or ""))


def template_id(namespace: Any, container: Any, template: str) -> str:
    """Stable id of a template within a namespace pattern and container."""
    raw = "\x1f".join((namespace_pattern(namespace), str(container or ""), template))
    return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()


def record_template(record: dict[str, Any]) -> tuple[str, str]:
    """(template_id, template) of a stored log record."""
    template = normalize_message(record.get("message"))
    return template_id(record.get("namespace"), record.get("container"), template), template


def count_bucket(count: int) -> int:
    """Power-of-two bucket (1, 2, 4, 8, ...): small changes in volume keep a key."""
    count = max(1, int(count))
    return 1 << (count.bit_length() - 1)


def digest_records(
    records: Iterable[dict[str, Any]],
    *,
    top: int = 15,
    exemplars: int = 3,
    exemplar_chars: int = 240,
    redact: Callable[[str], str] = lambda text: text,
) -> dict[str, Any]:
    """Templates with counts, first/last seen and a few (redacted, bounded)
    exemplars, most frequent first: the compact form of a log sample."""
    groups: dict[str, dict[str, Any]] = {}
    total = 0
    for record in records:
        total += 1
        tid, template = record_template(record)
        group = groups.get(tid)
        ts = str(record.get("timestamp") or "")
        if group is None:
            group = groups[tid] = {
                "template_id": tid, "template": template, "count": 0, "first_seen": ts, "last_seen": ts,
                "namespace": namespace_pattern(record.get("namespace")), "container": record.get("container") or "",
                "severity": record.get("severity_bucket") or record.get("severity") or "", "pods": set(),
                "exemplars": [],
            }
        group["count"] += 1
        if ts and (not group["first_seen"] or ts < group["first_seen"]):
            group["first_seen"] = ts
        if ts > group["last_seen"]:
            group["last_seen"] = ts
        if record.get("pod"):
            group["pods"].add(str(record["pod"]))
        message = str(record.get("message") or "")
        if len(group["exemplars"]) < exemplars and message:
            text = redact(message[: exemplar_chars * 2])
            text = text if len(text) <= exemplar_chars else text[:exemplar_chars] + "…"
            if text not in group["exemplars"]:
                group["exemplars"].append(text)
    ordered = sorted(groups.values(), key=lambda g: (-g["count"], g["template"]))
    out = []
    for group in ordered[:top]:
        group = dict(group)
        group["pods"] = len(group["pods"])
        # A one-line template that is already its own exemplar adds nothing.
        if group["exemplars"] == [group["template"]]:
            group["exemplars"] = []
        out.append(group)
    return {"rows": total, "distinct_templates": len(groups), "templates": out}
