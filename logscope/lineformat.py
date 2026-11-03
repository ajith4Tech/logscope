"""The stored line layout shared by the renderer (which writes it into the
Vector config) and the web app's parser (which reads it back):

    <timestamp> - <namespace> - <pod>/<container> - <message>

The timestamp is one whitespace-free token; render refuses a format.timestamp
or format.line that would break that, so the parser's TIMESTAMP_PATTERN
always matches what Vector writes."""

from __future__ import annotations

import re

# The timestamp field of a stored line: one token without whitespace.
TIMESTAMP_PATTERN = r"\S+"
FIELD_SEPARATOR = " - "

# Vector's format_timestamp uses chrono specifiers. These can produce
# whitespace: %c, %r, %v (with spaces or a space-padded field), %e, %k, %l
# (space-padded), %n and %t (newline, tab), and any "%_" (pad with spaces).
_WHITESPACE_SPECIFIER_RE = re.compile(r"%(?:[-0]?[crv]|[ekl]|[nt]|_)")  # %-e etc. are not padded
# Placeholders whose value can contain whitespace (the rest are Kubernetes
# names, scopes and buckets).
_SPACED_PLACEHOLDERS = ("{message}",)


def timestamp_format_problem(fmt: str) -> str | None:
    """Why a format.timestamp would produce a timestamp with whitespace, or None."""
    if re.search(r"\s", fmt):
        return f"format.timestamp {fmt!r} contains whitespace; the stored timestamp must be one token"
    match = _WHITESPACE_SPECIFIER_RE.search(fmt)
    if match:
        return (f"format.timestamp {fmt!r} uses {match.group(0)!r}, which can produce whitespace; "
                "the stored timestamp must be one token (use e.g. %Y-%m-%dT%H:%M:%SZ)")
    return None


def line_format_problem(template: str, key: str = "format.line") -> str | None:
    """Why a line template would put whitespace into the timestamp field
    (another placeholder or text glued to {timestamp}), or None."""
    for token in template.split():
        if "{timestamp}" not in token:
            continue
        spaced = [p for p in _SPACED_PLACEHOLDERS if p in token]
        if spaced:
            return (f"{key} {template!r} joins {{timestamp}} and {spaced[0]} without whitespace; the "
                    "timestamp field would contain the message's spaces")
    return None
