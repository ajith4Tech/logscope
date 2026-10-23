"""The URL filter set (see parseUrlState in app.js) and its one validator,
shared by saved views (state.py) and natural-language filters
(nl_filters.py). Values are kept in their URL form."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

FILTERS_MAX_BYTES = 8 * 1024

# The URL filter keys with the UI's limits.
TEXT_FILTERS = {"scope": 100, "ns": 253, "pod": 253, "ctr": 253, "sev": 64, "q": 500}
EXCLUDE_FILTERS = {"xscope": 100, "xns": 253, "xpod": 253, "xctr": 253, "xsev": 64}
EXCLUDE_MAX_VALUES = 50
EXCLUDE_MAX_CHARS = 20000
SEARCH_MODES = ("phrase", "raw")
# Relative presets: reopened relative to "now", never stored as from/to.
RANGES = ("today", "1h", "6h", "24h", "7d", "all")
FILTER_KEYS = frozenset({*TEXT_FILTERS, *EXCLUDE_FILTERS, "qmode", "range", "from", "to"})
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FRACTION_RE = re.compile(r"\.(\d+)")


class FilterError(Exception):
    """A filter set (or another request field) that cannot be applied;
    mapped to an HTTP status."""

    status = 422

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field


def clean_text(value: Any, field: str, max_len: int, error: type[FilterError] = FilterError) -> str:
    if not isinstance(value, str):
        raise error(f"'{field}' must be a string", field)
    text = value.strip()
    if not text:
        raise error(f"'{field}' must not be empty", field)
    if len(text) > max_len:
        raise error(f"'{field}' is longer than {max_len} characters", field)
    if _CONTROL_RE.search(text):
        raise error(f"'{field}' contains control characters", field)
    return text


def parse_time(text: str) -> datetime:
    """ISO-8601 as JavaScript writes it (any number of fraction digits, Z).
    ValueError when unparseable; a naive result is returned naive."""
    # fromisoformat (3.10) takes 3 or 6 fraction digits; JavaScript any number.
    text = _FRACTION_RE.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    return datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))


def _clean_time(value: Any, field: str) -> datetime:
    text = clean_text(value, field, 40)
    try:
        parsed = parse_time(text)
    except ValueError:
        raise FilterError(f"'{field}' must be an ISO-8601 time", field) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if not 2000 <= parsed.year <= 2100:
        raise FilterError(f"'{field}' must be between the years 2000 and 2100", field)
    return parsed


def iso_js(value: datetime) -> str:
    """The form JavaScript's toISOString() produces (what the URL carries)."""
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def validate_filters(raw: Any) -> dict[str, str]:
    """The URL filter keys only, validated like the UI's URL sanitizer
    (parseUrlState) but rejecting instead of dropping. Values are returned in
    their URL form. A relative preset stays `range`; only an absolute range
    is kept as from/to, and the two cannot be combined."""
    if not isinstance(raw, dict):
        raise FilterError("'filters' must be an object", "filters")
    unknown = sorted(str(key) for key in raw if key not in FILTER_KEYS)
    if unknown:
        raise FilterError(f"Unknown filter key '{unknown[0]}'", f"filters.{unknown[0]}")
    out: dict[str, str] = {}
    for key, max_len in TEXT_FILTERS.items():
        if key in raw:
            out[key] = clean_text(raw[key], f"filters.{key}", max_len)
    for key, max_len in EXCLUDE_FILTERS.items():
        if key not in raw:
            continue
        field = f"filters.{key}"
        value = raw[key]
        if isinstance(value, list):
            if not all(isinstance(item, str) for item in value):
                raise FilterError(f"'{field}' values must be strings", field)
            value = ",".join(value)
        if not isinstance(value, str):
            raise FilterError(f"'{field}' must be a comma-separated string", field)
        if len(value) > EXCLUDE_MAX_CHARS:
            raise FilterError(f"'{field}' is too long", field)
        values: list[str] = []
        for item in value.split(","):
            cleaned = clean_text(item, field, max_len)
            if cleaned not in values:
                values.append(cleaned)
        if len(values) > EXCLUDE_MAX_VALUES:
            raise FilterError(f"'{field}' lists more than {EXCLUDE_MAX_VALUES} values", field)
        out[key] = ",".join(values)
    if "qmode" in raw:
        if raw["qmode"] not in SEARCH_MODES:
            raise FilterError(f"'filters.qmode' must be one of {list(SEARCH_MODES)}", "filters.qmode")
        if raw["qmode"] != "phrase":  # the default; left out like in the URL
            out["qmode"] = raw["qmode"]
    if "range" in raw:
        if raw["range"] not in RANGES:
            raise FilterError(f"'filters.range' must be one of {list(RANGES)}", "filters.range")
        if "from" in raw or "to" in raw:
            raise FilterError("Use either a relative 'range' or absolute 'from'/'to', not both", "filters.range")
        if raw["range"] != "today":  # the default; left out like in the URL
            out["range"] = raw["range"]
    start = _clean_time(raw["from"], "filters.from") if "from" in raw else None
    end = _clean_time(raw["to"], "filters.to") if "to" in raw else None
    if start and end and end <= start:
        raise FilterError("'filters.to' must be after 'filters.from'", "filters.to")
    if start:
        out["from"] = iso_js(start)
    if end:
        out["to"] = iso_js(end)
    encoded = json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > FILTERS_MAX_BYTES:
        raise FilterError(f"'filters' is larger than {FILTERS_MAX_BYTES} bytes", "filters")
    return out


def sanitize_filters(raw: Any) -> tuple[dict[str, str], list[str]]:
    """Lenient form of validate_filters for untrusted proposals (model
    output): each key is validated on its own and dropped with a warning when
    invalid, instead of rejecting the whole set. An exclusion list keeps its
    valid values. The result always passes validate_filters."""
    if not isinstance(raw, dict):
        return {}, ["The proposal had no usable filters"] if raw not in (None, "") else []
    warnings: list[str] = []
    kept: dict[str, Any] = {}
    for key in sorted(raw, key=str):
        value = raw[key]
        if key not in FILTER_KEYS:
            warnings.append(f"Dropped unknown filter '{str(key)[:40]}'")
            continue
        if value is None or value == "" or value == []:
            continue
        if key in EXCLUDE_FILTERS:
            items = value if isinstance(value, list) else str(value).split(",") if isinstance(value, str) else None
            good = []
            for item in items or [None]:
                try:
                    good.append(validate_filters({key: item})[key] if isinstance(item, str) else None)
                except FilterError:
                    good.append(None)
            if None in good:
                warnings.append(f"Dropped an invalid '{key}' value")
            good = [g for g in dict.fromkeys(good) if g][:EXCLUDE_MAX_VALUES]
            if good:
                kept[key] = ",".join(good)
            continue
        try:
            kept.update(validate_filters({key: value}))
        except FilterError as exc:
            warnings.append(f"Dropped '{key}': {exc}")
    if "range" in raw and ("from" in kept or "to" in kept):
        kept.pop("range", None)
        warnings.append("Used the exact from/to times instead of the relative range")
    if "from" in kept and "to" in kept and kept["to"] <= kept["from"]:
        kept.pop("to")
        warnings.append("Dropped 'to': it was not after 'from'")
    try:
        return validate_filters(kept), warnings
    except FilterError as exc:  # only the overall size limit is left
        return {}, [*warnings, f"Dropped all filters: {exc}"]
