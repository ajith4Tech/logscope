"""Shared test helpers (not collected as tests)."""

from __future__ import annotations

from typing import Any

from webapp.api.actions import confirmation_response, describe_action, resolve_action, run_described_action
from webapp.api.patterns import normalize_message


def upsert_anomaly(store: Any, **fields: Any) -> int:
    """Insert or refresh one anomaly and return its id: AnomalyStore.record_detection
    without the outcome (the app itself only uses record_detection)."""
    anomaly_id, _ = store.record_detection(**fields)
    return anomaly_id


def execute_action(action_data: dict[str, Any], *, confirmed: bool = False) -> dict[str, Any]:
    """Validate and run a structured action without the HTTP layer's
    confirmation tokens: mutating actions need confirmed=True."""
    described = describe_action(resolve_action(action_data))
    if described["is_mutating"] and not confirmed:
        return confirmation_response(described)
    return run_described_action(described)


def pod_pattern(pod: Any) -> str:
    """web-7d9f8b6c5d-x2kqp -> web-<HASH>, db-0 -> db-<NUM>."""
    return normalize_message(pod)


def in_flight(flight: Any) -> int:
    """Calls a SingleFlight is running right now."""
    with flight._lock:
        return len(flight._calls)


def cache_stats(cache: Any) -> dict[str, int]:
    """Row counts of an AiCache's table."""
    with cache._db.lock:
        row = cache._db.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(hits), 0), COALESCE(SUM(helpful_up), 0), "
            "COALESCE(SUM(helpful_down), 0) FROM ai_cache").fetchone()
    return {"entries": int(row[0]), "hits": int(row[1]), "helpful_up": int(row[2]), "helpful_down": int(row[3])}
