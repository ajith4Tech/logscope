"""Persistent cache of AI answers (state table ai_cache), keyed by log
template rather than by record, with a small in-memory front, single-flight
for identical in-flight requests, a TTL, and 👍/👎 feedback: one vote per
(entry, browser session), and an entry with at least DROP_NET_DOWN more 👎
than 👍 is dropped on its next lookup.
"""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from .state import StateDB

DEFAULT_TTL_HOURS = 168  # 7 days
FRONT_MAX_ENTRIES = 256
FRONT_TTL_SECS = 60.0
SINGLE_FLIGHT_WAIT_SECS = 600.0
_PRUNE_EVERY_SECS = 3600.0
DROP_NET_DOWN = 2
KINDS = ("line", "filtered", "anomaly", "nl_filters")
TIERS = ("fast", "deep")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class _Call:
    __slots__ = ("done", "result", "error")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: Any = None
        self.error: BaseException | None = None


class SingleFlight:
    """Concurrent calls with the same key share one execution: the first
    caller runs fn, the others wait for its result (or its exception)."""

    def __init__(self, wait_secs: float = SINGLE_FLIGHT_WAIT_SECS):
        self._calls: dict[str, _Call] = {}
        self._lock = threading.Lock()
        self._wait = wait_secs

    def do(self, key: str, fn: Callable[[], Any]) -> tuple[Any, bool]:
        """(result, shared): shared is True for a caller that waited."""
        with self._lock:
            call = self._calls.get(key)
            leader = call is None
            if leader:
                call = self._calls[key] = _Call()
        if not leader:
            if not call.done.wait(self._wait):
                raise TimeoutError("Timed out waiting for an identical AI request")
            if call.error is not None:
                raise call.error
            return call.result, True
        try:
            call.result = fn()
            return call.result, False
        except BaseException as exc:
            call.error = exc
            raise
        finally:
            with self._lock:
                self._calls.pop(key, None)
            call.done.set()


class AiCache:
    def __init__(self, db: StateDB, *, ttl_hours: float = DEFAULT_TTL_HOURS,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._db = db
        self.ttl = timedelta(hours=max(0.0, float(ttl_hours)))
        self._clock = clock
        self._front: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._front_lock = threading.Lock()
        self.flight = SingleFlight()
        self._last_prune = 0.0

    # -- in-memory front ----------------------------------------------------------

    def _front_get(self, key: str) -> dict[str, Any] | None:
        with self._front_lock:
            item = self._front.get(key)
            if item is None:
                return None
            entry, loaded = item
            if time.monotonic() - loaded > FRONT_TTL_SECS:
                del self._front[key]
                return None
            self._front.move_to_end(key)
            return entry

    def _front_put(self, key: str, entry: dict[str, Any]) -> None:
        with self._front_lock:
            self._front[key] = (entry, time.monotonic())
            self._front.move_to_end(key)
            while len(self._front) > FRONT_MAX_ENTRIES:
                self._front.popitem(last=False)

    def _front_drop(self, key: str) -> None:
        with self._front_lock:
            self._front.pop(key, None)

    # -- lookups ------------------------------------------------------------------

    def _expired(self, created_at: str, now: datetime) -> bool:
        return self.ttl.total_seconds() <= 0 or _parse(created_at) <= now - self.ttl

    def get(self, key: str) -> dict[str, Any] | None:
        """The cached entry (response, created_at, hits, age_secs, ...) or None.
        Expired entries and entries voted down are removed here."""
        now = self._clock()
        entry = self._front_get(key)
        if entry is None:
            with self._db.lock:
                row = self._db.conn.execute("SELECT * FROM ai_cache WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            entry = dict(row)
            try:
                entry["response"] = json.loads(entry["response"])
            except ValueError:
                self.delete(key)
                return None
        if self._expired(entry["created_at"], now) or entry["helpful_down"] - entry["helpful_up"] >= DROP_NET_DOWN:
            self.delete(key)
            return None
        stamp = _iso(now)
        with self._db.lock:
            self._db.conn.execute("UPDATE ai_cache SET hits = hits + 1, last_hit_at = ? WHERE key = ?", (stamp, key))
        entry = {**entry, "hits": int(entry["hits"]) + 1, "last_hit_at": stamp}
        self._front_put(key, entry)
        return {**entry, "age_secs": max(0, int((now - _parse(entry["created_at"])).total_seconds()))}

    def put(self, key: str, *, kind: str, tier: str, response: dict[str, Any], template_id: str = "") -> dict[str, Any]:
        if kind not in KINDS or tier not in TIERS:
            raise ValueError(f"invalid cache kind/tier {kind!r}/{tier!r}")
        now = _iso(self._clock())
        with self._db.lock:
            self._db.conn.execute(
                "INSERT INTO ai_cache (key, kind, template_id, model_tier, response, created_at, hits, last_hit_at, "
                "helpful_up, helpful_down) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, 0, 0) "
                "ON CONFLICT(key) DO UPDATE SET kind = excluded.kind, template_id = excluded.template_id, "
                "model_tier = excluded.model_tier, response = excluded.response, created_at = excluded.created_at, "
                "hits = 0, last_hit_at = NULL, helpful_up = 0, helpful_down = 0",
                (key, kind, template_id, tier, json.dumps(response, ensure_ascii=False), now),
            )
            self._db.conn.execute("DELETE FROM ai_cache_votes WHERE key = ?", (key,))
        self._front_drop(key)
        self._maybe_prune()
        return {"key": key, "created_at": now}

    def delete(self, key: str) -> None:
        with self._db.lock:
            self._db.conn.execute("DELETE FROM ai_cache WHERE key = ?", (key,))
            self._db.conn.execute("DELETE FROM ai_cache_votes WHERE key = ?", (key,))
        self._front_drop(key)

    def feedback(self, key: str, vote: str, client_id: str) -> dict[str, int]:
        """Record 👍 ("up") or 👎 ("down") from one client; a repeat vote from
        the same client replaces its earlier one. KeyError for an unknown key."""
        if vote not in ("up", "down"):
            raise ValueError("'vote' must be 'up' or 'down'")
        now = _iso(self._clock())
        with self._db.lock:
            if self._db.conn.execute("SELECT 1 FROM ai_cache WHERE key = ?", (key,)).fetchone() is None:
                raise KeyError(key)
            self._db.conn.execute(
                "INSERT INTO ai_cache_votes (key, client_id, vote, voted_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key, client_id) DO UPDATE SET vote = excluded.vote, voted_at = excluded.voted_at",
                (key, client_id, 1 if vote == "up" else -1, now))
            up, down = self._db.conn.execute(
                "SELECT COALESCE(SUM(vote = 1), 0), COALESCE(SUM(vote = -1), 0) FROM ai_cache_votes WHERE key = ?",
                (key,)).fetchone()
            self._db.conn.execute("UPDATE ai_cache SET helpful_up = ?, helpful_down = ? WHERE key = ?",
                                  (int(up), int(down), key))
        self._front_drop(key)
        return {"helpful_up": int(up), "helpful_down": int(down)}

    def _maybe_prune(self) -> None:
        now = time.monotonic()
        if now - self._last_prune < _PRUNE_EVERY_SECS:
            return
        self._last_prune = now
        self.prune()

    def prune(self) -> int:
        cutoff = _iso(self._clock() - self.ttl)
        with self._db.lock:
            removed = self._db.conn.execute("DELETE FROM ai_cache WHERE created_at <= ?", (cutoff,)).rowcount
            self._db.conn.execute("DELETE FROM ai_cache_votes WHERE key NOT IN (SELECT key FROM ai_cache)")
            return removed
