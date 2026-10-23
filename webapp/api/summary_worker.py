"""Automatic anomaly summaries off the detection loop.

The insights job hands pending anomalies to enqueue(), which never blocks:
only anomalies at or above webapp.ai.auto_summary_min_urgency are queued,
and only while the anomaly_auto_summary feature is on (default off). Two
worker threads take up to 5 queued anomalies that share a namespace or a
detection window and answer them with signatures, the cache, or one batched
provider call. Over budget, a batch is dropped (its anomalies stay pending
and are offered again on a later detection run).
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .config import URGENCY_ORDER
from .explain import Explainer, anomaly_cache_key, decorate, meta_of
from .notify import anomaly_urgency

logger = logging.getLogger(__name__)

FEATURE = "anomaly_auto_summary"
MAX_WORKERS = 2
BATCH_SIZE = 5
MAX_QUEUE = 100


def _evidence(anomaly: dict[str, Any]) -> dict[str, Any]:
    evidence = anomaly.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = {}
    return evidence if isinstance(evidence, dict) else {}


def _window(anomaly: dict[str, Any]) -> str:
    return str(_evidence(anomaly).get("window_start") or "")


class SummaryWorker:
    def __init__(self, explainer: Explainer, store: Any, *, min_urgency: Callable[[], str],
                 workers: int = MAX_WORKERS, batch_size: int = BATCH_SIZE, max_queue: int = MAX_QUEUE):
        self.explainer = explainer
        self.store = store
        self._min_urgency = min_urgency
        self.workers = max(1, workers)
        self.batch_size = max(1, batch_size)
        self.max_queue = max(1, max_queue)
        self._queue: deque[dict[str, Any]] = deque()
        self._queued: set[int] = set()  # queued or being summarized
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.dropped = 0
        self.summarized = 0
        self.last_error: str | None = None
        self.last_error_at: str | None = None

    # -- intake (called from the insights loop; never blocks on a provider) ------

    def wants(self, anomaly: dict[str, Any]) -> bool:
        if not self.explainer.settings.enabled(FEATURE):
            return False
        threshold = URGENCY_ORDER.get(self._min_urgency(), URGENCY_ORDER["urgent"])
        return URGENCY_ORDER.get(anomaly_urgency(anomaly, _evidence(anomaly)), 0) >= threshold

    def enqueue(self, anomalies: list[dict[str, Any]]) -> int:
        added = 0
        with self._cond:
            for anomaly in anomalies:
                anomaly_id = int(anomaly["id"])
                if anomaly_id in self._queued or not self.wants(anomaly):
                    continue
                if len(self._queue) >= self.max_queue:
                    self.dropped += 1
                    continue
                self._queue.append(anomaly)
                self._queued.add(anomaly_id)
                added += 1
            if added:
                self._cond.notify_all()
        return added

    def pending(self) -> int:
        with self._cond:
            return len(self._queue)

    # -- lifecycle ----------------------------------------------------------------

    def start(self) -> None:
        for n in range(self.workers):
            thread = threading.Thread(target=self._loop, daemon=True, name=f"ai-summary-{n}")
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()
        for thread in self._threads:
            thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self._cond:
            return {"queued": len(self._queue), "in_progress": len(self._queued) - len(self._queue),
                    "summarized": self.summarized, "dropped": self.dropped, "workers": self.workers,
                    "last_error": self.last_error, "last_error_at": self.last_error_at}

    # -- work ---------------------------------------------------------------------

    def take_batch(self, timeout: float | None = 1.0) -> list[dict[str, Any]]:
        """The oldest queued anomaly plus up to batch_size-1 others sharing its
        namespace (non-empty) or its detection window."""
        with self._cond:
            if not self._queue and timeout:
                self._cond.wait(timeout)
            if not self._queue:
                return []
            first = self._queue.popleft()
            batch = [first]
            namespace, window = first.get("namespace") or "", _window(first)
            for anomaly in list(self._queue):
                if len(batch) >= self.batch_size:
                    break
                if (namespace and anomaly.get("namespace") == namespace) or (window and _window(anomaly) == window):
                    self._queue.remove(anomaly)
                    batch.append(anomaly)
            return batch

    def _loop(self) -> None:
        while not self._stop.is_set():
            batch = self.take_batch()
            if batch:
                self.process(batch)

    def _save(self, anomaly: dict[str, Any], response: dict[str, Any]) -> None:
        self.store.save_ai_summary(int(anomaly["id"]), response.get("summary") or "",
                                   response.get("suggested_action") or "", response.get("steps"),
                                   meta=meta_of(response))
        self.summarized += 1

    def process(self, batch: list[dict[str, Any]]) -> None:
        try:
            remaining = []
            for anomaly in batch:
                answer = self.explainer.anomaly_signature_answer(anomaly)
                if answer:
                    self.explainer.service.signature_hit(FEATURE)
                    self._save(anomaly, decorate(answer, source="signature", tier=None))
                    continue
                if not self.explainer.configured():
                    continue
                hit = self.explainer._cached(anomaly_cache_key("fast", anomaly), FEATURE, "fast")
                if hit:
                    self._save(anomaly, hit)
                    continue
                remaining.append(anomaly)
            if not remaining:
                return
            if len(remaining) == 1:
                response = self.explainer.summarize_anomaly(
                    remaining[0], feature=FEATURE, skip_signature=True, rate_limited=False)
                if response.get("degraded"):
                    self.dropped += 1
                    return
                self._save(remaining[0], response)
                return
            answers = self.explainer.summarize_batch(remaining, feature=FEATURE)
            if not answers:
                self.dropped += len(remaining)
            for anomaly in remaining:
                answer = answers.get(int(anomaly["id"]))
                if answer:
                    self._save(anomaly, answer)
        except Exception as exc:  # noqa: BLE001 - the worker keeps going; visible in /api/status
            self.last_error = str(exc)[:500]
            self.last_error_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            logger.warning("Automatic anomaly summary failed: %s", self.last_error)
        finally:
            with self._cond:
                for anomaly in batch:
                    self._queued.discard(int(anomaly["id"]))
