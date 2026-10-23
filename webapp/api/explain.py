"""Every AI explanation path, cheapest answer first:

1. signature  - a known pattern from the signature KB (free, outcome=signature)
2. cache      - an earlier answer for the same log template (outcome=cache_hit)
3. AI         - one metered provider call (fast tier = settings.model, deep
                tier = settings.deep_model), shared by identical in-flight
                requests (single-flight) and stored in the cache.

Responses carry source (signature | cache | ai), tier, generated_at, age_secs
and cache_key (for 👍/👎 and Regenerate).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .actions import step_execution_fields
from .ai_cache import AiCache
from .ai_settings import AiService, AiSettings, metered_feature
from .ai_summary import compact_log_payload, redact_text
from .patterns import count_bucket, digest_records, namespace_pattern, normalize_message, record_template
from .signatures import FILTERED_COVERAGE, Signature, SignatureKB, fill_command

FILTERED_SAMPLE_ROWS = 500  # rows sampled for the template digest of a filtered explain
TOP_TEMPLATES = 15


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ids(record: dict[str, Any]) -> dict[str, str]:
    return {k: str(record.get(k) or "") for k in ("namespace", "pod", "container")}


# Cached answers are stored with the source record's names as placeholders
# and filled with the requesting record's names when served.
PLACEHOLDERS = {"namespace": "{namespace}", "pod": "{pod}", "container": "{container}"}
_PRIORITY = ("pod", "container", "namespace")  # same string for two fields: the most specific wins
_NAME_CHARS = r"[A-Za-z0-9_-]"
_CONTEXT_WORDS = r"(?:namespace|ns|pod|container|-n|-c|--namespace|--container)"
_PLACEHOLDER_RE = re.compile(r"\{(namespace|pod|container)\}")


def _distinctive(name: str) -> bool:
    """A name unlikely to be an ordinary word (has a digit, '-' or '.', or is
    long). Plain words like "default" or "app" are replaced in prose only
    where they are clearly used as a name."""
    return bool(re.search(r"[\d.-]", name)) or len(name) >= 12


def _token(name: str) -> str:
    # Whole names only: not inside a longer name ("app" in "application",
    # "default" in "default-backend"); "web-0." at a sentence end still counts.
    return rf"(?<![\w.-]){re.escape(name)}(?![\w-])(?!\.\w)"


def _ordered_names(values: dict[str, str]) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for field in _PRIORITY:
        name = str(values.get(field) or "")
        if name and name not in seen:
            seen[name] = field
    return sorted(((name, field) for name, field in seen.items()), key=lambda item: -len(item[0]))


def templatize_text(text: Any, values: dict[str, str], *, command: bool) -> str:
    """Replace the record's namespace/pod/container in one string with
    {namespace}/{pod}/{container}, longest name first, whole names only. In
    commands every occurrence is a name; in prose a plain word is replaced
    only next to "namespace"/"pod"/"container"/-n/-c, in quotes or in a path."""
    text = str(text or "")
    for name, field in _ordered_names(values):
        placeholder = PLACEHOLDERS[field]
        token = _token(name)
        if command or _distinctive(name):
            text = re.sub(token, placeholder, text)
            continue
        quoted = re.escape(name)
        for pattern, repl in (
            (rf"(?i)(\b{_CONTEXT_WORDS}\s+[\"'`]?){quoted}(?![\w-])", rf"\g<1>{placeholder}"),
            (rf"(?<![\w.-]){quoted}(?=\s+(?i:namespace|pod|container)\b)", placeholder),
            (rf"(?<=[\"'`]){quoted}(?=[\"'`])", placeholder),
            (rf"(?<![\w.-]){quoted}(?=/[\w{{])", placeholder),
            (rf"(?<=[\w}}]/){quoted}(?![\w-])", placeholder),
        ):
            text = re.sub(pattern, repl, text)
    return text


def templatize(response: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """The answer as stored in the cache, independent of the source record."""
    steps = [{**step, "title": templatize_text(step.get("title"), values, command=False),
              "command": templatize_text(step.get("command"), values, command=True),
              "explanation": templatize_text(step.get("explanation"), values, command=False)}
             for step in response.get("steps") or []]
    return {**response, "summary": templatize_text(response.get("summary"), values, command=False),
            "suggested_action": templatize_text(response.get("suggested_action"), values, command=False),
            "steps": steps, "_templated": True}


def _fill_prose(text: Any, values: dict[str, str]) -> str:
    return _PLACEHOLDER_RE.sub(lambda m: values.get(m.group(1)) or f"the {m.group(1)}", str(text or ""))


def fill(response: dict[str, Any], values: dict[str, str] | None) -> dict[str, Any]:
    """A stored answer for this record: placeholders filled with its names,
    every command re-validated (a command whose name is missing is dropped)."""
    if not response.get("_templated"):
        return response
    values = values or {}
    steps = []
    for step in response.get("steps") or []:
        raw = str(step.get("command") or "")
        command = fill_command(raw, values) if raw else ""
        steps.append({"title": _fill_prose(step.get("title"), values), "command": command or "",
                      "explanation": _fill_prose(step.get("explanation"), values),
                      **step_execution_fields(command or "", step.get("risk"))})
    return {**response, "summary": _fill_prose(response.get("summary"), values),
            "suggested_action": _fill_prose(response.get("suggested_action"), values), "steps": steps}


def decorate(result: dict[str, Any], *, source: str, tier: str | None, cache_key: str = "",
             generated_at: str = "", age_secs: int = 0) -> dict[str, Any]:
    out = {k: v for k, v in result.items() if not k.startswith("_")}
    out.update(source=source, tier=tier, cache_key=cache_key, generated_at=generated_at or _now_iso(),
               age_secs=age_secs, cached=source == "cache")
    if source == "signature":
        out["can_ask_ai"] = True  # the UI offers "Ask AI anyway"
    return out


def filtered_cache_key(tier: str, digest: dict[str, Any]) -> str:
    shape = sorted([t["template_id"], count_bucket(t["count"])] for t in digest["templates"])
    return f"filtered:{tier}:" + hashlib.sha1(json.dumps(shape).encode(), usedforsecurity=False).hexdigest()


def line_cache_key(tier: str, record: dict[str, Any]) -> tuple[str, str]:
    tid, _ = record_template(record)
    return f"line:{tier}:{tid}:{record.get('severity_bucket') or ''}", tid


def anomaly_cache_key(tier: str, anomaly: dict[str, Any]) -> str:
    # Namespace pattern included: error spikes have an empty rule_key, and a
    # summary for one namespace must not answer for another.
    rule = hashlib.sha1(normalize_message(anomaly.get("rule_key") or "").encode(),
                        usedforsecurity=False).hexdigest()[:16]
    return f"anomaly:{tier}:{anomaly.get('type') or ''}:{namespace_pattern(anomaly.get('namespace'))}:{rule}"


def _evidence(anomaly: dict[str, Any]) -> dict[str, Any]:
    evidence = anomaly.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = {}
    return evidence if isinstance(evidence, dict) else {}


def anomaly_signature(kb: SignatureKB, anomaly: dict[str, Any]) -> Signature | None:
    evidence = _evidence(anomaly)
    messages = [m for m in (evidence.get("sample_messages") or []) if isinstance(m, str)]
    falco_rule = anomaly.get("rule_key") if anomaly.get("type") == "new_falco_rule" else ""
    for message in [anomaly.get("rule_key") or "", *messages]:
        rule = kb.match(message, str(falco_rule or ""))
        if rule:
            return rule
    return None


def anomaly_template_summary(kb: SignatureKB, anomaly: dict[str, Any]) -> dict[str, Any]:
    """The free summary shown before (or instead of) any AI call: what
    changed, counts against the baseline, top templates, matching signature."""
    ev = _evidence(anomaly)
    kind = str(anomaly.get("type") or "")
    where = "/".join(x for x in (anomaly.get("namespace"), anomaly.get("pod")) if x) or "the cluster"
    count = ev.get("current_count")
    expected = ev.get("expected_count")
    minutes = ev.get("observed_minutes")
    days = ev.get("baseline_window_days")
    ratio = None
    try:
        if expected is not None and float(expected) > 0:
            ratio = round(float(count) / float(expected), 1)
    except (TypeError, ValueError):
        ratio = None
    span = f" in {minutes:g} min" if isinstance(minutes, (int, float)) else ""
    vs = (f", {ratio:g}× the {float(expected):g} expected from the last {days} days" if ratio is not None
          else (f", with no comparable activity in the last {days} days" if days else ""))
    if kind == "error_rate_spike":
        headline = f"{count} error lines in {where}{span}{vs}."
    elif kind == "message_frequency":
        headline = f"One message pattern in {where} appeared {count} times{span}{vs}."
    elif kind == "severity_shift":
        try:
            headline = (f"Share of {anomaly.get('severity') or 'this severity'} lines in {where} moved from "
                        f"{float(ev.get('baseline_share', 0)):.0%} to {float(ev.get('current_share', 0)):.0%}.")
        except (TypeError, ValueError):
            headline = f"The severity mix in {where} changed."
    elif kind == "new_falco_rule":
        headline = (f"Falco rule seen for the first time in {days or 'several'} days: {count} event(s){span}.")
    else:
        headline = f"{kind or 'Anomaly'} in {where}."
    messages = [m for m in (ev.get("sample_messages") or []) if isinstance(m, str)]
    digest = digest_records([{"message": m, "namespace": anomaly.get("namespace")} for m in messages],
                            top=5, exemplars=0, redact=redact_text)
    rule = anomaly_signature(kb, anomaly)
    return {
        "headline": headline,
        "counts": {"current": count, "expected": expected, "baseline_avg_per_hour": ev.get("baseline_avg_per_hour"),
                   "ratio": ratio, "baseline_share": ev.get("baseline_share"), "current_share": ev.get("current_share")},
        "templates": [{"template": t["template"], "count": t["count"]} for t in digest["templates"]],
        "signature": ({"id": rule.id, "title": rule.title, "explanation": rule.explanation, "severity": rule.severity}
                      if rule else None),
    }


class Explainer:
    """Shared by the HTTP handlers and the anomaly summary worker. The
    provider functions are injected (the server passes its own module-level
    names, which tests replace)."""

    def __init__(self, *, settings: AiSettings, service: AiService, cache: AiCache, kb: SignatureKB,
                 line_fn: Callable, logs_fn: Callable, anomaly_fn: Callable, batch_fn: Callable,
                 rate_limit: Callable[[], None] | None = None, configured: Callable[[], bool] | None = None):
        self.settings = settings
        self.service = service
        self.cache = cache
        self.kb = kb
        self.line_fn = line_fn
        self.logs_fn = logs_fn
        self.anomaly_fn = anomaly_fn
        self.batch_fn = batch_fn
        self.rate_limit = rate_limit
        self.configured = configured or settings.configured

    # -- shared steps -----------------------------------------------------------

    def _require_configured(self) -> None:
        if not self.configured():
            raise ValueError("AI provider is not configured")

    def _cached(self, key: str, feature: str, tier: str, values: dict[str, str] | None = None) -> dict | None:
        entry = self.cache.get(key)
        if not entry or not (entry["response"].get("steps") or entry["response"].get("summary")):
            return None
        self.service.cache_hit(feature, tier)
        response = fill(entry["response"], values)
        return decorate(response, source="cache", tier=tier, cache_key=key, generated_at=entry["created_at"],
                        age_secs=entry["age_secs"])

    def _call_cached(self, *, key: str, kind: str, feature: str, tier: str, template_id: str,
                     fn: Callable, input_chars: int, values: dict[str, str] | None = None,
                     rate_limited: bool = True, subjects: list[str] | None = None) -> dict[str, Any]:
        """One provider call per key at a time; the answer is cached when it
        has steps. Followers of an in-flight call get its answer as a cache hit."""

        def compute() -> dict[str, Any]:
            result = self.service.call(feature, fn, input_chars=input_chars, tier=tier, subjects=subjects,
                                       before_call=self.rate_limit if rate_limited else None)
            if result is None:
                raise RuntimeError("AI summarization returned no result")
            if result.get("degraded"):
                return result
            stored = {**(templatize(result, values) if values else result), "_generated_at": _now_iso()}
            if result.get("steps"):
                self.cache.put(key, kind=kind, tier=tier, response=stored, template_id=template_id)
            return stored

        result, shared = self.cache.flight.do(key, compute)
        if result.get("degraded"):
            return {**result, "cached": False, "tier": tier}
        if shared:
            self.service.cache_hit(feature, tier)
        response = fill(result, values)
        return decorate(response, source="cache" if shared else "ai", tier=tier,
                        cache_key=key if result.get("steps") else "", generated_at=result.get("_generated_at", ""))

    # -- explain one line -------------------------------------------------------

    def explain_line(self, record: dict[str, Any], *, tier: str = "fast", regenerate: bool = False,
                     skip_signature: bool = False) -> dict[str, Any]:
        values = _ids(record)
        if not skip_signature:
            rule = self.kb.match_record(record)
            if rule:
                self.service.signature_hit("explain_line")
                return decorate(self.kb.answer(rule, values), source="signature", tier=None)
        self._require_configured()
        key, tid = line_cache_key(tier, record)
        if not regenerate:
            hit = self._cached(key, "explain_line", tier, values)
            if hit:
                return hit
        line_fn = self.line_fn
        return self._call_cached(
            key=key, kind="line", feature="explain_line", tier=tier, template_id=tid, values=values,
            fn=lambda cfg: line_fn(record, cfg), input_chars=len(json.dumps(record, default=str)),
        )

    # -- explain filtered logs --------------------------------------------------

    def explain_filtered(self, filters: dict[str, Any], records: list[dict[str, Any]], *, sample_limit_reached: bool,
                         tier: str = "fast", regenerate: bool = False, skip_signature: bool = False) -> dict[str, Any]:
        extra = {"sample_count": len(records), "total_matching_exceeds_sample": sample_limit_reached}
        if not skip_signature:
            answer = self._filtered_signature(records)
            if answer:
                self.service.signature_hit("explain_filtered")
                return {**decorate(answer, source="signature", tier=None), **extra}
        self._require_configured()
        digest = digest_records(records, top=TOP_TEMPLATES, exemplars=0)
        key = filtered_cache_key(tier, digest)
        if not regenerate:
            hit = self._cached(key, "explain_filtered", tier)
            if hit:
                return {**hit, **extra}
        payload = compact_log_payload(records, filters, sample_limit_reached=sample_limit_reached, top=TOP_TEMPLATES)
        logs_fn = self.logs_fn
        result = self._call_cached(
            key=key, kind="filtered", feature="explain_filtered", tier=tier, template_id="",
            fn=lambda cfg: logs_fn(payload, cfg), input_chars=len(json.dumps(payload, default=str)),
        )
        return {**result, **extra}

    def _filtered_signature(self, records: list[dict[str, Any]]) -> dict[str, Any] | None:
        groups: dict[str, list] = {}
        for record in records:
            tid, _ = record_template(record)
            if tid in groups:
                groups[tid][0] += 1
            else:
                groups[tid] = [1, record]
        matches, covered = [], 0
        for count, record in sorted(groups.values(), key=lambda g: -g[0]):
            rule = self.kb.match_record(record)
            if rule:
                matches.append((rule, count, _ids(record)))
                covered += count
        if not records or covered / len(records) < FILTERED_COVERAGE:
            return None
        return self.kb.answer_many(matches[:5], len(records))

    # -- anomalies --------------------------------------------------------------

    def anomaly_signature_answer(self, anomaly: dict[str, Any]) -> dict[str, Any] | None:
        rule = anomaly_signature(self.kb, anomaly)
        return self.kb.answer(rule, _ids(anomaly)) if rule else None

    def summarize_anomaly(self, anomaly: dict[str, Any], *, feature: str = "anomaly_manual_summary",
                          tier: str = "fast", regenerate: bool = False, skip_signature: bool = False,
                          rate_limited: bool = True) -> dict[str, Any]:
        if not skip_signature:
            answer = self.anomaly_signature_answer(anomaly)
            if answer:
                self.service.signature_hit(feature)
                return decorate(answer, source="signature", tier=None)
        self._require_configured()
        key = anomaly_cache_key(tier, anomaly)
        if not regenerate:
            hit = self._cached(key, feature, tier, _ids(anomaly))
            if hit:
                return hit
        anomaly_fn = self.anomaly_fn
        return self._call_cached(
            key=key, kind="anomaly", feature=feature, tier=tier, template_id="", values=_ids(anomaly),
            fn=lambda cfg: anomaly_fn(anomaly, cfg), input_chars=len(json.dumps(anomaly, default=str)),
            rate_limited=rate_limited, subjects=[f"anomaly:{anomaly['id']}"] if anomaly.get("id") is not None else None,
        )

    def summarize_batch(self, anomalies: list[dict[str, Any]], *, feature: str) -> dict[int, dict[str, Any]]:
        """One provider call for several anomalies (fast tier). Each answer is
        cached under its own anomaly key. Returns {id: decorated response};
        a budget block returns {} (the anomalies stay pending)."""
        batch_fn = self.batch_fn
        result = self.service.call(
            feature, lambda cfg: batch_fn(anomalies, cfg),
            input_chars=len(json.dumps(anomalies, default=str)),
            subjects=[f"anomaly:{a['id']}" for a in anomalies],
        )
        if not isinstance(result, dict) or result.get("degraded"):
            return {}
        out: dict[int, dict[str, Any]] = {}
        by_id = {int(a["id"]): a for a in anomalies}
        for anomaly_id, answer in result.items():
            anomaly = by_id.get(int(anomaly_id))
            if anomaly is None:
                continue
            key = anomaly_cache_key("fast", anomaly)
            stored = {**templatize(answer, _ids(anomaly)), "_generated_at": _now_iso()}
            if answer.get("steps"):
                self.cache.put(key, kind="anomaly", tier="fast", response=stored)
            out[int(anomaly_id)] = decorate(fill(stored, _ids(anomaly)), source="ai", tier="fast", cache_key=key)
        return out


def meta_of(response: dict[str, Any]) -> dict[str, Any]:
    """What is stored with an anomaly's summary (ai_meta)."""
    return {k: response.get(k) for k in ("source", "tier", "generated_at", "cache_key", "signature") if response.get(k)}


__all__ = ["Explainer", "anomaly_template_summary", "meta_of", "metered_feature", "FILTERED_SAMPLE_ROWS"]
