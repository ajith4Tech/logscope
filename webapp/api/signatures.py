"""Signature knowledge base: known log patterns answered without an AI call.

Built-in rules live in signatures.yaml next to this module; operators append
their own with webapp.ai.signatures in config.yaml (validated the same way,
tried after the built-ins). Every explain path consults the signatures first;
a match is answered with source "signature" and costs nothing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .actions import describe_action, resolve_action, step_execution_fields

BUILTIN_PATH = Path(__file__).with_name("signatures.yaml")
PLACEHOLDERS = ("namespace", "pod", "container")
# Values used to check that a rule's commands are valid once filled in.
SAMPLE_VALUES = {"namespace": "default", "pod": "web-7d9f8b6c5d-x2kqp", "container": "app"}
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_SEVERITIES = ("error", "warning", "info")
_RISKS = ("read-only",)
_MAX_RULES = 500
_MAX_TEXT = 4000
# Share of sampled rows that matched templates must cover before a filtered
# explanation is answered from signatures alone.
FILTERED_COVERAGE = 0.8


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class Signature:
    id: str
    title: str
    explanation: str
    severity: str
    steps: tuple[dict[str, str], ...]
    message_re: re.Pattern[str] | None = None
    falco_rule_re: re.Pattern[str] | None = None
    builtin: bool = True
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


def _text(rule: dict[str, Any], key: str, where: str, *, required: bool = True) -> str:
    value = rule.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value.strip():
        raise SignatureError(f"{where}: '{key}' must be a non-empty string")
    if len(value) > _MAX_TEXT:
        raise SignatureError(f"{where}: '{key}' is longer than {_MAX_TEXT} characters")
    return value.strip()


def fill_command(command: str, values: dict[str, Any]) -> str | None:
    """The command with its placeholders filled, or None when one is missing."""
    missing = False

    def sub(match: re.Match[str]) -> str:
        nonlocal missing
        value = str(values.get(match.group(1)) or "").strip()
        if not value:
            missing = True
        return value

    filled = _PLACEHOLDER_RE.sub(sub, command)
    return None if missing else filled


def validate_command(command: str, where: str) -> None:
    """Placeholders known, and once filled the command maps to a registered,
    read-only action (the same validator the Actionable tab uses)."""
    unknown = sorted(set(_PLACEHOLDER_RE.findall(command)) - set(PLACEHOLDERS))
    if unknown:
        raise SignatureError(f"{where}: unknown placeholder {{{unknown[0]}}}")
    filled = fill_command(command, SAMPLE_VALUES) or ""
    try:
        described = describe_action(resolve_action({"command": filled}))
    except ValueError as exc:
        raise SignatureError(f"{where}: command {command!r} is not a supported diagnostic ({exc})") from None
    if described["is_mutating"] or described["risk"] != "read-only":
        raise SignatureError(f"{where}: command {command!r} is not read-only")


def _compile(pattern: Any, where: str) -> re.Pattern[str] | None:
    if pattern is None:
        return None
    if not isinstance(pattern, str) or not pattern or len(pattern) > 1000:
        raise SignatureError(f"{where}: must be a regular expression string")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise SignatureError(f"{where}: invalid regular expression ({exc})") from None


def parse_rule(rule: Any, *, builtin: bool, index: int) -> Signature:
    where = f"signature #{index + 1}"
    if not isinstance(rule, dict):
        raise SignatureError(f"{where}: must be a mapping")
    unknown = sorted(set(rule) - {"id", "match", "severity", "title", "explanation", "steps"})
    if unknown:
        raise SignatureError(f"{where}: unknown key '{unknown[0]}'")
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not _RULE_ID_RE.match(rule_id):
        raise SignatureError(f"{where}: 'id' must match {_RULE_ID_RE.pattern}")
    where = f"signature {rule_id!r}"
    match = rule.get("match")
    if not isinstance(match, dict) or not match or set(match) - {"message", "falco_rule"}:
        raise SignatureError(f"{where}: 'match' needs 'message' and/or 'falco_rule'")
    severity = str(rule.get("severity") or "info").lower()
    if severity not in _SEVERITIES:
        raise SignatureError(f"{where}: 'severity' must be one of {list(_SEVERITIES)}")
    steps_raw = rule.get("steps") or []
    if not isinstance(steps_raw, list) or not 1 <= len(steps_raw) <= 5:
        raise SignatureError(f"{where}: 'steps' must list 1 to 5 steps")
    steps = []
    for n, step in enumerate(steps_raw, start=1):
        step_where = f"{where} step {n}"
        if not isinstance(step, dict) or set(step) - {"title", "command", "explanation", "risk"}:
            raise SignatureError(f"{step_where}: needs title, command, explanation, risk")
        risk = str(step.get("risk") or "read-only")
        if risk not in _RISKS:
            raise SignatureError(f"{step_where}: risk must be read-only")
        command = _text(step, "command", step_where)
        validate_command(command, step_where)
        steps.append({"title": _text(step, "title", step_where), "command": command,
                      "explanation": _text(step, "explanation", step_where), "risk": risk})
    return Signature(
        id=rule_id, title=_text(rule, "title", where), explanation=_text(rule, "explanation", where),
        severity=severity, steps=tuple(steps), message_re=_compile(match.get("message"), f"{where} match.message"),
        falco_rule_re=_compile(match.get("falco_rule"), f"{where} match.falco_rule"), builtin=builtin, raw=rule,
    )


def load_rules(user_rules: Iterable[Any] = (), *, builtin_path: Path = BUILTIN_PATH) -> tuple[Signature, ...]:
    """Built-in rules, then the operator's. Raises SignatureError on any invalid rule."""
    with builtin_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    builtin = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(builtin, list):
        raise SignatureError(f"{builtin_path}: 'rules' must be a list")
    user = list(user_rules or [])
    if len(builtin) + len(user) > _MAX_RULES:
        raise SignatureError(f"At most {_MAX_RULES} signatures")
    rules = [parse_rule(r, builtin=True, index=i) for i, r in enumerate(builtin)]
    rules += [parse_rule(r, builtin=False, index=i) for i, r in enumerate(user)]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise SignatureError(f"Duplicate signature id {rule.id!r}")
        seen.add(rule.id)
    return tuple(rules)


def falco_rule_name(record: dict[str, Any]) -> str:
    """The Falco rule name of a security event (from its JSON line), or ""."""
    if not record.get("is_falco") and record.get("scope") != "security":
        return ""
    raw = str(record.get("raw_line") or "")
    start = raw.find("{")
    if start < 0:
        return ""
    try:
        data = json.loads(raw[start:])
    except ValueError:
        return ""
    rule = data.get("rule") if isinstance(data, dict) else None
    return str(rule) if isinstance(rule, str) else ""


class SignatureKB:
    def __init__(self, rules: tuple[Signature, ...]):
        self.rules = rules

    def match(self, message: Any, falco_rule: str = "") -> Signature | None:
        text = str(message or "")
        for rule in self.rules:
            if falco_rule and rule.falco_rule_re is not None and rule.falco_rule_re.search(falco_rule):
                return rule
            if rule.message_re is not None and rule.message_re.search(text):
                return rule
        return None

    def match_record(self, record: dict[str, Any]) -> Signature | None:
        return self.match(record.get("message"), falco_rule_name(record))

    def answer(self, rule: Signature, values: dict[str, Any]) -> dict[str, Any]:
        """The explanation response for one matched rule; steps get the
        record's identifiers (a step without them keeps only its text)."""
        steps = []
        for step in rule.steps:
            command = fill_command(step["command"], values) or ""
            fields = step_execution_fields(command, step["risk"])
            if command and not fields["is_supported"]:
                command, fields = "", step_execution_fields("", step["risk"])
            explanation = step["explanation"] if command else (
                f"{step['explanation']} (needs the pod's namespace/name, not present in this record)")
            steps.append({"title": step["title"], "command": command, "explanation": explanation, **fields})
        first = steps[0] if steps else None
        suggested = ""
        if first:
            suggested = f"{first['command']} — {first['explanation']}" if first["command"] else first["explanation"]
        return {
            "summary": f"{rule.title}. {rule.explanation}",
            "steps": steps,
            "suggested_action": suggested,
            "source": "signature",
            "signature": {"id": rule.id, "title": rule.title, "severity": rule.severity, "builtin": rule.builtin},
        }

    def answer_many(self, matches: list[tuple[Signature, int, dict[str, Any]]], total: int) -> dict[str, Any]:
        """Combined answer for several matched templates (filtered explain):
        [(rule, row count, identifiers)] most frequent first."""
        parts, steps, seen_rules, seen_cmds = [], [], [], set()
        for rule, count, values in matches:
            if rule.id in seen_rules:
                continue
            seen_rules.append(rule.id)
            parts.append(f"{rule.title} ({count} of {total} sampled lines). {rule.explanation}")
            for step in self.answer(rule, values)["steps"]:
                key = step["command"] or step["title"]
                if key not in seen_cmds and len(steps) < 5:
                    seen_cmds.add(key)
                    steps.append(step)
        first = steps[0] if steps else None
        return {
            "summary": "\n\n".join(parts),
            "steps": steps,
            "suggested_action": (f"{first['command']} — {first['explanation']}" if first and first["command"]
                                 else (first or {}).get("explanation", "")),
            "source": "signature",
            "signature": {"id": ",".join(seen_rules), "title": "; ".join(
                r.title for r in self.rules if r.id in seen_rules)},
        }
