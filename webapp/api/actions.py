"""Controlled execution and validation for Kubernetes diagnostic actions.

Arbitrary shell execution is strictly disallowed:
- No shell=True
- No os.system()
- No direct execution of arbitrary AI-generated shell strings

Actions are validated against a strict registry of supported Kubernetes
diagnostic operations. Read-only diagnostic actions run directly.
Mutating actions (such as rollout restart or rollback) require explicit confirmation.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shlex
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

# RFC 1123 DNS label: lowercase alphanumeric, hyphens allowed, 1-63 chars
_K8S_LABEL_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
# RFC 1123 DNS subdomain: lowercase alphanumeric, hyphens and dots allowed, 1-253 chars
_K8S_SUBDOMAIN_RE = re.compile(r"^[a-z0-9]([-a-z0-9\.]*[a-z0-9])?$")
# Container name: alphanumeric, hyphens, underscores, dots, 1-63 chars
_K8S_CONTAINER_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

_ALLOWED_OUTPUT_FORMATS = frozenset({"wide", "json", "yaml"})
_COMMAND_TIMEOUT_SECONDS = 15
_DEFAULT_LOG_TAIL_LINES = 100
_MAX_LOG_TAIL_LINES = 1000
# kubectl logs stops reading after this many bytes (--limit-bytes), and every
# command's stdout/stderr is cut to _MAX_OUTPUT_CHARS before it is returned.
_MAX_LOG_BYTES = 256 * 1024
_MAX_OUTPUT_CHARS = 256 * 1024
# Bytes read from each of stdout/stderr; the process is stopped beyond this,
# so a huge `get -o yaml` cannot exhaust the web app's memory.
_MAX_OUTPUT_BYTES = 1024 * 1024
# Longer suggested commands are not parsed (no registered action needs one).
_MAX_COMMAND_CHARS = 2000
# kubectl runs with only these variables from the web app's environment, so
# AI provider keys and S3 credentials never reach it (or its plugins).
_COMMAND_ENV_KEYS = (
    "PATH", "HOME", "KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
    "LANG", "LC_ALL", "TZ",
)

# Ordered from least to most dangerous; see assess_step_risk.
_RISK_LEVELS = ("read-only", "medium", "high")
# Shell control and substitution syntax. A suggestion containing any of it is
# never parsed into an action (only part of it would run) and is rated high,
# since pasting it into a shell runs everything.
_SHELL_SYNTAX_RE = re.compile(r"[;|&`<>\n\r]|\$\(|\$\{")
_RISK_ALIASES = {
    "read-only": "read-only", "readonly": "read-only", "low": "read-only", "safe": "read-only",
    "medium": "medium", "modifying": "medium", "mutating": "medium",
    "high": "high", "dangerous": "high", "destructive": "high",
}


def validate_namespace(ns: str | None) -> str:
    """Validate Kubernetes namespace. Returns cleaned namespace or empty string."""
    if not ns:
        return ""
    ns_str = str(ns).strip()
    if not ns_str:
        return ""
    if len(ns_str) > 63 or not _K8S_LABEL_RE.match(ns_str):
        raise ValueError(f"Invalid namespace name: {ns_str!r}")
    return ns_str


def validate_resource_name(name: str) -> str:
    """Validate Kubernetes resource name."""
    name_str = str(name).strip()
    if not name_str:
        raise ValueError("Resource name cannot be empty")
    if len(name_str) > 253 or not _K8S_SUBDOMAIN_RE.match(name_str):
        raise ValueError(f"Invalid resource name: {name_str!r}")
    return name_str


def validate_container_name(container: str | None) -> str:
    """Validate Kubernetes container name."""
    if not container:
        return ""
    c_str = str(container).strip()
    if not c_str:
        return ""
    if len(c_str) > 63 or not _K8S_CONTAINER_RE.match(c_str):
        raise ValueError(f"Invalid container name: {c_str!r}")
    return c_str


# ─────────────────────────────────────────────────────────────────────────────
# Action Registry
# ─────────────────────────────────────────────────────────────────────────────

SUPPORTED_ACTIONS: dict[str, dict[str, Any]] = {
    "get_pod": {
        "description": "Get pod status and metadata",
        "risk": "read-only",
        "is_mutating": False,
    },
    "get_pods": {
        "description": "List pods in namespace",
        "risk": "read-only",
        "is_mutating": False,
    },
    "describe_pod": {
        "description": "Describe pod details and events",
        "risk": "read-only",
        "is_mutating": False,
    },
    "get_pod_logs": {
        "description": "Fetch recent logs from pod container",
        "risk": "read-only",
        "is_mutating": False,
    },
    "get_events": {
        "description": "List events in namespace",
        "risk": "read-only",
        "is_mutating": False,
    },
    "get_deployment": {
        "description": "Get deployment status",
        "risk": "read-only",
        "is_mutating": False,
    },
    "describe_deployment": {
        "description": "Describe deployment configuration and conditions",
        "risk": "read-only",
        "is_mutating": False,
    },
    "rollout_status": {
        "description": "Check rollout status for a deployment",
        "risk": "read-only",
        "is_mutating": False,
    },
    # Controlled mutating actions (require explicit confirmation in UI)
    "rollout_restart": {
        "description": "Restart a deployment (mutating)",
        "risk": "medium",
        "is_mutating": True,
    },
    "rollout_undo": {
        "description": "Rollback a deployment to previous revision (mutating)",
        "risk": "medium",
        "is_mutating": True,
    },
}


# Command-line options a suggested kubectl command may carry. Value options
# set a field of the structured action; a field the matched action does not
# use is reported in ignored_args.
_VALUE_OPTIONS = {
    "-n": "namespace", "--namespace": "namespace",
    "-o": "output", "--output": "output",
    "-c": "container", "--container": "container",
    "--tail": "tail",
}
_BOOL_OPTIONS = {"-p": "previous", "--previous": "previous", "-f": "follow", "--follow": "follow"}
# Accepted but never passed to kubectl: they only narrow or reformat a read.
# Anything else (--context, --kubeconfig, --server, --as, --dry-run, -f FILE,
# --to-revision, ...) makes the command unsupported, because dropping it
# would run something different from what was suggested, and whether an
# unknown flag consumes the next word cannot be known.
_IGNORABLE_BOOL_FLAGS = frozenset({
    "-A", "--all-namespaces", "-w", "--watch", "--timestamps",
    "--show-labels", "--no-headers", "--show-kind",
})
_IGNORABLE_VALUE_FLAGS = frozenset({
    "-l", "--selector", "--field-selector", "--sort-by", "--since", "--since-time",
    "--request-timeout", "--limit-bytes", "--max-log-requests",
})
# The structured fields each action uses (besides "action" and "resource").
_ACTION_FIELDS = {
    "get_pod": ("namespace", "output"),
    "get_pods": ("namespace", "output"),
    "describe_pod": ("namespace",),
    "get_pod_logs": ("namespace", "container", "tail", "previous"),
    "get_events": ("namespace",),
    "get_deployment": ("namespace", "output"),
    "describe_deployment": ("namespace",),
    "rollout_status": ("namespace",),
    "rollout_restart": ("namespace",),
    "rollout_undo": ("namespace",),
}
_FIELD_DEFAULTS = {"namespace": "", "output": "", "container": "", "tail": _DEFAULT_LOG_TAIL_LINES, "previous": False}
_POD_TYPES = frozenset({"pod", "pods", "po"})
_DEPLOYMENT_TYPES = frozenset({"deployment", "deployments", "deploy", "deployment.apps", "deployments.apps"})


def _split_type_name(args: list[str]) -> tuple[str, str, int] | None:
    """(type, name, words used) for "TYPE NAME" or "TYPE/NAME" at args[0].
    Name is "" when only a type is given."""
    if not args:
        return None
    if "/" in args[0]:
        res_type, _, name = args[0].partition("/")
        return (res_type.lower(), name, 1) if res_type and name else None
    if len(args) > 1:
        return args[0].lower(), args[1], 2
    return args[0].lower(), "", 1


def _match_positionals(words: list[str]) -> dict[str, Any] | None:
    """Map the non-flag words to one registered action. Every word must be
    accounted for: an extra or unrecognised word makes the command unsupported
    instead of being dropped."""
    if not words:
        return None
    verb, rest = words[0].lower(), words[1:]
    target = _split_type_name(rest)
    if verb == "get" and target:
        res_type, name, used = target
        if used != len(rest):
            return None
        if res_type in _POD_TYPES:
            return {"action": "get_pod" if name else "get_pods", "resource": name}
        if res_type in ("events", "event", "ev") and not name:
            return {"action": "get_events", "resource": ""}
        if res_type in _DEPLOYMENT_TYPES and name:
            return {"action": "get_deployment", "resource": name}
    elif verb == "describe" and target:
        res_type, name, used = target
        if used != len(rest) or not name:
            return None
        if res_type in _POD_TYPES:
            return {"action": "describe_pod", "resource": name}
        if res_type in _DEPLOYMENT_TYPES:
            return {"action": "describe_deployment", "resource": name}
    elif verb in ("logs", "log") and rest and len(rest) <= 2:
        name = rest[0]
        if "/" in name:
            res_type, _, name = name.partition("/")
            if res_type.lower() not in _POD_TYPES or not name:
                return None  # e.g. deployment/x: kubectl would pick a pod
        parsed: dict[str, Any] = {"action": "get_pod_logs", "resource": name}
        if len(rest) == 2:  # kubectl logs POD CONTAINER
            parsed["container"] = rest[1]
        return parsed
    elif verb == "rollout" and len(rest) >= 2:
        sub = rest[0].lower()
        target = _split_type_name(rest[1:])
        actions = {"status": "rollout_status", "restart": "rollout_restart", "undo": "rollout_undo"}
        if sub in actions and target:
            res_type, name, used = target
            # A bare name is not a valid kubectl rollout target; it is not
            # guessed to be a deployment.
            if used == len(rest) - 1 and name and res_type in _DEPLOYMENT_TYPES:
                return {"action": actions[sub], "resource": name}
    return None


def parse_command_to_action(cmd_str: str) -> dict[str, Any] | None:
    """Parse a kubectl command line into a structured action dict.

    Returns None unless the whole command maps to one registered action:
    shell syntax, unknown flags, a flag without its value, extra words, or
    (for actions that change state) any flag that would be left out all make
    it unsupported. Flags that only narrow or reformat a read-only command
    are left out and listed in ignored_args.
    """
    text = str(cmd_str or "").strip()
    if not text or len(text) > _MAX_COMMAND_CHARS or _SHELL_SYNTAX_RE.search(text):
        return None
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    if len(tokens) < 2 or tokens[0] != "kubectl":
        return None

    options: dict[str, tuple[Any, list[str]]] = {}
    ignored: list[str] = []
    words: list[str] = []
    args = tokens[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if not arg.startswith("-") or arg == "-":
            words.append(arg)
            continue
        name, eq, inline = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if name in _VALUE_OPTIONS or name in _IGNORABLE_VALUE_FLAGS:
            if eq:
                value, used = inline, [arg]
            elif i < len(args):
                value, used = args[i], [arg, args[i]]
                i += 1
            else:
                return None  # flag without its value
            if name in _VALUE_OPTIONS:
                options[_VALUE_OPTIONS[name]] = (value, used)
            else:
                ignored.extend(used)
        elif name in _BOOL_OPTIONS:
            if eq and inline.lower() not in ("true", "false"):
                return None
            options[_BOOL_OPTIONS[name]] = (inline.lower() != "false", [arg])
        elif name in _IGNORABLE_BOOL_FLAGS and not eq:
            ignored.append(arg)
        else:
            return None

    parsed = _match_positionals(words)
    if parsed is None:
        return None
    action = parsed["action"]
    if "follow" in options and action != "get_pod_logs":
        return None  # -f is a file name for other verbs
    fields = _ACTION_FIELDS[action]
    for field in fields:
        parsed.setdefault(field, _FIELD_DEFAULTS[field])
    for field, (value, used) in options.items():
        if field not in fields:
            ignored.extend(used)
        elif field == "tail":
            try:
                tail = int(value)
            except ValueError:
                return None
            # kubectl's --tail=-1 means "all lines"; the bounded maximum runs.
            parsed["tail"] = _MAX_LOG_TAIL_LINES if tail < 0 else tail
        elif field == "output" and str(value).lower() not in _ALLOWED_OUTPUT_FORMATS:
            ignored.extend(used)
        elif field == "container" and parsed.get("container") and parsed["container"] != value:
            return None  # container given twice, differently
        else:
            parsed[field] = value.lower() if field == "output" else value
    if ignored:
        if SUPPORTED_ACTIONS[action]["is_mutating"]:
            # e.g. --dry-run, --to-revision: running the action without them
            # is not what was suggested.
            return None
        parsed["ignored_args"] = ignored
    return parsed


def build_kubectl_argv(action: dict[str, Any]) -> list[str]:
    """Construct a validated argv list for subprocess.run.

    Validates action name, namespace, resource name, and parameters.
    Raises ValueError on validation failure.
    """
    action_type = str(action.get("action") or "").strip()
    if action_type not in SUPPORTED_ACTIONS:
        raise ValueError(f"Unsupported action: {action_type!r}")

    namespace = validate_namespace(action.get("namespace"))
    resource = str(action.get("resource") or "").strip()
    output_fmt = str(action.get("output") or "").strip().lower()

    if output_fmt and output_fmt not in _ALLOWED_OUTPUT_FORMATS:
        output_fmt = ""

    argv: list[str] = ["kubectl"]

    if action_type == "get_pod":
        res_clean = validate_resource_name(resource)
        argv.extend(["get", "pod", res_clean])
        if namespace:
            argv.extend(["-n", namespace])
        if output_fmt:
            argv.extend(["-o", output_fmt])

    elif action_type == "get_pods":
        argv.extend(["get", "pods"])
        if namespace:
            argv.extend(["-n", namespace])
        if output_fmt:
            argv.extend(["-o", output_fmt])

    elif action_type == "describe_pod":
        res_clean = validate_resource_name(resource)
        argv.extend(["describe", "pod", res_clean])
        if namespace:
            argv.extend(["-n", namespace])

    elif action_type == "get_pod_logs":
        res_clean = validate_resource_name(resource)
        argv.extend(["logs", res_clean])
        if namespace:
            argv.extend(["-n", namespace])
        container = validate_container_name(action.get("container"))
        if container:
            argv.extend(["-c", container])
        # Always bounded: an absent or invalid tail uses the default, and
        # --limit-bytes caps very long lines.
        try:
            tail_int = int(action.get("tail"))
            # Negative means "all lines" to kubectl; run the bounded maximum.
            tail_int = _MAX_LOG_TAIL_LINES if tail_int < 0 else max(1, min(tail_int, _MAX_LOG_TAIL_LINES))
        except (ValueError, TypeError):
            tail_int = _DEFAULT_LOG_TAIL_LINES
        argv.extend([f"--tail={tail_int}", f"--limit-bytes={_MAX_LOG_BYTES}"])
        if _as_bool(action.get("previous")):
            argv.append("--previous")

    elif action_type == "get_events":
        argv.extend(["get", "events"])
        if namespace:
            argv.extend(["-n", namespace])
        argv.append("--sort-by=.metadata.creationTimestamp")

    elif action_type == "get_deployment":
        res_clean = validate_resource_name(resource)
        argv.extend(["get", "deployment", res_clean])
        if namespace:
            argv.extend(["-n", namespace])
        if output_fmt:
            argv.extend(["-o", output_fmt])

    elif action_type == "describe_deployment":
        res_clean = validate_resource_name(resource)
        argv.extend(["describe", "deployment", res_clean])
        if namespace:
            argv.extend(["-n", namespace])

    elif action_type == "rollout_status":
        res_clean = validate_resource_name(resource)
        argv.extend(["rollout", "status", f"deployment/{res_clean}"])
        if namespace:
            argv.extend(["-n", namespace])
        argv.append("--timeout=10s")

    elif action_type == "rollout_restart":
        res_clean = validate_resource_name(resource)
        argv.extend(["rollout", "restart", f"deployment/{res_clean}"])
        if namespace:
            argv.extend(["-n", namespace])

    elif action_type == "rollout_undo":
        res_clean = validate_resource_name(resource)
        argv.extend(["rollout", "undo", f"deployment/{res_clean}"])
        if namespace:
            argv.extend(["-n", namespace])

    else:
        raise ValueError(f"Action '{action_type}' does not have a registered builder")

    return argv


def _as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value == 1)


_STRUCTURED_FIELDS = ("namespace", "resource", "output", "container", "tail", "previous")


def resolve_action(action_data: dict[str, Any]) -> dict[str, Any]:
    """Turn a request body into one registered, structured action.

    Accepted shapes, in order of preference:
      {"action": {"action": "get_pod_logs", "namespace": ..., "container": ..., ...}}
      {"action": "get_pod_logs", "namespace": ..., ...}   (flat, older clients)
      {"command": "kubectl logs ..."}                      (parsed, allowlist only)
    Raises ValueError when nothing maps to a registered action.
    """
    raw_action = action_data.get("action")
    source: dict[str, Any] | None = None
    if isinstance(raw_action, dict) and str(raw_action.get("action") or "") in SUPPORTED_ACTIONS:
        source = raw_action
    elif isinstance(raw_action, str) and raw_action in SUPPORTED_ACTIONS:
        source = action_data
    else:
        command_str = str(action_data.get("command") or "").strip()
        if command_str:
            source = parse_command_to_action(command_str)
    if not source:
        raise ValueError(
            "Unsupported or invalid action. Only registered Kubernetes diagnostic "
            "commands (e.g. get pod, describe pod, logs, events, deployment status) "
            "are allowed."
        )
    structured: dict[str, Any] = {"action": str(source["action"])}
    for field in _STRUCTURED_FIELDS:
        if source.get(field) not in (None, ""):
            structured[field] = source[field]
    if source.get("ignored_args"):
        structured["ignored_args"] = [str(a) for a in source["ignored_args"]]
    return structured


def describe_action(structured: dict[str, Any]) -> dict[str, Any]:
    """Validate a structured action and return exactly what would run: the
    registry's risk, whether it mutates, and the kubectl command line.
    Raises ValueError for invalid names or unregistered actions."""
    argv = build_kubectl_argv(structured)
    spec = SUPPORTED_ACTIONS[structured["action"]]
    return {
        "action": structured["action"],
        "structured": structured,
        "risk": spec["risk"],
        "is_mutating": bool(spec["is_mutating"]),
        "argv": argv,
        "command": " ".join(shlex.quote(arg) for arg in argv),
        "ignored_args": list(structured.get("ignored_args") or []),
    }


def _keyword_risk(command: str) -> str:
    cmd_lower = command.lower()
    if any(k in cmd_lower for k in ("delete", "drain", "cordon", "purge", "rm ")):
        return "high"
    if any(k in cmd_lower for k in ("restart", "undo", "scale", "patch", "apply", "set ", "rollout", "edit", "exec")):
        return "medium"
    return "read-only"


def assess_step_risk(command: str, raw_risk: Any = None) -> str:
    """Server-side risk for a suggested command. A registered action uses the
    registry's level, anything else a keyword check. The model's own label can
    only raise the result, never lower it, because AI output is untrusted."""
    command = str(command or "").strip()
    base = "read-only"
    if command and _SHELL_SYNTAX_RE.search(command):
        return "high"
    if command:
        # A parsed command only ever runs the registered action's argv, so the
        # registry level describes what executes; unparsed text gets keywords.
        parsed = parse_command_to_action(command)
        base = SUPPORTED_ACTIONS[parsed["action"]]["risk"] if parsed else _keyword_risk(command)
    claimed = _RISK_ALIASES.get(str(raw_risk or "").strip().lower())
    if claimed is None:
        return base
    return max(base, claimed, key=_RISK_LEVELS.index)


def step_execution_fields(command: str, raw_risk: Any = None) -> dict[str, Any]:
    """Risk and execution details for one suggested command, derived on the
    server from the command text alone. `exec_command` is the exact kubectl
    line that would run (it can differ from the suggestion when read-only
    presentation flags are left out); `is_supported` is False for anything
    the registry cannot run exactly."""
    command = str(command or "").strip()
    fields: dict[str, Any] = {
        "risk": assess_step_risk(command, raw_risk),
        "action": None,
        "is_supported": False,
        "exec_command": "",
    }
    parsed = parse_command_to_action(command) if command else None
    if parsed is None:
        if command:
            fields["unsupported_reason"] = (
                "Not a supported diagnostic command (only registered kubectl get/describe/logs/"
                "events/rollout forms without unsupported flags can run)"
            )
        return fields
    fields["action"] = parsed
    try:
        described = describe_action(resolve_action({"action": parsed}))
    except ValueError as exc:
        fields["unsupported_reason"] = str(exc)
        return fields
    fields["is_supported"] = True
    fields["exec_command"] = described["command"]
    if described["ignored_args"]:
        fields["ignored_args"] = described["ignored_args"]
    return fields


def _cap_output(text: str) -> tuple[str, bool]:
    text = text.strip()
    if len(text) <= _MAX_OUTPUT_CHARS:
        return text, False
    return text[:_MAX_OUTPUT_CHARS] + f"\n… [output truncated at {_MAX_OUTPUT_CHARS} characters]", True


# ─────────────────────────────────────────────────────────────────────────────
# Confirmation and concurrency
# ─────────────────────────────────────────────────────────────────────────────

class ActionBusy(Exception):
    """The same action is already running, or too many actions are."""


class ConfirmationTokens:
    """Proof that a person was shown one exact command before it changes
    cluster state. A token is bound to the argv it was issued for (HMAC with
    a per-process key), expires, and can be used once, so a confirmation
    cannot be replayed, reused for a different command, or forged by a
    client that never displayed the command."""

    def __init__(self, ttl_secs: int = 300):
        self._key = secrets.token_bytes(32)
        self._ttl = ttl_secs
        self._used: dict[str, float] = {}  # nonce -> expiry
        self._lock = threading.Lock()

    def _mac(self, expiry: int, nonce: str, argv: list[str]) -> str:
        message = f"{expiry}.{nonce}.".encode() + json.dumps(argv, separators=(",", ":")).encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def issue(self, argv: list[str]) -> str:
        expiry = int(time.time()) + self._ttl
        nonce = secrets.token_urlsafe(12)
        return f"{expiry}.{nonce}.{self._mac(expiry, nonce, argv)}"

    def consume(self, token: Any, argv: list[str]) -> bool:
        if not isinstance(token, str) or token.count(".") != 2 or len(token) > 200:
            return False
        raw_expiry, nonce, mac = token.split(".")
        try:
            expiry = int(raw_expiry)
        except ValueError:
            return False
        now = time.time()
        if expiry < now or not hmac.compare_digest(mac, self._mac(expiry, nonce, argv)):
            return False
        with self._lock:
            for old in [n for n, exp in self._used.items() if exp < now]:
                del self._used[old]
            if nonce in self._used:
                return False
            self._used[nonce] = expiry
        return True


class ActionGate:
    """At most `max_concurrent` actions at once and never the same argv
    twice concurrently (a double submit gets ActionBusy, not a second run)."""

    def __init__(self, max_concurrent: int = 2):
        self.max_concurrent = max(1, max_concurrent)
        self._running: set[tuple[str, ...]] = set()
        self._lock = threading.Lock()

    @contextmanager
    def slot(self, argv: list[str]) -> Iterator[None]:
        key = tuple(argv)
        with self._lock:
            if key in self._running:
                raise ActionBusy("This exact action is already running; wait for it to finish")
            if len(self._running) >= self.max_concurrent:
                raise ActionBusy(f"{self.max_concurrent} actions are already running; try again shortly")
            self._running.add(key)
        try:
            yield
        finally:
            with self._lock:
                self._running.discard(key)


def confirmation_response(described: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    response = {
        "success": False,
        "requires_confirmation": True,
        "action": described["action"],
        "structured": described["structured"],
        "command": described["command"],
        "risk": described["risk"],
        "message": (
            f"Action '{described['action']}' modifies cluster state. "
            "Explicit confirmation is required before running this action."
        ),
    }
    if token:
        response["confirm_token"] = token
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Execution
# ─────────────────────────────────────────────────────────────────────────────

def _command_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _COMMAND_ENV_KEYS if key in os.environ}


def _run_command(argv: list[str], *, timeout: float, max_bytes: int) -> tuple[int, str, str, bool, bool]:
    """Run argv without a shell. Returns (exit code, stdout, stderr,
    output_limited, timed_out). Each stream keeps at most max_bytes; past
    that the process is stopped instead of buffering the rest."""
    # argv comes from build_kubectl_argv (allowlisted verbs, validated names), never a shell string.
    proc = subprocess.Popen(  # noqa: S603
        argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=_command_env(),
    )
    buffers = (bytearray(), bytearray())
    limited = threading.Event()

    def pump(stream, buf: bytearray) -> None:
        try:
            while True:
                data = stream.read1(65536)
                if not data:
                    return
                room = max_bytes - len(buf)
                if room > 0:
                    buf += data[:room]
                if len(data) > room:
                    limited.set()
                    with contextlib.suppress(OSError):
                        proc.kill()
        finally:
            stream.close()

    readers = [
        threading.Thread(target=pump, args=(proc.stdout, buffers[0]), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, buffers[1]), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for reader in readers:
        reader.join(timeout=5)
    out, err = (bytes(b).decode("utf-8", errors="replace") for b in buffers)
    return proc.returncode, out, err, limited.is_set(), timed_out


def run_described_action(described: dict[str, Any]) -> dict[str, Any]:
    """Run an action already validated by describe_action. Confirmation and
    concurrency are the caller's responsibility (see the HTTP handler)."""
    action_type = described["action"]
    base = {"command": described["command"], "action": action_type, "risk": described["risk"]}
    logger.info("Running action %s: %s", action_type, described["command"])
    start_time = time.monotonic()
    try:
        code, stdout, stderr, limited, timed_out = _run_command(
            described["argv"], timeout=_COMMAND_TIMEOUT_SECONDS, max_bytes=_MAX_OUTPUT_BYTES
        )
    except FileNotFoundError:
        return {**base, "success": False, "exit_code": -1, "stdout": "",
                "stderr": "kubectl executable not found on system PATH", "duration_ms": 0}
    except Exception as exc:
        logger.exception("Error executing action %s", action_type)
        return {**base, "success": False, "exit_code": -1, "stdout": "",
                "stderr": f"Could not start kubectl ({type(exc).__name__})",
                "duration_ms": int((time.monotonic() - start_time) * 1000)}
    duration_ms = int((time.monotonic() - start_time) * 1000)
    stdout, stdout_truncated = _cap_output(stdout)
    stderr, stderr_truncated = _cap_output(stderr)
    notes = []
    if timed_out:
        notes.append(f"Command timed out after {_COMMAND_TIMEOUT_SECONDS}s")
    if limited:
        notes.append(f"Output exceeded {_MAX_OUTPUT_BYTES} bytes; the command was stopped")
    if notes:
        stderr = "\n".join(filter(None, [stderr, *notes]))
    logger.info("Action %s finished with exit code %s in %d ms", action_type, code, duration_ms)
    return {
        **base,
        "success": code == 0 and not timed_out and not limited,
        "exit_code": -1 if timed_out else code,
        "stdout": stdout,
        "stderr": stderr,
        "output_truncated": stdout_truncated or stderr_truncated or limited,
        "duration_ms": duration_ms,
    }

