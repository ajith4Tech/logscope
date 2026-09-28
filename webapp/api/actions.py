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

import logging
import re
import shlex
import subprocess
import time
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
_MAX_LOG_TAIL_LINES = 1000


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


def parse_command_to_action(cmd_str: str) -> dict[str, Any] | None:
    """Parse a kubectl-style CLI command string into a structured action dict.

    Returns None if the command cannot be safely parsed into a supported action.
    """
    text = str(cmd_str or "").strip()
    if not text:
        return None

    try:
        tokens = shlex.split(text)
    except Exception:
        return None

    if not tokens or tokens[0] != "kubectl":
        return None

    # Strip kubectl
    args = tokens[1:]
    if not args:
        return None

    # Parse common flags (-n / --namespace, -o / --output)
    namespace = ""
    output_format = ""
    container = ""
    tail = 100
    previous = False
    clean_args: list[str] = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-n", "--namespace"):
            if i + 1 < len(args):
                namespace = args[i + 1]
                i += 2
                continue
        elif arg.startswith("--namespace="):
            namespace = arg.split("=", 1)[1]
            i += 1
            continue
        elif arg in ("-o", "--output"):
            if i + 1 < len(args):
                output_format = args[i + 1]
                i += 2
                continue
        elif arg.startswith("--output="):
            output_format = arg.split("=", 1)[1]
            i += 1
            continue
        elif arg in ("-c", "--container"):
            if i + 1 < len(args):
                container = args[i + 1]
                i += 2
                continue
        elif arg.startswith("--container="):
            container = arg.split("=", 1)[1]
            i += 1
            continue
        elif arg == "--previous":
            previous = True
            i += 1
            continue
        elif arg.startswith("--tail="):
            try:
                tail = int(arg.split("=", 1)[1])
            except ValueError:
                pass
            i += 1
            continue
        elif arg == "--tail":
            if i + 1 < len(args):
                try:
                    tail = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
                continue
        elif arg.startswith("-"):
            # Skip or ignore other flags like --sort-by if safe
            i += 1
            continue
        else:
            clean_args.append(arg)
            i += 1

    if not clean_args:
        return None

    verb = clean_args[0].lower()

    if verb == "get":
        if len(clean_args) < 2:
            return None
        res_type = clean_args[1].lower()
        res_name = clean_args[2] if len(clean_args) > 2 else ""

        if res_type in ("pod", "pods", "po"):
            if res_name:
                return {
                    "action": "get_pod",
                    "resource": res_name,
                    "namespace": namespace,
                    "output": output_format,
                }
            return {
                "action": "get_pods",
                "resource": "",
                "namespace": namespace,
                "output": output_format,
            }
        elif res_type in ("events", "event"):
            return {
                "action": "get_events",
                "resource": "",
                "namespace": namespace,
            }
        elif res_type in ("deployment", "deployments", "deploy"):
            if res_name:
                return {
                    "action": "get_deployment",
                    "resource": res_name,
                    "namespace": namespace,
                    "output": output_format,
                }

    elif verb == "describe":
        if len(clean_args) < 3:
            return None
        res_type = clean_args[1].lower()
        res_name = clean_args[2]

        if res_type in ("pod", "pods", "po"):
            return {
                "action": "describe_pod",
                "resource": res_name,
                "namespace": namespace,
            }
        elif res_type in ("deployment", "deployments", "deploy"):
            return {
                "action": "describe_deployment",
                "resource": res_name,
                "namespace": namespace,
            }

    elif verb in ("logs", "log"):
        if len(clean_args) < 2:
            return None
        res_name = clean_args[1]
        # Handle pod/name format
        if res_name.startswith("pod/"):
            res_name = res_name[4:]
        return {
            "action": "get_pod_logs",
            "resource": res_name,
            "namespace": namespace,
            "container": container,
            "tail": tail,
            "previous": previous,
        }

    elif verb == "rollout":
        if len(clean_args) < 3:
            return None
        subverb = clean_args[1].lower()
        res_spec = clean_args[2]
        res_name = res_spec
        if "/" in res_spec:
            prefix, name = res_spec.split("/", 1)
            if prefix.lower() in ("deployment", "deployments", "deploy"):
                res_name = name

        if subverb == "status":
            return {
                "action": "rollout_status",
                "resource": res_name,
                "namespace": namespace,
            }
        elif subverb == "restart":
            return {
                "action": "rollout_restart",
                "resource": res_name,
                "namespace": namespace,
            }
        elif subverb == "undo":
            return {
                "action": "rollout_undo",
                "resource": res_name,
                "namespace": namespace,
            }

    return None


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
        tail = action.get("tail")
        if tail is not None:
            try:
                tail_int = max(1, min(int(tail), _MAX_LOG_TAIL_LINES))
                argv.extend([f"--tail={tail_int}"])
            except (ValueError, TypeError):
                argv.extend(["--tail=100"])
        if action.get("previous"):
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


def execute_action(
    action_data: dict[str, Any],
    *,
    confirmed: bool = False,
) -> dict[str, Any]:
    """Validate and execute a structured Kubernetes diagnostic action.

    Accepts either an action dict or a dict with 'command'.
    Mutating actions require confirmed=True.
    """
    raw_action = action_data.get("action")
    command_str = str(action_data.get("command") or "").strip()

    structured: dict[str, Any] | None = None

    if raw_action and str(raw_action) in SUPPORTED_ACTIONS:
        structured = {
            "action": str(raw_action),
            "namespace": action_data.get("namespace", ""),
            "resource": action_data.get("resource", ""),
            "output": action_data.get("output", ""),
            "container": action_data.get("container", ""),
            "tail": action_data.get("tail"),
            "previous": action_data.get("previous", False),
        }
    elif command_str:
        structured = parse_command_to_action(command_str)

    if not structured:
        raise ValueError(
            "Unsupported or invalid action. Only registered Kubernetes diagnostic "
            "commands (e.g. get pod, describe pod, logs, events, deployment status) "
            "are allowed."
        )

    action_type = structured["action"]
    action_spec = SUPPORTED_ACTIONS.get(action_type, {})
    is_mutating = bool(action_spec.get("is_mutating", False))
    risk = action_spec.get("risk", "read-only")

    if is_mutating and not confirmed:
        return {
            "success": False,
            "requires_confirmation": True,
            "action": action_type,
            "risk": risk,
            "message": (
                f"Action '{action_type}' modifies cluster state. "
                "Explicit confirmation is required before running this action."
            ),
        }

    argv = build_kubectl_argv(structured)
    display_command = " ".join(shlex.quote(arg) for arg in argv)

    start_time = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            shell=False,  # Strictly no shell
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
        duration_ms = int((time.monotonic() - start_time) * 1000)

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        success = (proc.returncode == 0)

        return {
            "success": success,
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "command": display_command,
            "action": action_type,
            "risk": risk,
            "duration_ms": duration_ms,
        }

    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Command timed out after {_COMMAND_TIMEOUT_SECONDS}s",
            "command": display_command,
            "action": action_type,
            "risk": risk,
            "duration_ms": duration_ms,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "kubectl executable not found on system PATH",
            "command": display_command,
            "action": action_type,
            "risk": risk,
            "duration_ms": 0,
        }
    except Exception as exc:
        logger.exception("Error executing action %s", action_type)
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": display_command,
            "action": action_type,
            "risk": risk,
            "duration_ms": int((time.monotonic() - start_time) * 1000),
        }
