from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse, urlsplit

from logscope.resources import default_server_config, ui_asset
from logscope.version import __version__

from .actions import (
    ActionBusy,
    ActionGate,
    ConfirmationTokens,
    confirmation_response,
    describe_action,
    resolve_action,
    run_described_action,
)
from .ai_settings import (
    TEST_FEATURE,
    AiFeatureDisabled,
    AiService,
    AiSettings,
    AuthFailureLimiter,
    ClientRateLimiter,
    SecretBox,
    SettingsError,
    UsageMeter,
    load_admin_token,
    tokens_equal,
)
from .ai_cache import AiCache
from .ai_summary import (
    explain_log_line,
    explain_logs,
    ping_problem,
    ping_provider,
    summarize_anomalies_batch,
    summarize_anomaly,
)
from .explain import FILTERED_SAMPLE_ROWS, Explainer, anomaly_template_summary, meta_of
from .signatures import SignatureKB, load_rules
from .summary_worker import SummaryWorker
from .config import AppConfig, load_app_config
from .ingest import S3Ingestor
from .insights import AnomalyStore, InsightsJob
from .notify import MattermostNotifier
from .state import SavedViews, StateDB, ViewError, ViewNotFound, default_state_db_path
from .storage import FILTER_FIELDS, MAX_SQLITE_INT, LogStorage, decode_cursor, open_connection

_MAX_BODY_BYTES = 1024 * 1024  # JSON bodies are tiny; refuse anything larger
_PRUNE_INTERVAL_SECS = 3600
_DB_BUSY_GRACE_SECS = 60  # readiness tolerates the shared DB connection being busy this long
_DEFAULT_AI_RATE_LIMIT_PER_MINUTE = 10
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Host names always accepted in the Host header (see _host_trusted). IP
# literals are accepted too: DNS rebinding needs an attacker-controlled name.
_DEFAULT_TRUSTED_HOSTS = ("localhost",)
# Probes are answered whatever the Host header says (kubelet sends the pod IP).
_HOST_CHECK_EXEMPT_PATHS = frozenset({"/healthz", "/readyz"})
# Ingestion counts as stale when no poll has succeeded for this many poll
# intervals (and at least _INGEST_STALE_MIN_SECS).
_INGEST_STALE_POLLS = 5
_INGEST_STALE_MIN_SECS = 300
_FTS_MIGRATION_PAUSE_SECS = 0.05
# After a failed migration step (e.g. disk full) the backfill retries with
# this backoff instead of waiting for a restart.
_FTS_MIGRATION_RETRY_SECS = 60
_FTS_MIGRATION_RETRY_MAX_SECS = 1800
# Filter values longer than this are rejected (400); searches are short.
_MAX_QUERY_PARAM_CHARS = 1000
# Search modes: "phrase" (default; words matched as written) or "raw" FTS5
# query syntax. Values per exclusion parameter (xns, xpod, ...).
_SEARCH_MODES = frozenset({"phrase", "raw"})
_MAX_EXCLUDED_VALUES = 50
# HTTP requests handled at once; more get an immediate 503 instead of a
# thread each (ThreadingHTTPServer has no limit of its own).
_DEFAULT_MAX_CONCURRENT_REQUESTS = 64

# Applied to every response. The UI loads only same-origin script/CSS and calls
# same-origin APIs (fetch); 'unsafe-inline' is limited to styles because
# app.js renders inline style="width:…" attributes for dashboard bars.
_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'",
    ),
)

logger = logging.getLogger("logscope.webapp")
access_logger = logging.getLogger("logscope.access")


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _first(params: dict[str, list[str]], name: str, default: str | None = None) -> str | None:
    values = params.get(name)
    if not values:
        return default
    return values[0]


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Ignoring non-integer %s=%r; using %d", name, raw, default)
        return default


class _RequestTooLarge(Exception):
    pass


class _UnsupportedMediaType(Exception):
    pass


class _RateLimited(Exception):
    def __init__(self, retry_after: float):
        super().__init__("rate limited")
        self.retry_after = retry_after


class _RateLimiter:
    """Process-wide token bucket for AI calls. A single bucket keeps memory
    bounded and is keyed on nothing the client controls, so forwarding headers
    or many source addresses cannot spread requests over several buckets.
    State is in memory and per replica (N replicas allow N times the rate)."""

    def __init__(self, per_minute: int):
        self.capacity = max(0, per_minute)
        self._tokens = float(self.capacity)
        self._rate = self.capacity / 60.0
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.capacity == 0:  # 0 disables the limit
            return
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self._rate)
            self._updated = now
            if self._tokens >= 1:
                self._tokens -= 1
                return
            raise _RateLimited((1 - self._tokens) / self._rate)


def _normalize_netloc(netloc: str, scheme: str) -> str | None:
    """host:port with the scheme's default port filled in, or None if unparseable."""
    try:
        parts = urlsplit(f"//{netloc}")
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    return f"{host}:{port if port is not None else _DEFAULT_PORTS[scheme]}"


def _parse_trusted_hosts(raw: str) -> tuple[frozenset[str], tuple[str, ...], bool]:
    """LOGSCOPE_TRUSTED_HOSTS: comma-separated host names, "*.example.com"
    suffix wildcards, or "*" to accept any Host (disables the check).
    Returns (exact names, wildcard suffixes, allow_any)."""
    exact: set[str] = set(_DEFAULT_TRUSTED_HOSTS)
    suffixes: list[str] = []
    allow_any = False
    for item in raw.split(","):
        name = item.strip().lower().rstrip(".")
        if not name:
            continue
        if name == "*":
            allow_any = True
        elif name.startswith("*."):
            suffixes.append(name[1:])  # ".example.com"
        else:
            exact.add(name)
    return frozenset(exact), tuple(suffixes), allow_any


def _host_name(host_header: str) -> str | None:
    """Lower-cased host part of a Host header, or None if unparseable."""
    try:
        host = urlsplit(f"//{host_header.strip()}").hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _seconds_since(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        then = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - then).total_seconds())


def _coerce_limit(raw: str | None, default: int, maximum: int) -> int:
    if raw is None:
        return default
    value = int(raw)
    return max(1, min(value, maximum))


class AppHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, app, *, max_concurrent: int | None = None):
        super().__init__(server_address, RequestHandlerClass)
        self.app = app
        limit = max_concurrent or _env_int("LOGSCOPE_MAX_CONCURRENT_REQUESTS", _DEFAULT_MAX_CONCURRENT_REQUESTS)
        self._slots = threading.BoundedSemaphore(max(1, limit))

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                    b"Retry-After: 1\r\nConnection: close\r\nContent-Length: 30\r\n\r\n"
                    b'{"error":"Server busy; retry"}'
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class LogscopeHandler(BaseHTTPRequestHandler):
    """Routes only the paths below. Based on BaseHTTPRequestHandler (not
    SimpleHTTPRequestHandler) so no method can fall through to serving files
    from the working directory; other methods get 501 from the base class."""

    server: AppHTTPServer
    # Socket read timeout so a stalled client cannot hold a worker thread forever.
    timeout = 60

    def log_message(self, format, *args):  # noqa: A003
        return

    def log_request(self, code="-", size="-"):  # noqa: ARG002
        # Method, path (no query string: it can carry search terms taken from
        # log content), status and peer address. Never headers or bodies.
        try:
            status = int(code)
        except (TypeError, ValueError):
            status = 0
        quiet = self.command in ("GET", "HEAD") and status < 400
        access_logger.log(
            logging.DEBUG if quiet else logging.INFO,
            "%s %s %s %s", self.client_address[0], self.command, urlparse(self.path).path, status,
        )

    def end_headers(self) -> None:
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("X-Logscope-Version", __version__)
        super().end_headers()

    def _send_json(self, payload: dict, status: int = 200, headers: dict[str, str] | None = None) -> None:
        data = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _origin_allowed(self) -> bool:
        """CSRF guard for state-changing requests.

        Browsers send Origin on cross-origin POST/PATCH, so a present Origin
        must match the Host this request was addressed to (or an explicitly
        allowed origin). Without Origin, Sec-Fetch-Site still flags a
        cross-site browser request; requests carrying neither come from
        non-browser clients (curl, scripts), which cannot ride a user's
        browser credentials. X-Forwarded-* headers are not consulted.
        """
        origin = self.headers.get("Origin")
        if origin is None:
            site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            return site in ("", "same-origin", "none")
        origin = origin.strip().rstrip("/")
        if origin in self.server.app.allowed_origins:
            return True
        try:
            parts = urlsplit(origin)
        except ValueError:
            return False
        if parts.scheme not in _DEFAULT_PORTS or parts.path or parts.query:
            return False  # includes the opaque "null" origin
        actual = _normalize_netloc(parts.netloc, parts.scheme)
        expected = _normalize_netloc(self.headers.get("Host") or "", parts.scheme)
        return actual is not None and actual == expected

    def _host_trusted(self) -> bool:
        """DNS-rebinding guard. A page on an attacker's domain that resolves to
        this server sends its own name as Host, and its Origin matches that Host,
        so the Origin check alone cannot tell it apart. Only names in
        LOGSCOPE_TRUSTED_HOSTS (plus localhost and IP literals) are served."""
        app = self.server.app
        if app.trust_any_host or urlparse(self.path).path in _HOST_CHECK_EXEMPT_PATHS:
            return True
        host = _host_name(self.headers.get("Host") or "")
        if not host:
            return False
        if host in app.trusted_hosts or _is_ip_literal(host):
            return True
        return any(host.endswith(suffix) for suffix in app.trusted_host_suffixes)

    def _read_body_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        if length > _MAX_BODY_BYTES:
            raise _RequestTooLarge()
        media_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise _UnsupportedMediaType()
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}

    def _serve_asset(self, name: str, content_type: str) -> None:
        path = ui_asset(name)  # source checkout, installed package or PyInstaller bundle
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _guarded(self, handler, *, state_changing: bool = False) -> None:
        """Turn bad input into a JSON 4xx and unexpected failures into a logged
        JSON 500, instead of dropping the connection with a stderr traceback."""
        try:
            if not self._host_trusted():
                self._send_json(
                    {"error": "Untrusted Host header; add this host name to LOGSCOPE_TRUSTED_HOSTS"},
                    status=421,
                )
                return
            if state_changing and not self._origin_allowed():
                self._send_json({"error": "Cross-origin request rejected"}, status=403)
                return
            handler()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except _RequestTooLarge:
            self._send_json({"error": "Request body too large"}, status=413)
        except _UnsupportedMediaType:
            self._send_json({"error": "Content-Type must be application/json"}, status=415)
        except AiFeatureDisabled as exc:
            self._send_json({"error": "ai_feature_disabled", "feature": exc.feature}, status=403)
        except _RateLimited as exc:
            retry_after = max(1, int(exc.retry_after + 0.999))
            self._send_json(
                {"error": f"AI request rate limit reached; retry in {retry_after}s"},
                status=429,
                headers={"Retry-After": str(retry_after)},
            )
        except ValueError as exc:
            self._send_json({"error": f"Invalid request: {exc}"}, status=400)
        except Exception:
            logger.exception("Unhandled error serving %s %s", self.command, urlparse(self.path).path)
            self._send_json({"error": "Internal server error"}, status=500)

    def do_GET(self):  # noqa: N802
        self._guarded(self._handle_get)

    def do_HEAD(self):  # noqa: N802
        # Same routes and status codes as GET, headers only.
        self._guarded(self._handle_get)

    def do_POST(self):  # noqa: N802
        self._guarded(self._handle_post, state_changing=True)

    def do_PATCH(self):  # noqa: N802
        self._guarded(self._handle_patch, state_changing=True)

    def do_DELETE(self):  # noqa: N802
        self._guarded(self._handle_delete, state_changing=True)

    def do_PUT(self):  # noqa: N802
        self._guarded(self._handle_put, state_changing=True)

    def _admin_authorized(self) -> bool:
        """Bearer admin token (constant-time compare). A correct token always
        succeeds; wrong tokens are counted per client address, and past 10 in
        a minute a wrong token gets 429 instead of 401."""
        app = self.server.app
        ip = self.client_address[0]
        scheme, _, token = (self.headers.get("Authorization") or "").strip().partition(" ")
        token = token.strip()
        if scheme.lower() == "bearer" and tokens_equal(token, app.admin_token) and token:
            return True
        wait = app.admin_auth_failures.retry_after(ip)
        if wait > 0:
            retry_after = max(1, int(wait + 0.999))
            self._send_json({"error": f"Too many failed admin token attempts; retry in {retry_after}s"},
                            status=429, headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
            return False
        app.admin_auth_failures.fail(ip)
        self._send_json({"error": "A valid admin token is required"}, status=401,
                        headers={"WWW-Authenticate": 'Bearer realm="logscope-settings"', "Cache-Control": "no-store"})
        return False

    def _handle_settings(self, method: str, path: str) -> bool:
        """/api/settings/ai[/test|/usage]: admin token on top of the Origin
        check (applied here to GET as well). Returns False for other paths."""
        if path != "/api/settings" and not path.startswith("/api/settings/"):
            return False
        app = self.server.app
        if method == "GET" and not self._origin_allowed():
            self._send_json({"error": "Cross-origin request rejected"}, status=403)
            return True
        if not self._admin_authorized():
            return True
        no_store = {"Cache-Control": "no-store"}
        route = (method, path.rstrip("/"))
        try:
            if route == ("GET", "/api/settings/ai"):
                self._send_json(app.api_settings(), headers=no_store)
            elif route == ("PUT", "/api/settings/ai"):
                body = self._read_body_json() if int(self.headers.get("Content-Length", 0) or 0) else None
                app.ai_settings.update(body)
                self._send_json(app.api_settings(), headers=no_store)
            elif route == ("POST", "/api/settings/ai/test"):
                self._send_json(app.api_settings_test(), headers=no_store)
            elif route == ("GET", "/api/settings/ai/usage"):
                days = _bounded_int(_first(parse_qs(urlparse(self.path).query), "days", "7"), "days")
                self._send_json(app.ai_meter.summary(days), headers=no_store)
            elif route[1] in ("/api/settings/ai", "/api/settings/ai/test", "/api/settings/ai/usage"):
                self._send_json({"error": "Method not allowed"}, status=405)
            else:
                self._send_json({"error": "Not found"}, status=404)
        except SettingsError as exc:
            payload = {"error": str(exc)}
            if exc.field:
                payload["field"] = exc.field
            self._send_json(payload, status=exc.status, headers=no_store)
        return True

    def _view_route(self, path: str) -> tuple[bool, int | None, str | None]:
        """/api/views[/<id>[/<action>]] -> (matched, id, action). An id that is
        not a storable integer matches with id None (answered with 404)."""
        parts = path.strip("/").split("/")
        if parts[:2] != ["api", "views"] or len(parts) > 4:
            return False, None, None
        if len(parts) == 2:
            return True, None, None
        try:
            view_id = _bounded_int(parts[2], "id") if parts[2].isdigit() else None
        except ValueError:
            view_id = None
        return True, view_id, parts[3] if len(parts) == 4 else None

    def _handle_views(self, method: str, path: str) -> bool:
        """Saved views. Returns False when the path is not a views route.
        Errors: 404 unknown view, 409 duplicate name, 422 invalid field."""
        matched, view_id, action = self._view_route(path)
        if not matched:
            return False
        views = self.server.app.views
        try:
            if view_id is None and path.strip("/") != "api/views":
                raise ViewNotFound("Saved view not found")
            if action is None and view_id is None and method == "GET":
                self._send_json({"views": views.list()})
            elif action is None and view_id is None and method == "POST":
                self._send_json({"view": views.create(self._read_body_json())}, status=201)
            elif action is None and view_id is not None and method == "GET":
                self._send_json({"view": views.get(view_id)})
            elif action is None and view_id is not None and method == "PATCH":
                self._send_json({"view": views.update(view_id, self._read_body_json())})
            elif action is None and view_id is not None and method == "DELETE":
                views.delete(view_id)
                self._send_json({"ok": True, "id": view_id})
            elif action == "use" and view_id is not None and method == "POST":
                self._send_json({"view": views.mark_used(view_id)})
            elif action not in (None, "use"):
                raise ViewNotFound("Not found")
            else:
                self._send_json({"error": "Method not allowed"}, status=405)
        except ViewError as exc:
            payload = {"error": str(exc)}
            if exc.field:
                payload["field"] = exc.field
            self._send_json(payload, status=exc.status)
        return True

    def _handle_get(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        app = self.server.app
        if parsed.path == "/healthz":
            # Liveness: the process answers and the ingest loop is still running.
            alive = app.healthy()
            self._send_json({"status": "ok" if alive else "ingest loop stopped"}, status=200 if alive else 503)
            return
        if parsed.path == "/readyz":
            # Readiness: the local cache answers, or has been busy with another
            # query for less than _DB_BUSY_GRACE_SECS. S3 or AI outages do not
            # make the pod unready; they surface in /api/status last_error.
            ready, busy = app.ready()
            payload = {"status": "ok" if ready else "database unavailable"}
            if busy:
                payload["db"] = "busy"
            self._send_json(payload, status=200 if ready else 503)
            return
        if parsed.path in ("/", "/index.html"):
            self._serve_asset("index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._serve_asset("app.js", "application/javascript; charset=utf-8")
            return
        if parsed.path == "/styles.css":
            self._serve_asset("styles.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/api/status":
            self._send_json(app.status())
            return
        if parsed.path == "/api/facets":
            self._send_json(app.storage.query_facets(_query_params(params)))
            return
        if parsed.path == "/api/fields":
            self._send_json(app.storage.query_fields(_query_params(params)))
            return
        if parsed.path == "/api/histogram":
            self._send_json(app.storage.query_histogram(_query_params(params)))
            return
        if parsed.path == "/api/dashboard":
            self._send_json(app.api_dashboard(params))
            return
        if parsed.path == "/api/logs":
            self._send_json(app.api_logs(params))
            return
        if parsed.path == "/api/logs/context":
            self._send_json(app.api_log_context(params))
            return
        if parsed.path == "/api/tail":
            self._send_json(app.api_tail(params))
            return
        if parsed.path == "/api/anomalies":
            self._send_json(app.api_anomalies(params))
            return
        if self._handle_views("GET", parsed.path):
            return
        if self._handle_settings("GET", parsed.path):
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_put(self) -> None:
        if self._handle_settings("PUT", urlparse(self.path).path):
            return
        self.send_error(HTTPStatus.NOT_IMPLEMENTED)

    def _handle_post(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        app = self.server.app
        if parsed.path == "/api/actions/execute":
            if not app.actions_enabled:
                self._send_json(
                    {"error": "Action execution is disabled on this server (LOGSCOPE_ACTIONS_ENABLED=false)"},
                    status=403,
                )
                return
            body = self._read_body_json()
            try:
                described = describe_action(resolve_action(body))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            if described["is_mutating"] and not (
                body.get("confirmed") is True
                and app.confirmations.consume(body.get("confirm_token"), described["argv"])
            ):
                # The token proves the person saw exactly this command; a
                # missing, stale, reused or mismatched one gets a fresh prompt.
                self._send_json(confirmation_response(described, app.confirmations.issue(described["argv"])))
                return
            try:
                with app.action_gate.slot(described["argv"]):
                    res = run_described_action(described)
            except ActionBusy as exc:
                self._send_json({"error": str(exc)}, status=409)
                return
            self._send_json(res)
            return
        if parsed.path == "/api/actions/validate":
            # Read-only: resolves a suggested step to the exact registered
            # action and kubectl line, so the UI can confirm what will run.
            body = self._read_body_json()
            try:
                described = describe_action(resolve_action(body))
            except ValueError as exc:
                self._send_json({"valid": False, "error": str(exc)}, status=400)
                return
            payload = {
                "valid": True,
                "action": described["action"],
                "structured": described["structured"],
                "command": described["command"],
                "risk": described["risk"],
                "is_mutating": described["is_mutating"],
                "ignored_args": described["ignored_args"],
            }
            if described["is_mutating"] and app.actions_enabled:
                payload["confirm_token"] = app.confirmations.issue(described["argv"])
            self._send_json(payload)
            return
        if parsed.path == "/api/explain":
            try:
                result = app.api_explain(params)
                self._send_json(result)
            except RuntimeError as exc:
                self._send_json({"error": str(exc)}, status=502)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/explain-line":
            body = self._read_body_json()
            try:
                result = app.api_explain_line(body)
                self._send_json(result)
            except RuntimeError as exc:
                self._send_json({"error": str(exc)}, status=502)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "anomalies"] and parts[3] == "summarize":
            # Manual AI summary of one anomaly (feature anomaly_manual_summary).
            try:
                anomaly_id = _bounded_int(parts[2], "anomaly id")
            except ValueError:
                self._send_json({"error": "Invalid anomaly id"}, status=400)
                return
            try:
                body = self._read_body_json()
                result = app.api_summarize_anomaly(anomaly_id, _ai_options(body.get))
            except LookupError:
                self._send_json({"error": "Anomaly not found"}, status=404)
                return
            except RuntimeError as exc:
                self._send_json({"error": str(exc)}, status=502)
                return
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            self._send_json(result)
            return
        if parsed.path == "/api/ai/feedback":
            # 👍/👎 on a cached answer: one vote per (entry, browser session),
            # 30 votes per minute per address.
            wait = app.feedback_limiter.allow(self.client_address[0])
            if wait > 0:
                retry_after = max(1, int(wait + 0.999))
                self._send_json({"error": f"Too many feedback votes; retry in {retry_after}s"}, status=429,
                                headers={"Retry-After": str(retry_after)})
                return
            try:
                self._send_json(app.api_ai_feedback(self._read_body_json(), self.headers.get(FEEDBACK_CLIENT_HEADER)))
            except LookupError:
                self._send_json({"error": "No cached answer with this key (it may have expired)"}, status=404)
            return
        if self._handle_views("POST", parsed.path):
            return
        if self._handle_settings("POST", parsed.path):
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_patch(self) -> None:
        parsed = urlparse(self.path)
        app = self.server.app
        # PATCH /api/anomalies/:id
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "anomalies":
            try:
                anomaly_id = _bounded_int(parts[2], "anomaly id")
            except ValueError:
                self._send_json({"error": "Invalid anomaly id"}, status=400)
                return
            body = self._read_body_json()
            status = body.get("status", "")
            if not status:
                self._send_json({"error": "Missing 'status' field"}, status=400)
                return
            try:
                updated = app.anomaly_store.set_status(anomaly_id, status)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            if not updated:
                self._send_json({"error": "Anomaly not found"}, status=404)
                return
            self._send_json({"ok": True, "id": anomaly_id, "status": status})
            return
        if self._handle_views("PATCH", parsed.path):
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_delete(self) -> None:
        if self._handle_views("DELETE", urlparse(self.path).path):
            return
        self.send_error(HTTPStatus.NOT_FOUND)


def _query_params(params: dict[str, list[str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("scope", "namespace", "pod", "container", "severity_bucket", "start", "end", "before", "q"):
        value = _first(params, key)
        if value:
            if len(value) > _MAX_QUERY_PARAM_CHARS:
                raise ValueError(f"'{key}' is longer than {_MAX_QUERY_PARAM_CHARS} characters")
            out[key] = value
    qmode = _first(params, "qmode")
    if qmode:
        if qmode not in _SEARCH_MODES:
            raise ValueError(f"'qmode' must be one of {sorted(_SEARCH_MODES)}")
        if qmode == "raw":  # phrase is the default; leaving it out keeps cache keys stable
            out["qmode"] = qmode
    for _field, key in FILTER_FIELDS:
        # Values to leave out: repeated parameters and/or comma-separated
        # (Kubernetes names, scopes and severities never contain commas).
        values = sorted({v.strip() for raw in params.get(key, []) for v in raw.split(",") if v.strip()})
        if not values:
            continue
        if len(values) > _MAX_EXCLUDED_VALUES:
            raise ValueError(f"'{key}' lists more than {_MAX_EXCLUDED_VALUES} values")
        if any(len(v) > _MAX_QUERY_PARAM_CHARS for v in values):
            raise ValueError(f"A '{key}' value is longer than {_MAX_QUERY_PARAM_CHARS} characters")
        out[key] = values
    return out


def _bounded_int(raw, name: str) -> int:
    """A non-negative integer SQLite can store; ValueError (400) otherwise."""
    if isinstance(raw, bool):
        raise ValueError(f"Invalid '{name}'")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid '{name}'") from None
    if not 0 <= value <= MAX_SQLITE_INT:
        raise ValueError(f"'{name}' is out of range")
    return value


_TRUE = ("1", "true", "yes", "on")
# Random per-browser-session id the UI keeps in sessionStorage: one vote per
# (cache entry, client id); a repeat vote replaces the earlier one.
FEEDBACK_CLIENT_HEADER = "X-Logscope-Client"
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_FEEDBACK_PER_MINUTE = 30


def _ai_options(get: Any) -> dict[str, Any]:
    """tier / regenerate / skip_signature from a JSON body or query string
    (get(name) returns the raw value or None)."""
    tier = get("tier") or "fast"
    if tier not in ("fast", "deep"):
        raise ValueError("'tier' must be 'fast' or 'deep'")
    flag = lambda name: get(name) is True or str(get(name) or "").strip().lower() in _TRUE  # noqa: E731
    return {"tier": tier, "regenerate": flag("regenerate"), "skip_signature": flag("skip_signature")}


class WebApp:
    def __init__(self, cfg: AppConfig, *, extra_trusted_hosts: tuple[str, ...] = ()):
        self.cfg = cfg
        self.storage = LogStorage(
            cfg.webapp.db_path, journal_mode=os.environ.get("LOGSCOPE_SQLITE_JOURNAL_MODE", "wal")
        )
        self.ingestor = S3Ingestor(cfg, self.storage)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._ingest_loop, daemon=True)
        self._fts_thread = threading.Thread(target=self._fts_migration_loop, daemon=True)
        self._started_at = time.monotonic()
        self._last_poll_finished: float | None = None
        self.anomaly_store = AnomalyStore(cfg.webapp.db_path)
        # Detection reads through its own connection: with WAL it neither waits
        # for nor blocks the shared connection used by ingest and HTTP queries.
        self.insights = InsightsJob(
            cfg,
            open_connection(cfg.webapp.db_path),
            self.anomaly_store,
            dispatcher=self._dispatch_summaries,
        )
        # Optional Mattermost notifications; own thread and connection, so a
        # slow webhook never delays ingestion or detection.
        self.notifier = MattermostNotifier(cfg, cfg.webapp.db_path)
        # Saved views live in the durable state database, not the cache.
        self.state_db = StateDB(cfg.webapp.state_db_path or default_state_db_path())
        self.views = SavedViews(self.state_db)
        # AI settings from the UI (see ai_settings): admin token and master
        # key files sit next to the state database unless set by environment.
        state_dir = self.state_db.path.parent
        self.admin_token, self.admin_token_source = load_admin_token(state_dir)
        self.admin_auth_failures = AuthFailureLimiter()
        self.feedback_limiter = ClientRateLimiter(max_failures=_FEEDBACK_PER_MINUTE)
        self.ai_settings = AiSettings(self.state_db, cfg.ai, SecretBox(state_dir))
        self.ai_meter = UsageMeter(self.state_db, self.ai_settings, notify=self._budget_notice)
        self.ai = AiService(self.ai_settings, self.ai_meter)
        # Cheapest answer first: signatures, then the template cache, then one
        # metered call (see explain.py).
        self.ai_cache = AiCache(self.state_db, ttl_hours=cfg.ai.cache_ttl_hours)
        self.signatures = SignatureKB(load_rules(cfg.ai.signatures))
        self.explainer = Explainer(
            settings=self.ai_settings, service=self.ai, cache=self.ai_cache, kb=self.signatures,
            # Late-bound module names (tests replace them).
            line_fn=lambda record, ai_cfg: explain_log_line(record, ai_cfg),
            logs_fn=lambda payload, ai_cfg: explain_logs(payload, ai_cfg),
            anomaly_fn=lambda anomaly, ai_cfg: summarize_anomaly(anomaly, ai_cfg),
            batch_fn=lambda anomalies, ai_cfg: summarize_anomalies_batch(anomalies, ai_cfg),
            rate_limit=lambda: self.ai_rate_limiter.acquire(),
            configured=lambda: self.ai_configured(),
        )
        # Automatic anomaly summaries run here, never in the detection loop.
        self.summary_worker = SummaryWorker(
            self.explainer, self.anomaly_store, min_urgency=lambda: self.cfg.ai.auto_summary_min_urgency)
        # kubectl actions run with this process's credentials and the HTTP API
        # has no auth of its own, so they are opt-in: LOGSCOPE_ACTIONS_ENABLED=true.
        self.actions_enabled = _env_flag("LOGSCOPE_ACTIONS_ENABLED", False)
        self.confirmations = ConfirmationTokens()
        self.action_gate = ActionGate(max_concurrent=_env_int("LOGSCOPE_MAX_CONCURRENT_ACTIONS", 2))
        self.trusted_hosts, self.trusted_host_suffixes, self.trust_any_host = _parse_trusted_hosts(
            ",".join([os.environ.get("LOGSCOPE_TRUSTED_HOSTS", ""), *extra_trusted_hosts])
        )
        # Extra origins accepted for POST/PATCH besides the request's own Host
        # (e.g. when a proxy rewrites Host). Exact "scheme://host[:port]" values.
        self.allowed_origins = frozenset(
            o.strip().rstrip("/")
            for o in os.environ.get("LOGSCOPE_ALLOWED_ORIGINS", "").split(",")
            if o.strip()
        )
        # Bounds operator-triggered AI calls (/api/explain, /api/explain-line);
        # cached answers are free and not counted. 0 disables the limit.
        self.ai_rate_limiter = _RateLimiter(
            _env_int("LOGSCOPE_AI_RATE_LIMIT_PER_MINUTE", _DEFAULT_AI_RATE_LIMIT_PER_MINUTE)
        )
        self._last_prune_at: float | None = None
        self._db_busy_since: float | None = None

    def start(self) -> None:
        self._thread.start()
        if self.storage.fts_layout == "migrating":
            self._fts_thread.start()
        if self.cfg.insights.enabled:
            self.insights.start()
        self.summary_worker.start()
        self.notifier.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        if self._fts_thread.is_alive():
            self._fts_thread.join(timeout=5)
        if self.cfg.insights.enabled:
            self.insights.stop()
        self.summary_worker.stop()
        self.notifier.stop()

    def _ingest_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.ingestor.ingest_once()
                self._maybe_prune()
            except Exception:
                logger.exception("Ingest loop iteration failed")
            self._last_poll_finished = time.monotonic()
            self._stop.wait(self.cfg.webapp.poll_interval_secs)

    def _fts_migration_loop(self) -> None:
        """Move a database created by an older version to the smaller
        full-text index in the background. Searches keep using the old index
        until the swap; progress is committed per batch, so a restart resumes.
        A failed step (e.g. disk full) is retried with backoff and reported
        in /api/status storage.fts_migration.last_error."""
        logger.info("Migrating the full-text index to external content (runs in the background)")
        retry = _FTS_MIGRATION_RETRY_SECS
        while not self._stop.is_set():
            try:
                if self.storage.migrate_fts_step():
                    self.storage.fts_migration_error = None
                    return
            except sqlite3.Error as exc:
                self.storage.fts_migration_error = f"{type(exc).__name__}: {exc}"[:300]
                logger.warning("Full-text index migration paused (%s); retrying in %ds", exc, retry)
                self._stop.wait(retry)
                retry = min(retry * 2, _FTS_MIGRATION_RETRY_MAX_SECS)
                continue
            self.storage.fts_migration_error = None
            retry = _FTS_MIGRATION_RETRY_SECS
            self._stop.wait(_FTS_MIGRATION_PAUSE_SECS)  # let other threads take the lock

    def _maybe_prune(self) -> None:
        days = self.cfg.webapp.retention_days
        if days <= 0:
            return
        now = time.monotonic()
        if self._last_prune_at is not None and now - self._last_prune_at < _PRUNE_INTERVAL_SECS:
            return
        self._last_prune_at = now
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        removed = self.storage.prune_records_before(cutoff)
        if removed:
            logger.info("Pruned %d cached records older than %s", removed, cutoff)

    def healthy(self) -> bool:
        # Liveness stays "the ingest loop is running": S3 or AI outages must not
        # restart the pod. Staleness is reported by /api/status instead.
        return self._thread.is_alive()

    def ingest_health(self, status: dict) -> dict:
        """How current the cache is. state: ok | degraded (some objects or a
        prefix failing, still polling) | stale (no successful poll recently) |
        stalled (the loop has not finished a poll recently) | starting | stopped."""
        poll = self.cfg.webapp.poll_interval_secs
        stale_after = max(_INGEST_STALE_POLLS * poll, _INGEST_STALE_MIN_SECS)
        now = time.monotonic()
        since_success = _seconds_since(status.get("last_successful_ingest_at"))
        since_loop = None if self._last_poll_finished is None else now - self._last_poll_finished
        failures = self.storage.object_failure_summary()
        if not self._thread.is_alive():
            state = "stopped"
        elif since_loop is None:
            state = "starting" if now - self._started_at < stale_after else "stalled"
        elif since_loop > stale_after + poll:
            state = "stalled"
        elif since_success is None or since_success > stale_after:
            state = "stale"
        elif (
            status.get("last_error")
            or failures["failing_objects"]
            or (status.get("storage") or {}).get("disk_low")
        ):
            state = "degraded"
        else:
            state = "ok"
        return {
            "state": state,
            "poll_interval_secs": poll,
            "stale_after_secs": stale_after,
            "seconds_since_last_success": None if since_success is None else int(since_success),
            "seconds_since_last_poll": None if since_loop is None else int(since_loop),
            **failures,
        }

    def status(self) -> dict:
        """Never fails because the database does: a locked or broken database
        is reported in `database_error` (with the ingest state it implies)
        instead of turning the whole status endpoint into a 500."""
        try:
            status = self.storage.get_status()
            status["ingest"] = self.ingest_health(status)
        except sqlite3.Error as exc:
            logger.warning("Status query failed: %s", exc)
            status = {
                "database_error": f"{type(exc).__name__}: {exc}"[:300],
                "ingest": {"state": "unknown", "poll_interval_secs": self.cfg.webapp.poll_interval_secs},
            }
        status["version"] = __version__
        status["ai_configured"] = self.ai_configured()
        status["ai_summary_queue"] = self.summary_worker.status()
        try:
            status["ai_features"] = dict(self.ai_settings.snapshot().flags)
            budget = self.ai_meter.budget_status()
            status["ai_budget"] = budget
            status["ai_warnings"] = self.ai_settings.warnings() + [
                f"AI budget {item['budget']} is at {item['ratio'] * 100:.0f}% today (UTC)"
                + (" — calls are being skipped" if item["used"] >= item["limit"] else "")
                for item in budget if item["ratio"] >= 0.8
            ]
        except sqlite3.Error as exc:
            status["ai_warnings"] = [f"AI settings unavailable ({type(exc).__name__})"]
        status["actions_enabled"] = self.actions_enabled
        status["insights"] = self.insights.status()
        try:
            status["notifications"] = self.notifier.status()
        except sqlite3.Error as exc:
            status["notifications"] = {"enabled": bool(self.cfg.mattermost.enabled),
                                       "status_error": f"{type(exc).__name__}"}
        return status

    def ready(self) -> tuple[bool, bool]:
        """(ready, busy). A connection busy with a long query is still working;
        only one that stays busy past the grace period is reported unready."""
        if self.storage.ping():
            self._db_busy_since = None
            return True, False
        now = time.monotonic()
        if self._db_busy_since is None:
            self._db_busy_since = now
        return now - self._db_busy_since < _DB_BUSY_GRACE_SECS, True

    def ai_configured(self) -> bool:
        """True when the effective provider+model+key combination is usable."""
        return self.ai_settings.configured()

    def _budget_notice(self, text: str) -> None:
        if self.notifier.configured:
            self.notifier.send_text(text)

    def _dispatch_summaries(self, anomalies: list[dict]) -> int:
        """Insights' hand-off: queues anomalies for automatic summaries
        (anomaly_auto_summary on, urgency at or above the configured minimum)."""
        return self.summary_worker.enqueue(anomalies)

    def api_summarize_anomaly(self, anomaly_id: int, options: dict | None = None) -> dict:
        options = options or {}
        self.ai.require("anomaly_manual_summary")
        anomaly = self.anomaly_store.get_anomaly(anomaly_id)
        if anomaly is None:
            raise LookupError(anomaly_id)
        result = self.explainer.summarize_anomaly(anomaly, feature="anomaly_manual_summary", **options)
        if not result.get("degraded"):
            self.anomaly_store.save_ai_summary(
                anomaly_id, result["summary"], result.get("suggested_action", ""), result.get("steps"),
                meta=meta_of(result))
        return {**result, "id": anomaly_id}

    def api_ai_feedback(self, body: dict, client_id: str | None) -> dict:
        key = body.get("key")
        if not isinstance(key, str) or not key or len(key) > 300:
            raise ValueError("'key' is required")
        if not client_id or not _CLIENT_ID_RE.match(client_id):
            raise ValueError(f"The {FEEDBACK_CLIENT_HEADER} header must hold the browser session's client id")
        try:
            counts = self.ai_cache.feedback(key, str(body.get("vote") or ""), client_id)
        except KeyError:
            raise LookupError(key) from None
        return {"ok": True, "key": key, **counts}

    def api_settings(self) -> dict:
        view = self.ai_settings.public_view()
        view["admin_token_source"] = self.admin_token_source
        view["budget_status"] = self.ai_meter.budget_status()
        return view

    def api_settings_test(self) -> dict:
        """One minimal provider call with the saved settings (metered as
        settings_test, rate limited, outside the budgets)."""
        cfg = self.ai_settings.effective()
        problem = ping_problem(cfg)
        if problem:  # nothing to send: not a metered call
            return {"ok": False, "latency_ms": 0, "model": cfg.model, "error": problem}
        result = self.ai.call(TEST_FEATURE, ping_provider, before_call=self.ai_rate_limiter.acquire,
                              check_budget=False)
        return {k: result[k] for k in ("ok", "latency_ms", "model", "error") if k in result}

    def api_anomalies(self, params: dict[str, list[str]]) -> dict:
        flat = {
            key: _first(params, key)
            for key in ("status", "type", "namespace")
            if _first(params, key)
        }
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        result = self.anomaly_store.query_anomalies(flat, limit=limit)
        for item in result["items"]:
            # Free: what changed, counts vs baseline, top templates, signature.
            item["template_summary"] = anomaly_template_summary(self.signatures, item)
        return result

    def api_dashboard(self, params: dict[str, list[str]]) -> dict:
        flat = _query_params(params)
        return self.storage.query_dashboard(flat)

    def api_explain(self, params: dict[str, list[str]]) -> dict:
        """Explain the currently filtered logs: signatures when they cover the
        sample, else the template cache, else one AI call with the sample's
        top templates (not raw rows)."""
        self.ai.require("explain_filtered")
        options = _ai_options(lambda name: _first(params, name))
        flat = _query_params(params)
        data = self.storage.query_logs(flat, limit=FILTERED_SAMPLE_ROWS, cursor=None, direction="desc")
        items = data.get("items") or []
        if not items:
            if not self.ai_configured():
                raise ValueError("AI provider is not configured")
            return {"summary": "No logs found matching the current filters.", "steps": [], "suggested_action": "",
                    "sample_count": 0, "total_matching_exceeds_sample": False, "cached": False, "source": "none"}
        return self.explainer.explain_filtered(flat, items, sample_limit_reached=bool(data.get("has_more")), **options)

    def api_explain_line(self, body: dict) -> dict:
        """Explain a single already-fetched log row, re-derived by id from
        storage (never trusting client-supplied message text)."""
        self.ai.require("explain_line")
        options = _ai_options(body.get)
        record_id = body.get("id")
        if record_id is None:
            raise ValueError("Missing 'id' field")
        record_id = _bounded_int(record_id, "id")
        record = self.storage.get_record_by_id(record_id)
        if record is None:
            if not self.ai_configured():
                raise ValueError("AI provider is not configured")
            raise ValueError("Log record not found")
        return self.explainer.explain_line(record, **options)

    def api_logs(self, params: dict[str, list[str]]) -> dict:
        flat = _query_params(params)
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        cursor = decode_cursor(_first(params, "cursor"))
        result = self.storage.query_logs(flat, limit=limit, cursor=cursor, direction="desc")
        result["last_updated_at"] = self.storage.get_state("last_successful_ingest_at")
        return result

    def api_log_context(self, params: dict[str, list[str]]) -> dict:
        """Entries around one record of the same namespace/pod/container
        (see LogStorage.query_context). `start` / `before` optionally limit
        it to the active time range."""
        raw_id = _first(params, "id")
        if raw_id is None:
            raise ValueError("Missing 'id'")
        record_id = _bounded_int(raw_id, "id")
        lines_before = _bounded_int(_first(params, "lines_before", "10"), "lines_before")
        lines_after = _bounded_int(_first(params, "lines_after", "10"), "lines_after")
        bounds = _query_params(params)
        result = self.storage.query_context(
            record_id,
            lines_before=lines_before,
            lines_after=lines_after,
            start=bounds.get("start"),
            before=bounds.get("before"),
        )
        if result is None:
            raise ValueError("Log record not found (it may have aged out of the cache)")
        return result

    def api_tail(self, params: dict[str, list[str]]) -> dict:
        """New records since `after_id` (the `last_id` of the previous call, or
        `max_id` from /api/logs). Omit after_id to get the current position."""
        flat = _query_params(params)
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        raw_after = _first(params, "after_id")
        after_id = None
        if raw_after is not None:
            after_id = _bounded_int(raw_after, "after_id")
        result = self.storage.query_tail(flat, after_id=after_id, limit=limit)
        result["last_updated_at"] = self.storage.get_state("last_successful_ingest_at")
        return result


def build_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Run the Logscope web app")
    parser.add_argument("--config", default=str(default_server_config()))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None, prog: str | None = None) -> None:
    args = build_parser(prog).parse_args(argv)
    logging.basicConfig(
        level=os.environ.get("LOGSCOPE_LOG_LEVEL", "INFO").upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        cfg = load_app_config(Path(args.config))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.error("Invalid configuration in %s: %s", args.config, exc)
        sys.exit(2)
    # A host name given to --host is how this server is reached; trust it.
    bind_host = args.host.strip().lower()
    extra_hosts = () if bind_host in ("", "0.0.0.0", "::") or _is_ip_literal(bind_host) else (bind_host,)
    try:
        app = WebApp(cfg, extra_trusted_hosts=extra_hosts)
    except (OSError, sqlite3.Error, ValueError) as exc:
        logger.error("Cannot open database %s or %s: %s", cfg.webapp.db_path, cfg.webapp.state_db_path, exc)
        sys.exit(2)
    app.start()
    server = AppHTTPServer((args.host, args.port), LogscopeHandler, app)

    def _shutdown(signum, _frame):
        logger.info("Received signal %s; shutting down", signum)
        # shutdown() blocks until serve_forever() returns, so call it off-thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    try:
        logger.info(
            "Logscope %s web app listening on http://%s:%s (bucket region %s, db %s, actions %s, AI %s)",
            __version__, args.host, args.port, cfg.s3_region, cfg.webapp.db_path,
            "enabled" if app.actions_enabled else "disabled",
            "configured" if app.ai_configured() else "not configured",
        )
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        server.server_close()
        logger.info("Logscope web app stopped")


if __name__ == "__main__":
    main()