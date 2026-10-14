from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit

from .actions import SUPPORTED_ACTIONS, execute_action, parse_command_to_action
from .ai_summary import SUPPORTED_PROVIDERS, explain_log_line, explain_logs, summarize_anomaly
from .config import AppConfig, load_app_config
from .ingest import S3Ingestor
from .insights import AnomalyStore, InsightsJob
from .storage import LogStorage, decode_cursor

_EXPLAIN_CACHE_TTL = 300  # seconds — reuse cached answer for same filter set
_EXPLAIN_SAMPLE_SIZE = 50  # max log lines sent to the AI
_EXPLAIN_LINE_CACHE_TTL = 600  # per-line explanations rarely change; cache longer
_MAX_BODY_BYTES = 1024 * 1024  # JSON bodies are tiny; refuse anything larger
_PRUNE_INTERVAL_SECS = 3600
_DB_BUSY_GRACE_SECS = 60  # readiness tolerates the shared DB connection being busy this long
_DEFAULT_AI_RATE_LIMIT_PER_MINUTE = 10
_DEFAULT_PORTS = {"http": 80, "https": 443}

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


ROOT = Path(__file__).resolve().parents[2]
UI_DIR = ROOT / "webapp" / "ui"


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


def _coerce_limit(raw: str | None, default: int, maximum: int) -> int:
    if raw is None:
        return default
    value = int(raw)
    return max(1, min(value, maximum))


class AppHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, app):
        super().__init__(server_address, RequestHandlerClass)
        self.app = app


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

    def _serve_asset(self, path: Path, content_type: str) -> None:
        if not path.exists():
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
            self._serve_asset(UI_DIR / "index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._serve_asset(UI_DIR / "app.js", "application/javascript; charset=utf-8")
            return
        if parsed.path == "/styles.css":
            self._serve_asset(UI_DIR / "styles.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/api/status":
            status = app.storage.get_status()
            status["ai_configured"] = app.ai_configured()
            status["actions_enabled"] = app.actions_enabled
            self._send_json(status)
            return
        if parsed.path == "/api/facets":
            self._send_json(app.storage.query_facets(_query_params(params)))
            return
        if parsed.path == "/api/dashboard":
            self._send_json(app.api_dashboard(params))
            return
        if parsed.path == "/api/logs":
            self._send_json(app.api_logs(params))
            return
        if parsed.path == "/api/tail":
            self._send_json(app.api_tail(params))
            return
        if parsed.path == "/api/anomalies":
            self._send_json(app.api_anomalies(params))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

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
            confirmed = bool(body.get("confirmed", False))
            try:
                res = execute_action(body, confirmed=confirmed)
                self._send_json(res)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return
        if parsed.path == "/api/actions/validate":
            body = self._read_body_json()
            cmd = str(body.get("command") or "").strip()
            parsed_action = parse_command_to_action(cmd) if cmd else None
            if parsed_action:
                act = parsed_action["action"]
                spec = SUPPORTED_ACTIONS.get(act, {})
                self._send_json({
                    "valid": True,
                    "action": act,
                    "risk": spec.get("risk", "read-only"),
                    "is_mutating": spec.get("is_mutating", False),
                    "parsed": parsed_action,
                })
            else:
                self._send_json({
                    "valid": False,
                    "error": "Unsupported or unparseable command",
                }, status=400)
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
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_patch(self) -> None:
        parsed = urlparse(self.path)
        app = self.server.app
        # PATCH /api/anomalies/:id
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "anomalies":
            try:
                anomaly_id = int(parts[2])
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
        self.send_error(HTTPStatus.NOT_FOUND)


def _query_params(params: dict[str, list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("scope", "namespace", "pod", "container", "severity_bucket", "start", "end", "q"):
        value = _first(params, key)
        if value:
            out[key] = value
    return out


class WebApp:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.storage = LogStorage(cfg.webapp.db_path)
        self.ingestor = S3Ingestor(cfg, self.storage)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._ingest_loop, daemon=True)
        self.anomaly_store = AnomalyStore(cfg.webapp.db_path)
        self.insights = InsightsJob(
            cfg,
            self.storage.conn,
            self.anomaly_store,
            summarizer=lambda anomaly: summarize_anomaly(anomaly, cfg.ai),
            records_lock=self.storage.lock,
        )
        # Server-side explain caches: filter-set explain and per-line explain
        self._explain_cache: dict[str, tuple[dict, float]] = {}
        self._explain_line_cache: dict[int, tuple[dict, float]] = {}
        self._explain_lock = threading.Lock()
        # kubectl actions run with this pod's credentials and the HTTP API has no
        # auth, so deployments that expose the UI should set this to false.
        self.actions_enabled = _env_flag("LOGSCOPE_ACTIONS_ENABLED", True)
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
        if self.cfg.insights.enabled:
            self.insights.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        if self.cfg.insights.enabled:
            self.insights.stop()

    def _ingest_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.ingestor.ingest_once()
                self._maybe_prune()
            except Exception:
                logger.exception("Ingest loop iteration failed")
            self._stop.wait(self.cfg.webapp.poll_interval_secs)

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
        return self._thread.is_alive()

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
        """True when an AI provider+model+key combination is usable."""
        provider = str(self.cfg.ai.provider or "").strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            return False
        model = str(self.cfg.ai.model or "").strip()
        api_key = os.environ.get(self.cfg.ai.api_key_env, "")
        return bool(model and api_key)

    def api_anomalies(self, params: dict[str, list[str]]) -> dict:
        flat = {
            key: _first(params, key)
            for key in ("status", "type", "namespace")
            if _first(params, key)
        }
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        return self.anomaly_store.query_anomalies(flat, limit=limit)

    def api_dashboard(self, params: dict[str, list[str]]) -> dict:
        flat = _query_params(params)
        return self.storage.query_dashboard(flat)

    def api_explain(self, params: dict[str, list[str]]) -> dict:
        """Re-derive a bounded log sample from filters, summarize via AI.
        Server-side cache: same filter set returns cached result for _EXPLAIN_CACHE_TTL seconds.
        """
        if not self.ai_configured():
            raise ValueError("AI provider is not configured")
        flat = _query_params(params)
        cache_key = hashlib.sha1(
            json.dumps(flat, sort_keys=True).encode()
        ).hexdigest()
        now = time.monotonic()
        with self._explain_lock:
            cached = self._explain_cache.get(cache_key)
            if cached:
                result, expiry = cached
                if now < expiry and bool(result.get("steps")):
                    return {**result, "cached": True}
        data = self.storage.query_logs(flat, limit=_EXPLAIN_SAMPLE_SIZE, cursor=None, direction="desc")
        items = data.get("items") or []
        total_matching_exceeds_sample = bool(data.get("has_more"))
        if not items:
            return {"summary": "No logs found matching the current filters.", "steps": [], "suggested_action": "", "sample_count": 0, "total_matching_exceeds_sample": False, "cached": False}
        sample = [
            {
                "timestamp": item.get("timestamp"),
                "severity": item.get("severity_bucket"),
                "namespace": item.get("namespace"),
                "pod": item.get("pod"),
                "container": item.get("container"),
                "message": item.get("message"),
            }
            for item in items
        ]
        payload = {
            "filters": flat,
            "total_matching_exceeds_sample": total_matching_exceeds_sample,
            "sample_size": len(sample),
            "log_sample": sample,
        }
        self.ai_rate_limiter.acquire()
        result = explain_logs(payload, self.cfg.ai)
        if result is None:
            raise RuntimeError("AI summarization returned no result")
        response = {
            **result,
            "sample_count": len(sample),
            "total_matching_exceeds_sample": total_matching_exceeds_sample,
            "cached": False,
        }
        with self._explain_lock:
            self._explain_cache[cache_key] = (response, now + _EXPLAIN_CACHE_TTL)
        return response

    def api_explain_line(self, body: dict) -> dict:
        """Explain a single already-fetched log row, re-derived by id from
        storage (never trusting client-supplied message text)."""
        if not self.ai_configured():
            raise ValueError("AI provider is not configured")
        record_id = body.get("id")
        if record_id is None:
            raise ValueError("Missing 'id' field")
        try:
            record_id = int(record_id)
        except (TypeError, ValueError):
            raise ValueError("Invalid 'id' field")

        now = time.monotonic()
        with self._explain_lock:
            cached = self._explain_line_cache.get(record_id)
            if cached:
                result, expiry = cached
                if now < expiry and bool(result.get("steps")):
                    return {**result, "cached": True}

        record = self.storage.get_record_by_id(record_id)
        if record is None:
            raise ValueError("Log record not found")

        self.ai_rate_limiter.acquire()
        result = explain_log_line(record, self.cfg.ai)
        if result is None:
            raise RuntimeError("AI summarization returned no result")
        response = {**result, "cached": False}
        with self._explain_lock:
            self._explain_line_cache[record_id] = (response, now + _EXPLAIN_LINE_CACHE_TTL)
        return response

    def api_logs(self, params: dict[str, list[str]]) -> dict:
        flat = _query_params(params)
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        cursor = decode_cursor(_first(params, "cursor"))
        result = self.storage.query_logs(flat, limit=limit, cursor=cursor, direction="desc")
        result["last_updated_at"] = self.storage.get_state("last_successful_ingest_at")
        return result

    def api_tail(self, params: dict[str, list[str]]) -> dict:
        flat = _query_params(params)
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        cursor = decode_cursor(_first(params, "cursor"))
        result = self.storage.query_logs(flat, limit=limit, cursor=cursor, direction="asc")
        result["last_updated_at"] = self.storage.get_state("last_successful_ingest_at")
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Logscope web app")
    parser.add_argument("--config", default=str(ROOT / "config.yaml"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main() -> None:
    args = build_parser().parse_args()
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
    try:
        app = WebApp(cfg)
    except (OSError, sqlite3.Error) as exc:
        logger.error("Cannot open database %s: %s", cfg.webapp.db_path, exc)
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
            "Logscope web app listening on http://%s:%s (bucket region %s, db %s, actions %s, AI %s)",
            args.host, args.port, cfg.s3_region, cfg.webapp.db_path,
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