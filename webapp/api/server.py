from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .ai_summary import explain_log_line, explain_logs, summarize_anomaly
from .config import AppConfig, load_app_config
from .ingest import S3Ingestor
from .insights import AnomalyStore, InsightsJob
from .storage import LogStorage, decode_cursor

_EXPLAIN_CACHE_TTL = 300  # seconds — reuse cached answer for same filter set
_EXPLAIN_SAMPLE_SIZE = 50  # max log lines sent to the AI
_EXPLAIN_LINE_CACHE_TTL = 600  # per-line explanations rarely change; cache longer


ROOT = Path(__file__).resolve().parents[2]
UI_DIR = ROOT / "webapp" / "ui"


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _first(params: dict[str, list[str]], name: str, default: str | None = None) -> str | None:
    values = params.get(name)
    if not values:
        return default
    return values[0]


def _coerce_limit(raw: str | None, default: int, maximum: int) -> int:
    if raw is None:
        return default
    value = int(raw)
    return max(1, min(value, maximum))


class AppHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, app):
        super().__init__(server_address, RequestHandlerClass)
        self.app = app


class LogscopeHandler(SimpleHTTPRequestHandler):
    server: AppHTTPServer

    def log_message(self, format, *args):  # noqa: A003
        return

    def _send_json(self, payload: dict, status: int = 200) -> None:
        data = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
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
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        app = self.server.app
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
            self._send_json(status)
            return
        if parsed.path == "/api/facets":
            self._send_json(app.storage.query_facets(_query_params(params)))
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

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        app = self.server.app
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

    def do_PATCH(self):  # noqa: N802
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
        )
        # Server-side explain caches: filter-set explain and per-line explain
        self._explain_cache: dict[str, tuple[dict, float]] = {}
        self._explain_line_cache: dict[int, tuple[dict, float]] = {}
        self._explain_lock = threading.Lock()

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
            self.ingestor.ingest_once()
            self._stop.wait(self.cfg.webapp.poll_interval_secs)

    def ai_configured(self) -> bool:
        """True when an AI provider+model+key combination is usable."""
        provider = str(self.cfg.ai.provider or "").strip().lower()
        if provider not in ("openrouter", "gemini"):
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
                if now < expiry:
                    return {**result, "cached": True}
        data = self.storage.query_logs(flat, limit=_EXPLAIN_SAMPLE_SIZE, cursor=None, direction="desc")
        items = data.get("items") or []
        total_matching_exceeds_sample = bool(data.get("has_more"))
        if not items:
            return {"summary": "No logs found matching the current filters.", "suggested_action": "", "sample_count": 0, "total_matching_exceeds_sample": False, "cached": False}
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
                if now < expiry:
                    return {**result, "cached": True}

        record = self.storage.get_record_by_id(record_id)
        if record is None:
            raise ValueError("Log record not found")

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
        result["last_updated_at"] = self.storage.get_status().get("last_successful_ingest_at")
        return result

    def api_tail(self, params: dict[str, list[str]]) -> dict:
        flat = _query_params(params)
        limit = _coerce_limit(_first(params, "limit"), self.cfg.webapp.page_size_default, self.cfg.webapp.page_size_max)
        cursor = decode_cursor(_first(params, "cursor"))
        result = self.storage.query_logs(flat, limit=limit, cursor=cursor, direction="asc")
        result["last_updated_at"] = self.storage.get_status().get("last_successful_ingest_at")
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Logscope web app")
    parser.add_argument("--config", default=str(ROOT / "config.yaml"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_app_config(Path(args.config))
    app = WebApp(cfg)
    app.start()
    server = AppHTTPServer((args.host, args.port), LogscopeHandler, app)
    try:
        print(f"Logscope web app listening on http://{args.host}:{args.port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        server.server_close()


if __name__ == "__main__":
    main()