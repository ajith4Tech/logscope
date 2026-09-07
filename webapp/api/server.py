from __future__ import annotations

import argparse
import json
import threading
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import AppConfig, load_app_config
from .ingest import S3Ingestor
from .storage import LogStorage, decode_cursor


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
            self._send_json(app.storage.get_status())
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

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _ingest_loop(self) -> None:
        while not self._stop.is_set():
            self.ingestor.ingest_once()
            self._stop.wait(self.cfg.webapp.poll_interval_secs)

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