"""logscope: single entry point for the web app and its operator tools.

    logscope serve        [--host H] [--port P] [--config FILE]    the web app (UI + API)
    logscope render       [-c FILE] [-o DIR]                       Vector Helm values / vector.yaml
    logscope s3-lifecycle [-c FILE] [--secret FILE]                S3 retention rule (one-time)
    logscope db           [--db FILE] backup|verify|restore|compact [--state] ...
    logscope healthcheck  [--port P]                               GET /healthz on 127.0.0.1; exit 0/1
    logscope selfcheck    [--config FILE]                          local checks, no network calls
    logscope version

The older entry points keep working: python -m webapp.api.server,
python -m webapp.api.dbtool, scripts/render.py, scripts/apply_s3_lifecycle.py.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from .version import __revision__, __version__

# Subcommands that hand their remaining arguments to an existing tool's own
# parser (so `logscope serve --help` shows that tool's options).
_DELEGATED = {
    "serve": "Run the web app (UI + API); options as python -m webapp.api.server",
    "render": "Render Vector Helm values, vector.yaml and the backup CronJob from config",
    "s3-lifecycle": "Apply the S3 lifecycle retention rule from config (LOGSCOPE_* overrides apply)",
    "db": "Back up, verify, restore or compact the SQLite cache (--state: saved views)",
}

_HEALTHCHECK_TIMEOUT_SECS = 5.0


def _serve(argv: list[str]) -> int:
    from webapp.api import server

    server.main(argv, prog="logscope serve")
    return 0


def _render(argv: list[str]) -> int:
    from . import render

    return render.main(argv, prog="logscope render")


def _s3_lifecycle(argv: list[str]) -> int:
    from . import s3_lifecycle

    return s3_lifecycle.main(argv, prog="logscope s3-lifecycle")


def _db(argv: list[str]) -> int:
    from webapp.api import dbtool

    return dbtool.main(argv, prog="logscope db")


_HANDLERS = {"serve": _serve, "render": _render, "s3-lifecycle": _s3_lifecycle, "db": _db}


def healthcheck(port: int, path: str = "/healthz", timeout: float = _HEALTHCHECK_TIMEOUT_SECS) -> int:
    """0 when http://127.0.0.1:<port><path> answers 200, else 1. Standard
    library only, and never through HTTP(S)_PROXY."""
    import urllib.error
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with opener.open(url, timeout=timeout) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (OSError, ValueError) as exc:
        print(f"unhealthy: {url}: {exc}", file=sys.stderr)
        return 1
    if status != 200:
        print(f"unhealthy: {url} returned HTTP {status}", file=sys.stderr)
        return 1
    print(f"healthy: {url}")
    return 0


class _Report:
    """Collects selfcheck lines; any FAIL makes the exit status 1."""

    def __init__(self) -> None:
        self.failed = False

    def line(self, level: str, name: str, detail: str) -> None:
        if level == "FAIL":
            self.failed = True
        print(f"{level:<4}  {name:<12} {detail}")

    def ok(self, name: str, detail: str) -> None:
        self.line("ok", name, detail)

    def warn(self, name: str, detail: str) -> None:
        self.line("WARN", name, detail)

    def fail(self, name: str, detail: str) -> None:
        self.line("FAIL", name, detail)


def _check_fts5(report: _Report) -> None:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE VIRTUAL TABLE selfcheck USING fts5(body)")
        conn.execute("INSERT INTO selfcheck(body) VALUES ('fts5 probe')")
        hits = conn.execute("SELECT COUNT(*) FROM selfcheck WHERE selfcheck MATCH 'probe'").fetchone()[0]
    except sqlite3.Error as exc:
        report.fail("fts5", f"SQLite {sqlite3.sqlite_version} has no usable FTS5: {exc}")
        return
    finally:
        conn.close()
    if hits == 1:
        report.ok("fts5", f"SQLite {sqlite3.sqlite_version} with FTS5")
    else:
        report.fail("fts5", f"SQLite {sqlite3.sqlite_version}: FTS5 query returned {hits} rows, expected 1")


def _probe_writable(directory: Path) -> str | None:
    """None when a file can be created in directory, else the reason."""
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".logscope-selfcheck-"):
            pass
    except OSError as exc:
        return f"{type(exc).__name__}: {exc.strerror or exc}"
    return None


def _check_writable(report: _Report, name: str, db_path: Path) -> None:
    """The database file (if present) and its directory must be writable
    (SQLite writes -wal/-journal files beside it). A missing directory is
    created by the app, so its nearest existing parent must be writable."""
    if db_path.exists():
        if not os.access(db_path, os.W_OK):
            report.fail(name, f"{db_path} exists but is not writable")
            return
        directory = db_path.parent
    else:
        directory = db_path.parent
        while not directory.exists() and directory != directory.parent:
            directory = directory.parent
    reason = _probe_writable(directory)
    if reason:
        report.fail(name, f"{db_path}: cannot write in {directory} ({reason})")
    else:
        report.ok(name, f"{db_path} ({'exists' if db_path.exists() else 'will be created'}; {directory} writable)")


def is_frozen_bundle() -> bool:
    from .resources import is_frozen

    return is_frozen()


def _check_modules(report: _Report, need_anthropic: bool) -> None:
    """boto3 with botocore's S3 service model (data files), and the anthropic
    SDK. A missing SDK fails the check in a bundle (the build is incomplete)
    or when the config selects it; otherwise it is reported only."""
    try:
        import boto3  # noqa: F401
        import botocore.session

        botocore.session.get_session().get_service_model("s3")
    except Exception as exc:  # noqa: BLE001 - report any import or data problem
        report.fail("boto3", f"S3 client unavailable: {type(exc).__name__}: {exc}")
    else:
        report.ok("boto3", f"boto3 {boto3.__version__}, S3 service model present")
    try:
        import anthropic
    except Exception as exc:  # noqa: BLE001
        (report.fail if need_anthropic else report.warn)(
            "anthropic", f"SDK not importable: {type(exc).__name__}: {exc}")
    else:
        report.ok("anthropic", f"SDK {anthropic.__version__}")
    try:
        import cryptography
        from cryptography.fernet import Fernet

        probe = Fernet(Fernet.generate_key())
        if probe.decrypt(probe.encrypt(b"selfcheck")) != b"selfcheck":
            raise ValueError("round-trip mismatch")
    except Exception as exc:  # noqa: BLE001
        # Needed only for an API key stored from the Settings UI.
        (report.fail if is_frozen_bundle() else report.warn)(
            "cryptography", f"unavailable: {type(exc).__name__}; a key stored from the Settings UI cannot be used")
    else:
        report.ok("cryptography", f"{cryptography.__version__}, Fernet round-trip ok")


def _report_ai(report: _Report, cfg) -> None:
    from webapp.api.ai_summary import SUPPORTED_PROVIDERS

    ai = cfg.ai
    provider = str(ai.provider or "").strip().lower()
    if provider in ("", "none") or provider not in SUPPORTED_PROVIDERS:
        report.ok("ai", f"disabled (provider {ai.provider!r})")
        return
    missing = []
    if not str(ai.model or "").strip():
        missing.append("webapp.ai.model")
    if not os.environ.get(ai.api_key_env):
        missing.append(f"${ai.api_key_env}")
    if missing:
        report.warn("ai", f"provider {provider} set but {', '.join(missing)} missing: AI features stay off "
                          "unless set in the Settings UI")
    else:
        report.ok("ai", f"provider {provider}, model {ai.model}, key from ${ai.api_key_env}")


def _report_s3(report: _Report, cfg) -> None:
    report.ok("s3", f"s3://{cfg.s3_bucket}/{cfg.s3_key_prefix.split('{{', 1)[0]} in {cfg.s3_region}")
    if cfg.s3_access_key_id and cfg.s3_secret_access_key:
        source = "deploy/k3s/s3-secret.yaml beside the config"
    elif os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        source = "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"
    elif os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") and os.environ.get("AWS_ROLE_ARN"):
        source = "web identity (AWS_ROLE_ARN)"
    elif os.environ.get("AWS_PROFILE") or os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        source = "AWS profile / container credentials"
    else:
        source = None
    if source:
        report.ok("s3-creds", f"from {source} (not verified: no network calls)")
    else:
        report.warn("s3-creds", "no explicit credentials found; boto3 falls back to its default chain")
    endpoint = os.environ.get("AWS_ENDPOINT_URL_S3") or os.environ.get("AWS_ENDPOINT_URL")
    if endpoint:
        report.ok("s3-endpoint", f"override {endpoint}")


def selfcheck(config: Path) -> int:
    """Local readiness checks; never contacts S3 or an AI provider."""
    report = _Report()
    report.ok("version", f"{__version__}{f' ({__revision__})' if __revision__ else ''}, Python {sys.version.split()[0]}")
    _check_fts5(report)
    from webapp.api.config import load_app_config

    from .resources import is_frozen

    try:
        cfg = load_app_config(config)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report.fail("config", f"{config}: {type(exc).__name__}: {exc}")
        cfg = None
    else:
        report.ok("config", f"{config} loads")
    provider = str(getattr(getattr(cfg, "ai", None), "provider", "") or "").strip().lower()
    _check_modules(report, need_anthropic=is_frozen() or provider == "anthropic")
    if cfg is not None:
        _check_writable(report, "db", cfg.webapp.db_path)
        _check_writable(report, "state-db", cfg.webapp.state_db_path)
        tmp = Path(os.environ.get("SQLITE_TMPDIR") or tempfile.gettempdir())
        reason = _probe_writable(tmp) if tmp.is_dir() else "missing"
        (report.warn if reason else report.ok)("tmp", f"{tmp} {'not writable: ' + reason if reason else 'writable'}")
        _report_ai(report, cfg)
        _report_s3(report, cfg)
    print("selfcheck: " + ("FAILED" if report.failed else "passed"))
    return 1 if report.failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logscope",
        description="Logscope: Kubernetes log viewer with anomaly insights, and its operator tools.",
        epilog="Run `logscope <command> --help` for a command's options.",
    )
    parser.add_argument("--version", action="version", version=f"logscope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    for name, help_text in _DELEGATED.items():
        sub.add_parser(name, help=help_text, add_help=False)
    p_health = sub.add_parser("healthcheck", help="Exit 0 when GET http://127.0.0.1:$PORT/healthz returns 200")
    p_health.add_argument("--port", type=int, default=int(os.environ.get("PORT") or 8000),
                          help="port the server listens on (default: $PORT or 8000)")
    p_health.add_argument("--path", default="/healthz", help=argparse.SUPPRESS)
    p_health.add_argument("--timeout", type=float, default=_HEALTHCHECK_TIMEOUT_SECS, help="seconds (default: 5)")
    p_self = sub.add_parser("selfcheck", help="Check FTS5, config, writable paths, AI and S3 settings (no network)")
    from .resources import default_server_config

    p_self.add_argument("--config", type=Path, default=default_server_config(),
                        help=f"config file (default: {default_server_config()})")
    sub.add_parser("version", help="Print the version")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _HANDLERS:
        return _HANDLERS[argv[0]](argv[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "healthcheck":
        return healthcheck(args.port, args.path, args.timeout)
    if args.command == "selfcheck":
        return selfcheck(args.config)
    if args.command == "version":
        print(f"logscope {__version__}" + (f" ({__revision__})" if __revision__ else ""))
        return 0
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
