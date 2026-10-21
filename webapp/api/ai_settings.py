"""AI settings managed from the UI, usage metering and daily budgets.

Precedence for every field: an environment variable (set directly or from a
Kubernetes Secret) wins and is read-only in the UI; otherwise the value saved
from the Settings UI applies; otherwise config.yaml. For the API key that is
$<webapp.ai.api_key_env> > the key stored from the UI > none.

Secrets on disk, next to the state database (<state_dir>):
- admin.token: the bearer token for the settings endpoints, generated once
  (mode 0600) unless LOGSCOPE_ADMIN_TOKEN is set. Only its path is logged.
- secret.key: the Fernet master key that encrypts the stored API key,
  generated once (mode 0600) unless LOGSCOPE_SECRET_KEY is set.

The stored key is kept only as a Fernet token (ai_settings.api_key_enc) plus
its last four characters; neither the token nor the key is ever returned by
an endpoint or written to a log. Rotation: start with the new key in
LOGSCOPE_SECRET_KEY and the old one in LOGSCOPE_SECRET_KEY_PREVIOUS (comma
separated); the stored key is re-encrypted with the new key on startup. A key
that no configured master key can decrypt is reported (key_set false plus a
warning) and has to be entered again.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import math
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .ai_summary import SUPPORTED_PROVIDERS, capture_usage, is_local_base_url
from .config import AiConfig
from .state import StateDB

logger = logging.getLogger(__name__)

ADMIN_TOKEN_ENV = "LOGSCOPE_ADMIN_TOKEN"
SECRET_KEY_ENV = "LOGSCOPE_SECRET_KEY"
SECRET_KEY_PREVIOUS_ENV = "LOGSCOPE_SECRET_KEY_PREVIOUS"
ALLOWED_HOSTS_ENV = "LOGSCOPE_AI_ALLOWED_HOSTS"
ADMIN_TOKEN_FILE = "admin.token"
SECRET_KEY_FILE = "secret.key"
# Environment variables that pin a field (and make it read-only in the UI).
FIELD_ENV = {
    "provider": "LOGSCOPE_AI_PROVIDER",
    "model": "LOGSCOPE_AI_MODEL",
    "deep_model": "LOGSCOPE_AI_DEEP_MODEL",
    "base_url": "LOGSCOPE_AI_BASE_URL",
}
SETTINGS_FIELDS = tuple(FIELD_ENV)
CLEAR_KEY = "__clear__"

FEATURES = ("explain_line", "explain_filtered", "anomaly_auto_summary", "anomaly_manual_summary", "nl_filters")
DEFAULT_FLAGS = {feature: feature != "anomaly_auto_summary" for feature in FEATURES}
# Metered but outside the feature flags and per-feature budgets.
TEST_FEATURE = "settings_test"
# Every "Deep analysis" run is metered under this feature (whatever it
# explains), so it has its own daily_calls budget.
DEEP_FEATURE = "deep_analysis"
BUDGET_FEATURES = FEATURES + (DEEP_FEATURE,)
TIERS = ("fast", "deep")
OUTCOMES = ("ok", "error", "cache_hit", "budget_blocked", "signature")
# Outcomes that reached the provider: they count against the budgets.
_BILLED_OUTCOMES = ("ok", "error")
BUDGET_WARN_RATIO = 0.8

OFFICIAL_HOSTS = frozenset(
    {"openrouter.ai", "generativelanguage.googleapis.com", "api.openai.com", "api.anthropic.com"}
)
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
_KEY_MIN, _KEY_MAX = 8, 1000
_PRICE_MAX = 100_000.0  # USD per million tokens
_PRICES_MAX_MODELS = 200
_BUDGET_INT_MAX = 10**15
_USAGE_DAYS_MAX = 31


class SettingsError(Exception):
    """A settings request that cannot be applied; mapped to an HTTP status."""

    def __init__(self, message: str, field: str | None = None, status: int = 422):
        super().__init__(message)
        self.field = field
        self.status = status


class AiFeatureDisabled(Exception):
    def __init__(self, feature: str):
        super().__init__(feature)
        self.feature = feature


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


# ─── Secret files ────────────────────────────────────────────────────────────


def _read_or_create(path: Path, generate: Callable[[], str], what: str) -> str:
    """The file's value, created once with mode 0600 (directory 0700 when
    created here). Only the path is logged, never the value."""
    for _ in range(3):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            value = None
        if value:
            if path.stat().st_mode & 0o077:
                os.chmod(path, 0o600)
                logger.warning("Restricted %s to mode 0600: %s", what, path)
            return value
        if value == "":  # an interrupted earlier write
            path.unlink(missing_ok=True)
        if not path.parent.exists():
            os.makedirs(path.parent, mode=0o700, exist_ok=True)
        new = generate()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue  # another process won the race; read its value
        try:
            os.write(fd, (new + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        logger.info("Generated the %s: %s", what, path)
        return new
    raise OSError(f"Cannot create {path}")


def load_admin_token(state_dir: Path) -> tuple[str, str]:
    """(token, source): LOGSCOPE_ADMIN_TOKEN, else <state_dir>/admin.token."""
    token = _env(ADMIN_TOKEN_ENV)
    if token:
        return token, "env"
    path = Path(state_dir) / ADMIN_TOKEN_FILE
    token = _read_or_create(path, lambda: secrets.token_urlsafe(32), "Settings admin token")
    logger.info("Settings admin token is in %s", path)
    return token, "file"


def tokens_equal(supplied: str, expected: str) -> bool:
    """Constant-time comparison (hmac.compare_digest) of UTF-8 bytes."""
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


class ClientRateLimiter:
    """Events per client IP in a sliding window (failed admin-token attempts,
    feedback votes). Memory is bounded: idle addresses are dropped, and the
    table is capped."""

    def __init__(self, max_failures: int = 10, window_secs: float = 60.0, max_clients: int = 10_000):
        self.max_failures = max_failures
        self.window = window_secs
        self.max_clients = max_clients
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, ip: str, now: float) -> deque[float] | None:
        times = self._failures.get(ip)
        if times is None:
            return None
        while times and times[0] <= now - self.window:
            times.popleft()
        if not times:
            del self._failures[ip]
            return None
        return times

    def retry_after(self, ip: str) -> float:
        """Seconds until this address may try again; 0 when it may now."""
        now = time.monotonic()
        with self._lock:
            times = self._recent(ip, now)
            if times is None or len(times) < self.max_failures:
                return 0.0
            return max(0.0, times[-self.max_failures] + self.window - now)

    def fail(self, ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            if ip not in self._failures and len(self._failures) >= self.max_clients:
                for other in list(self._failures):
                    self._recent(other, now)
                if len(self._failures) >= self.max_clients:
                    self._failures.pop(next(iter(self._failures)))
            self._failures.setdefault(ip, deque(maxlen=self.max_failures * 2)).append(now)

    def allow(self, ip: str) -> float:
        """Counts one event unless the address is over the limit. Returns 0
        when allowed, else the seconds to wait (the event is not counted)."""
        wait = self.retry_after(ip)
        if wait > 0:
            return wait
        self.fail(ip)
        return 0.0


# The admin-token use; same class.
AuthFailureLimiter = ClientRateLimiter


# ─── Encryption ──────────────────────────────────────────────────────────────


def _fernet_key(raw: str) -> bytes:
    """A Fernet key as given, or one derived (HKDF-SHA256) from any secret of
    at least 32 characters."""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    try:
        Fernet(raw.encode("ascii"))
        return raw.encode("ascii")
    except (ValueError, UnicodeEncodeError):
        pass
    if len(raw) < 32:
        raise ValueError("must be a Fernet key or a random string of at least 32 characters")
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"logscope-settings-v1").derive(
        raw.encode("utf-8")
    )
    return base64.urlsafe_b64encode(derived)


class SecretBox:
    """Encrypts the stored API key with the master key. unavailable (with a
    reason) when cryptography is missing or a configured key is invalid; the
    rest of the app keeps working."""

    def __init__(self, state_dir: Path):
        self.error: str | None = None
        self.source = "env" if _env(SECRET_KEY_ENV) else "file"
        self._fernet = None
        try:
            from cryptography.fernet import Fernet, MultiFernet
        except ImportError:
            self.error = "the 'cryptography' package is not installed"
            logger.warning("Stored AI keys are unavailable: %s", self.error)
            return
        try:
            primary = _env(SECRET_KEY_ENV) or _read_or_create(
                Path(state_dir) / SECRET_KEY_FILE, lambda: Fernet.generate_key().decode("ascii"), "settings master key"
            )
            keys = [_fernet_key(primary)]
            keys += [_fernet_key(k.strip()) for k in _env(SECRET_KEY_PREVIOUS_ENV).split(",") if k.strip()]
        except ValueError as exc:
            self.error = f"{SECRET_KEY_ENV} or {SECRET_KEY_PREVIOUS_ENV} {exc}"
            logger.warning("Stored AI keys are unavailable: %s", self.error)
            return
        except OSError as exc:
            self.error = f"cannot create {SECRET_KEY_FILE} ({type(exc).__name__})"
            logger.warning("Stored AI keys are unavailable: %s", self.error)
            return
        self._fernet = MultiFernet([Fernet(k) for k in keys])

    @property
    def available(self) -> bool:
        return self._fernet is not None

    def encrypt(self, plain: str) -> str:
        if self._fernet is None:
            raise SettingsError(f"Key storage is unavailable: {self.error}", "api_key")
        return self._fernet.encrypt(plain.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str | None:
        """The plain value, or None when no configured master key opens it."""
        if self._fernet is None:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError):
            return None

    def rotate(self, token: str) -> str | None:
        """The token re-encrypted with the primary key, or None if undecryptable."""
        if self._fernet is None:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return self._fernet.rotate(token.encode("ascii")).decode("ascii")
        except (InvalidToken, ValueError):
            return None


# ─── Validation ──────────────────────────────────────────────────────────────


def allowed_hosts() -> frozenset[str]:
    extra = {h.strip().lower().rstrip(".").strip("[]") for h in _env(ALLOWED_HOSTS_ENV).split(",") if h.strip()}
    return OFFICIAL_HOSTS | LOCAL_HOSTS | frozenset(extra)


def validate_base_url(raw: Any) -> str:
    """"" (provider default) or an http(s) URL on an allowlisted host:
    https unless the host is local. No credentials, query or fragment."""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise SettingsError("'base_url' must be a string", "base_url")
    text = raw.strip()
    if not text:
        return ""
    if len(text) > 500 or re.search(r"[\x00-\x20\x7f]", text):
        raise SettingsError("'base_url' is not a valid URL", "base_url")
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(text)
        host = (parts.hostname or "").lower().rstrip(".")
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        raise SettingsError("'base_url' is not a valid URL", "base_url") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not host:
        raise SettingsError("'base_url' must be an http(s) URL", "base_url")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise SettingsError("'base_url' must not contain credentials", "base_url")
    if parts.query or parts.fragment:
        raise SettingsError("'base_url' must not have a query or fragment", "base_url")
    local = host in LOCAL_HOSTS
    if host not in allowed_hosts():
        raise SettingsError(
            f"'base_url' host {host!r} is not allowed; add it to {ALLOWED_HOSTS_ENV} to use it", "base_url"
        )
    if scheme != "https" and not local:
        raise SettingsError("'base_url' must use https (http only for localhost)", "base_url")
    return text.rstrip("/")


def _clean_provider(value: Any) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or value.strip().lower() not in SUPPORTED_PROVIDERS:
        raise SettingsError(f"'provider' must be one of {list(SUPPORTED_PROVIDERS)}", "provider")
    return value.strip().lower()


def _clean_model(value: Any, name: str) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or not _MODEL_RE.match(value.strip()):
        raise SettingsError(f"'{name}' must be a model id (letters, digits and ._:/@+-, at most 200)", name)
    return value.strip()


def _number(value: Any, name: str, *, integer: bool, maximum: float) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise SettingsError(f"'{name}' must be a number or null", name)
    if integer and value != int(value):
        raise SettingsError(f"'{name}' must be a whole number", name)
    if value < 0 or value > maximum:
        raise SettingsError(f"'{name}' must be between 0 and {maximum:g}", name)
    return int(value) if integer else float(value)


def clean_flags(raw: Any, name: str = "flags") -> dict[str, bool]:
    if not isinstance(raw, dict):
        raise SettingsError(f"'{name}' must be an object", name)
    out: dict[str, bool] = {}
    for key, value in raw.items():
        if key not in FEATURES:
            raise SettingsError(f"Unknown feature '{key}'", f"{name}.{key}")
        if not isinstance(value, bool):
            raise SettingsError(f"'{name}.{key}' must be true or false", f"{name}.{key}")
        out[key] = value
    return out


def clean_budgets(raw: Any, name: str = "budgets") -> dict[str, Any]:
    """{daily_tokens, daily_cost_usd, daily_calls: {feature: n}}; null = no limit."""
    if not isinstance(raw, dict):
        raise SettingsError(f"'{name}' must be an object", name)
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key == "daily_tokens":
            out[key] = _number(value, f"{name}.{key}", integer=True, maximum=_BUDGET_INT_MAX)
        elif key == "daily_cost_usd":
            out[key] = _number(value, f"{name}.{key}", integer=False, maximum=1e9)
        elif key == "daily_calls":
            if value is None:
                value = {}
            if not isinstance(value, dict):
                raise SettingsError(f"'{name}.daily_calls' must be an object", f"{name}.daily_calls")
            calls: dict[str, int | None] = {}
            for feature, limit in value.items():
                if feature not in BUDGET_FEATURES:
                    raise SettingsError(f"Unknown feature '{feature}'", f"{name}.daily_calls.{feature}")
                calls[feature] = _number(limit, f"{name}.daily_calls.{feature}", integer=True,
                                         maximum=_BUDGET_INT_MAX)
            out[key] = calls
        else:
            raise SettingsError(f"Unknown budget '{key}'", f"{name}.{key}")
    return out


def clean_prices(raw: Any, name: str = "prices") -> dict[str, dict[str, float]]:
    """{model: {input, output, cached}} in USD per million tokens; cached
    defaults to the input price."""
    if not isinstance(raw, dict):
        raise SettingsError(f"'{name}' must be an object", name)
    if len(raw) > _PRICES_MAX_MODELS:
        raise SettingsError(f"'{name}' lists more than {_PRICES_MAX_MODELS} models", name)
    out: dict[str, dict[str, float]] = {}
    for model, price in raw.items():
        model_id = _clean_model(model, f"{name} model")
        if not model_id:
            raise SettingsError("Price table model ids must not be empty", name)
        if not isinstance(price, dict) or set(price) - {"input", "output", "cached"}:
            raise SettingsError(f"'{name}.{model_id}' must have input, output and optional cached",
                                f"{name}.{model_id}")
        entry: dict[str, float] = {}
        for key in ("input", "output", "cached"):
            value = _number(price.get(key), f"{name}.{model_id}.{key}", integer=False, maximum=_PRICE_MAX)
            if value is None and key != "cached":
                raise SettingsError(f"'{name}.{model_id}.{key}' is required", f"{name}.{model_id}.{key}")
            if value is not None:
                entry[key] = value
        out[model_id] = entry
    return out


def estimate_tokens(chars: int) -> int:
    """chars/4, rounded up: the fallback when a provider reports no usage."""
    return int(math.ceil(max(0, chars) / 4))


def cost_usd(prices: dict[str, dict[str, float]], model: str, tokens_in: int, tokens_out: int,
             cached: int) -> float | None:
    """Estimated cost, or None when the model has no price (tokens are still
    counted). tokens_in includes the cached tokens."""
    price = prices.get(model)
    if price is None:
        lowered = model.lower()
        price = next((p for m, p in prices.items() if m.lower() == lowered), None)
    if price is None:
        return None
    cached = min(max(0, cached), max(0, tokens_in))
    cached_price = price.get("cached", price["input"])
    total = (tokens_in - cached) * price["input"] + cached * cached_price + tokens_out * price["output"]
    return round(total / 1_000_000, 8)


# ─── Settings ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Snapshot:
    cfg: AiConfig
    sources: dict[str, str]
    flags: dict[str, bool]
    budgets: dict[str, Any]
    prices: dict[str, dict[str, float]]
    prices_source: str
    key_set: bool
    key_last4: str
    key_source: str
    warnings: tuple[str, ...] = field(default_factory=tuple)


class AiSettings:
    """The effective AI settings behind a cached getter. update() writes the
    UI values and invalidates the cache, so the next provider call uses them
    without a restart."""

    def __init__(self, db: StateDB, base: AiConfig, box: SecretBox):
        self._db = db
        self._base = base
        self._box = box
        self._lock = threading.RLock()
        self._snapshot: _Snapshot | None = None
        self._warned_tokens: set[str] = set()
        self._rotate_stored_key()

    # -- storage --------------------------------------------------------------

    def _row(self) -> dict[str, Any]:
        with self._db.lock:
            row = self._db.conn.execute("SELECT * FROM ai_settings WHERE id = 1").fetchone()
        if row is None:
            return {}
        out = dict(row)
        for key, default in (("feature_flags", {}), ("budgets", {}), ("prices", None)):
            try:
                out[key] = json.loads(out[key]) if out.get(key) else default
            except ValueError:
                out[key] = default
        return out

    def _write(self, values: dict[str, Any]) -> None:
        values = dict(values)
        for key in ("feature_flags", "budgets", "prices"):
            if key in values and values[key] is not None:
                values[key] = json.dumps(values[key], sort_keys=True)
        values["updated_at"] = _iso(_utc_now())
        columns = list(values)  # names from this module only
        with self._db.lock:
            self._db.conn.execute(
                "INSERT INTO ai_settings (id, updated_at) VALUES (1, ?) ON CONFLICT(id) DO NOTHING",
                (values["updated_at"],),
            )
            self._db.conn.execute(
                f"UPDATE ai_settings SET {', '.join(f'{c} = ?' for c in columns)} WHERE id = 1",
                tuple(values[c] for c in columns),
            )

    def _rotate_stored_key(self) -> None:
        """Re-encrypt the stored key with the primary master key (after a
        rotation that kept the old key in LOGSCOPE_SECRET_KEY_PREVIOUS)."""
        if not self._box.available or not _env(SECRET_KEY_PREVIOUS_ENV):
            return
        token = self._row().get("api_key_enc")
        if not token:
            return
        rotated = self._box.rotate(token)
        if rotated and rotated != token:
            self._write({"api_key_enc": rotated})
            logger.info("Re-encrypted the stored AI key with the current master key")

    # -- effective values -----------------------------------------------------

    def invalidate(self) -> None:
        with self._lock:
            self._snapshot = None

    def snapshot(self) -> _Snapshot:
        with self._lock:
            if self._snapshot is None:
                self._snapshot = self._build()
            return self._snapshot

    def effective(self) -> AiConfig:
        return self.snapshot().cfg

    def _build(self) -> _Snapshot:
        row = self._row()
        base = self._base
        values: dict[str, str] = {}
        sources: dict[str, str] = {}
        for name, env_name in FIELD_ENV.items():
            env_value = _env(env_name)
            ui_value = str(row.get(name) or "").strip()
            if env_value:
                values[name], sources[name] = env_value, "env"
            elif ui_value:
                values[name], sources[name] = ui_value, "ui"
            else:
                values[name], sources[name] = str(getattr(base, name) or ""), "config"
        warnings: list[str] = []
        env_key = os.environ.get(base.api_key_env, "") if base.api_key_env else ""
        api_key, key_source = "", "none"
        if env_key:
            api_key, key_source = env_key, "env"
        elif row.get("api_key_enc"):
            plain = self._box.decrypt(row["api_key_enc"])
            if plain:
                api_key, key_source = plain, "ui"
            else:
                reason = (f"key storage is unavailable ({self._box.error})" if not self._box.available
                          else "it cannot be decrypted with the current master key (was LOGSCOPE_SECRET_KEY "
                               "or secret.key changed?)")
                warnings.append(f"The API key saved in Settings is not usable: {reason}. Enter it again.")
                if row["api_key_enc"] not in self._warned_tokens:
                    self._warned_tokens.add(row["api_key_enc"])
                    logger.warning("The stored AI key cannot be used: %s", reason)
        flags = {**DEFAULT_FLAGS, **base.features, **(row.get("feature_flags") or {})}
        budgets = {**base.budgets, **(row.get("budgets") or {})}
        calls = {**(base.budgets.get("daily_calls") or {}), **((row.get("budgets") or {}).get("daily_calls") or {})}
        budgets["daily_calls"] = calls
        ui_prices = row.get("prices")
        prices, prices_source = (ui_prices, "ui") if isinstance(ui_prices, dict) else (base.prices, "config")
        cfg = replace(base, provider=values["provider"], model=values["model"], deep_model=values["deep_model"],
                      base_url=values["base_url"], prices=prices, features=flags, budgets=budgets, api_key=api_key)
        return _Snapshot(
            cfg=cfg, sources=sources, flags=flags, budgets=budgets, prices=prices, prices_source=prices_source,
            key_set=bool(api_key), key_last4=api_key[-4:] if len(api_key) >= 8 else "",
            key_source=key_source, warnings=tuple(warnings),
        )

    def enabled(self, feature: str) -> bool:
        return bool(self.snapshot().flags.get(feature, False))

    def configured(self) -> bool:
        cfg = self.effective()
        return bool(str(cfg.provider or "").strip().lower() in SUPPORTED_PROVIDERS
                    and str(cfg.model or "").strip() and (cfg.api_key or is_local_base_url(cfg.base_url)))

    def warnings(self) -> list[str]:
        return list(self.snapshot().warnings)

    def public_view(self) -> dict[str, Any]:
        """GET /api/settings/ai. Never contains the key or its ciphertext."""
        snap = self.snapshot()
        cfg = snap.cfg
        return {
            "provider": cfg.provider,
            "model": cfg.model,
            "deep_model": cfg.deep_model,
            "base_url": cfg.base_url,
            "sources": dict(snap.sources),
            "key_set": snap.key_set,
            "key_last4": snap.key_last4,
            "key_source": snap.key_source,
            "key_env": self._base.api_key_env,
            "key_storage_available": self._box.available,
            "flags": dict(snap.flags),
            "budgets": json.loads(json.dumps(snap.budgets)),
            "prices": json.loads(json.dumps(snap.prices)),
            "prices_source": snap.prices_source,
            "providers": list(SUPPORTED_PROVIDERS),
            "features": list(FEATURES),
            "budget_features": list(BUDGET_FEATURES),
            "allowed_hosts": sorted(allowed_hosts()),
            "warnings": list(snap.warnings),
        }

    # -- updates ----------------------------------------------------------------

    def update(self, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise SettingsError("Request body must be a JSON object")
        known = {*SETTINGS_FIELDS, "api_key", "flags", "budgets", "prices"}
        unknown = sorted(str(k) for k in body if k not in known)
        if unknown:
            raise SettingsError(f"Unknown field '{unknown[0]}'", unknown[0])
        snap = self.snapshot()
        for name in SETTINGS_FIELDS:
            if name in body and snap.sources[name] == "env":
                raise SettingsError(f"'{name}' is set by {FIELD_ENV[name]}; change it there", name, status=409)
        values: dict[str, Any] = {}
        if "provider" in body:
            values["provider"] = _clean_provider(body["provider"]) or None
        for name in ("model", "deep_model"):
            if name in body:
                values[name] = _clean_model(body[name], name) or None
        if "base_url" in body:
            values["base_url"] = validate_base_url(body["base_url"]) or None
        row = self._row()
        if "flags" in body:
            values["feature_flags"] = {**(row.get("feature_flags") or {}), **clean_flags(body["flags"])}
        if "budgets" in body:
            update = clean_budgets(body["budgets"])
            merged = {**(row.get("budgets") or {}), **{k: v for k, v in update.items() if k != "daily_calls"}}
            if "daily_calls" in update:
                merged["daily_calls"] = {**((row.get("budgets") or {}).get("daily_calls") or {}),
                                         **update["daily_calls"]}
            values["budgets"] = merged
        if "prices" in body:
            values["prices"] = None if body["prices"] is None else clean_prices(body["prices"])
        key = body.get("api_key")
        if key is not None and key != "":
            if not isinstance(key, str):
                raise SettingsError("'api_key' must be a string", "api_key")
            if snap.key_source == "env":
                raise SettingsError(f"The API key is set by {self._base.api_key_env}; change it there",
                                    "api_key", status=409)
            if key == CLEAR_KEY:
                values["api_key_enc"] = None
                values["key_last4"] = None
            else:
                key = key.strip()
                if not _KEY_MIN <= len(key) <= _KEY_MAX or re.search(r"[\x00-\x20\x7f]", key):
                    raise SettingsError(
                        f"'api_key' must be {_KEY_MIN}-{_KEY_MAX} characters without spaces", "api_key")
                values["api_key_enc"] = self._box.encrypt(key)
                values["key_last4"] = key[-4:]
        if values:
            self._write(values)
        self.invalidate()
        return self.public_view()


# ─── Metering and budgets ────────────────────────────────────────────────────


def _day_bounds(day: datetime) -> tuple[str, str]:
    start = day.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return _iso(start), _iso(start + timedelta(days=1))


class UsageMeter:
    """One ai_usage row per AI request (cache hits and budget blocks
    included); budgets are checked against the current UTC day."""

    def __init__(self, db: StateDB, settings: AiSettings, *, notify: Callable[[str], None] | None = None,
                 clock: Callable[[], datetime] = _utc_now):
        self._db = db
        self._settings = settings
        self._notify = notify
        self._clock = clock
        self._notified: set[tuple[str, str]] = set()
        self._notify_lock = threading.Lock()

    def record(self, feature: str, outcome: str, *, provider: str = "", model: str = "", tokens_in: int = 0,
               tokens_out: int = 0, cached_tokens: int = 0, latency_ms: int = 0,
               subject: str | None = None) -> dict[str, Any]:
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        prices = self._settings.snapshot().prices
        cost = cost_usd(prices, model, tokens_in, tokens_out, cached_tokens) if outcome in _BILLED_OUTCOMES else 0.0
        row = {
            "ts": _iso(self._clock()), "feature": feature, "provider": provider or "", "model": model or "",
            "tokens_in": int(tokens_in), "tokens_out": int(tokens_out), "cached_tokens": int(cached_tokens),
            "cost_usd_est": cost, "latency_ms": int(latency_ms), "outcome": outcome, "subject": subject,
        }
        with self._db.lock:
            self._db.conn.execute(
                "INSERT INTO ai_usage (ts, feature, provider, model, tokens_in, tokens_out, cached_tokens, "
                "cost_usd_est, latency_ms, outcome, subject) VALUES (:ts, :feature, :provider, :model, :tokens_in, "
                ":tokens_out, :cached_tokens, :cost_usd_est, :latency_ms, :outcome, :subject)",
                row,
            )
        if outcome in _BILLED_OUTCOMES:
            self._maybe_notify()
        return row

    def record_blocked_once(self, feature: str, subject: str, *, provider: str = "", model: str = "") -> bool:
        """A budget_blocked row for this subject (e.g. "anomaly:42") unless one
        was already written today (UTC). Returns whether a row was written."""
        start, end = _day_bounds(self._clock())
        with self._db.lock:
            seen = self._db.conn.execute(
                "SELECT 1 FROM ai_usage WHERE outcome = 'budget_blocked' AND subject = ? AND ts >= ? AND ts < ? "
                "LIMIT 1", (subject, start, end)).fetchone()
            if seen:
                return False
            self.record(feature, "budget_blocked", provider=provider, model=model, subject=subject)
        return True

    def _today(self) -> dict[str, Any]:
        start, end = _day_bounds(self._clock())
        with self._db.lock:
            totals = self._db.conn.execute(
                "SELECT COALESCE(SUM(tokens_in + tokens_out), 0), COALESCE(SUM(cost_usd_est), 0) FROM ai_usage "
                "WHERE ts >= ? AND ts < ? AND outcome IN ('ok', 'error')", (start, end),
            ).fetchone()
            calls = dict(self._db.conn.execute(
                "SELECT feature, COUNT(*) FROM ai_usage WHERE ts >= ? AND ts < ? AND outcome IN ('ok', 'error') "
                "GROUP BY feature", (start, end),
            ).fetchall())
        return {"tokens": int(totals[0]), "cost_usd": float(totals[1]), "calls": calls}

    def budget_status(self) -> list[dict[str, Any]]:
        """Each configured budget with today's use: {budget, used, limit, ratio}."""
        budgets = self._settings.snapshot().budgets
        today = self._today()
        out: list[dict[str, Any]] = []

        def add(key: str, used: float, limit: Any) -> None:
            if limit is None:
                return
            ratio = (used / limit) if limit > 0 else 1.0
            out.append({"budget": key, "used": round(used, 6), "limit": limit, "ratio": round(ratio, 4)})

        add("daily_tokens", today["tokens"], budgets.get("daily_tokens"))
        add("daily_cost_usd", today["cost_usd"], budgets.get("daily_cost_usd"))
        for feature, limit in sorted((budgets.get("daily_calls") or {}).items()):
            add(f"daily_calls.{feature}", today["calls"].get(feature, 0), limit)
        return out

    def check(self, feature: str) -> str | None:
        """The exhausted budget that blocks a call for this feature, or None."""
        for item in self.budget_status():
            key = item["budget"]
            if key.startswith("daily_calls.") and key != f"daily_calls.{feature}":
                continue
            if item["used"] >= item["limit"]:
                return key
        return None

    def warnings(self) -> list[dict[str, Any]]:
        return [item for item in self.budget_status() if item["ratio"] >= BUDGET_WARN_RATIO]

    def _maybe_notify(self) -> None:
        if self._notify is None:
            return
        day = self._clock().strftime("%Y-%m-%d")
        messages = []
        with self._notify_lock:
            self._notified = {k for k in self._notified if k[0] == day}
            for item in self.warnings():
                ident = (day, item["budget"])
                if ident in self._notified:
                    continue
                self._notified.add(ident)
                messages.append(
                    f"Logscope AI budget `{item['budget']}` is at {item['ratio'] * 100:.0f}% for {day} (UTC): "
                    f"{item['used']:g} of {item['limit']:g}. Calls are skipped once it is reached."
                )
        for message in messages:
            threading.Thread(target=self._send, args=(message,), daemon=True, name="ai-budget-notice").start()

    def _send(self, message: str) -> None:
        try:
            self._notify(message)  # type: ignore[misc]
        except Exception as exc:  # noqa: BLE001 - a notice must never break a request
            logger.warning("AI budget notice failed (%s)", type(exc).__name__)

    def summary(self, days: int = 7) -> dict[str, Any]:
        """Today and the last `days` UTC days, by feature: calls (billed),
        tokens, cost, cache-hit % and blocked calls."""
        days = max(1, min(int(days), _USAGE_DAYS_MAX))
        now = self._clock()
        today_start, end = _day_bounds(now)
        first = _iso(datetime.fromisoformat(today_start.replace("Z", "+00:00")) - timedelta(days=days - 1))
        with self._db.lock:
            rows = self._db.conn.execute(
                "SELECT substr(ts, 1, 10) AS day, feature, outcome, COUNT(*) AS n, "
                "COALESCE(SUM(tokens_in), 0) AS tin, COALESCE(SUM(tokens_out), 0) AS tout, "
                "COALESCE(SUM(cached_tokens), 0) AS tcached, COALESCE(SUM(cost_usd_est), 0) AS cost, "
                "SUM(CASE WHEN cost_usd_est IS NULL THEN 1 ELSE 0 END) AS unpriced "
                "FROM ai_usage WHERE ts >= ? AND ts < ? GROUP BY day, feature, outcome",
                (first, end),
            ).fetchall()

        def empty() -> dict[str, Any]:
            return {"calls": 0, "errors": 0, "cache_hits": 0, "signature_hits": 0, "blocked": 0, "tokens_in": 0,
                    "tokens_out": 0, "cached_tokens": 0, "cost_usd": 0.0, "unpriced_calls": 0}

        def add(bucket: dict[str, Any], row: Any) -> None:
            n = int(row["n"])
            outcome = row["outcome"]
            if outcome in _BILLED_OUTCOMES:
                bucket["calls"] += n
                bucket["errors"] += n if outcome == "error" else 0
                bucket["tokens_in"] += int(row["tin"])
                bucket["tokens_out"] += int(row["tout"])
                bucket["cached_tokens"] += int(row["tcached"])
                bucket["cost_usd"] += float(row["cost"])
                bucket["unpriced_calls"] += int(row["unpriced"] or 0)
            elif outcome == "cache_hit":
                bucket["cache_hits"] += n
            elif outcome == "signature":
                bucket["signature_hits"] += n
            elif outcome == "budget_blocked":
                bucket["blocked"] += n

        def finish(bucket: dict[str, Any]) -> dict[str, Any]:
            # Answered requests: provider calls, cache hits and signature hits.
            served = bucket["calls"] + bucket["cache_hits"] + bucket["signature_hits"]
            bucket["cache_hit_pct"] = round(100.0 * bucket["cache_hits"] / served, 1) if served else 0.0
            bucket["signature_hit_pct"] = round(100.0 * bucket["signature_hits"] / served, 1) if served else 0.0
            bucket["free_pct"] = round(100.0 * (bucket["cache_hits"] + bucket["signature_hits"]) / served, 1) \
                if served else 0.0
            bucket["tokens"] = bucket["tokens_in"] + bucket["tokens_out"]
            bucket["cost_usd"] = round(bucket["cost_usd"], 6)
            return bucket

        today_key = today_start[:10]
        today: dict[str, dict[str, Any]] = {}
        period: dict[str, dict[str, Any]] = {}
        by_day: dict[str, dict[str, Any]] = {}
        for row in rows:
            feature = row["feature"]
            if row["day"] == today_key:
                add(today.setdefault(feature, empty()), row)
            add(period.setdefault(feature, empty()), row)
            add(by_day.setdefault(row["day"], empty()), row)
        day_list = []
        for offset in range(days - 1, -1, -1):
            key = (now - timedelta(days=offset)).astimezone(timezone.utc).strftime("%Y-%m-%d")
            day_list.append({"day": key, **finish(by_day.get(key) or empty())})
        total_today = empty()
        for bucket in today.values():
            for k, v in bucket.items():
                total_today[k] += v
        total_period = empty()
        for bucket in period.values():
            for k, v in bucket.items():
                total_period[k] += v
        return {
            "days": days,
            "today": {"date": today_key, "total": finish(total_today),
                      "by_feature": {k: finish(v) for k, v in sorted(today.items())}},
            "period": {"from": first[:10], "total": finish(total_period),
                       "by_feature": {k: finish(v) for k, v in sorted(period.items())}},
            "by_day": day_list,
            "budgets": self.budget_status(),
        }


# ─── Metered calls ───────────────────────────────────────────────────────────

def model_for(tier: str, cfg: AiConfig) -> str:
    """fast: settings.model; deep: settings.deep_model (else model)."""
    return (cfg.deep_model or cfg.model) if tier == "deep" else cfg.model


def tier_config(tier: str, cfg: AiConfig) -> AiConfig:
    return replace(cfg, model=model_for(tier, cfg)) if tier == "deep" else cfg


def metered_feature(feature: str, tier: str) -> str:
    return DEEP_FEATURE if tier == "deep" else feature


def budget_response(budget: str) -> dict[str, Any]:
    return {
        "degraded": True,
        "reason": "budget",
        "budget": budget,
        "summary": "",
        "steps": [],
        "suggested_action": "",
        "error": f"The daily AI budget '{budget}' is used up; the call was skipped (resets at 00:00 UTC).",
    }


def _result_chars(result: Any) -> int:
    if not isinstance(result, dict):
        return 0
    return len(json.dumps({k: result.get(k) for k in ("summary", "steps")}, ensure_ascii=False))


class AiService:
    """Feature flags, budgets and metering around every provider call."""

    def __init__(self, settings: AiSettings, meter: UsageMeter):
        self.settings = settings
        self.meter = meter

    def require(self, feature: str) -> None:
        if not self.settings.enabled(feature):
            raise AiFeatureDisabled(feature)

    def cache_hit(self, feature: str, tier: str = "fast") -> None:
        cfg = self.settings.effective()
        self.meter.record(metered_feature(feature, tier), "cache_hit", provider=cfg.provider,
                          model=model_for(tier, cfg))

    def signature_hit(self, feature: str) -> None:
        self.meter.record(feature, "signature")

    def call(self, feature: str, fn: Callable[[AiConfig], Any], *, input_chars: int = 0,
             before_call: Callable[[], None] | None = None, check_budget: bool = True,
             tier: str = "fast", subjects: list[str] | None = None) -> Any:
        """fn(effective_cfg) under the budget check and metering. Returns
        budget_response(...) when a budget is exhausted (no call is made).
        before_call (e.g. the rate limiter) runs only for a real call. The
        deep tier runs with deep_model and is metered (and budgeted) as
        deep_analysis."""
        if tier not in TIERS:
            raise ValueError(f"'tier' must be one of {list(TIERS)}")
        cfg = tier_config(tier, self.settings.effective())
        feature = metered_feature(feature, tier)
        model = cfg.model
        if check_budget:
            blocked = self.meter.check(feature)
            if blocked:
                if subjects:
                    # Retried work (pending anomalies) is blocked again on every
                    # run: one row per subject and UTC day is enough.
                    for subject in subjects:
                        self.meter.record_blocked_once(feature, subject, provider=cfg.provider, model=model)
                else:
                    self.meter.record(feature, "budget_blocked", provider=cfg.provider, model=model)
                return budget_response(blocked)
        if before_call is not None:
            before_call()
        started = time.monotonic()
        with capture_usage() as usage:
            try:
                result = fn(cfg)
            except Exception:
                self._record(feature, "error", cfg, model, usage, input_chars, None, started)
                raise
        if result is not None:
            self._record(feature, "ok" if not (isinstance(result, dict) and result.get("ok") is False) else "error",
                         cfg, model, usage, input_chars, result, started)
        return result

    def _record(self, feature: str, outcome: str, cfg: AiConfig, model: str, usage: dict[str, Any],
                input_chars: int, result: Any, started: float) -> None:
        tokens_in = usage.get("tokens_in")
        if tokens_in is None:
            tokens_in = estimate_tokens(int(usage.get("input_chars") or input_chars))
        tokens_out = usage.get("tokens_out")
        if tokens_out is None:
            tokens_out = estimate_tokens(_result_chars(result))
        try:
            self.meter.record(
                feature, outcome, provider=str(cfg.provider or ""), model=model, tokens_in=tokens_in,
                tokens_out=tokens_out, cached_tokens=int(usage.get("cached_tokens") or 0),
                latency_ms=int((time.monotonic() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001 - metering must not turn an answer into an error
            logger.warning("Could not record AI usage (%s)", type(exc).__name__)
