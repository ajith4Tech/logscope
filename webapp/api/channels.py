"""Notification channels shared by anomaly notifications (notify.py) and
alerts (alerts.py): Mattermost and Slack incoming webhooks and a generic JSON
webhook, with one delivery path (timeout, retries with backoff, no redirects).

Channels created from the UI are stored in the state database
(notification_channels) with the URL and the optional HMAC secret encrypted
by the settings master key (ai_settings.SecretBox). Both are write-only: the
API shows the URL's last six characters and whether a secret is set. A webhook
URL is a credential, so it never appears in a response, an error text or a
log line. The Mattermost webhook configured by environment
(webapp.mattermost.webhook_url_env) is offered as the read-only channel 0;
its URL is never copied into the database.

SSRF guard for UI channels (check_destination): https only unless the host
is localhost or listed in LOGSCOPE_ALERT_ALLOWED_HOSTS; the host is resolved
first and link-local and cloud metadata addresses are always refused,
loopback and private ranges unless the host is allowed. The connection goes
to the vetted address (no second lookup, so DNS rebinding cannot swap it) and
redirects are never followed.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib import error, request
from urllib.parse import urlsplit

from .state import StateDB

logger = logging.getLogger(__name__)

ALLOWED_HOSTS_ENV = "LOGSCOPE_ALERT_ALLOWED_HOSTS"
CHANNEL_TYPES = ("mattermost", "slack", "webhook")
ENV_CHANNEL_ID = 0
SEND_TIMEOUT_SECS = 10
SEND_ATTEMPTS = 5
RETRY_BASE_SECS = 1.0
SIGNATURE_HEADER = "X-Logscope-Signature"
CHANNELS_MAX = 50
CLEAR = "__clear__"
_TRANSIENT_HTTP = {408, 425, 429, 500, 502, 503, 504}
_NAME_MAX = 80
_URL_MAX = 2000
_SECRET_MIN, _SECRET_MAX = 16, 256
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
# Always refused, allowed host or not.
_METADATA = (ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("fe80::/10"),
             ipaddress.ip_network("fd00:ec2::254/128"), ipaddress.ip_network("100.100.100.200/32"))


class DeliveryError(Exception):
    """A failed delivery. The message never contains the URL."""

    def __init__(self, message: str, *, transient: bool):
        super().__init__(message)
        self.transient = transient


class ChannelError(Exception):
    def __init__(self, message: str, field: str | None = None, status: int = 422):
        super().__init__(message)
        self.field = field
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def allowed_hosts() -> frozenset[str]:
    raw = os.environ.get(ALLOWED_HOSTS_ENV, "")
    return frozenset(h.strip().lower().rstrip(".").strip("[]") for h in raw.split(",") if h.strip())


def _host_allowed(host: str) -> bool:
    return host == "localhost" or host in allowed_hosts()


def check_url_shape(url: Any, field: str = "url") -> str:
    """Syntax and scheme only (no DNS): an http(s) URL without credentials or
    fragment, https unless the host is allowed. ChannelError otherwise."""
    if not isinstance(url, str) or not url.strip():
        raise ChannelError(f"'{field}' is required", field)
    text = url.strip()
    if len(text) > _URL_MAX or _CONTROL_RE.search(text):
        raise ChannelError(f"'{field}' is not a valid URL", field)
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower().rstrip(".")
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        raise ChannelError(f"'{field}' is not a valid URL", field) from None
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise ChannelError(f"'{field}' must be an https URL", field)
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ChannelError(f"'{field}' must not contain credentials or a fragment", field)
    if parts.scheme.lower() != "https" and not _host_allowed(host):
        raise ChannelError(f"'{field}' must use https (http only for localhost or a host in {ALLOWED_HOSTS_ENV})",
                           field)
    return text


def _refused(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, host_allowed: bool) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in net for net in _METADATA) or ip.is_link_local:
        return "a link-local or metadata address"
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return "a reserved address"
    if ip.is_loopback and not host_allowed:
        return "a loopback address"
    if ip.is_private and not ip.is_loopback and not host_allowed:
        return "a private address"
    return None


def check_destination(url: str, *, resolve: Callable[..., list] = socket.getaddrinfo) -> tuple[str, int, str]:
    """(host, port, vetted IP) for a UI channel URL, after the SSRF checks.
    DeliveryError (not transient) when refused."""
    try:
        check_url_shape(url)
    except ChannelError as exc:
        raise DeliveryError(str(exc).replace("'url' ", "The URL "), transient=False) from None
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower().rstrip(".")
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    allowed = _host_allowed(host)
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            infos = resolve(host, port, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            raise DeliveryError("The webhook host does not resolve", transient=True) from None
        addresses = []
        for info in infos:
            try:
                addresses.append(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
            except ValueError:
                continue
    if not addresses:
        raise DeliveryError("The webhook host does not resolve", transient=True)
    for address in addresses:  # every address must pass: no picking a "good" one
        reason = _refused(address, allowed)
        if reason:
            raise DeliveryError(f"The webhook host resolves to {reason}; refused", transient=False)
    return host, port, str(addresses[0])


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _status_error(status: int) -> DeliveryError:
    if 300 <= status < 400:
        return DeliveryError(f"HTTP {status} redirect refused", transient=False)
    return DeliveryError(f"HTTP {status}", transient=status in _TRANSIENT_HTTP)


def post_guarded(url: str, body: bytes, headers: dict[str, str], timeout: float = SEND_TIMEOUT_SECS) -> None:
    """One POST to a UI channel: SSRF checks, connection to the vetted
    address, no redirects."""
    host, port, ip = check_destination(url)
    parts = urlsplit(url.strip())
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    cls = _PinnedHTTPS if parts.scheme.lower() == "https" else _PinnedHTTP
    conn = cls(host, port, ip, timeout)
    try:
        conn.request("POST", path, body=body, headers={**headers, "Host": parts.netloc.rsplit("@", 1)[-1]})
        response = conn.getresponse()
        response.read(4096)
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise DeliveryError(f"network error ({type(exc).__name__})", transient=True) from None
    finally:
        conn.close()
    if not 200 <= status < 300:
        raise _status_error(status)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never re-post the payload elsewhere
        return None


def post_webhook(url: str, payload: dict[str, Any], timeout: float = SEND_TIMEOUT_SECS) -> None:
    """POST JSON to an operator-configured webhook (the environment's
    Mattermost URL: trusted, so no address checks). Raises DeliveryError
    whose message never contains the URL."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    # The operator's webhook URL; MattermostNotifier accepts http(s) URLs only.
    req = request.Request(url, data=body, method="POST", headers={  # noqa: S310
        "Content-Type": "application/json", "User-Agent": "logscope-webapp/1.0",
    })
    opener = request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read(4096)
    except error.HTTPError as exc:
        raise _status_error(exc.code) from None
    except (error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DeliveryError(f"network error ({type(reason).__name__})", transient=True) from None


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Channel:
    id: int
    name: str
    type: str
    url: str = ""  # plain; never serialised
    secret: str = ""
    enabled: bool = True
    source: str = "ui"  # ui | env

    def __repr__(self) -> str:  # keep the URL and secret out of any repr/log
        return f"Channel(id={self.id}, type={self.type}, source={self.source})"


@dataclass
class Message:
    """What a channel renders: a title, markdown lines, links and the JSON
    body for the generic webhook."""

    title: str
    lines: list[str]
    links: list[tuple[str, str]]
    data: dict[str, Any]


def render(channel_type: str, message: Message) -> dict[str, Any]:
    if channel_type == "webhook":
        return message.data
    if channel_type == "slack":
        links = " · ".join(f"<{url}|{label}>" for label, url in message.links)
        text = "\n".join([f"*{message.title}*", *message.lines, *([links] if links else [])])
        return {"text": text}
    links = " · ".join(f"[{label}]({url})" for label, url in message.links)
    text = "\n".join([f"#### {message.title}", *message.lines, *([links] if links else [])])
    return {"text": text, "username": "Logscope"}


class Deliverer:
    """Sends one message to one channel with retries (SEND_ATTEMPTS, backoff
    RETRY_BASE_SECS × 2^n on transient failures). Returns None or the error
    text of the last attempt."""

    def __init__(self, *, sleep: Callable[[float], None] = time.sleep, guarded: Callable[..., None] = post_guarded,
                 trusted: Callable[..., None] = post_webhook, attempts: int = SEND_ATTEMPTS,
                 base_delay: float = RETRY_BASE_SECS):
        self._sleep = sleep
        self._guarded = guarded
        self._trusted = trusted
        self.attempts = attempts
        self.base_delay = base_delay

    def send(self, channel: Channel, message: Message) -> str | None:
        payload = render(channel.type, message)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "logscope-webapp/1.0"}
        if channel.type == "webhook" and channel.secret:
            headers[SIGNATURE_HEADER] = sign(channel.secret, body)
        last = "not sent"
        for attempt in range(1, self.attempts + 1):
            try:
                if channel.source == "env":
                    self._trusted(channel.url, payload)
                else:
                    self._guarded(channel.url, body, headers)
                return None
            except DeliveryError as exc:
                last = str(exc)
                if not exc.transient:
                    break
            except Exception as exc:  # noqa: BLE001 - keep the URL out of messages
                last = f"unexpected error ({type(exc).__name__})"
                break
            if attempt < self.attempts:
                self._sleep(self.base_delay * 2 ** (attempt - 1))
        logger.warning("Delivery to channel %s (%s) failed: %s", channel.id, channel.type, last)
        return last[:300]


def _clean_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ChannelError("'name' is required", "name")
    text = value.strip()
    if len(text) > _NAME_MAX or re.search(r"[\x00-\x1f\x7f]", text):
        raise ChannelError(f"'name' must be at most {_NAME_MAX} characters without control characters", "name")
    return text


class ChannelStore:
    """notification_channels plus the environment's Mattermost webhook as
    read-only channel 0."""

    def __init__(self, db: StateDB, box: Any, *, env_url: Callable[[], str]):
        self._db = db
        self._box = box
        self._env_url = env_url
        self._lock = threading.Lock()

    def _env_channel(self) -> Channel | None:
        url = self._env_url()
        if not url:
            return None
        return Channel(ENV_CHANNEL_ID, "Mattermost (environment)", "mattermost", url=url, source="env")

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        return {"id": int(row["id"]), "name": row["name"], "type": row["type"],
                "url_hint": f"…{row['url_last6']}", "has_secret": bool(row["secret_enc"]),
                "enabled": bool(row["enabled"]), "source": "ui", "read_only": False,
                "created_at": row["created_at"], "updated_at": row["updated_at"]}

    def list(self) -> list[dict[str, Any]]:
        out = []
        env = self._env_channel()
        if env is not None:
            out.append({"id": ENV_CHANNEL_ID, "name": env.name, "type": env.type, "url_hint": "(environment)",
                        "has_secret": False, "enabled": True, "source": "env", "read_only": True,
                        "created_at": None, "updated_at": None})
        with self._db.lock:
            rows = self._db.conn.execute("SELECT * FROM notification_channels ORDER BY name COLLATE NOCASE, id")
            out += [self._public(row) for row in rows]
        return out

    def ids(self) -> set[int]:
        return {item["id"] for item in self.list()}

    def get(self, channel_id: int) -> Channel | None:
        """The channel with its decrypted URL (for delivery only)."""
        if channel_id == ENV_CHANNEL_ID:
            return self._env_channel()
        with self._db.lock:
            row = self._db.conn.execute("SELECT * FROM notification_channels WHERE id = ?", (channel_id,)).fetchone()
        if row is None:
            return None
        url = self._box.decrypt(row["url_enc"]) or ""
        secret = (self._box.decrypt(row["secret_enc"]) or "") if row["secret_enc"] else ""
        return Channel(int(row["id"]), row["name"], row["type"], url=url, secret=secret,
                       enabled=bool(row["enabled"]), source="ui")

    def _row(self, channel_id: int) -> Any:
        if channel_id == ENV_CHANNEL_ID:
            raise ChannelError("The environment channel is read-only; change it in the deployment", status=409)
        row = self._db.conn.execute("SELECT * FROM notification_channels WHERE id = ?", (channel_id,)).fetchone()
        if row is None:
            raise ChannelError("Channel not found", status=404)
        return row

    def _encrypt(self, plain: str, field: str) -> str:
        if not getattr(self._box, "available", False):
            raise ChannelError(f"Secret storage is unavailable: {getattr(self._box, 'error', '')}", field)
        return self._box.encrypt(plain)

    def _values(self, body: Any, *, partial: bool) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise ChannelError("Request body must be a JSON object")
        unknown = sorted(str(k) for k in body if k not in ("name", "type", "url", "secret", "enabled"))
        if unknown:
            raise ChannelError(f"Unknown field '{unknown[0]}'", unknown[0])
        values: dict[str, Any] = {}
        if "name" in body or not partial:
            values["name"] = _clean_name(body.get("name"))
        if "type" in body or not partial:
            if body.get("type") not in CHANNEL_TYPES:
                raise ChannelError(f"'type' must be one of {list(CHANNEL_TYPES)}", "type")
            values["type"] = body["type"]
        if "url" in body or not partial:
            url = check_url_shape(body.get("url"))
            values["url_enc"] = self._encrypt(url, "url")
            values["url_last6"] = url[-6:]
        secret = body.get("secret")
        if secret not in (None, ""):
            if secret == CLEAR:
                values["secret_enc"] = None
            elif not isinstance(secret, str) or not _SECRET_MIN <= len(secret) <= _SECRET_MAX \
                    or _CONTROL_RE.search(secret):
                raise ChannelError(f"'secret' must be {_SECRET_MIN}-{_SECRET_MAX} characters without spaces",
                                   "secret")
            else:
                values["secret_enc"] = self._encrypt(secret, "secret")
        if "enabled" in body:
            if not isinstance(body["enabled"], bool):
                raise ChannelError("'enabled' must be true or false", "enabled")
            values["enabled"] = int(body["enabled"])
        return values

    def _name_free(self, name: str, except_id: int | None = None) -> None:
        for row in self._db.conn.execute("SELECT id, name FROM notification_channels"):
            if row["id"] != except_id and str(row["name"]).casefold() == name.casefold():
                raise ChannelError(f"A channel named '{row['name']}' already exists", "name", status=409)

    def create(self, body: Any) -> dict[str, Any]:
        values = self._values(body, partial=False)
        now = _now()
        with self._db.lock:
            if int(self._db.conn.execute("SELECT COUNT(*) FROM notification_channels").fetchone()[0]) >= CHANNELS_MAX:
                raise ChannelError(f"At most {CHANNELS_MAX} channels")
            self._name_free(values["name"])
            cur = self._db.conn.execute(
                "INSERT INTO notification_channels (name, type, url_enc, url_last6, secret_enc, enabled, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (values["name"], values["type"], values["url_enc"], values["url_last6"], values.get("secret_enc"),
                 values.get("enabled", 1), now, now))
            return self._public(self._row(int(cur.lastrowid)))

    def update(self, channel_id: int, body: Any) -> dict[str, Any]:
        values = self._values(body, partial=True)
        with self._db.lock:
            self._row(channel_id)
            if "name" in values:
                self._name_free(values["name"], channel_id)
            if values:
                columns = list(values)  # names from _values only
                self._db.conn.execute(
                    f"UPDATE notification_channels SET {', '.join(f'{c} = ?' for c in columns)}, updated_at = ? "
                    "WHERE id = ?", (*(values[c] for c in columns), _now(), channel_id))
            return self._public(self._row(channel_id))

    def delete(self, channel_id: int) -> None:
        with self._db.lock:
            self._row(channel_id)
            self._db.conn.execute("DELETE FROM notification_channels WHERE id = ?", (channel_id,))
            # Rules stop referring to it.
            for row in self._db.conn.execute("SELECT id, channel_ids FROM alert_rules").fetchall():
                try:
                    ids = [i for i in json.loads(row["channel_ids"] or "[]") if i != channel_id]
                except ValueError:
                    ids = []
                self._db.conn.execute("UPDATE alert_rules SET channel_ids = ? WHERE id = ?",
                                      (json.dumps(ids), row["id"]))
