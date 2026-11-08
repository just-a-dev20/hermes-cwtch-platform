"""Cwtch platform adapter: Hermes as a Cwtch contact, through libCwtch in a child process.

Cwtch has no daemon or server API to talk to: the official C binding (libCwtch) runs the Cwtch app and
its own Tor inside whichever process loads it. ``bridge.py`` hosts libCwtch in a child process (one per
adapter instance, so a Go panic or a reconnect never touches the gateway) and speaks JSON lines over
its stdin/stdout. This module owns everything Hermes-facing: config, the contact-accept policy, overlay
decoding and chunked sends. Scope: P2P conversations (DMs) with text; Cwtch groups and file sharing are
not bridged.

Config, env over ``config.yaml`` (``platforms.cwtch.extra``):
CWTCH_PROFILE_PASSWORD (secret, ``.env`` only; encrypts the bot's profile) · CWTCH_LIB_PATH / lib_path
(libCwtch.so, libCwtch.dll or libCwtch.*.dylib) · CWTCH_TOR_PATH / tor_path (default ``tor`` on PATH) ·
CWTCH_APP_DIR / app_dir (default ``<HERMES_HOME>/cwtch``, one dedicated directory per bot) ·
CWTCH_PROFILE_NAME / profile_name (display name for a new profile, default "Hermes") ·
CWTCH_AUTO_ACCEPT / auto_accept (default true; false = only CWTCH_ALLOWED_USERS are accepted) ·
CWTCH_ALLOWED_USERS (onion addresses) · CWTCH_ALLOW_ALL_USERS · CWTCH_HOME_CHANNEL[_NAME].
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Optional

from gateway.config import Platform
from gateway.platforms._shared import (
    apply_yaml_bridge as _apply_yaml_bridge, decode_json_list_literal as _decode_json_list_literal,
    extra_or_secret as _extra_or_secret, get_scoped_secret as _get_scoped_secret,
    platform_gate_env as _platform_gate_env, seed_extra_from_env as _seed_extra_from_env,
)
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType
from gateway.platforms.helpers import MessageDeduplicator, cancel_task
from hermes_constants import get_hermes_home

logger = logging.getLogger(__name__)

MAX_MESSAGE_LENGTH = 4000  # Cwtch documents no hard cap; keep each message to one modest Tor round-trip
READY_TIMEOUT = 25.0  # bridge start -> profile loaded, inside the runner's 30s connect budget
REQUEST_TIMEOUT = 30.0
STOP_TIMEOUT = 15.0  # the bridge bounds its own libCwtch shutdown at 10s
_BRIDGE_SCRIPT = Path(__file__).with_name("bridge.py")
_STREAM_LIMIT = 4 * 1024 * 1024  # one JSON line can carry a long message or a large contact list
_ONION_RE = re.compile(r"[a-z2-7]{56}")  # Tor v3 onion service id, Cwtch's only user identifier
_TRUTHY = {"1", "true", "yes", "on"}
# Host facts the bridge (and Go's os/user, Tor) need; nothing else of the gateway's env crosses over.
_CHILD_ENV_KEYS = ("PATH", "SYSTEMROOT", "WINDIR", "HOME", "USERPROFILE", "USER", "USERNAME", "LOGNAME",
                   "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "XDG_RUNTIME_DIR")



def _json_obj(raw: Any) -> dict:
    with contextlib.suppress(ValueError, TypeError):
        value = json.loads(raw)
        if isinstance(value, dict):
            return value
    return {}


# Cwtch message overlays (cwtch-ui lib/models/message.dart) -> the text Hermes sees.
_OVERLAY_TEXT: dict[int, Callable[[Any], str]] = {
    1: str,  # chat
    10: lambda d: str(_json_obj(d).get("body") or ""),  # quoted reply: {"quotedHash", "body"}
    100: lambda d: f"[Cwtch contact suggestion: {d}]",
    101: lambda d: "[Cwtch group invite: this bot does not join Cwtch groups]",
    200: lambda d: (f"[Cwtch file offer: {_json_obj(d).get('f') or 'unnamed file'}; "
                    "this bot does not download Cwtch files]"),
}


def decode_overlay(raw: str) -> str:
    """Text of a Cwtch message wrapper ``{"o": overlay, "d": data}``; "" for overlays without any."""
    wrapper = _json_obj(raw)
    try:
        render = _OVERLAY_TEXT.get(int(wrapper.get("o")))
    except (TypeError, ValueError):
        return ""
    return render(wrapper.get("d", "")).strip() if render else ""


def encode_text(text: str) -> str:
    return json.dumps({"o": 1, "d": text})  # chat overlay


def normalize_onion(value: Any) -> Optional[str]:
    """A Cwtch address as libCwtch spells it (56 lowercase base32 chars), or None."""
    onion = str(value or "").strip().lower().removesuffix(".onion")
    return onion if _ONION_RE.fullmatch(onion) else None


def _redact(onion: str) -> str:
    return f"{onion[:4]}…{onion[-4:]}" if len(onion) > 8 else "<none>"


def _as_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).strip().lower() in _TRUTHY


def _allowed_onions() -> set[str]:
    """CWTCH_ALLOWED_USERS read exactly as gateway authz reads it (``platform_gate_env``)."""
    raw = _decode_json_list_literal(_platform_gate_env("CWTCH_ALLOWED_USERS"))
    entries = raw if isinstance(raw, list) else str(raw).split(",")
    return {onion for entry in entries if (onion := normalize_onion(entry))}


def _child_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _CHILD_ENV_KEYS if key in os.environ}


def _received_at(value: str) -> datetime:
    """libCwtch stamps RFC 3339 with nanoseconds; Python parses at most microseconds."""
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value or "")
    try:
        parsed = datetime.fromisoformat(trimmed)
    except ValueError:
        return datetime.now(tz=UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


async def _reap(proc: asyncio.subprocess.Process) -> Optional[int]:
    """Wait for the bridge to exit, killing it after STOP_TIMEOUT; never raises, so callers in an exit
    path still get to report the failure."""
    try:
        return await asyncio.wait_for(proc.wait(), STOP_TIMEOUT)
    except TimeoutError:
        logger.warning("Cwtch: bridge did not exit within %.0fs; killing it", STOP_TIMEOUT)
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
    with contextlib.suppress(TimeoutError):
        return await asyncio.wait_for(proc.wait(), STOP_TIMEOUT)
    return None


class BridgeFailure(Exception):
    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


class CwtchAdapter(BasePlatformAdapter):
    """Cwtch P2P conversations through a per-adapter libCwtch bridge process.

    Two tasks read the bridge: the stdout reader only demultiplexes (replies resolve their request
    future; inbound events go on a queue), and the inbound consumer handles events in order. Anything
    that talks back to the bridge (accepting a contact, a busy-ack ``send`` from ``handle_message``) runs
    on the consumer, so it can never wait on the reader that has to deliver its reply."""

    MAX_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH
    splits_long_messages = True  # send() chunks with truncate_message()
    serial_receive_loop = True  # the consumer awaits each inbound event before taking the next

    def __init__(self, config, **kwargs):
        super().__init__(config=config, platform=Platform("cwtch"))
        extra = getattr(config, "extra", {}) or {}
        lib_path = str(_extra_or_secret(extra, "lib_path", "CWTCH_LIB_PATH", "")).strip()
        self.lib_path = str(Path(lib_path).expanduser()) if lib_path else ""
        self.tor_path = str(_extra_or_secret(extra, "tor_path", "CWTCH_TOR_PATH", "")).strip()
        app_dir = str(_extra_or_secret(extra, "app_dir", "CWTCH_APP_DIR", "")).strip()
        # Resolved here: the runner constructs each adapter inside its owning profile's scope.
        self.app_dir = (Path(app_dir).expanduser() if app_dir else get_hermes_home() / "cwtch").resolve()
        self.profile_name = str(_extra_or_secret(extra, "profile_name", "CWTCH_PROFILE_NAME", "")).strip() or "Hermes"
        self.auto_accept = _as_bool(_extra_or_secret(extra, "auto_accept", "CWTCH_AUTO_ACCEPT", True))
        self._password = str(_get_scoped_secret("CWTCH_PROFILE_PASSWORD", "") or "")
        self.onion = ""  # the bot's own Cwtch address, known once the profile loaded
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._inbound: asyncio.Queue = asyncio.Queue()
        self._ready: Optional[asyncio.Future] = None
        self._replies: dict[int, asyncio.Future] = {}
        self._request_ids = itertools.count(1)
        self._stopping = False
        self._tor_ready = False
        self._contacts: dict[str, dict] = {}  # onion -> {"onion", "name", "accepted", "blocked"}
        self._inbound_dedup = MessageDeduplicator()

    @property
    def name(self) -> str:
        return "Cwtch"

    @property
    def send_path_degraded(self) -> bool:
        """Connected (profile loaded) but Tor has not finished bootstrapping, so nothing is delivered yet."""
        return not self._tor_ready

    def _fail(self, code: str, message: str, *, retryable: bool) -> bool:
        logger.error("Cwtch: %s", message)
        self._set_fatal_error(code, message, retryable=retryable)
        return False

    def _config_problem(self) -> str:
        if not self._password:
            return "CWTCH_PROFILE_PASSWORD is not set (it encrypts the bot's Cwtch profile)"
        if not self.lib_path:
            return "CWTCH_LIB_PATH is not set (path to libCwtch.so / libCwtch.dll / libCwtch.*.dylib)"
        if not Path(self.lib_path).is_file():
            return f"libCwtch not found at {self.lib_path} (CWTCH_LIB_PATH)"
        return ""

    # ── lifecycle ────────────────────────────────────────────────────────────────────────────────

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if problem := self._config_problem():
            return self._fail("config_missing", problem, retryable=False)
        # One bridge per data directory: libCwtch's profile database cannot be opened twice.
        if not self._acquire_platform_lock("cwtch-app-dir", os.path.normcase(str(self.app_dir)),
                                           f"Cwtch data directory {self.app_dir}"):
            return False
        self._stopping = False
        try:
            ready = await self._start_bridge()
        except (BridgeFailure, OSError) as exc:  # OSError: spawn failed or the bridge died mid-handshake
            await self._stop_bridge()
            self._release_platform_lock()
            return self._fail("bridge_failed", str(exc), retryable=getattr(exc, "retryable", True))
        except asyncio.CancelledError:  # the runner's connect timeout
            await self._stop_bridge()
            self._release_platform_lock()
            raise
        self.onion = ready["onion"]
        self._mark_connected()
        logger.info("Cwtch: profile %s loaded; add this address in Cwtch to talk to the bot", self.onion)
        self._wire_plugin_handlers(None)
        return True

    async def disconnect(self) -> None:
        self._stopping = True
        self._mark_disconnected()
        await self._stop_bridge()
        with contextlib.suppress(Exception):
            self._release_platform_lock()

    async def _start_bridge(self) -> dict:
        loop = asyncio.get_running_loop()
        self._ready = loop.create_future()
        self._inbound = asyncio.Queue()
        self._tor_ready = False  # a new bridge starts its own Tor
        self._contacts = {}  # repopulated from the bridge's ``ready``
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", str(_BRIDGE_SCRIPT),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_child_env(),
            limit=_STREAM_LIMIT, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._reader_task = asyncio.create_task(self._read_bridge(self._proc))
        self._stderr_task = asyncio.create_task(self._pump_stderr(self._proc))
        self._consumer_task = asyncio.create_task(self._consume_inbound())
        # An empty or unusable tor_path is fine: libCwtch then runs the first viable `tor` on PATH.
        await self._write({"op": "start", "lib_path": self.lib_path, "tor_path": self.tor_path,
                           "app_dir": str(self.app_dir), "password": self._password, "name": self.profile_name})
        try:
            return await asyncio.wait_for(self._ready, READY_TIMEOUT)
        except TimeoutError as exc:
            raise BridgeFailure(f"the Cwtch bridge did not load the profile within {READY_TIMEOUT:.0f}s",
                                retryable=True) from exc

    async def _stop_bridge(self) -> None:
        proc, self._proc = self._proc, None
        if proc is not None:
            if proc.stdin is not None:  # EOF tells the bridge to shut libCwtch (and its Tor) down
                with contextlib.suppress(Exception):
                    proc.stdin.close()
            await _reap(proc)
        self._resolve_pending("Cwtch bridge stopped")
        current = asyncio.current_task()
        # This can run inside the reader's own exit chain (bridge died -> fatal -> runner disconnect);
        # a task cancelling itself would abort that chain before the reconnect is queued.
        for task in (self._consumer_task, self._reader_task, self._stderr_task):
            if task is not None and task is not current:
                await cancel_task(task)

    def _resolve_pending(self, error: str) -> None:
        for future in self._replies.values():
            if not future.done():
                future.set_result({"ok": False, "error": error})
        self._replies.clear()
        if self._ready is not None and not self._ready.done():
            self._ready.set_exception(BridgeFailure(error, retryable=True))

    # ── bridge I/O ───────────────────────────────────────────────────────────────────────────────

    def _bridge_alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def _write(self, payload: dict) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise ConnectionError("Cwtch bridge is not running")
        proc.stdin.write((json.dumps(payload) + "\n").encode("ascii"))
        await proc.stdin.drain()

    async def _request(self, payload: dict, timeout: float = REQUEST_TIMEOUT) -> dict:
        if not self._bridge_alive():
            return {"ok": False, "error": "Cwtch bridge is not running"}
        request_id = next(self._request_ids)
        future = asyncio.get_running_loop().create_future()
        self._replies[request_id] = future
        try:
            await self._write({**payload, "id": request_id})
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            return {"ok": False, "error": f"Cwtch bridge did not answer '{payload.get('op')}' in {timeout:.0f}s"}
        except (ConnectionError, OSError) as exc:
            return {"ok": False, "error": f"Cwtch bridge pipe closed: {exc}"}
        finally:
            self._replies.pop(request_id, None)

    async def _read_bridge(self, proc: asyncio.subprocess.Process) -> None:
        """Demultiplex bridge stdout; never awaits the bridge itself (see the class docstring)."""
        try:
            while line := await proc.stdout.readline():
                try:
                    message = json.loads(line)
                except ValueError:
                    logger.debug("Cwtch bridge: non-protocol line %.120r", line)
                    continue
                if isinstance(message, dict):
                    self._route(message)
        except (ValueError, asyncio.LimitOverrunError) as exc:
            logger.error("Cwtch bridge: unreadable output (%s)", exc)
        finally:
            await self._on_bridge_exit(proc)

    def _route(self, message: dict) -> None:
        event = message.get("event")
        if event is None:
            future = self._replies.pop(message.get("id"), None)
            if future is not None and not future.done():
                future.set_result(message)
        elif (route := self._ROUTES.get(event)) is not None:
            route(self, message)

    def _route_ready(self, message: dict) -> None:
        # Known contacts are recorded here, in stream order, so a message the bridge sends right after
        # ``ready`` already finds its (accepted) contact; pending requests go through the consumer
        # like any later contact event.
        for contact in message.get("contacts") or []:
            if onion := normalize_onion(contact.get("onion")):
                self._contacts[onion] = {**contact, "onion": onion}
                if not contact.get("accepted"):
                    self._inbound.put_nowait({"event": "contact", **contact})
        if self._ready is not None and not self._ready.done():
            self._ready.set_result(message)

    def _route_fatal(self, message: dict) -> None:
        error = str(message.get("error") or "Cwtch bridge failed")
        if self._ready is not None and not self._ready.done():
            self._ready.set_exception(BridgeFailure(error, retryable=bool(message.get("retryable", True))))
        else:
            logger.error("Cwtch bridge: %s", error)

    def _route_error(self, message: dict) -> None:
        logger.warning("Cwtch: libCwtch reported: %s", message.get("error"))

    def _route_delivery_failed(self, message: dict) -> None:
        logger.warning("Cwtch: message %s to %s was not delivered: %s", message.get("index"),
                       _redact(str(message.get("onion") or "")), message.get("error"))

    def _route_inbound(self, message: dict) -> None:
        self._inbound.put_nowait(message)

    def _route_tor(self, message: dict) -> None:
        progress = message.get("progress")
        if progress == 100 and not self._tor_ready:
            self._tor_ready = True
            logger.info("Cwtch: Tor is up; %s is reachable", self.onion or "the profile")
            if self._running:
                self._mark_connected()  # republish: send_path_degraded flipped
        elif progress != 100:
            if self._tor_ready and self._running:
                logger.warning("Cwtch: Tor connection lost (%s%%: %s)", progress, message.get("status"))
            self._tor_ready = False
            if self._running:
                self._mark_degraded()

    _ROUTES: dict[str, Callable[[CwtchAdapter, dict], None]] = {
        "ready": _route_ready, "fatal": _route_fatal, "tor": _route_tor, "error": _route_error,
        "delivery_failed": _route_delivery_failed, "contact": _route_inbound, "message": _route_inbound,
    }

    async def _pump_stderr(self, proc: asyncio.subprocess.Process) -> None:
        """libCwtch's own log (and anything Go prints) arrives here; it is chatty, so DEBUG."""
        while line := await proc.stderr.readline():
            logger.debug("[cwtch-bridge] %s", line.decode("utf-8", "replace").rstrip())

    async def _on_bridge_exit(self, proc: asyncio.subprocess.Process) -> None:
        code = await _reap(proc)  # stdout hit EOF, so the bridge is on its way out
        if self._ready is not None and not self._ready.done():
            self._ready.set_exception(BridgeFailure(f"the Cwtch bridge exited during start-up (code {code})",
                                                    retryable=True))
        if self._stopping or proc is not self._proc:
            return
        self._resolve_pending("Cwtch bridge exited")
        # A supervisor stop signals the whole process tree, so the bridge can die before disconnect().
        if getattr(getattr(self, "gateway_runner", None), "_stop_requested_by_signal", False):
            return
        self._set_fatal_error("bridge_exited", f"the Cwtch bridge exited unexpectedly (code {code})",
                              retryable=True)
        logger.error("Cwtch: bridge exited unexpectedly (code %s); reconnecting", code)
        await self._notify_fatal_error()

    # ── inbound ──────────────────────────────────────────────────────────────────────────────────

    async def _consume_inbound(self) -> None:
        while True:
            message = await self._inbound.get()
            try:
                if message.get("event") == "contact":
                    await self._on_contact(message)
                else:
                    await self._on_message(message)
            except Exception:
                logger.exception("Cwtch: error handling inbound %s", message.get("event"))

    def _should_accept(self, onion: str) -> bool:
        return self.auto_accept or onion in _allowed_onions()

    async def _on_contact(self, contact: dict) -> None:
        """Accept a contact request when the policy allows; Hermes authz still gates every message."""
        onion = normalize_onion(contact.get("onion"))
        if not onion:
            return
        known = {**self._contacts.get(onion, {}), **{k: v for k, v in contact.items() if k != "event"}}
        self._contacts[onion] = known
        if known.get("accepted") or known.get("blocked") or not self._should_accept(onion):
            return
        reply = await self._request({"op": "accept", "onion": onion})
        if reply.get("ok"):
            known["accepted"] = True
            logger.info("Cwtch: accepted contact request from %s", _redact(onion))
        else:
            logger.warning("Cwtch: could not accept %s: %s", _redact(onion), reply.get("error"))

    async def _on_message(self, message: dict) -> None:
        onion = normalize_onion(message.get("onion"))
        if not onion or onion == self.onion:
            return
        contact = self._contacts.get(onion) or {}
        if contact.get("blocked"):
            return
        if not contact.get("accepted"):
            if not self._should_accept(onion):
                logger.debug("Cwtch: ignoring message from unaccepted contact %s", _redact(onion))
                return
            await self._on_contact({"onion": onion, "accepted": False})
        message_id = f"{onion}:{message.get('index') or message.get('hash')}"
        if self._inbound_dedup.is_duplicate(message_id):
            return
        text = decode_overlay(message.get("data", ""))
        if not text:
            return
        # libCwtch sends the address as the nick until the contact shares a name. Leave it unset then:
        # with PII redaction on, the session prompt hashes ids but prints names verbatim.
        nick = str(message.get("name") or contact.get("name") or "")
        nick = "" if nick == onion else nick
        if nick:
            self._contacts.setdefault(onion, {"onion": onion})["name"] = nick
        source = self.build_source(chat_id=onion, chat_name=nick or None, chat_type="dm",
                                   user_id=onion, user_name=nick or None)
        logger.debug("Cwtch: message from %s (%d chars)", _redact(onion), len(text))
        await self.handle_message(MessageEvent(
            text=text, message_type=MessageType.TEXT, source=source, message_id=message_id,
            timestamp=_received_at(str(message.get("received") or "")), raw_message=message))

    # ── outbound ─────────────────────────────────────────────────────────────────────────────────

    async def send(self, chat_id: str, content: str, reply_to: Optional[str] = None,
                   metadata: Optional[dict[str, Any]] = None) -> SendResult:
        onion = normalize_onion(chat_id)
        if not onion:
            return SendResult(success=False, error=f"not a Cwtch address: {chat_id!r}")
        message_id = None
        for chunk in self.truncate_message(content, self.MAX_MESSAGE_LENGTH):
            reply = await self._request({"op": "send", "onion": onion, "message": encode_text(chunk)})
            if not reply.get("ok"):
                return SendResult(success=False, error=str(reply.get("error") or "Cwtch send failed"))
            message_id = reply.get("message_id") or message_id
        return SendResult(success=True, message_id=message_id)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Cwtch has no typing indicator."""

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        onion = normalize_onion(chat_id) or chat_id
        return {"chat_id": chat_id, "type": "dm", "name": (self._contacts.get(onion) or {}).get("name") or chat_id}

    async def list_channels(self) -> Optional[list[dict[str, Any]]]:
        """Accepted contacts for the channel directory; None (not []) while the bridge is down, so the
        directory keeps its session-history targets."""
        reply = await self._request({"op": "contacts"}, timeout=10.0)
        if not reply.get("ok"):
            return None
        return [{"id": c["onion"], "name": c.get("name") or c["onion"], "type": "dm"}
                for c in reply.get("contacts") or [] if c.get("accepted") and normalize_onion(c.get("onion"))]


# ── plugin registration ──────────────────────────────────────────────────────────────────────────

def check_requirements() -> bool:
    """Passive gate: the one Cwtch secret, the profile password, is configured."""
    return bool(_get_scoped_secret("CWTCH_PROFILE_PASSWORD"))


def validate_config(config) -> bool:
    extra = getattr(config, "extra", {}) or {}
    return bool(_get_scoped_secret("CWTCH_PROFILE_PASSWORD")
                and str(_extra_or_secret(extra, "lib_path", "CWTCH_LIB_PATH", "")).strip())


def is_connected(config) -> bool:
    return validate_config(config)


def _env_enablement() -> Optional[dict]:
    """``env_enablement_fn``: seed ``PlatformConfig.extra`` from the profile's env; None until both the
    password and the libCwtch path are set."""
    if not str(_get_scoped_secret("CWTCH_PROFILE_PASSWORD", "") or "").strip():
        return None
    lib_path = str(_get_scoped_secret("CWTCH_LIB_PATH", "") or "").strip()
    if not lib_path:
        return None
    return {"lib_path": lib_path, **_seed_extra_from_env((
        ("CWTCH_TOR_PATH", "tor_path", None), ("CWTCH_APP_DIR", "app_dir", None),
        ("CWTCH_PROFILE_NAME", "profile_name", None), ("CWTCH_AUTO_ACCEPT", "auto_accept", _as_bool),
    ), home_env="CWTCH_HOME_CHANNEL")}


_YAML_BRIDGE = (  # (extra key, env var, kind); CWTCH_PROFILE_PASSWORD is never read from config.yaml
    ("lib_path", "CWTCH_LIB_PATH", "str"), ("tor_path", "CWTCH_TOR_PATH", "str"),
    ("app_dir", "CWTCH_APP_DIR", "str"), ("profile_name", "CWTCH_PROFILE_NAME", "str"),
    ("auto_accept", "CWTCH_AUTO_ACCEPT", "lower"), ("home_channel", "CWTCH_HOME_CHANNEL", "str"),
    ("allowed_users", "CWTCH_ALLOWED_USERS", "csv"), ("allow_all_users", "CWTCH_ALLOW_ALL_USERS", "lower"),
)


def _apply_yaml_config(yaml_cfg: dict, cwtch_cfg: dict) -> Optional[dict]:
    """``apply_yaml_config_fn``: bridge ``platforms.cwtch.extra`` into ``CWTCH_*`` env (env wins; skipped
    under a secondary profile's scope) and seed the same keys into that profile's ``extra``."""
    extra = cwtch_cfg.get("extra", cwtch_cfg) or {}
    return _apply_yaml_bridge(extra, _YAML_BRIDGE) if isinstance(extra, dict) else None


def _parse_target_ref(raw: str) -> Optional[tuple[str, Optional[str]]]:
    """``send_message`` target syntax: a bare Cwtch onion address."""
    onion = normalize_onion(raw)
    return (onion, None) if onion else None


def interactive_setup() -> None:
    """``hermes gateway setup`` → Cwtch (writes the profile's ``.env``; CLI helpers imported lazily)."""
    from hermes_cli.cli_output import print_info, print_success, print_warning, prompt
    from hermes_cli.config import get_env_value, save_env_value
    from hermes_cli.gateway_setup_wizard import confirm_reconfigure, print_setup_header

    print_setup_header("Cwtch")
    if not confirm_reconfigure("Cwtch", "CWTCH_PROFILE_PASSWORD"):
        return
    for line in ("Cwtch runs peer-to-peer over Tor; Hermes hosts its own Cwtch profile. You need:",
                 "  1. libCwtch (libCwtch.so / libCwtch.dll / libCwtch.x64.dylib) from a Cwtch release.",
                 "  2. A tor binary (on PATH, or give its path below)."):
        print_info(line)
    lib_path = prompt("Path to libCwtch", default=get_env_value("CWTCH_LIB_PATH") or "")
    if not lib_path:
        print_warning("The libCwtch path is required; skipping Cwtch setup")
        return
    password = prompt("Password for the bot's Cwtch profile (encrypts it on disk; blank = keep current)",
                      password=True)
    if not password and not get_env_value("CWTCH_PROFILE_PASSWORD"):
        print_warning("A profile password is required; skipping Cwtch setup")
        return
    save_env_value("CWTCH_LIB_PATH", lib_path.strip())
    if password:
        save_env_value("CWTCH_PROFILE_PASSWORD", password)
    if tor_path := prompt("Path to tor (blank = tor on PATH)", default=get_env_value("CWTCH_TOR_PATH") or ""):
        save_env_value("CWTCH_TOR_PATH", tor_path.strip())
    allowed = prompt("Cwtch addresses allowed to talk to the bot (comma-separated; blank = pairing)",
                     default=get_env_value("CWTCH_ALLOWED_USERS") or "")
    if allowed:
        save_env_value("CWTCH_ALLOWED_USERS", allowed.replace(" ", ""))
    print_success("Cwtch configured.")
    print_info("Start the gateway: it logs the bot's Cwtch address. Add that address as a contact in Cwtch.")


def register(ctx) -> None:
    ctx.register_platform(
        name="cwtch", label="Cwtch", adapter_factory=CwtchAdapter,
        dashboard_description="Talk to Hermes over Cwtch (peer-to-peer over Tor, via libCwtch).",
        docs_url="https://github.com/just-a-dev20/hermes-cwtch-platform#readme",
        check_fn=check_requirements, validate_config=validate_config, is_connected=is_connected,
        required_env=["CWTCH_PROFILE_PASSWORD", "CWTCH_LIB_PATH"],
        install_hint="Needs libCwtch (from a Cwtch release) and a tor binary; no pip packages",
        setup_fn=interactive_setup, env_enablement_fn=_env_enablement, apply_yaml_config_fn=_apply_yaml_config,
        cron_deliver_env_var="CWTCH_HOME_CHANNEL", parse_target_ref_fn=_parse_target_ref,
        allowed_users_env="CWTCH_ALLOWED_USERS", allow_all_env="CWTCH_ALLOW_ALL_USERS",
        max_message_length=MAX_MESSAGE_LENGTH, emoji="🧅",
        pii_safe=True,  # onion addresses are long-lived identities; hash them for the model when redacting
        allow_update_command=True,
        platform_hint=(
            "You are chatting via Cwtch, a peer-to-peer messenger over Tor; contacts are known only by "
            "their onion address. Use plain text (markdown shows literally). Text only: you cannot send "
            "or receive images, voice notes or files here. Delivery can take a few seconds, so keep "
            "replies concise."))
