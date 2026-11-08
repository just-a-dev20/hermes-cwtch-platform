"""libCwtch host process for the Cwtch platform adapter (stdlib only; started as ``python -I bridge.py``).

libCwtch is the official C binding of the Cwtch Go library (git.openprivacy.ca/cwtch.im/autobindings).
It keeps ONE application per process in Go globals, launches its own Tor, and hands out events through
a blocking ``c_GetAppBusEvent``. Hosting it in a child process gives each adapter instance its own app,
Tor and Go runtime: a Go panic kills the bridge instead of the gateway, and a reconnect is a fresh
process instead of a half-shut-down Go global.

Wire protocol, one ASCII JSON object per line:

* stdin: ``{"op": "start", "lib_path", "tor_path", "app_dir", "password", "name"}`` first, then
  requests ``{"id": n, "op": "send" | "accept" | "contacts", ...}``. EOF (or ``{"op": "shutdown"}``)
  shuts libCwtch down and exits, so the bridge never outlives the gateway.
* stdout: replies ``{"id": n, "ok": bool, ...}`` and events ``{"event": "ready" | "tor" | "contact" |
  "message" | "delivery_failed" | "error" | "fatal", ...}``.

fd 1 is pointed at stderr before libCwtch loads, so nothing the Go side prints can corrupt the protocol.
The bridge relays message payloads verbatim (Cwtch overlay JSON); the adapter owns their meaning.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import queue
import signal
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Optional

STATE_FILE = "hermes-profile.json"  # the onion of the profile this bridge created, per app dir
# Both boot waits together stay inside the adapter's READY_TIMEOUT, so the adapter hears this bridge's
# verdict (a wrong password is not retryable) instead of timing out first. Neither waits on Tor.
START_TIMEOUT = 8.0  # c_StartCwtch -> CwtchStarted: settings and storage only (live: < 0.1s)
# c_LoadProfiles / c_CreateProfile are synchronous; when the password opens the profile its NewPeer
# follows at once (live: ~1s), so running out here means the password is wrong, not that it is slow.
PROFILE_TIMEOUT = 10.0
CONTACT_TIMEOUT = 15.0  # c_ImportBundle -> ContactCreated
SHUTDOWN_TIMEOUT = 10.0
_LOADED_ZERO = "Loaded 0 profiles"  # libCwtch's AppErrLoaded0; it also fires on starts that succeed


def _cstr(value: str) -> tuple[bytes, int]:
    """libCwtch takes every string as a ``(char*, int len)`` pair and copies it (``C.GoStringN``)."""
    raw = value.encode("utf-8")
    return raw, len(raw)


class LibCwtch:
    """The libCwtch exports this bridge calls, with their C signatures (autobindings ``spec``)."""

    def __init__(self, path: str):
        lib = ctypes.CDLL(path)
        s, i, p = ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p
        for name, args, res in (
            ("c_StartCwtch", [s, i, s, i], i), ("c_GetAppBusEvent", [], p), ("c_FreePointer", [p], None),
            ("c_LoadProfiles", [s, i], None), ("c_CreateProfile", [s, i, s, i, ctypes.c_char], p),
            ("c_AcceptConversation", [s, i, i], None), ("c_SendMessage", [s, i, i, s, i], p),
            ("c_ImportBundle", [s, i, s, i], p), ("c_ShutdownCwtch", [], None),
        ):
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, res
        self._lib = lib

    def _take(self, ptr: Optional[int]) -> str:
        """Copy a returned string and hand the pointer back (libCwtch ``MEMORY.md``: the library owns it)."""
        if not ptr:
            return ""
        try:
            return ctypes.string_at(ptr).decode("utf-8", "replace")
        finally:
            self._lib.c_FreePointer(ptr)

    def start(self, app_dir: str, tor_path: str) -> int:
        return self._lib.c_StartCwtch(*_cstr(app_dir), *_cstr(tor_path))

    def next_event(self) -> str:
        return self._take(self._lib.c_GetAppBusEvent())

    def load_profiles(self, password: str) -> None:
        self._lib.c_LoadProfiles(*_cstr(password))

    def create_profile(self, name: str, password: str) -> str:
        return self._take(self._lib.c_CreateProfile(*_cstr(name), *_cstr(password), b"\x01"))  # autostart

    def accept_conversation(self, profile: str, conversation: int) -> None:
        self._lib.c_AcceptConversation(*_cstr(profile), conversation)

    def send_message(self, profile: str, conversation: int, message: str) -> str:
        return self._take(self._lib.c_SendMessage(*_cstr(profile), conversation, *_cstr(message)))

    def import_bundle(self, profile: str, bundle: str) -> str:
        return self._take(self._lib.c_ImportBundle(*_cstr(profile), *_cstr(bundle)))

    def shutdown(self) -> None:
        self._lib.c_ShutdownCwtch()


def _read_state(path: Path) -> str:
    try:
        return str(json.loads(path.read_text(encoding="utf-8-sig")).get("onion") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def _write_state(path: Path, onion: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"onion": onion}), encoding="utf-8")
    os.replace(tmp, path)


class BootError(Exception):
    """libCwtch or the profile did not come up; ``retryable`` is False when only new config can fix it."""

    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


def _contact_entry(contact: dict) -> dict:
    return {"onion": contact.get("onion", ""), "name": contact.get("localname") or contact.get("name") or "",
            "accepted": bool(contact.get("accepted")), "blocked": bool(contact.get("blocked"))}


class Bridge:
    """One libCwtch app hosting one Cwtch profile: the app-bus event pump plus the request handlers.

    The pump thread and the request thread share the onion -> conversation index under ``_cond``;
    waits (start, profile load, new contact) are condition waits on what the pump records."""

    def __init__(self, lib: Any, emit: Callable[[dict], None]):
        self.lib, self.emit = lib, emit
        self.onion = ""  # our profile; events for any other profile are ignored
        self._cond = threading.Condition()
        self._started = False
        self._start_error = ""
        self._loaded: dict[str, list] = {}  # profile onion -> contacts from its NewPeer event
        self._conversations: dict[str, int] = {}  # remote onion -> conversation id
        self._contacts: dict[str, dict] = {}  # remote onion -> contact entry (P2P only)
        self._tor_progress: Optional[int] = None
        self._closed = False  # the adapter closed stdin: every wait ends

    # ── app-bus events (pump thread) ─────────────────────────────────────────────────────────────

    def pump(self) -> None:
        while self.handle_event(self.lib.next_event()):
            pass

    def handle_event(self, raw: str) -> bool:
        """Apply one app-bus event; False once libCwtch announced its shutdown."""
        try:
            event = json.loads(raw)
            etype, data = event.get("EventType", ""), event.get("Data") or {}
        except (ValueError, AttributeError):
            return True
        if etype == "Shutdown":
            return False
        handler = self._EVENT_HANDLERS.get(etype)
        if handler is not None:
            handler(self, data)
        return True

    def _ours(self, data: dict) -> bool:
        return bool(self.onion) and data.get("ProfileOnion") == self.onion

    def _on_started(self, data: dict) -> None:
        with self._cond:
            self._started = True
            self._cond.notify_all()

    def _on_error(self, data: dict) -> None:
        error = str(data.get("Error") or "unknown libCwtch error")
        if error == _LOADED_ZERO:
            return
        with self._cond:
            if not self._started:
                self._start_error = error
            self._cond.notify_all()
        self.emit({"event": "error", "error": error})

    def _on_acn_status(self, data: dict) -> None:
        try:
            progress = int(data.get("Progress", ""))
        except ValueError:
            return
        if progress != self._tor_progress:
            self._tor_progress = progress
            self.emit({"event": "tor", "progress": progress, "status": str(data.get("Status") or "")})

    def _on_new_peer(self, data: dict) -> None:
        try:
            contacts = json.loads(data.get("ContactsJson") or "[]") or []
        except ValueError:
            contacts = []
        with self._cond:
            self._loaded[str(data.get("Identity") or "")] = contacts
            self._cond.notify_all()

    def _on_contact_created(self, data: dict) -> None:
        if not self._ours(data):
            return
        remote = str(data.get("RemotePeer") or "")
        try:
            conversation = int(data.get("ConversationID", ""))
        except ValueError:
            return
        entry = {"onion": remote, "name": "", "accepted": data.get("accepted") == "true",
                 "blocked": data.get("blocked") == "true"}
        with self._cond:
            self._conversations[remote] = conversation
            self._contacts[remote] = entry
            self._cond.notify_all()
        self.emit({"event": "contact", **entry})

    def _on_message_from_peer(self, data: dict) -> None:
        if not self._ours(data):
            return
        remote = str(data.get("RemotePeer") or "")
        with self._cond, contextlib.suppress(ValueError):
            self._conversations.setdefault(remote, int(data.get("ConversationID", "")))
        self.emit({
            "event": "message", "onion": remote, "name": str(data.get("Nick") or ""),
            "data": str(data.get("Data") or ""), "index": str(data.get("Index") or ""),
            "hash": str(data.get("ContentHash") or ""), "received": str(data.get("TimestampReceived") or ""),
        })

    def _on_indexed_failure(self, data: dict) -> None:
        if self._ours(data):
            self.emit({"event": "delivery_failed", "onion": str(data.get("Handle") or ""),
                       "index": str(data.get("Index") or ""), "error": str(data.get("Error") or "")})

    _EVENT_HANDLERS = {
        "CwtchStarted": _on_started, "CwtchStartError": _on_error, "AppError": _on_error, "PeerError": _on_error,
        "ACNStatus": _on_acn_status, "NewPeer": _on_new_peer, "ContactCreated": _on_contact_created,
        "NewMessageFromPeer": _on_message_from_peer, "IndexedFailure": _on_indexed_failure,
    }

    # ── boot (request thread) ────────────────────────────────────────────────────────────────────

    def close(self) -> None:
        """The adapter closed stdin (disconnect, or its connect timed out): end every wait now, so the
        bridge shuts libCwtch and Tor down itself instead of being killed mid-boot."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def _wait(self, predicate: Callable[[], Any], timeout: float) -> bool:
        with self._cond:
            self._cond.wait_for(lambda: self._closed or predicate(), timeout)
            return bool(predicate())

    def _boot_wait(self, predicate: Callable[[], Any], timeout: float, error: str, *, retryable: bool) -> None:
        if not self._wait(predicate, timeout):
            if self._closed:
                raise BootError("the adapter closed the bridge during start-up", retryable=True)
            raise BootError(error, retryable=retryable)

    def _own(self, onion: str) -> None:
        """Claim *onion* before its profile loads so none of its events are filtered out."""
        with self._cond:
            self.onion = onion

    def boot(self, app_dir: str, tor_path: str, password: str, name: str) -> None:
        """Start libCwtch and load (or, on first run, create) this bridge's profile; emits ``ready``.
        Raises :class:`BootError`."""
        Path(app_dir).mkdir(parents=True, exist_ok=True)
        # health: allow HX012 -- separate stdlib-only process, no Hermes profile scope
        threading.Thread(target=self.pump, name="cwtch-app-bus", daemon=True).start()
        if self.lib.start(app_dir, tor_path) != 0:
            raise BootError("c_StartCwtch refused to start", retryable=True)
        self._boot_wait(lambda: self._started or self._start_error, START_TIMEOUT,
                        f"libCwtch did not report CwtchStarted within {START_TIMEOUT:.0f}s", retryable=True)
        if self._start_error:
            raise BootError(self._start_error, retryable=True)
        state = Path(app_dir) / STATE_FILE
        onion = _read_state(state)
        if onion:
            # LoadProfiles opens every profile in app_dir that this password decrypts, hence the
            # dedicated data directory; only ours is bridged.
            self._own(onion)
            self.lib.load_profiles(password)
            self._boot_wait(lambda: onion in self._loaded, PROFILE_TIMEOUT,
                            f"Cwtch profile {onion[:6]}… recorded in {STATE_FILE} did not load "
                            "(wrong CWTCH_PROFILE_PASSWORD, or the profile was deleted)", retryable=False)
        else:
            onion = self.lib.create_profile(name, password)
            if not onion:
                raise BootError("c_CreateProfile did not return a profile", retryable=True)
            self._own(onion)
            _write_state(state, onion)  # the profile exists on disk now; never create a second one
            self._boot_wait(lambda: onion in self._loaded, PROFILE_TIMEOUT,
                            f"the new Cwtch profile {onion[:6]}… did not come up", retryable=True)
        with self._cond:
            for contact in self._loaded[onion]:
                if isinstance(contact, dict) and contact.get("onion") and not contact.get("isGroup"):
                    # setdefault: a ContactCreated seen since NewPeer is newer than this snapshot
                    self._conversations.setdefault(contact["onion"], int(contact.get("identifier", -1)))
                    self._contacts.setdefault(contact["onion"], _contact_entry(contact))
            contacts = [dict(c) for c in self._contacts.values()]
        self.emit({"event": "ready", "onion": onion, "contacts": contacts})

    # ── requests (request thread) ────────────────────────────────────────────────────────────────

    def request(self, req: dict) -> dict:
        handler = self._REQUEST_HANDLERS.get(req.get("op"))
        if handler is None:
            return {"ok": False, "error": f"unknown op {req.get('op')!r}"}
        try:
            return handler(self, req)
        except (LookupError, ValueError, TypeError) as exc:
            return {"ok": False, "error": str(exc)}

    def _conversation_for(self, onion: str, *, create: bool) -> int:
        """The conversation id for *onion*; ``create`` adds the contact first (``c_ImportBundle`` with a
        bare onion creates an accepted P2P conversation and publishes ContactCreated)."""
        with self._cond:
            if onion in self._conversations:
                return self._conversations[onion]
        if not create:
            raise LookupError(f"no Cwtch conversation with {onion[:6]}…")
        self.lib.import_bundle(self.onion, onion)
        if not self._wait(lambda: onion in self._conversations, CONTACT_TIMEOUT):
            raise LookupError(f"Cwtch did not add contact {onion[:6]}…")
        with self._cond:
            return self._conversations[onion]

    def _req_send(self, req: dict) -> dict:
        conversation = self._conversation_for(str(req["onion"]), create=True)
        stored = self.lib.send_message(self.onion, conversation, str(req["message"]))
        if not stored:
            return {"ok": False, "error": "libCwtch did not accept the message"}
        try:
            message_id = json.loads(stored).get("ID", "")
        except (ValueError, AttributeError):
            message_id = ""
        return {"ok": True, "message_id": str(message_id)}

    def _req_accept(self, req: dict) -> dict:
        onion = str(req["onion"])
        self.lib.accept_conversation(self.onion, self._conversation_for(onion, create=False))
        with self._cond:
            if onion in self._contacts:
                self._contacts[onion]["accepted"] = True
        return {"ok": True}

    def _req_contacts(self, req: dict) -> dict:
        with self._cond:
            return {"ok": True, "contacts": [dict(c) for c in self._contacts.values()]}

    _REQUEST_HANDLERS = {"send": _req_send, "accept": _req_accept, "contacts": _req_contacts}

    def shutdown(self) -> None:
        """``c_ShutdownCwtch`` stops Tor and the profile engines; bounded so a wedged Go side cannot
        keep the bridge (and its Tor) alive after the adapter is gone."""
        # health: allow HX012 -- separate stdlib-only process, no Hermes profile scope
        worker = threading.Thread(target=self.lib.shutdown, name="cwtch-shutdown", daemon=True)
        worker.start()
        worker.join(SHUTDOWN_TIMEOUT)


def _protocol_stream():
    """Move the protocol onto a private fd and point fd 1 at stderr, before libCwtch (Go) loads."""
    sys.stdout.flush()
    fd = os.dup(1)
    os.dup2(2, 1)
    return os.fdopen(fd, "w", encoding="ascii", newline="\n")


def _read_requests(stream, inbox: queue.Queue, bridge: Bridge) -> None:
    """stdin -> *inbox* from the start, so EOF is seen even while boot() is still waiting."""
    for line in stream:
        inbox.put(line)
    inbox.put(None)
    bridge.close()


def serve(bridge: Bridge, lines, emit: Callable[[dict], None]) -> None:
    """Answer requests until EOF or ``shutdown``; every reply echoes the request ``id``."""
    for line in lines:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except ValueError:
            emit({"event": "error", "error": "malformed request line"})
            continue
        if not isinstance(req, dict):
            continue
        if req.get("op") == "shutdown":
            return
        emit({**bridge.request(req), "id": req.get("id")})


def main() -> int:
    # A terminal Ctrl+C reaches the whole process group; the gateway's disconnect (stdin EOF) is what
    # stops this bridge, so libCwtch always gets an orderly shutdown.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    proto = _protocol_stream()
    lock = threading.Lock()

    def emit(obj: dict) -> None:
        with lock:
            proto.write(json.dumps(obj) + "\n")
            proto.flush()

    stdin = sys.stdin
    try:
        cfg = json.loads(stdin.readline())
        lib_path, tor_path, app_dir = cfg["lib_path"], cfg["tor_path"], cfg["app_dir"]
        password, name = cfg["password"], cfg.get("name") or "Hermes"
    except (ValueError, KeyError, TypeError, AttributeError):
        emit({"event": "fatal", "error": "bridge expected a start line", "retryable": False})
        return 2
    try:
        lib = LibCwtch(lib_path)
    except (OSError, AttributeError) as exc:  # not a shared library, or not libCwtch
        emit({"event": "fatal", "error": f"cannot load libCwtch from {lib_path}: {exc}", "retryable": False})
        return 2
    bridge = Bridge(lib, emit)
    inbox: queue.Queue = queue.Queue()
    # health: allow HX012 -- separate stdlib-only process, no Hermes profile scope
    threading.Thread(target=_read_requests, args=(stdin, inbox, bridge), name="cwtch-stdin", daemon=True).start()
    try:
        bridge.boot(app_dir, tor_path, password, name)
        serve(bridge, iter(inbox.get, None), emit)
        return 0
    except BootError as exc:
        emit({"event": "fatal", "error": str(exc), "retryable": exc.retryable})
        return 2
    finally:
        bridge.shutdown()


if __name__ == "__main__":
    code = main()
    sys.stderr.flush()
    os._exit(code)  # the app-bus thread is parked inside c_GetAppBusEvent; don't wait on it
