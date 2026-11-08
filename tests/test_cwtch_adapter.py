"""Behaviour contracts for the Cwtch platform plugin.

``bridge.py`` runs its event pump and request handlers over ``FakeLib``, a stand-in for the libCwtch
exports. ``CwtchAdapter`` drives a real child process: a scripted bridge that speaks the same JSON-lines
protocol, so only libCwtch and Tor are faked.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import queue
import sys
import threading
import time
from pathlib import Path

import pytest

cwtch = importlib.import_module("hermes_cwtch_platform.adapter")  # loaded by conftest.py
bridge = importlib.import_module("hermes_cwtch_platform.bridge")


def wait_until(predicate, timeout: float = 10.0, what: str = "the condition"):
    deadline = time.monotonic() + timeout
    while not (value := predicate()):
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}")
        time.sleep(0.02)
    return value


async def async_wait_until(predicate, timeout: float = 10.0, what: str = "the condition"):
    deadline = time.monotonic() + timeout
    while not (value := predicate()):
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}")
        await asyncio.sleep(0.02)
    return value


OURS = "o" * 56
ALICE = "a" * 56
BOB = "b" * 56
NEW = "n" * 56


def chat(text: str) -> str:
    return json.dumps({"o": 1, "d": text})


# ── bridge.py over a fake libCwtch ───────────────────────────────────────────────────────────────


class FakeLib:
    """libCwtch stand-in: calls are recorded, and each answers with the events libCwtch publishes."""

    def __init__(self, profiles: dict | None = None):
        self.events: queue.Queue = queue.Queue()
        self.calls: list[tuple] = []
        self.profiles = dict(profiles or {})  # onion -> (password, contacts)
        self.next_conversation = 10

    def emit(self, etype: str, **data) -> None:
        self.events.put(json.dumps({"EventType": etype, "EventID": "e", "Data": data}))

    def start(self, app_dir, tor_path):
        self.calls.append(("start", app_dir, tor_path))
        self.emit("CwtchStarted")
        return 0

    def next_event(self):
        return self.events.get()

    def load_profiles(self, password):
        self.calls.append(("load", password))
        for onion, (pw, contacts) in self.profiles.items():
            if pw == password:
                self.emit("NewPeer", Identity=onion, ContactsJson=json.dumps(contacts))

    def create_profile(self, name, password):
        self.calls.append(("create", name))
        self.profiles[OURS] = (password, [])
        self.emit("NewPeer", Identity=OURS, Created="true", ContactsJson="null")
        return OURS

    def accept_conversation(self, profile, conversation):
        self.calls.append(("accept", profile, conversation))

    def send_message(self, profile, conversation, message):
        self.calls.append(("send", profile, conversation, message))
        return json.dumps({"ID": 7, "ContentHash": "h"})

    def import_bundle(self, profile, bundle):
        self.calls.append(("import", profile, bundle))
        conversation, self.next_conversation = self.next_conversation, self.next_conversation + 1
        self.emit("ContactCreated", ProfileOnion=profile, RemotePeer=bundle,
                  ConversationID=str(conversation), accepted="true")
        return "importBundle.success"

    def shutdown(self):
        self.calls.append(("shutdown",))
        self.emit("Shutdown")


def _booted(tmp_path, lib=None):
    lib = lib or FakeLib()
    emitted: list[dict] = []
    b = bridge.Bridge(lib, emitted.append)
    b.boot(str(tmp_path / "app"), "/usr/bin/tor", "pw", "Bot")
    return b, lib, emitted


def test_first_boot_creates_the_profile_and_records_its_onion(tmp_path):
    b, lib, emitted = _booted(tmp_path)

    assert ("create", "Bot") in lib.calls
    assert not any(call[0] == "load" for call in lib.calls)  # nothing else in app_dir is brought online
    assert json.loads((tmp_path / "app" / bridge.STATE_FILE).read_text(encoding="utf-8")) == {"onion": OURS}
    assert emitted[-1] == {"event": "ready", "onion": OURS, "contacts": []}
    b.shutdown()


def test_restart_loads_the_recorded_profile_and_its_p2p_contacts(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / bridge.STATE_FILE).write_text(json.dumps({"onion": OURS}), encoding="utf-8")
    contacts = [{"onion": ALICE, "name": "alice", "accepted": True, "identifier": 3},
                {"onion": "g" * 56, "isGroup": True, "identifier": 4}]
    lib = FakeLib({OURS: ("pw", contacts)})

    b, lib, emitted = _booted(tmp_path, lib)

    assert not any(call[0] == "create" for call in lib.calls)
    assert emitted[-1]["contacts"] == [{"onion": ALICE, "name": "alice", "accepted": True, "blocked": False}]
    assert b.request({"op": "send", "onion": ALICE, "message": chat("hi")}) == {"ok": True, "message_id": "7"}
    assert ("send", OURS, 3, chat("hi")) in lib.calls  # the conversation id from the profile's contact list
    b.shutdown()


def test_a_profile_the_password_cannot_open_is_a_non_retryable_boot_error(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "PROFILE_TIMEOUT", 0.3)
    app = tmp_path / "app"
    app.mkdir()
    (app / bridge.STATE_FILE).write_text(json.dumps({"onion": OURS}), encoding="utf-8")
    lib = FakeLib({OURS: ("another password", [])})

    with pytest.raises(bridge.BootError) as excinfo:
        bridge.Bridge(lib, lambda _e: None).boot(str(app), "tor", "pw", "Bot")

    assert excinfo.value.retryable is False
    assert "CWTCH_PROFILE_PASSWORD" in str(excinfo.value)


def test_a_new_profile_that_never_comes_up_is_retryable_not_a_password_error(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "PROFILE_TIMEOUT", 0.3)

    class MuteCreate(FakeLib):
        def create_profile(self, name, password):
            return OURS  # created, but its NewPeer never arrives

    with pytest.raises(bridge.BootError) as excinfo:
        bridge.Bridge(MuteCreate(), lambda _e: None).boot(str(tmp_path / "app"), "tor", "pw", "Bot")

    assert excinfo.value.retryable is True
    assert "PASSWORD" not in str(excinfo.value)
    assert json.loads((tmp_path / "app" / bridge.STATE_FILE).read_text(encoding="utf-8")) == {"onion": OURS}


def test_the_bridge_reaches_its_boot_verdict_before_the_adapter_gives_up():
    """Otherwise the adapter times out first and reports a wrong password as retryable."""
    assert bridge.START_TIMEOUT + bridge.PROFILE_TIMEOUT < cwtch.READY_TIMEOUT


def test_closing_stdin_ends_a_boot_that_is_still_waiting(tmp_path):
    """A disconnect mid-boot must not leave the bridge waiting until the adapter kills it."""

    class SilentLib(FakeLib):
        def start(self, app_dir, tor_path):
            return 0  # never reports CwtchStarted

    b = bridge.Bridge(SilentLib(), lambda _e: None)
    closer = threading.Timer(0.2, b.close)
    closer.start()
    started = time.monotonic()

    with pytest.raises(bridge.BootError) as excinfo:
        b.boot(str(tmp_path / "app"), "tor", "pw", "Bot")

    assert time.monotonic() - started < bridge.START_TIMEOUT
    assert "closed" in str(excinfo.value)
    assert excinfo.value.retryable is True


def test_libcwtch_reporting_zero_loaded_profiles_is_not_an_error(tmp_path):
    """libCwtch publishes AppError "Loaded 0 profiles" on successful starts too."""
    b, lib, emitted = _booted(tmp_path)
    lib.emit("AppError", Error="Loaded 0 profiles")
    lib.emit("AppError", Error="something real")

    wait_until(lambda: any(e.get("event") == "error" for e in emitted), what="the real error")

    assert [e for e in emitted if e.get("event") == "error"] == [{"event": "error", "error": "something real"}]
    b.shutdown()


def test_a_stranger_surfaces_as_a_contact_request_then_its_message(tmp_path):
    b, lib, emitted = _booted(tmp_path)
    lib.emit("ContactCreated", ProfileOnion=OURS, RemotePeer=ALICE, ConversationID="3", accepted="false")
    lib.emit("NewMessageFromPeer", ProfileOnion="x" * 56, RemotePeer=BOB, ConversationID="9",
             Data=chat("for another profile"), Index="1")
    lib.emit("NewMessageFromPeer", ProfileOnion=OURS, RemotePeer=ALICE, ConversationID="3",
             Data=chat("hello"), Index="5", ContentHash="h5", Nick="alice", TimestampReceived="t")

    wait_until(lambda: any(e.get("event") == "message" for e in emitted), what="the bridged message")

    contact = next(e for e in emitted if e.get("event") == "contact")
    message = next(e for e in emitted if e.get("event") == "message")
    assert contact == {"event": "contact", "onion": ALICE, "name": "", "accepted": False, "blocked": False}
    assert message == {"event": "message", "onion": ALICE, "name": "alice", "data": chat("hello"),
                       "index": "5", "hash": "h5", "received": "t"}
    assert [e for e in emitted if e.get("event") == "message"] == [message]  # other profile's traffic dropped
    assert b.request({"op": "accept", "onion": ALICE}) == {"ok": True}
    assert ("accept", OURS, 3) in lib.calls
    b.shutdown()


def test_sending_to_a_new_address_adds_the_contact_first(tmp_path):
    b, lib, _ = _booted(tmp_path)

    reply = b.request({"op": "send", "onion": NEW, "message": chat("hi")})

    assert reply == {"ok": True, "message_id": "7"}
    assert lib.calls.index(("import", OURS, NEW)) < lib.calls.index(("send", OURS, 10, chat("hi")))
    assert b.request({"op": "accept", "onion": BOB})["ok"] is False  # accept never invents a contact
    b.shutdown()


def test_serve_echoes_request_ids_and_stops_at_shutdown(tmp_path):
    b, _lib, _ = _booted(tmp_path)
    replies: list[dict] = []
    lines = [json.dumps({"id": 1, "op": "contacts"}), "not json", json.dumps({"id": 2, "op": "bogus"}),
             json.dumps({"op": "shutdown"}), json.dumps({"id": 3, "op": "contacts"})]

    bridge.serve(b, iter(lines), replies.append)

    assert replies == [{"ok": True, "contacts": [], "id": 1},
                       {"event": "error", "error": "malformed request line"},
                       {"ok": False, "error": "unknown op 'bogus'", "id": 2}]
    b.shutdown()


# ── CwtchAdapter over a real (fake) bridge process ───────────────────────────────────────────────

_FAKE_BRIDGE = r'''
import json, sys
from pathlib import Path

here = Path(__file__).parent
scenario = json.loads((here / "scenario.json").read_text(encoding="utf-8"))
log = open(here / "requests.jsonl", "a", encoding="utf-8")

def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def record(obj):
    log.write(json.dumps(obj) + "\n")
    log.flush()

record(json.loads(sys.stdin.readline()))
if scenario.get("fatal"):
    emit({"event": "fatal", **scenario["fatal"]})
    sys.exit(2)
if scenario.get("tor_boot_event", True):
    emit({"event": "tor", "progress": 40, "status": "bootstrapping"})
emit({"event": "ready", "onion": scenario["onion"], "contacts": scenario.get("contacts", [])})
for event in scenario.get("events", []):
    emit(event)
sends = 0
for line in sys.stdin:
    req = json.loads(line)
    record(req)
    if req["op"] == "send":
        if scenario.get("crash_on_send"):
            sys.exit(3)
        sends += 1
        emit({"id": req["id"], "ok": True, "message_id": str(sends)})
    elif req["op"] == "contacts":
        emit({"id": req["id"], "ok": True, "contacts": scenario.get("contacts", [])})
    else:
        emit({"id": req["id"], "ok": True})
record({"op": "eof"})
'''


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch):
        self.dir = tmp_path / "fake-bridge"
        self.dir.mkdir()
        (self.dir / "bridge.py").write_text(_FAKE_BRIDGE, encoding="utf-8")
        lib = tmp_path / "libCwtch.so"
        lib.write_bytes(b"")
        self.app_dir = tmp_path / "cwtch-data"
        monkeypatch.setattr(cwtch, "_BRIDGE_SCRIPT", self.dir / "bridge.py")
        monkeypatch.setenv("CWTCH_PROFILE_PASSWORD", "s3cret")
        monkeypatch.setenv("CWTCH_LIB_PATH", str(lib))
        monkeypatch.setenv("CWTCH_TOR_PATH", "/opt/tor/bin/tor")  # handed to libCwtch as-is
        monkeypatch.setenv("CWTCH_APP_DIR", str(self.app_dir))
        self.dispatched: list = []
        self.fatal: list = []

    def scenario(self, **scenario) -> Harness:
        (self.dir / "scenario.json").write_text(json.dumps({"onion": OURS, **scenario}), encoding="utf-8")
        return self

    def adapter(self):
        from gateway.config import PlatformConfig
        adapter = cwtch.CwtchAdapter(PlatformConfig(enabled=True))

        async def _record(event):
            self.dispatched.append(event)

        adapter.handle_message = _record
        adapter.set_fatal_error_handler(lambda a: self.fatal.append(a.fatal_error_code))
        return adapter

    def requests(self, op: str | None = None) -> list[dict]:
        path = self.dir / "requests.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        reqs = [json.loads(line) for line in lines]
        return [r for r in reqs if r.get("op") == op] if op else reqs


@pytest.fixture
def harness(tmp_path, monkeypatch):
    return Harness(tmp_path, monkeypatch)


def _request_event(onion: str, accepted: bool = False) -> dict:
    return {"event": "contact", "onion": onion, "name": "", "accepted": accepted, "blocked": False}


def _message_event(onion: str, data: str, index: str) -> dict:
    return {"event": "message", "onion": onion, "name": "alice", "data": data, "index": index,
            "hash": "h" + index, "received": "2026-11-08T12:00:00.123456789Z"}


@pytest.mark.asyncio
async def test_connect_hands_the_bridge_its_profile_and_waits_for_tor(harness):
    harness.scenario(events=[{"event": "tor", "progress": 100, "status": "done"}])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        assert adapter.onion == OURS
        await async_wait_until(lambda: not adapter.send_path_degraded, what="Tor ready")
        start = harness.requests("start")[0]
        assert start["password"] == "s3cret"
        assert start["app_dir"] == str(harness.app_dir)
        assert start["tor_path"] == "/opt/tor/bin/tor"
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_a_stranger_is_accepted_and_their_message_reaches_the_gateway(harness):
    harness.scenario(events=[_request_event(ALICE), _message_event(ALICE, chat("hello bot"), "5")])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        await async_wait_until(lambda: harness.dispatched, what="the inbound message")
        event = harness.dispatched[0]
        assert event.text == "hello bot"
        assert (event.source.chat_id, event.source.user_id, event.source.chat_type) == (ALICE, ALICE, "dm")
        assert event.source.user_name == "alice"
        assert event.message_id == f"{ALICE}:5"
        assert [r["onion"] for r in harness.requests("accept")] == [ALICE]
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_a_contact_without_a_nick_stays_hashed_for_the_model(harness):
    """libCwtch sends the address as the nick until a contact shares a name."""
    from gateway.session import SessionContext, build_session_context_prompt

    unnamed = {**_message_event(ALICE, chat("hi"), "1"), "name": ALICE}
    harness.scenario(contacts=[{"onion": ALICE, "name": "", "accepted": True, "blocked": False}], events=[unnamed])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        await async_wait_until(lambda: harness.dispatched, what="the inbound message")
        source = harness.dispatched[0].source
        prompt = build_session_context_prompt(
            SessionContext(source=source, connected_platforms=[source.platform], home_channels={}), redact_pii=True)
        assert ALICE not in prompt
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_without_auto_accept_only_allowlisted_contacts_get_through(harness, monkeypatch):
    monkeypatch.setenv("CWTCH_AUTO_ACCEPT", "false")
    monkeypatch.setenv("CWTCH_ALLOWED_USERS", BOB)
    harness.scenario(events=[
        _request_event(ALICE), _message_event(ALICE, chat("let me in"), "1"),
        _request_event(BOB), _message_event(BOB, chat("hi, it's bob"), "2"),
    ])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        # The consumer is serial: once Bob's later message is dispatched, Alice's was already handled.
        await async_wait_until(lambda: harness.dispatched, what="Bob's message")
        assert [e.text for e in harness.dispatched] == ["hi, it's bob"]
        assert [r["onion"] for r in harness.requests("accept")] == [BOB]
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_quoted_replies_dispatch_their_body_and_textless_overlays_are_dropped(harness):
    quote = json.dumps({"o": 10, "d": json.dumps({"quotedHash": "q", "body": "replying"})})
    harness.scenario(contacts=[{"onion": ALICE, "name": "alice", "accepted": True, "blocked": False}],
                     events=[_message_event(ALICE, json.dumps({"o": 411, "d": "x"}), "1"),
                             _message_event(ALICE, quote, "2")])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        await async_wait_until(lambda: harness.dispatched, what="the quoted reply")
        assert [e.text for e in harness.dispatched] == ["replying"]
        assert harness.requests("accept") == []  # already-accepted contacts are left alone
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_send_wraps_text_in_the_chat_overlay_and_chunks_long_replies(harness):
    harness.scenario()
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        result = await adapter.send(ALICE.upper() + ".onion", "x" * 9000)
        assert result.success is True
        sends = harness.requests("send")
        assert len(sends) == 3
        assert {s["onion"] for s in sends} == {ALICE}
        bodies = [json.loads(s["message"]) for s in sends]
        assert {b["o"] for b in bodies} == {1}
        assert all(len(b["d"]) <= cwtch.MAX_MESSAGE_LENGTH for b in bodies)
        assert result.message_id == "3"

        refused = await adapter.send("@alice", "hi")
        assert refused.success is False
        assert len(harness.requests("send")) == 3  # an invalid address never reaches the bridge
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_list_channels_offers_only_accepted_contacts(harness):
    harness.scenario(contacts=[{"onion": ALICE, "name": "alice", "accepted": True, "blocked": False},
                               {"onion": BOB, "name": "", "accepted": False, "blocked": False}])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        assert await adapter.list_channels() == [{"id": ALICE, "name": "alice", "type": "dm"}]
    finally:
        await adapter.disconnect()
    assert await adapter.list_channels() is None  # bridge gone: keep the directory's known targets


@pytest.mark.asyncio
async def test_a_profile_that_cannot_load_fails_connect_without_retry(harness):
    harness.scenario(fatal={"error": "profile did not load (wrong CWTCH_PROFILE_PASSWORD)", "retryable": False})
    adapter = harness.adapter()

    assert await adapter.connect() is False

    assert adapter.fatal_error_code == "bridge_failed"
    assert adapter.fatal_error_retryable is False
    assert "CWTCH_PROFILE_PASSWORD" in adapter.fatal_error_message


@pytest.mark.asyncio
async def test_missing_libcwtch_is_reported_before_anything_starts(harness, tmp_path, monkeypatch):
    monkeypatch.setenv("CWTCH_LIB_PATH", str(tmp_path / "nowhere" / "libCwtch.so"))
    harness.scenario()
    adapter = harness.adapter()

    assert await adapter.connect() is False

    assert adapter.fatal_error_code == "config_missing"
    assert adapter.fatal_error_retryable is False
    assert harness.requests() == []  # no bridge was spawned


@pytest.mark.asyncio
async def test_a_bridge_crash_after_connect_fails_the_send_and_asks_for_a_reconnect(harness):
    harness.scenario(crash_on_send=True)
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        result = await adapter.send(ALICE, "hi")
        assert result.success is False
        await async_wait_until(lambda: harness.fatal, what="the fatal-error notification")
        assert harness.fatal == ["bridge_exited"]
        assert adapter.fatal_error_retryable is True
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_a_data_directory_held_by_another_gateway_is_never_opened(harness, monkeypatch):
    """libCwtch's profile database cannot be opened twice."""
    import gateway.status as gateway_status
    seen: list[str] = []

    def _held(scope, identity, metadata=None):
        seen.append(identity)
        return False, {"pid": 4242, "profile": "other"}

    monkeypatch.setattr(gateway_status, "acquire_scoped_lock", _held)
    harness.scenario()
    adapter = harness.adapter()

    assert await adapter.connect() is False

    assert adapter.fatal_error_code == "cwtch-app-dir_lock"
    assert "other" in adapter.fatal_error_message
    assert seen == [os.path.normcase(str(harness.app_dir.resolve()))]
    assert harness.requests() == []


@pytest.mark.asyncio
async def test_a_reconnect_reports_degraded_until_the_new_bridges_tor_is_up(harness):
    harness.scenario(events=[{"event": "tor", "progress": 100, "status": "done"}])
    adapter = harness.adapter()
    try:
        assert await adapter.connect() is True
        await async_wait_until(lambda: not adapter.send_path_degraded, what="Tor ready")
        await adapter.disconnect()
        harness.scenario(tor_boot_event=False)  # the new bridge says nothing about Tor yet
        assert await adapter.connect() is True
        assert adapter.send_path_degraded is True
    finally:
        await adapter.disconnect()


@pytest.mark.asyncio
async def test_disconnect_shuts_the_bridge_down_and_releases_the_data_directory(harness, monkeypatch):
    import gateway.status_scoped_locks as scoped_locks
    released: list[tuple] = []
    real_release = scoped_locks.release_scoped_lock
    monkeypatch.setattr(scoped_locks, "release_scoped_lock",
                        lambda scope, identity: released.append((scope, identity)) or real_release(scope, identity))
    harness.scenario()
    adapter = harness.adapter()
    assert await adapter.connect() is True

    await adapter.disconnect()

    assert harness.requests()[-1] == {"op": "eof"}  # stdin EOF is the bridge's shutdown signal
    assert released == [("cwtch-app-dir", os.path.normcase(str(harness.app_dir.resolve())))]
    assert adapter.is_connected is False


@pytest.mark.asyncio
async def test_the_real_bridge_reports_a_file_that_is_not_libcwtch_as_a_config_error(tmp_path, monkeypatch):
    """The shipped bridge.py, end to end up to the library load."""
    not_a_library = tmp_path / "libCwtch.so"
    not_a_library.write_bytes(b"definitely not a shared object")
    monkeypatch.setenv("CWTCH_PROFILE_PASSWORD", "s3cret")
    monkeypatch.setenv("CWTCH_LIB_PATH", str(not_a_library))
    monkeypatch.setenv("CWTCH_APP_DIR", str(tmp_path / "cwtch-data"))
    from gateway.config import PlatformConfig
    adapter = cwtch.CwtchAdapter(PlatformConfig(enabled=True))

    assert await adapter.connect() is False

    assert adapter.fatal_error_code == "bridge_failed"
    assert adapter.fatal_error_retryable is False
    assert "cannot load libCwtch" in adapter.fatal_error_message


# ── registration surface ─────────────────────────────────────────────────────────────────────────


def test_target_refs_accept_only_onion_addresses():
    assert cwtch._parse_target_ref(f"  {ALICE.upper()}.onion ") == (ALICE, None)
    assert cwtch._parse_target_ref("alice") is None
    assert cwtch._parse_target_ref("a" * 55) is None


def test_overlays_decode_to_text():
    assert cwtch.decode_overlay(chat("plain")) == "plain"
    assert cwtch.decode_overlay(json.dumps({"o": 200, "d": json.dumps({"f": "notes.pdf", "s": 3})})) == (
        "[Cwtch file offer: notes.pdf; this bot does not download Cwtch files]")
    assert cwtch.decode_overlay("not json") == ""
    assert cwtch.decode_overlay(json.dumps({"o": "x"})) == ""


def test_yaml_config_seeds_extra_and_bridges_env_but_never_the_password(monkeypatch):
    for var in ("CWTCH_LIB_PATH", "CWTCH_AUTO_ACCEPT", "CWTCH_PROFILE_PASSWORD"):
        monkeypatch.setenv(var, "")  # registers the var for restore, then leaves it unset
        monkeypatch.delenv(var)
    cfg = {"extra": {"lib_path": "/opt/cwtch/libCwtch.so", "auto_accept": False, "password": "nope"}}

    seeded = cwtch._apply_yaml_config({}, cfg)

    assert seeded == {"lib_path": "/opt/cwtch/libCwtch.so", "auto_accept": False}
    assert cwtch._get_scoped_secret("CWTCH_LIB_PATH") == "/opt/cwtch/libCwtch.so"
    assert cwtch._get_scoped_secret("CWTCH_AUTO_ACCEPT") == "false"
    assert cwtch._get_scoped_secret("CWTCH_PROFILE_PASSWORD") is None  # .env only, never config.yaml


def test_env_enablement_reads_only_through_the_profile_secret_scope(monkeypatch):
    """Under multiplexing os.environ holds the default profile's values; a raw read would enable Cwtch
    for the wrong profile."""
    import gateway.platforms._shared as shared
    import hermes_cli.config as cli_config

    scope = {"CWTCH_PROFILE_PASSWORD": "pw", "CWTCH_LIB_PATH": "/opt/cwtch/libCwtch.so", "CWTCH_AUTO_ACCEPT": "false"}
    raw_reads: list[str] = []
    monkeypatch.setattr(shared, "_scoped_get_secret", lambda name, default=None: scope.get(name, default))
    monkeypatch.setattr(cli_config, "get_env_value", lambda key: raw_reads.append(key))
    monkeypatch.setattr(os, "getenv", lambda key, default=None: raw_reads.append(key) or default)

    seed = cwtch._env_enablement()

    assert seed["lib_path"] == "/opt/cwtch/libCwtch.so"
    assert seed["auto_accept"] is False
    assert raw_reads == []


def test_declining_to_reconfigure_leaves_the_setup_untouched(monkeypatch):
    from hermes_cli import cli_output
    import hermes_cli.config as cli_config
    import hermes_cli.gateway as gateway_cli

    def _forbidden(*_a, **_kw):
        raise AssertionError("the wizard went on after the user declined")

    monkeypatch.setattr(gateway_cli, "get_env_value", lambda name: "already set")
    monkeypatch.setattr(gateway_cli, "prompt_yes_no", lambda *_a, **_kw: False)
    monkeypatch.setattr(cli_output, "prompt", _forbidden)
    monkeypatch.setattr(cli_config, "save_env_value", _forbidden)

    cwtch.interactive_setup()
