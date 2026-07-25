"""Regression tests for XO websocket reconnect after keepalive death.

Production incident (first live dogfood): the persistent XO JSON-RPC socket
died from an idle keepalive ping timeout ("sent 1011 (internal error)
keepalive ping timeout; no close frame received"). Every subsequent XO call
raised ConnectionClosedError from the cached socket, so /v1/vm/quote and
/v1/vm/create returned 503 until a manual service restart even though XO
itself was reachable the whole time.
"""

import asyncio
import json
from typing import Any, cast

import pytest
from websockets.exceptions import ConnectionClosedError
from websockets.frames import Close, CloseCode

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.providers.xcpng import XCPNGProvider


def _keepalive_death() -> ConnectionClosedError:
    # What websockets raises once a keepalive ping timeout has closed the
    # connection: sent 1011, no close frame received.
    return ConnectionClosedError(
        None, Close(CloseCode.INTERNAL_ERROR, "keepalive ping timeout")
    )


class _DeadWebSocket:
    """A socket that died while idle: every operation raises ConnectionClosedError."""

    def __init__(self) -> None:
        self.close_calls = 0

    async def send(self, raw: str) -> None:
        raise _keepalive_death()

    async def recv(self) -> str:
        raise _keepalive_death()

    async def close(self) -> None:
        self.close_calls += 1


class _AliveWebSocket:
    """Minimal serialized JSON-RPC responder (send, then matching recv)."""

    def __init__(self) -> None:
        self.pending_ids: list[int] = []
        self.sent_methods: list[str] = []

    async def send(self, raw: str) -> None:
        msg = json.loads(raw)
        self.pending_ids.append(int(msg["id"]))
        self.sent_methods.append(msg["method"])

    async def recv(self) -> str:
        await asyncio.sleep(0)
        request_id = self.pending_ids.pop(0)
        return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": request_id})

    async def close(self) -> None: ...


class _ObjectQueryWebSocket:
    """Responds to xo.getAllObjects with a preset VM object map; any other
    method (e.g. a resent vm.create) echoes its request id as the result,
    matching _AliveWebSocket's convention. Records every method sent so a
    test can assert whether vm.create was actually resent.
    """

    def __init__(self, objects: dict[str, dict]) -> None:
        self._objects = objects
        self.pending: list[tuple[int, str]] = []
        self.sent_methods: list[str] = []

    async def send(self, raw: str) -> None:
        msg = json.loads(raw)
        self.pending.append((int(msg["id"]), msg["method"]))
        self.sent_methods.append(msg["method"])

    async def recv(self) -> str:
        await asyncio.sleep(0)
        request_id, method = self.pending.pop(0)
        result = self._objects if method == "xo.getAllObjects" else request_id
        return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})

    async def close(self) -> None: ...


@pytest.mark.asyncio
async def test_xo_call_reconnects_once_after_keepalive_death(monkeypatch):
    provider = XCPNGProvider(XCPNGConfig())
    dead = _DeadWebSocket()
    alive = _AliveWebSocket()
    provider._xo_ws = cast(Any, dead)
    reconnects: list[int] = []

    async def connect_locked() -> None:
        assert provider._xo_ws is None, "dead socket must be dropped before reconnecting"
        reconnects.append(1)
        provider._xo_ws = cast(Any, alive)

    monkeypatch.setattr(provider, "_xo_connect_locked", connect_locked)

    result = await provider._xo_call("xo.getAllObjects", filter={"type": "host"})

    assert result is not None
    assert reconnects == [1]
    assert dead.close_calls == 1
    assert alive.sent_methods == ["xo.getAllObjects"]


@pytest.mark.asyncio
async def test_xo_call_retries_only_once_then_propagates(monkeypatch):
    provider = XCPNGProvider(XCPNGConfig())
    provider._xo_ws = cast(Any, _DeadWebSocket())
    reconnects: list[int] = []

    async def connect_locked() -> None:
        reconnects.append(1)
        # The replacement socket is dead too (XO genuinely down this time).
        provider._xo_ws = cast(Any, _DeadWebSocket())

    monkeypatch.setattr(provider, "_xo_connect_locked", connect_locked)

    with pytest.raises(ConnectionClosedError):
        await provider._xo_call("system.getInfo")

    assert reconnects == [1]


@pytest.mark.asyncio
async def test_concurrent_callers_share_one_reconnect(monkeypatch):
    provider = XCPNGProvider(XCPNGConfig())
    alive = _AliveWebSocket()
    provider._xo_ws = cast(Any, _DeadWebSocket())
    reconnects: list[int] = []

    async def connect_locked() -> None:
        reconnects.append(1)
        provider._xo_ws = cast(Any, alive)

    monkeypatch.setattr(provider, "_xo_connect_locked", connect_locked)

    first, second = await asyncio.gather(
        provider._xo_call("test.first"),
        provider._xo_call("test.second"),
    )

    assert first != second
    assert reconnects == [1]


@pytest.mark.asyncio
async def test_xo_call_vm_create_adopts_existing_clone_after_reconnect(monkeypatch):
    """XO can execute vm.create and lose the response before the connection
    dies. Blindly retrying would create a second same-label guest that the
    orchestrator's pre-create stale-clone sweep never sees (it only runs
    before this call). After reconnecting, _xo_call must find the clone
    that already landed under its name_label and adopt it instead of
    resending vm.create."""
    provider = XCPNGProvider(XCPNGConfig())
    provider._xo_ws = cast(Any, _DeadWebSocket())
    responder = _ObjectQueryWebSocket(
        objects={"existing-uuid": {"name_label": "hyrule-vm123", "type": "VM"}}
    )

    async def connect_locked() -> None:
        provider._xo_ws = cast(Any, responder)

    monkeypatch.setattr(provider, "_xo_connect_locked", connect_locked)

    result = await provider._xo_call(
        "vm.create", name_label="hyrule-vm123", template="tpl-uuid"
    )

    assert result == "existing-uuid"
    assert responder.sent_methods == ["xo.getAllObjects"]


@pytest.mark.asyncio
async def test_xo_call_vm_create_retries_when_no_clone_landed(monkeypatch):
    """If XO never executed the create (connection died before send
    completed, or genuinely failed), no clone exists under name_label and
    the normal single-retry behavior resends vm.create."""
    provider = XCPNGProvider(XCPNGConfig())
    provider._xo_ws = cast(Any, _DeadWebSocket())
    responder = _ObjectQueryWebSocket(objects={})

    async def connect_locked() -> None:
        provider._xo_ws = cast(Any, responder)

    monkeypatch.setattr(provider, "_xo_connect_locked", connect_locked)

    result = await provider._xo_call(
        "vm.create", name_label="hyrule-vm123", template="tpl-uuid"
    )

    assert result is not None
    assert responder.sent_methods == ["xo.getAllObjects", "vm.create"]
