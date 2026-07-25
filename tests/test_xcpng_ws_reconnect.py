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
