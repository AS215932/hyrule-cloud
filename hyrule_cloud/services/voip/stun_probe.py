"""Minimal STUN client (RFC 5389) used to confirm our public STUN responder.

Sends a Binding Request and parses XOR-MAPPED-ADDRESS from the success response.
Used by the /v1/voip/check STUN arm to report that a reachable public STUN
responder (the hyrule-tunnel-proxy daemon on UDP 3478) is available. Only the
IPv4/IPv6 mapped-address parse is needed; no auth or ICE attributes.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct

_MAGIC_COOKIE = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def _build_binding_request(txid: bytes) -> bytes:
    # type (2) | length (2) | magic cookie (4) | transaction id (12)
    return struct.pack(">HHI", _BINDING_REQUEST, 0, _MAGIC_COOKIE) + txid


def _parse_xor_mapped_address(data: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie = struct.unpack(">HHI", data[:8])
    if msg_type != _BINDING_SUCCESS or cookie != _MAGIC_COOKIE or data[8:20] != txid:
        return None
    body = data[20 : 20 + msg_len]
    offset = 0
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack(">HH", body[offset : offset + 4])
        value = body[offset + 4 : offset + 4 + attr_len]
        if attr_type == _ATTR_XOR_MAPPED_ADDRESS and len(value) >= 8:
            family = value[1]
            xport = struct.unpack(">H", value[2:4])[0] ^ (_MAGIC_COOKIE >> 16)
            if family == 0x01:  # IPv4
                raw = bytes(b ^ c for b, c in zip(value[4:8], struct.pack(">I", _MAGIC_COOKIE)))
                return socket.inet_ntop(socket.AF_INET, raw), xport
            if family == 0x02:  # IPv6
                mask = struct.pack(">I", _MAGIC_COOKIE) + txid
                raw = bytes(b ^ c for b, c in zip(value[4:20], mask))
                return socket.inet_ntop(socket.AF_INET6, raw), xport
        # Attributes are 4-byte aligned.
        offset += 4 + attr_len + ((4 - attr_len % 4) % 4)
    return None


_MappedResult = tuple[str, int] | None


class _STUNProtocol(asyncio.DatagramProtocol):
    def __init__(self, txid: bytes, future: asyncio.Future[_MappedResult]):
        self._txid = txid
        self._future = future

    def datagram_received(self, data: bytes, _addr: object) -> None:
        if not self._future.done():
            self._future.set_result(_parse_xor_mapped_address(data, self._txid))

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


def split_host_port(endpoint: str, default_port: int = 3478) -> tuple[str, int]:
    """Split a STUN endpoint into (host, port), handling IPv6 literals.

    Accepts ``[2001:db8::1]:3478`` (bracketed with port), ``[2001:db8::1]`` or a
    bare ``2001:db8::1`` (IPv6, default port), and ``host:port`` / ``host`` for
    names/IPv4. Splitting on the first colon would corrupt an IPv6 literal.
    """
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        host, sep, rest = endpoint[1:].partition("]")
        if sep and rest.startswith(":") and rest[1:]:
            return host, int(rest[1:])
        return host, default_port
    # Bare IPv6 literal (2+ colons and no brackets) => host, default port.
    if endpoint.count(":") >= 2:
        return endpoint, default_port
    host, sep, port_str = endpoint.partition(":")
    if sep and port_str:
        return host, int(port_str)
    return host, default_port


async def stun_binding(host: str, port: int = 3478, timeout: float = 3.0) -> tuple[str, int] | None:
    """Return the (ip, port) STUN maps us to, or None if unreachable/unparsable."""
    loop = asyncio.get_running_loop()
    txid = os.urandom(12)
    future: asyncio.Future[_MappedResult] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _STUNProtocol(txid, future),
            remote_addr=(host, port),
        )
    except OSError:
        return None
    try:
        transport.sendto(_build_binding_request(txid))
        return await asyncio.wait_for(future, timeout)
    except (TimeoutError, OSError):
        return None
    finally:
        transport.close()
