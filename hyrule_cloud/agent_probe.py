"""Agent-side network probes.

These functions must run in the environment being measured. They deliberately
contain no platform fingerprinting or persistence; the control-plane API owns
session correlation and the 15-minute retention boundary.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
from urllib.parse import urlsplit

_STUN_BINDING_REQUEST = 0x0001
_STUN_BINDING_SUCCESS = 0x0101
_STUN_MAGIC_COOKIE = 0x2112A442
_MAPPED_ADDRESS = 0x0001
_XOR_MAPPED_ADDRESS = 0x0020


def _stun_target(url: str) -> tuple[str, int]:
    parsed = urlsplit(url if "://" in url else url.replace(":", "://", 1))
    if parsed.scheme.lower() not in {"stun", "stuns"} or not parsed.hostname:
        raise ValueError("STUN target must use a stun: or stuns: URL")
    if parsed.scheme.lower() == "stuns":
        raise ValueError("TLS STUN is not supported by the local UDP probe")
    return parsed.hostname, parsed.port or 3478


def _mapped_address(payload: bytes, transaction_id: bytes) -> str | None:
    if len(payload) < 20:
        return None
    message_type, message_length, cookie, response_id = struct.unpack(
        "!HHI12s", payload[:20]
    )
    if (
        message_type != _STUN_BINDING_SUCCESS
        or cookie != _STUN_MAGIC_COOKIE
        or response_id != transaction_id
    ):
        return None
    offset = 20
    end = min(len(payload), 20 + message_length)
    cookie_bytes = struct.pack("!I", _STUN_MAGIC_COOKIE)
    while offset + 4 <= end:
        attribute_type, attribute_length = struct.unpack("!HH", payload[offset : offset + 4])
        value = payload[offset + 4 : offset + 4 + attribute_length]
        offset += 4 + ((attribute_length + 3) // 4) * 4
        if attribute_type not in {_MAPPED_ADDRESS, _XOR_MAPPED_ADDRESS} or len(value) < 8:
            continue
        family = value[1]
        packed_length = 4 if family == 0x01 else 16 if family == 0x02 else 0
        if not packed_length or len(value) < 4 + packed_length:
            continue
        packed = value[4 : 4 + packed_length]
        if attribute_type == _XOR_MAPPED_ADDRESS:
            mask = cookie_bytes if packed_length == 4 else cookie_bytes + transaction_id
            packed = bytes(left ^ right for left, right in zip(packed, mask, strict=True))
        try:
            address = ipaddress.ip_address(packed)
        except ValueError:
            continue
        return str(address) if address.is_global else None
    return None


async def stun_binding_address(url: str, *, timeout_seconds: float = 3.0) -> str | None:
    """Return the public RFC 5389 mapped address reported by a STUN server."""

    host, port = _stun_target(url)
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    transaction_id = os.urandom(12)
    request = struct.pack("!HHI12s", _STUN_BINDING_REQUEST, 0, _STUN_MAGIC_COOKIE, transaction_id)
    for family, socktype, protocol, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, protocol)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_sendto(sock, request, sockaddr), timeout_seconds)
            payload, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout_seconds)
        except (OSError, TimeoutError):
            continue
        finally:
            sock.close()
        mapped = _mapped_address(payload, transaction_id)
        if mapped is not None:
            return mapped
    return None


async def trigger_dns_observation(hostname: str) -> bool:
    """Resolve a unique name through the runtime's configured recursive DNS."""

    try:
        await asyncio.get_running_loop().getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        # NXDOMAIN/no-data is expected: the authoritative query is the evidence.
        return True
    except OSError:
        return False
    return True
