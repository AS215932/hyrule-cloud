"""STUN client codec tests (RFC 5389 XOR-MAPPED-ADDRESS)."""
from __future__ import annotations

import socket
import struct

from hyrule_cloud.services.voip.stun_probe import (
    _MAGIC_COOKIE,
    _build_binding_request,
    _parse_xor_mapped_address,
)


def _success_with_xor_mapped(txid: bytes, ip: str, port: int, family: int = 0x01) -> bytes:
    xport = port ^ (_MAGIC_COOKIE >> 16)
    if family == 0x01:
        raw = bytes(b ^ c for b, c in zip(socket.inet_pton(socket.AF_INET, ip), struct.pack(">I", _MAGIC_COOKIE)))
    else:
        mask = struct.pack(">I", _MAGIC_COOKIE) + txid
        raw = bytes(b ^ c for b, c in zip(socket.inet_pton(socket.AF_INET6, ip), mask))
    value = bytes([0x00, family]) + struct.pack(">H", xport) + raw
    attr = struct.pack(">HH", 0x0020, len(value)) + value
    header = struct.pack(">HHI", 0x0101, len(attr), _MAGIC_COOKIE) + txid
    return header + attr


def test_roundtrip_ipv4():
    txid = b"0123456789ab"
    packet = _success_with_xor_mapped(txid, "203.0.113.7", 51234)
    assert _parse_xor_mapped_address(packet, txid) == ("203.0.113.7", 51234)


def test_roundtrip_ipv6():
    txid = b"abcdef012345"
    packet = _success_with_xor_mapped(txid, "2a0c:b641:b50:2::e0", 40000, family=0x02)
    assert _parse_xor_mapped_address(packet, txid) == ("2a0c:b641:b50:2::e0", 40000)


def test_rejects_wrong_txid():
    txid = b"0123456789ab"
    packet = _success_with_xor_mapped(txid, "203.0.113.7", 51234)
    assert _parse_xor_mapped_address(packet, b"ffffffffffff") is None


def test_binding_request_shape():
    txid = b"0123456789ab"
    req = _build_binding_request(txid)
    msg_type, length, cookie = struct.unpack(">HHI", req[:8])
    assert msg_type == 0x0001 and length == 0 and cookie == _MAGIC_COOKIE
    assert req[8:20] == txid
