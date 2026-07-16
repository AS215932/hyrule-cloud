from __future__ import annotations

import ipaddress
import struct

import pytest

from hyrule_cloud.agent_probe import (
    _STUN_BINDING_SUCCESS,
    _STUN_MAGIC_COOKIE,
    _XOR_MAPPED_ADDRESS,
    _mapped_address,
    _stun_target,
)


def test_stun_target_accepts_standard_udp_url() -> None:
    assert _stun_target("stun:stun.hyrule.host:3478") == (
        "stun.hyrule.host",
        3478,
    )
    assert _stun_target("stun://[2001:4860:4860::8888]:4444") == (
        "2001:4860:4860::8888",
        4444,
    )
    with pytest.raises(ValueError, match="TLS STUN"):
        _stun_target("stuns:stun.hyrule.host:5349")


def test_xor_mapped_address_parser_returns_only_public_address() -> None:
    transaction_id = bytes.fromhex("00112233445566778899aabb")
    address = ipaddress.ip_address("8.8.8.8").packed
    cookie = struct.pack("!I", _STUN_MAGIC_COOKIE)
    xor_address = bytes(left ^ right for left, right in zip(address, cookie, strict=True))
    value = b"\x00\x01" + struct.pack("!H", 443 ^ (_STUN_MAGIC_COOKIE >> 16)) + xor_address
    attribute = struct.pack("!HH", _XOR_MAPPED_ADDRESS, len(value)) + value
    response = struct.pack(
        "!HHI12s",
        _STUN_BINDING_SUCCESS,
        len(attribute),
        _STUN_MAGIC_COOKIE,
        transaction_id,
    ) + attribute
    assert _mapped_address(response, transaction_id) == "8.8.8.8"
    assert _mapped_address(response, b"different-id!") is None
