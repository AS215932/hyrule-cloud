"""Customer VM network-config rendering and IPv6 prefix allocation helpers."""

from __future__ import annotations

import hashlib
from ipaddress import IPv6Address, IPv6Network
from typing import Any, cast

import yaml  # type: ignore[import-untyped]

CUSTOMER_VM_INTERFACE = "enX0"
CUSTOMER_VM_ADDRESS_HOST_ID = 2
RESERVED_PREFIX_INDEXES = {0}


def supports_static_network_config(os_name: str) -> bool:
    """Return whether Hyrule can render static guest networking for this OS."""
    return os_name.lower().startswith("debian")


def customer_prefix_count(supernet: IPv6Network) -> int:
    if supernet.version != 6:
        raise ValueError("customer supernet must be IPv6")
    if supernet.prefixlen > 64:
        raise ValueError("customer supernet must be /64 or shorter")
    return 1 << (64 - supernet.prefixlen)


def prefix_index_candidate(vm_id: str, supernet: IPv6Network) -> int:
    usable = customer_prefix_count(supernet) - len(RESERVED_PREFIX_INDEXES)
    if usable <= 0:
        raise ValueError("customer supernet has no usable /64 prefixes")
    digest = hashlib.sha256(vm_id.encode()).digest()
    return int.from_bytes(digest[:8], "big") % usable + 1


def prefix_for_index(supernet: IPv6Network, prefix_index: int) -> IPv6Network:
    count = customer_prefix_count(supernet)
    if prefix_index < 0 or prefix_index >= count:
        raise ValueError(f"prefix index {prefix_index} is outside {supernet}")
    prefix_int = int(supernet.network_address) + (prefix_index << 64)
    return IPv6Network((prefix_int, 64))


def vm_address_for_prefix(prefix: IPv6Network) -> IPv6Address:
    if prefix.prefixlen != 64:
        raise ValueError("customer VM prefix must be a /64")
    return IPv6Address(int(prefix.network_address) + CUSTOMER_VM_ADDRESS_HOST_ID)


def parse_dns_servers(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def render_debian_network_config(
    *,
    address: str,
    prefix: str,
    gateway: str,
    dns_servers: list[str],
    interface: str = CUSTOMER_VM_INTERFACE,
) -> str:
    network = IPv6Network(prefix, strict=True)
    address_with_prefix = f"{IPv6Address(address)}/{network.prefixlen}"
    config: dict[str, Any] = {
        "version": 2,
        "ethernets": {
            interface: {
                "addresses": [address_with_prefix],
                "nameservers": {"addresses": dns_servers},
                "routes": [
                    {
                        "to": "::/0",
                        "via": str(IPv6Address(gateway)),
                        "on-link": True,
                    }
                ],
            }
        },
    }
    return cast(str, yaml.dump(config, default_flow_style=False, sort_keys=False, width=120))
