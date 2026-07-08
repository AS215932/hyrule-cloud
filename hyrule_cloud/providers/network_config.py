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


def validate_customer_network_settings(*, supernet: str, gateway: str, dns: str) -> None:
    """Fail fast on malformed customer-network settings.

    Called at startup so an operator typo surfaces as a boot failure instead
    of a paid VM failing in background provisioning after the charge.
    Raises ValueError on any problem.
    """
    net = IPv6Network(supernet, strict=True)
    # Prefix indexes persist in a 32-bit Integer column (VMRow.ipv6_prefix_index);
    # a supernet shorter than /33 can produce indexes past 2^31-1 and fail the
    # INSERT after payment.
    if net.prefixlen < 33:
        raise ValueError(
            f"customer supernet {net} is too large: prefix indexes must fit a "
            f"32-bit integer, so the supernet must be /33 or longer"
        )
    usable = customer_prefix_count(net) - len(RESERVED_PREFIX_INDEXES)
    if usable <= 0:
        raise ValueError(
            f"customer supernet {net} has no usable /64 prefixes "
            f"(index 0 is reserved; the supernet must be /63 or shorter)"
        )
    gateway_ip = IPv6Address(gateway)
    if gateway_ip not in net:
        raise ValueError(f"customer gateway {gateway_ip} is not inside {net}")
    servers = parse_dns_servers(dns)
    if not servers:
        raise ValueError("at least one customer DNS server is required")
    for server in servers:
        # DNS may live outside the supernet (public/DNS64 resolver) but must
        # be a valid IPv6 address.
        IPv6Address(server)


def render_debian_network_config(
    *,
    address: str,
    prefix: str,
    gateway: str,
    dns_servers: list[str],
    interface: str = CUSTOMER_VM_INTERFACE,
    customer_supernet: IPv6Network | None = None,
) -> str:
    network = IPv6Network(prefix, strict=True)
    if network.prefixlen != 64:
        raise ValueError("customer VM prefix must be a /64")
    address_ip = IPv6Address(address)
    if address_ip not in network:
        raise ValueError(f"VM address {address_ip} is not inside {network}")

    gateway_ip = IPv6Address(gateway)
    dns_ips = [IPv6Address(server) for server in dns_servers]
    if not dns_ips:
        raise ValueError("at least one DNS server is required")
    if customer_supernet is not None:
        if not network.subnet_of(customer_supernet):
            raise ValueError(f"VM prefix {network} is not inside {customer_supernet}")
        # The gateway must be on-link (the default route is via on-link), but
        # DNS resolvers only need to be reachable IPv6 addresses — a public
        # or NAT64/DNS64 resolver outside the customer allocation is a normal
        # production configuration.
        if gateway_ip not in customer_supernet:
            raise ValueError(f"gateway {gateway_ip} is not inside {customer_supernet}")

    address_with_prefix = f"{address_ip}/{network.prefixlen}"
    config: dict[str, Any] = {
        "version": 2,
        "ethernets": {
            interface: {
                "addresses": [address_with_prefix],
                "nameservers": {"addresses": [str(dns_ip) for dns_ip in dns_ips]},
                "routes": [
                    {
                        "to": "::/0",
                        "via": str(gateway_ip),
                        "on-link": True,
                    }
                ],
            }
        },
    }
    return cast(str, yaml.dump(config, default_flow_style=False, sort_keys=False, width=120))
