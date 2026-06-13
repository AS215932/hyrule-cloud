"""Abuse controls for active network diagnostics."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Dangerous service ports that Hyrule public diagnostics never probe. Common
# mail/SIP/web ports are not in this set; they are governed by the explicit
# public diagnostic allowlist below.
_BLOCKED_PORTS = {0, 135, 137, 138, 139, 445, 3306, 5432, 6379, 11211, 27017}

# Public, single-service diagnostic allowlist. This is intentionally not a
# scanner range: callers must declare one service/port per request.
_DEFAULT_ALLOWED_TCP_PORTS = {
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    993,
    995,
    2525,
    5060,
    5061,
    8080,
    8443,
}


class UnsafeTargetError(ValueError):
    pass


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        ]
    )


def normalize_host(target: str) -> str:
    value = target.strip()
    if not value:
        raise UnsafeTargetError("target is empty")
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        host = value.split("/", 1)[0]
        if host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        elif host.count(":") == 1:
            host = host.rsplit(":", 1)[0]
    if not host:
        raise UnsafeTargetError("target host is empty")
    return host.rstrip(".").lower()


def allowed_tcp_ports() -> list[int]:
    return sorted(_DEFAULT_ALLOWED_TCP_PORTS)


def classify_ip_scope(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    return "public"


def assert_public_host(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Domain names are resolved below by the active probe before connect.
        return
    if _is_blocked_ip(ip):
        raise UnsafeTargetError(f"blocked non-public target: {ip}")


def resolve_public_addresses(host: str, *, family: int = socket.AF_UNSPEC) -> list[str]:
    assert_public_host(host)
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"unable to resolve target: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        ip = ipaddress.ip_address(addr)
        if _is_blocked_ip(ip):
            raise UnsafeTargetError(f"blocked resolved non-public target: {ip}")
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise UnsafeTargetError("target resolved to no usable addresses")
    return addresses


def assert_safe_port(port: int, *, allowed_ports: set[int] | None = None) -> None:
    allowed = allowed_ports or _DEFAULT_ALLOWED_TCP_PORTS
    if port < 1 or port > 65535:
        raise UnsafeTargetError("invalid TCP port")
    if port in _BLOCKED_PORTS:
        raise UnsafeTargetError(f"blocked TCP port: {port}")
    if port not in allowed:
        raise UnsafeTargetError(f"TCP port {port} is not in the public diagnostic allowlist")


def assert_safe_active_probe_target(
    target: str,
    *,
    port: int | None = None,
    family: int = socket.AF_UNSPEC,
    allowed_ports: set[int] | None = None,
) -> list[str]:
    """Validate a public active-probe target and return resolved addresses.

    This is the shared abuse-control gate for web, path, port, NAT callback,
    SIP/VoIP, and speedtest diagnostics. Private/reserved/loopback/link-local
    destinations are always blocked in the public API, including when a domain
    resolves to one of those addresses.
    """
    host = normalize_host(target)
    if port is not None:
        assert_safe_port(port, allowed_ports=allowed_ports)
    return resolve_public_addresses(host, family=family)


def safe_url(url_or_host: str, *, default_scheme: str = "https") -> str:
    value = url_or_host.strip()
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTargetError("only http and https URLs are allowed")
    host = parsed.hostname or ""
    normalize_host(value)
    resolve_public_addresses(host)
    return value
