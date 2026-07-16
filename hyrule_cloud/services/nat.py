"""Server-observed address classification for the free /v1/nat/ip endpoint."""

from __future__ import annotations

import ipaddress

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify_address(value: str) -> tuple[str, bool]:
    """Classify a server-observed IP as cgnat, private, global, or non_global.

    Only ever applied to the address this server actually observed for the
    caller — classification of caller-supplied addresses is not a product
    (an agent can range-check its own inputs).
    """
    ip = ipaddress.ip_address(value)
    if ip in _CGNAT:
        return "cgnat", True
    if ip.is_private:
        return "private", False
    if ip.is_global:
        return "global", False
    return "non_global", False
