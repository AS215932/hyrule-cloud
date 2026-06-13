"""Server-only NAT/CGNAT hints."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from hyrule_cloud.models import NATLookupRequest, NATLookupResponse

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def lookup_nat(body: NATLookupRequest) -> NATLookupResponse:
    evidence: list[str] = []
    cgnat_likely = False
    for label, value in [
        ("observed_public_ip", body.observed_public_ip),
        ("customer_reported_wan_ip", body.customer_reported_wan_ip),
        ("customer_reported_lan_ip", body.customer_reported_lan_ip),
    ]:
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            evidence.append(f"{label} is not a valid IP address")
            continue
        if ip in _CGNAT:
            cgnat_likely = True
            evidence.append(f"{label} is inside 100.64.0.0/10 CGNAT space")
        elif ip.is_private:
            evidence.append(f"{label} is private RFC1918/internal address space")
        elif ip.is_global:
            evidence.append(f"{label} is globally routable")
        else:
            evidence.append(f"{label} is {ip!s} with non-global scope")
    if body.observed_public_ip and body.customer_reported_wan_ip and body.observed_public_ip != body.customer_reported_wan_ip:
        cgnat_likely = True
        evidence.append("observed_public_ip differs from customer_reported_wan_ip")
    recommendation = "Ask ISP for public IPv4, use IPv6, or use VPN/tunnel/NAT traversal." if cgnat_likely else "CGNAT is not obvious from supplied server-side evidence."
    return NATLookupResponse(
        cgnat_likely=cgnat_likely,
        evidence=evidence or ["No customer WAN/LAN evidence supplied."],
        recommendation=recommendation,
        generated_at=datetime.now(UTC),
    )
