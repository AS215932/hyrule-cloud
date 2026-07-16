"""IP intelligence service: geo placeholder, ASN/ISP, rDNS, RDAP/WHOIS, reputation."""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime

import dns.exception
import dns.resolver

from hyrule_cloud.models import (
    IPGeoResult,
    IPLookupRequest,
    IPLookupResponse,
    IPLookupView,
    IPNetworkResult,
    IPReputationResult,
    RDAPLookupRequest,
    RegistrySubject,
    RegistrySubjectType,
    WhoisLookupRequest,
)
from hyrule_cloud.services.cache import TTLCache
from hyrule_cloud.services.dns.lookup import reverse
from hyrule_cloud.services.registry.lookup import rdap_lookup, whois_lookup

_cache: TTLCache[IPLookupResponse] = TTLCache(max_entries=2048)


def geo_intel_enabled() -> bool:
    """Whether a real geolocation provider (e.g. a local MaxMind DB) is configured.

    Until then the geo view only returns a not_configured placeholder, so paid
    requests for it are refused before charging (see api/ip.py).
    """
    return False


def reputation_intel_enabled() -> bool:
    """Whether a real IP reputation source is configured.

    Mirrors threat_intel_enabled: the view is a placeholder until a licensed or
    owner-verified provider adapter exists, so it must not be billable.
    """
    return False


def _team_cymru_name(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        return ".".join(reversed(address.split("."))) + ".origin.asn.cymru.com"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _parse_cymru_txt(value: str) -> IPNetworkResult:
    # Format: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
    cleaned = value.strip().strip('"')
    parts = [part.strip() for part in cleaned.split("|")]
    asn: int | None = None
    if parts and parts[0].isdigit():
        asn = int(parts[0])
    return IPNetworkResult(
        asn=asn,
        asn_name=f"AS{asn}" if asn is not None else None,
        isp=f"AS{asn}" if asn is not None else None,
        prefix=parts[1] if len(parts) > 1 else None,
        registry=parts[3].lower() if len(parts) > 3 else None,
    )


def _asn_lookup_sync(address: str) -> IPNetworkResult:
    name = _team_cymru_name(address)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    try:
        answer = resolver.resolve(name, "TXT")
        for rdata in answer:
            strings = getattr(rdata, "strings", None)
            if strings:
                return _parse_cymru_txt(b"".join(strings).decode())
            return _parse_cymru_txt(rdata.to_text())
    except Exception:
        return IPNetworkResult()
    return IPNetworkResult()


async def lookup_ip(req: IPLookupRequest) -> IPLookupResponse:
    ip = str(ipaddress.ip_address(req.address))
    key = f"{ip}:{','.join(sorted(view.value for view in req.views))}"
    cached = _cache.get(key)
    if cached is not None:
        return cached

    sources: dict[str, str] = {}
    geo: IPGeoResult | None = None
    network: IPNetworkResult | None = None
    reverse_dns: list[str] = []
    rdap: dict[str, object] | None = None
    whois: dict[str, object] | None = None
    reputation: IPReputationResult | None = None
    bgp: dict[str, object] | None = None
    partial = False

    if IPLookupView.GEO in req.views:
        # Contract-complete placeholder: a local MaxMind DB/provider adapter lands
        # in the data-source step. Keeping the field explicit avoids pretending
        # a random public web API is authoritative.
        geo = IPGeoResult(source="not_configured")
        sources["geo"] = "not_configured"

    if IPLookupView.ASN in req.views:
        network = await asyncio.to_thread(_asn_lookup_sync, ip)
        sources["team_cymru"] = "ok" if network.asn else "degraded"
        partial = partial or network.asn is None

    if IPLookupView.RDNS in req.views:
        try:
            ptr = await reverse(ip)
            reverse_dns = [answer.value.rstrip(".") for answer in ptr.answers]
            sources["dns"] = "ok"
        except (ValueError, dns.exception.DNSException, Exception):
            sources["dns"] = "degraded"
            partial = True

    if IPLookupView.RDAP in req.views:
        rdap_result = await rdap_lookup(
            RDAPLookupRequest(
                subject=RegistrySubject(type=RegistrySubjectType.IP, value=ip),
                include_raw=False,
            )
        )
        rdap = rdap_result.parsed
        sources["rdap"] = "ok" if "error" not in rdap_result.parsed else "degraded"
        partial = partial or "error" in rdap_result.parsed

    if IPLookupView.WHOIS in req.views:
        whois_result = await whois_lookup(
            WhoisLookupRequest(
                subject=RegistrySubject(type=RegistrySubjectType.IP, value=ip),
                include_raw=False,
            )
        )
        whois = whois_result.parsed
        sources["whois"] = "ok" if "error" not in whois_result.parsed else "degraded"
        partial = partial or "error" in whois_result.parsed

    if IPLookupView.REPUTATION in req.views:
        reputation = IPReputationResult()
        sources["reputation"] = "not_configured"

    if IPLookupView.BGP in req.views:
        bgp = {"message": "Use /v1/bgp/ip for routing-specific paid BGP lookup."}
        sources["bgp"] = "delegated"

    response = IPLookupResponse(
        request_id="ipq_contract",
        address=ip,
        geo=geo,
        network=network,
        reverse_dns=reverse_dns,
        rdap=rdap,
        whois=whois,
        reputation=reputation,
        bgp=bgp,
        sources=sources,
        partial=partial,
        generated_at=datetime.now(UTC),
    )
    _cache.set(key, response, ttl_seconds=req.max_age_seconds or 3600)
    return response
