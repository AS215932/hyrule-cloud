"""Contract-first IP intelligence API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import not_implemented, payment_price, quote, require_payment
from hyrule_cloud.models import (
    CapabilityEndpoint,
    IPLookupRequest,
    IPLookupResponse,
    IPLookupView,
    IPPricingResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.intel.ip import (
    geo_intel_enabled,
    reputation_intel_enabled,
)
from hyrule_cloud.services.intel.ip import lookup_ip as ip_lookup_service

router = APIRouter(prefix="/v1/ip", tags=["IP intelligence"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_ip_capabilities() -> ProductCapabilityResponse:
    # Don't advertise the geo/reputation views while no data provider is
    # configured — they 501 before charging. Mirrors the threat/voip
    # gated-capabilities pattern.
    paid_endpoints = [
        CapabilityEndpoint(path="/v1/ip/lookup", method="POST", paid=True, description="IP intelligence lookup"),
        CapabilityEndpoint(path="/v1/ip/{address}", method="GET", paid=True, description="Convenience full IP lookup"),
        CapabilityEndpoint(path="/v1/ip/{address}/asn", method="GET", paid=True, description="IP ASN/ISP lookup"),
        CapabilityEndpoint(path="/v1/ip/{address}/rdns", method="GET", paid=True, description="Reverse DNS lookup"),
    ]
    if geo_intel_enabled():
        paid_endpoints.append(
            CapabilityEndpoint(path="/v1/ip/{address}/geo", method="GET", paid=True, description="IP geolocation")
        )
    if reputation_intel_enabled():
        paid_endpoints.append(
            CapabilityEndpoint(path="/v1/ip/{address}/reputation", method="GET", paid=True, description="IP reputation lookup")
        )
    return ProductCapabilityResponse(
        service="ip",
        purpose="IP ASN/ISP, reverse DNS, RDAP/WHOIS, and BGP context; geolocation and reputation views activate once their data providers are configured.",
        separation_of_concerns="Use /v1/bgp for routing-specific workflows and /v1/mx for mail troubleshooting.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/ip/capabilities", method="GET", description="IP intelligence capabilities"),
            CapabilityEndpoint(path="/v1/ip/pricing", method="GET", description="IP lookup pricing"),
            CapabilityEndpoint(path="/v1/ip/lookup/quote", method="POST", description="Quote an IP intelligence lookup"),
        ],
        paid_endpoints=paid_endpoints,
    )


@router.get("/pricing", response_model=IPPricingResponse)
async def get_ip_pricing(request: Request) -> IPPricingResponse:
    return IPPricingResponse(lookup_usd=str(payment_price(request, "price_ip_lookup", "0.003")))


def _unconfigured_views(views: list[IPLookupView]) -> Response | None:
    # geo/reputation have no data provider yet: refuse before charging rather
    # than bill for a not_configured placeholder.
    if IPLookupView.GEO in views and not geo_intel_enabled():
        return not_implemented(
            "ip.lookup.geo",
            "IP geolocation provider is not configured; omit the geo view.",
        )
    if IPLookupView.REPUTATION in views and not reputation_intel_enabled():
        return not_implemented(
            "ip.lookup.reputation",
            "IP reputation provider is not configured; omit the reputation view.",
        )
    return None


@router.post("/lookup/quote", response_model=PaidEndpointQuote)
async def quote_ip_lookup(request: Request, body: IPLookupRequest) -> PaidEndpointQuote | Response:
    if refusal := _unconfigured_views(body.views):
        return refusal
    return quote(payment_price(request, "price_ip_lookup", "0.003"), "ip_lookup", "/v1/ip/lookup")


async def _paid(request: Request) -> Response | None:
    amount = payment_price(request, "price_ip_lookup", "0.003")
    result = await require_payment(request, amount, "Hyrule IP intelligence lookup")
    return result if isinstance(result, Response) else None


@router.post("/lookup", response_model=IPLookupResponse)
async def ip_lookup(request: Request, body: IPLookupRequest) -> IPLookupResponse | Response:
    if refusal := _unconfigured_views(body.views):
        return refusal
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(body)


@router.get("/{address}/geo", response_model=IPLookupResponse)
async def ip_geo(request: Request, address: str) -> IPLookupResponse | Response:
    if refusal := _unconfigured_views([IPLookupView.GEO]):
        return refusal
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address, views=[IPLookupView.GEO]))


@router.get("/{address}/asn", response_model=IPLookupResponse)
async def ip_asn(request: Request, address: str) -> IPLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address, views=[IPLookupView.ASN]))


@router.get("/{address}/rdns", response_model=IPLookupResponse)
async def ip_rdns(request: Request, address: str) -> IPLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address, views=[IPLookupView.RDNS]))


@router.get("/{address}/reputation", response_model=IPLookupResponse)
async def ip_reputation(request: Request, address: str) -> IPLookupResponse | Response:
    if refusal := _unconfigured_views([IPLookupView.REPUTATION]):
        return refusal
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address, views=[IPLookupView.REPUTATION]))


@router.get("/{address}", response_model=IPLookupResponse)
async def ip_get(request: Request, address: str) -> IPLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address))
