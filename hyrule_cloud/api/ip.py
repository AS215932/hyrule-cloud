"""Contract-first IP intelligence API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import payment_price, quote, require_payment
from hyrule_cloud.models import (
    CapabilityEndpoint,
    IPLookupRequest,
    IPLookupResponse,
    IPLookupView,
    IPPricingResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.intel.ip import lookup_ip as ip_lookup_service

router = APIRouter(prefix="/v1/ip", tags=["IP intelligence"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_ip_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="ip",
        purpose="IP geolocation, ASN/ISP, reverse DNS, reputation, RDAP/WHOIS, and BGP context.",
        separation_of_concerns="Use /v1/bgp for routing-specific workflows and /v1/mx for mail troubleshooting.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/ip/capabilities", method="GET", description="IP intelligence capabilities"),
            CapabilityEndpoint(path="/v1/ip/pricing", method="GET", description="IP lookup pricing"),
            CapabilityEndpoint(path="/v1/ip/lookup/quote", method="POST", description="Quote an IP intelligence lookup"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/ip/lookup", method="POST", paid=True, description="IP intelligence lookup"),
            CapabilityEndpoint(path="/v1/ip/{address}", method="GET", paid=True, description="Convenience full IP lookup"),
            CapabilityEndpoint(path="/v1/ip/{address}/geo", method="GET", paid=True, description="IP geolocation"),
            CapabilityEndpoint(path="/v1/ip/{address}/asn", method="GET", paid=True, description="IP ASN/ISP lookup"),
            CapabilityEndpoint(path="/v1/ip/{address}/rdns", method="GET", paid=True, description="Reverse DNS lookup"),
            CapabilityEndpoint(path="/v1/ip/{address}/reputation", method="GET", paid=True, description="IP reputation lookup"),
        ],
    )


@router.get("/pricing", response_model=IPPricingResponse)
async def get_ip_pricing(request: Request) -> IPPricingResponse:
    return IPPricingResponse(lookup_usd=str(payment_price(request, "price_ip_lookup", "0.003")))


@router.post("/lookup/quote", response_model=PaidEndpointQuote)
async def quote_ip_lookup(request: Request, body: IPLookupRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_ip_lookup", "0.003"), "ip_lookup", "/v1/ip/lookup")


async def _paid(request: Request) -> Response | None:
    amount = payment_price(request, "price_ip_lookup", "0.003")
    result = await require_payment(request, amount, "Hyrule IP intelligence lookup")
    return result if isinstance(result, Response) else None


@router.post("/lookup", response_model=IPLookupResponse)
async def ip_lookup(request: Request, body: IPLookupRequest) -> IPLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(body)


@router.get("/{address}/geo", response_model=IPLookupResponse)
async def ip_geo(request: Request, address: str) -> IPLookupResponse | Response:
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
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address, views=[IPLookupView.REPUTATION]))


@router.get("/{address}", response_model=IPLookupResponse)
async def ip_get(request: Request, address: str) -> IPLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await ip_lookup_service(IPLookupRequest(address=address))
