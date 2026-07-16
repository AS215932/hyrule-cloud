"""Contract-first IP intelligence API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from hyrule_cloud.api._contract import (
    config_from_request,
    not_implemented,
    payment_price,
    quote,
    require_payment,
)
from hyrule_cloud.models import (
    CapabilityEndpoint,
    IPLookupRequest,
    IPLookupResponse,
    IPLookupView,
    IPPricingResponse,
    IPQualityRequest,
    IPQualityResponse,
    IPSourcesResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.providers.ip_quality import IPQualityProvider, IPQualityProviderError
from hyrule_cloud.services.intel.ip import (
    geo_intel_enabled,
    reputation_intel_enabled,
)
from hyrule_cloud.services.intel.ip import lookup_ip as ip_lookup_service
from hyrule_cloud.services.intel.ip_quality import (
    build_quality_report,
    quality_gate_status,
    quality_report_enabled,
    quality_sources,
)

router = APIRouter(prefix="/v1/ip", tags=["IP intelligence"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_ip_capabilities(request: Request) -> ProductCapabilityResponse:
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
    free_endpoints = [
        CapabilityEndpoint(path="/v1/ip/capabilities", method="GET", description="IP intelligence capabilities"),
        CapabilityEndpoint(path="/v1/ip/pricing", method="GET", description="IP lookup pricing"),
        CapabilityEndpoint(path="/v1/ip/sources", method="GET", description="IP intelligence source inventory and readiness"),
        CapabilityEndpoint(path="/v1/ip/lookup/quote", method="POST", description="Quote an IP intelligence lookup"),
    ]
    if quality_report_enabled(config_from_request(request)):
        free_endpoints.append(
            CapabilityEndpoint(
                path="/v1/ip/quality/quote",
                method="POST",
                description="Quote a licensed IP quality report",
            )
        )
        paid_endpoints.append(
            CapabilityEndpoint(
                path="/v1/ip/quality",
                method="POST",
                paid=True,
                description="Licensed IP quality, reputation, routing, and consistency report",
            )
        )
    return ProductCapabilityResponse(
        service="ip",
        purpose="IP ASN/ISP, reverse DNS, RDAP/WHOIS, and BGP context; geolocation and reputation views activate once their data providers are configured.",
        separation_of_concerns="Use /v1/bgp for routing-specific workflows and /v1/mx for mail troubleshooting.",
        free_endpoints=free_endpoints,
        paid_endpoints=paid_endpoints,
    )


@router.get("/pricing", response_model=IPPricingResponse)
async def get_ip_pricing(request: Request) -> IPPricingResponse:
    quality_price = None
    if quality_report_enabled(config_from_request(request)):
        quality_price = str(payment_price(request, "price_ip_quality", "0.02"))
    return IPPricingResponse(
        lookup_usd=str(payment_price(request, "price_ip_lookup", "0.003")),
        quality_report_usd=quality_price,
    )


@router.get("/sources", response_model=IPSourcesResponse)
async def get_ip_sources(request: Request) -> IPSourcesResponse:
    return quality_sources(config_from_request(request))


def _quality_refusal(request: Request) -> Response | None:
    status = quality_gate_status(config_from_request(request))
    if status.enabled:
        return None
    return not_implemented(
        "ip.quality",
        "IP quality reports are unavailable until both licensed providers, resale approvals, the explicit launch flag, and the provider-cost guard are configured.",
    )


@router.post("/quality/quote", response_model=PaidEndpointQuote)
async def quote_ip_quality(
    request: Request, body: IPQualityRequest
) -> PaidEndpointQuote | Response:
    if refusal := _quality_refusal(request):
        return refusal
    return quote(
        payment_price(request, "price_ip_quality", "0.02"),
        "ip_quality_report",
        "/v1/ip/quality",
    )


@router.post("/quality", response_model=IPQualityResponse)
async def ip_quality(
    request: Request, body: IPQualityRequest
) -> IPQualityResponse | Response:
    if refusal := _quality_refusal(request):
        return refusal
    amount = payment_price(request, "price_ip_quality", "0.02")
    state = getattr(request.app.state, "_typed_state", None)
    gate = getattr(state, "payment_gate", None)
    if gate is None:
        payment = await require_payment(
            request,
            amount,
            "Hyrule licensed IP quality report",
        )
        if isinstance(payment, Response):
            return payment
        return JSONResponse(status_code=503, content={"error": "payment_gate_unavailable"})

    verified = await gate.verify_only(
        request,
        amount,
        description="Hyrule licensed IP quality report",
    )
    if isinstance(verified, Response):
        return verified

    provider = getattr(state, "ip_quality_provider", None)
    owns_provider = provider is None
    if provider is None:
        provider = IPQualityProvider(config_from_request(request).ip_quality)
    try:
        report = await build_quality_report(body, provider)
    except IPQualityProviderError as exc:
        return JSONResponse(
            status_code=503,
            content={
                "error": "ip_quality_sources_unavailable",
                "sources": list(exc.providers),
                "retryable": True,
            },
        )
    finally:
        if owns_provider:
            await provider.close()

    if not await gate.settle_verified(request, verified):
        return JSONResponse(status_code=502, content={"error": "payment_settlement_failed"})
    report.charged_amount_usd = str(amount)
    return report


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
