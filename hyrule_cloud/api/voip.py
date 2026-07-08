"""VoIP/SIP diagnostics API."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import (
    diagnostic_quote,
    not_implemented,
    payment_price,
    require_paid_diagnostic,
)
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DiagnosticJobResponse,
    DiagnosticResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    VoIPCheckRequest,
    VoIPNumberLookupRequest,
    VoIPPricingResponse,
    VoIPSourcesResponse,
)
from hyrule_cloud.services.voip.diagnostics import voip_check, voip_number_lookup, voip_sources

router = APIRouter(prefix="/v1/voip", tags=["VoIP/SIP diagnostics"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_voip_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="voip",
        purpose="Paid SIP DNS, SIP TLS/OPTIONS, STUN/TURN, and pluggable number carrier/CNAM/spam/E911 diagnostics.",
        separation_of_concerns="/v1/voip diagnoses VoIP/SIP and number-provider context; /v1/dns handles raw DNS lookups; /v1/ports checks single transport reachability.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/voip/capabilities", method="GET", description="VoIP diagnostic capabilities"),
            CapabilityEndpoint(path="/v1/voip/sources", method="GET", description="Configured VoIP/number provider source status"),
            CapabilityEndpoint(path="/v1/voip/pricing", method="GET", description="VoIP diagnostic pricing"),
            CapabilityEndpoint(path="/v1/voip/check/quote", method="POST", description="Quote SIP/VoIP diagnostic check"),
            CapabilityEndpoint(path="/v1/voip/number/lookup/quote", method="POST", description="Quote number intelligence lookup"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/voip/check", method="POST", paid=True, description="Run SIP DNS/TLS/OPTIONS/STUN diagnostics"),
            CapabilityEndpoint(path="/v1/voip/number/lookup", method="POST", paid=True, description="Run carrier/CNAM/spam/E911 lookup through configured providers"),
        ],
    )


@router.get("/sources", response_model=VoIPSourcesResponse)
async def get_voip_sources() -> VoIPSourcesResponse:
    return VoIPSourcesResponse(sources=voip_sources())


@router.get("/pricing", response_model=VoIPPricingResponse)
async def get_voip_pricing(request: Request) -> VoIPPricingResponse:
    return VoIPPricingResponse(
        check_usd=str(payment_price(request, "price_voip_check", "0.01")),
        number_lookup_usd=str(payment_price(request, "price_voip_number_lookup", "0.05")),
        report_usd=str(payment_price(request, "price_voip_report", "0.08")),
    )


@router.post("/check/quote", response_model=PaidEndpointQuote)
async def quote_voip_check(request: Request, body: VoIPCheckRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_voip_check", default="0.01", name="voip_check", paid_endpoint="/v1/voip/check")


@router.post("/number/lookup/quote", response_model=PaidEndpointQuote)
async def quote_voip_number(request: Request, body: VoIPNumberLookupRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_voip_number_lookup", default="0.05", name="voip_number_lookup", paid_endpoint="/v1/voip/number/lookup")


@router.post("/check", response_model=DiagnosticResponse)
async def run_voip_check(request: Request, body: VoIPCheckRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_voip_check", default="0.01", description="Hyrule VoIP/SIP diagnostic check"):
        return payment
    return await voip_check(body)


@router.post("/number/lookup", response_model=DiagnosticResponse)
async def run_voip_number_lookup(request: Request, body: VoIPNumberLookupRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_voip_number_lookup", default="0.05", description="Hyrule VoIP number intelligence lookup"):
        return payment
    return await voip_number_lookup(body)


@router.post("/report", response_model=DiagnosticResponse)
async def run_voip_report(request: Request, body: VoIPCheckRequest) -> DiagnosticResponse | Response:
    # The evidence pack is not built yet (this would just re-run /check at 8x
    # the price): refuse before charging. Use POST /v1/voip/check instead.
    return not_implemented("voip.report.create")


@router.post("/jobs", response_model=DiagnosticJobResponse)
async def create_voip_job(request: Request, body: VoIPCheckRequest) -> DiagnosticJobResponse | Response:
    # Async report jobs have no retrieval backend yet: refuse before charging.
    return not_implemented("voip.jobs.create")


@router.get("/jobs/{job_id}", response_model=DiagnosticJobResponse)
async def get_voip_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("voip.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_voip_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("voip.jobs.download")
