"""Threat intelligence and reputation diagnostics API."""

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
    DiagnosticResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    ThreatLookupRequest,
    ThreatPricingResponse,
    ThreatSourcesResponse,
    ThreatSubject,
    ThreatSubjectType,
    ThreatView,
)
from hyrule_cloud.services.threat.lookup import (
    threat_intel_enabled,
    threat_lookup,
    threat_sources,
)

router = APIRouter(prefix="/v1/threat", tags=["Threat and reputation"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_threat_capabilities() -> ProductCapabilityResponse:
    # Don't advertise paid endpoints (or their quote) while no reputation
    # source is configured — they all 501 before charging. Mirrors the manifest
    # gate and the shared gated-capabilities pattern.
    enabled = threat_intel_enabled()
    free_endpoints = [
        CapabilityEndpoint(path="/v1/threat/capabilities", method="GET", description="Threat diagnostic capabilities"),
        CapabilityEndpoint(path="/v1/threat/sources", method="GET", description="Configured and disabled source status"),
        CapabilityEndpoint(path="/v1/threat/pricing", method="GET", description="Threat lookup pricing"),
    ]
    paid_endpoints: list[CapabilityEndpoint] = []
    if enabled:
        free_endpoints.append(
            CapabilityEndpoint(path="/v1/threat/lookup/quote", method="POST", description="Quote a threat lookup")
        )
        paid_endpoints = [
            CapabilityEndpoint(path="/v1/threat/lookup", method="POST", paid=True, description="Run domain/IP/cert reputation lookup"),
            CapabilityEndpoint(path="/v1/threat/domain/{domain}", method="GET", paid=True, description="Domain reputation shortcut"),
            CapabilityEndpoint(path="/v1/threat/ip/{address}", method="GET", paid=True, description="IP reputation shortcut"),
            CapabilityEndpoint(path="/v1/threat/cert/{sha256}", method="GET", paid=True, description="Certificate reputation shortcut"),
            CapabilityEndpoint(path="/v1/threat/rbl", method="GET", paid=True, description="RBL/DNSBL view"),
            CapabilityEndpoint(path="/v1/threat/ct", method="GET", paid=True, description="Certificate Transparency view"),
        ]
    return ProductCapabilityResponse(
        service="threat",
        purpose="Paid open-source-first domain/IP/certificate reputation, RBL, CT, RDAP/WHOIS, and licensed-source-ready threat intelligence.",
        separation_of_concerns="/v1/threat summarizes reputation/threat context; /v1/ip and /v1/mx expose network/mail-specific primitives.",
        free_endpoints=free_endpoints,
        paid_endpoints=paid_endpoints,
    )


@router.get("/sources", response_model=ThreatSourcesResponse)
async def get_threat_sources() -> ThreatSourcesResponse:
    return ThreatSourcesResponse(sources=threat_sources())


@router.get("/pricing", response_model=ThreatPricingResponse)
async def get_threat_pricing(request: Request) -> ThreatPricingResponse:
    return ThreatPricingResponse(lookup_usd=str(payment_price(request, "price_threat_lookup", "0.01")))


@router.post("/lookup/quote", response_model=PaidEndpointQuote)
async def quote_threat_lookup(request: Request, body: ThreatLookupRequest) -> PaidEndpointQuote | Response:
    if not threat_intel_enabled():
        return not_implemented("threat.lookup")
    return diagnostic_quote(request, price_attr="price_threat_lookup", default="0.01", name="threat_lookup", paid_endpoint="/v1/threat/lookup")


@router.post("/lookup", response_model=DiagnosticResponse)
async def run_threat_lookup(request: Request, body: ThreatLookupRequest) -> DiagnosticResponse | Response:
    # No licensed reputation source is configured, so a paid lookup would only
    # return contract metadata. Refuse before charging until one is wired up.
    if not threat_intel_enabled():
        return not_implemented("threat.lookup")
    if payment := await require_paid_diagnostic(request, price_attr="price_threat_lookup", default="0.01", description="Hyrule threat/reputation lookup"):
        return payment
    return await threat_lookup(body)


@router.get("/domain/{domain}", response_model=DiagnosticResponse)
async def threat_domain(request: Request, domain: str) -> DiagnosticResponse | Response:
    return await run_threat_lookup(request, ThreatLookupRequest(subject=ThreatSubject(type=ThreatSubjectType.DOMAIN, value=domain)))


@router.get("/ip/{address}", response_model=DiagnosticResponse)
async def threat_ip(request: Request, address: str) -> DiagnosticResponse | Response:
    return await run_threat_lookup(request, ThreatLookupRequest(subject=ThreatSubject(type=ThreatSubjectType.IP, value=address)))


@router.get("/cert/{sha256}", response_model=DiagnosticResponse)
async def threat_cert(request: Request, sha256: str) -> DiagnosticResponse | Response:
    return await run_threat_lookup(request, ThreatLookupRequest(subject=ThreatSubject(type=ThreatSubjectType.CERT, value=sha256)))


@router.get("/rbl", response_model=DiagnosticResponse)
async def threat_rbl(request: Request, target: str) -> DiagnosticResponse | Response:
    subject_type = ThreatSubjectType.IP if _looks_like_ip(target) else ThreatSubjectType.DOMAIN
    return await run_threat_lookup(request, ThreatLookupRequest(subject=ThreatSubject(type=subject_type, value=target), views=[ThreatView.RBL]))


@router.get("/ct", response_model=DiagnosticResponse)
async def threat_ct(request: Request, domain: str) -> DiagnosticResponse | Response:
    return await run_threat_lookup(request, ThreatLookupRequest(subject=ThreatSubject(type=ThreatSubjectType.DOMAIN, value=domain), views=[ThreatView.CT]))


def _looks_like_ip(value: str) -> bool:
    return ":" in value or value.replace(".", "").isdigit()
