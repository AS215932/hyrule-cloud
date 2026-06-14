"""Contract-first read-only DNS lookup/diagnostics API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import payment_price, quote, require_payment
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DNSAuthorityCompareRequest,
    DNSDiagnosticResponse,
    DNSLookupRecordType,
    DNSLookupRequest,
    DNSLookupResponse,
    DNSPricingResponse,
    DNSPropagationRequest,
    DNSRecordRecommendationRequest,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.dns.diagnostics import (
    authority_vs_recursive,
    dnssec_report,
    propagation,
    recommend_records,
    resolver_detect,
)
from hyrule_cloud.services.dns.lookup import lookup as dns_lookup_service
from hyrule_cloud.services.dns.lookup import reverse as dns_reverse_service

router = APIRouter(prefix="/v1/dns", tags=["DNS lookup"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_dns_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="dns",
        purpose="Read-only recursive DNS lookup, reverse lookup, trace, DNSSEC, resolver, and zone health diagnostics.",
        separation_of_concerns="/v1/dns never registers domains and never mutates authoritative zone records; use /v1/domain and /v1/zone for those workflows.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/dns/capabilities", method="GET", description="DNS lookup capabilities"),
            CapabilityEndpoint(path="/v1/dns/record-types", method="GET", description="Supported DNS lookup record types"),
            CapabilityEndpoint(path="/v1/dns/pricing", method="GET", description="DNS lookup pricing"),
            CapabilityEndpoint(path="/v1/dns/lookup/quote", method="POST", description="Quote a DNS lookup"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/dns/lookup", method="POST", paid=True, description="Canonical DNS lookup"),
            CapabilityEndpoint(path="/v1/dns/resolve", method="GET", paid=True, description="Convenience DNS resolve endpoint"),
            CapabilityEndpoint(path="/v1/dns/reverse", method="GET", paid=True, description="PTR lookup for IP address"),
            CapabilityEndpoint(path="/v1/dns/trace", method="GET", paid=True, description="DNS delegation trace"),
            CapabilityEndpoint(path="/v1/dns/dnssec", method="GET", paid=True, description="DNSSEC validation check"),
            CapabilityEndpoint(path="/v1/dns/servers", method="GET", paid=True, description="Authoritative DNS server discovery"),
            CapabilityEndpoint(path="/v1/dns/zone-check", method="GET", paid=True, description="Read-only zone health check"),
            CapabilityEndpoint(path="/v1/dns/propagation", method="POST", paid=True, description="Compare answers across public recursive resolvers"),
            CapabilityEndpoint(path="/v1/dns/recommend-records", method="POST", paid=True, description="Recommend records for web, mail, SIP, verification, or reverse DNS workflows"),
            CapabilityEndpoint(path="/v1/dns/authority-vs-recursive", method="POST", paid=True, description="Compare authoritative/system answer with recursive resolvers"),
            CapabilityEndpoint(path="/v1/dns/resolver-detect", method="POST", paid=True, description="Explain resolver-detection limits and observed request metadata"),
            CapabilityEndpoint(path="/v1/dns/dnssec/report", method="POST", paid=True, description="DNSSEC-focused report"),
        ],
    )


@router.get("/record-types")
async def get_dns_record_types() -> dict[str, list[str]]:
    return {"record_types": [record_type.value for record_type in DNSLookupRecordType]}


@router.get("/pricing", response_model=DNSPricingResponse)
async def get_dns_pricing(request: Request) -> DNSPricingResponse:
    return DNSPricingResponse(lookup_usd=str(payment_price(request, "price_dns_lookup", "0.001")))


@router.post("/lookup/quote", response_model=PaidEndpointQuote)
async def quote_dns_lookup(request: Request, body: DNSLookupRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_dns_lookup", "0.001"), "dns_lookup", "/v1/dns/lookup")


async def _paid(request: Request) -> Response | None:
    amount = payment_price(request, "price_dns_lookup", "0.001")
    result = await require_payment(request, amount, "Hyrule DNS lookup")
    return result if isinstance(result, Response) else None


@router.post("/lookup", response_model=DNSLookupResponse)
async def dns_lookup(request: Request, body: DNSLookupRequest) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_lookup_service(body)


@router.get("/resolve", response_model=DNSLookupResponse)
async def dns_resolve(request: Request, name: str, type: DNSLookupRecordType = DNSLookupRecordType.A) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_lookup_service(DNSLookupRequest(name=name, type=type))


@router.get("/reverse", response_model=DNSLookupResponse)
async def dns_reverse(request: Request, address: str) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_reverse_service(address)


@router.get("/trace", response_model=DNSLookupResponse)
async def dns_trace(request: Request, name: str, type: DNSLookupRecordType = DNSLookupRecordType.A) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_lookup_service(DNSLookupRequest(name=name, type=type, trace=True))


@router.get("/dnssec", response_model=DNSLookupResponse)
async def dns_dnssec(request: Request, name: str) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_lookup_service(DNSLookupRequest(name=name, type=DNSLookupRecordType.DS, dnssec=True))


@router.get("/servers", response_model=DNSLookupResponse)
async def dns_servers(request: Request, domain: str) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_lookup_service(DNSLookupRequest(name=domain, type=DNSLookupRecordType.NS))


@router.get("/zone-check", response_model=DNSLookupResponse)
async def dns_zone_check(request: Request, domain: str) -> DNSLookupResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dns_lookup_service(DNSLookupRequest(name=domain, type=DNSLookupRecordType.SOA, dnssec=True))


@router.post("/propagation", response_model=DNSDiagnosticResponse)
async def dns_propagation(request: Request, body: DNSPropagationRequest) -> DNSDiagnosticResponse | Response:
    if payment := await _paid(request):
        return payment
    return await propagation(body)


@router.post("/recommend-records", response_model=DNSDiagnosticResponse)
async def dns_recommend_records(request: Request, body: DNSRecordRecommendationRequest) -> DNSDiagnosticResponse | Response:
    if payment := await _paid(request):
        return payment
    return recommend_records(body)


@router.post("/authority-vs-recursive", response_model=DNSDiagnosticResponse)
async def dns_authority_vs_recursive(request: Request, body: DNSAuthorityCompareRequest) -> DNSDiagnosticResponse | Response:
    if payment := await _paid(request):
        return payment
    return await authority_vs_recursive(body)


@router.post("/resolver-detect", response_model=DNSDiagnosticResponse)
async def dns_resolver_detect(request: Request) -> DNSDiagnosticResponse | Response:
    if payment := await _paid(request):
        return payment
    return resolver_detect(dict(request.headers))


@router.post("/dnssec/report", response_model=DNSDiagnosticResponse)
async def dns_dnssec_report(request: Request, name: str) -> DNSDiagnosticResponse | Response:
    if payment := await _paid(request):
        return payment
    return await dnssec_report(name)
