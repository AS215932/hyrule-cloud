"""Contract-first read-only DNS lookup/diagnostics API routes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from hyrule_cloud.api._contract import (
    config_from_request,
    payment_price,
    quote,
    require_payment,
)
from hyrule_cloud.config import DNSBlocklistConfig, DNSFilteringConfig
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DNSAuthorityCompareRequest,
    DNSBlocklistCheckResponse,
    DNSBlocklistSourcesResponse,
    DNSDiagnosticResponse,
    DNSDomainCheckRequest,
    DNSFilteringCheckResponse,
    DNSFilteringResolversResponse,
    DNSLookupRecordType,
    DNSLookupRequest,
    DNSLookupResponse,
    DNSPricingResponse,
    DNSPropagationRequest,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.dns.blocklists import (
    BlocklistService,
    BlocklistUnavailableError,
)
from hyrule_cloud.services.dns.diagnostics import (
    authority_vs_recursive,
    dnssec_report,
    propagation,
    resolver_detect,
)
from hyrule_cloud.services.dns.domain import normalize_domain
from hyrule_cloud.services.dns.filtering import (
    DNSFilteringService,
    DomainNotResolvableError,
    filtering_resolver_catalog,
)
from hyrule_cloud.services.dns.lookup import lookup as dns_lookup_service
from hyrule_cloud.services.dns.lookup import reverse as dns_reverse_service

router = APIRouter(prefix="/v1/dns", tags=["DNS lookup"])

_dns_inflight_auth: set[str] = set()


@asynccontextmanager
async def _authorization_guard(request: Request) -> AsyncIterator[None]:
    key = request.headers.get("payment-signature") or request.headers.get("x-payment")
    if not key:
        yield
        return
    if key in _dns_inflight_auth:
        raise HTTPException(409, "payment authorization already in flight")
    _dns_inflight_auth.add(key)
    try:
        yield
    finally:
        _dns_inflight_auth.discard(key)


def _blocklist_service(request: Request) -> BlocklistService:
    state = getattr(request.app.state, "_typed_state", None)
    service = getattr(state, "dns_blocklists", None)
    if isinstance(service, BlocklistService):
        return service
    cfg = config_from_request(request)
    blocklist_cfg = getattr(cfg, "dns_blocklists", None) or DNSBlocklistConfig()
    return BlocklistService(blocklist_cfg)


def _filtering_service(request: Request) -> DNSFilteringService | None:
    state = getattr(request.app.state, "_typed_state", None)
    service = getattr(state, "dns_filtering", None)
    return service if isinstance(service, DNSFilteringService) else None


def _filtering_config(request: Request) -> DNSFilteringConfig:
    return (
        getattr(config_from_request(request), "dns_filtering", None)
        or DNSFilteringConfig()
    )


async def _verify_deferred(
    request: Request,
    *,
    amount: Any,
    description: str,
    domain: str,
) -> Response | Any:
    state = getattr(request.app.state, "_typed_state", None)
    gate = getattr(state, "payment_gate", None)
    if gate is None or not hasattr(gate, "verify_only"):
        return JSONResponse(
            status_code=402,
            content={
                "payment_required": True,
                "amount": str(amount),
                "description": description,
            },
        )
    return await gate.verify_only(
        request,
        amount=amount,
        description=description,
        extra_body={"domain": domain},
    )


async def _settle_deferred(request: Request, verified: Any) -> bool:
    state = getattr(request.app.state, "_typed_state", None)
    gate = getattr(state, "payment_gate", None)
    return bool(gate is not None and await gate.settle_verified(request, verified))


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_dns_capabilities(request: Request) -> ProductCapabilityResponse:
    blocklists_ready = _blocklist_service(request).is_ready()
    filtering_enabled = _filtering_config(request).enabled
    free_endpoints = [
        CapabilityEndpoint(path="/v1/dns/capabilities", method="GET", description="DNS lookup capabilities"),
        CapabilityEndpoint(path="/v1/dns/record-types", method="GET", description="Supported DNS lookup record types"),
        CapabilityEndpoint(path="/v1/dns/pricing", method="GET", description="DNS lookup pricing"),
        CapabilityEndpoint(path="/v1/dns/lookup/quote", method="POST", description="Quote a DNS lookup"),
        CapabilityEndpoint(path="/v1/dns/blocklists/sources", method="GET", description="Blocklist catalog and snapshot freshness"),
        CapabilityEndpoint(path="/v1/dns/filtering/resolvers", method="GET", description="Public DNS filtering resolver matrix"),
    ]
    if blocklists_ready:
        free_endpoints.append(
            CapabilityEndpoint(path="/v1/dns/blocklists/check/quote", method="POST", description="Quote a domain blocklist check")
        )
    if filtering_enabled:
        free_endpoints.append(
            CapabilityEndpoint(path="/v1/dns/filtering/check/quote", method="POST", description="Quote a live DNS filtering check")
        )
    paid_endpoints = [
        CapabilityEndpoint(path="/v1/dns/lookup", method="POST", paid=True, description="Canonical DNS lookup"),
        CapabilityEndpoint(path="/v1/dns/resolve", method="GET", paid=True, description="Convenience DNS resolve endpoint"),
        CapabilityEndpoint(path="/v1/dns/reverse", method="GET", paid=True, description="PTR lookup for IP address"),
        CapabilityEndpoint(path="/v1/dns/trace", method="GET", paid=True, description="DNS delegation trace"),
        CapabilityEndpoint(path="/v1/dns/dnssec", method="GET", paid=True, description="DNSSEC validation check"),
        CapabilityEndpoint(path="/v1/dns/servers", method="GET", paid=True, description="Authoritative DNS server discovery"),
        CapabilityEndpoint(path="/v1/dns/zone-check", method="GET", paid=True, description="Read-only zone health check"),
        CapabilityEndpoint(path="/v1/dns/propagation", method="POST", paid=True, description="Compare answers across public recursive resolvers"),
        CapabilityEndpoint(path="/v1/dns/authority-vs-recursive", method="POST", paid=True, description="Compare authoritative/system answer with recursive resolvers"),
        CapabilityEndpoint(path="/v1/dns/resolver-detect", method="POST", paid=True, description="Explain resolver-detection limits and observed request metadata"),
        CapabilityEndpoint(path="/v1/dns/dnssec/report", method="POST", paid=True, description="DNSSEC-focused report"),
    ]
    if blocklists_ready:
        paid_endpoints.append(
            CapabilityEndpoint(path="/v1/dns/blocklists/check", method="POST", paid=True, description="Search the maintained DNS-capable blocklist catalog")
        )
    if filtering_enabled:
        paid_endpoints.append(
            CapabilityEndpoint(path="/v1/dns/filtering/check", method="POST", paid=True, description="Check public DNS filtering profiles from Hyrule")
        )
    return ProductCapabilityResponse(
        service="dns",
        purpose="Read-only DNS lookup, blocklist membership, filtering-resolver evidence, DNSSEC, resolver, and zone health diagnostics.",
        separation_of_concerns="/v1/dns never registers domains and never mutates authoritative zone records; use /v1/domains for those workflows.",
        free_endpoints=free_endpoints,
        paid_endpoints=paid_endpoints,
    )


@router.get("/record-types")
async def get_dns_record_types() -> dict[str, list[str]]:
    return {"record_types": [record_type.value for record_type in DNSLookupRecordType]}


@router.get("/pricing", response_model=DNSPricingResponse)
async def get_dns_pricing(request: Request) -> DNSPricingResponse:
    return DNSPricingResponse(
        lookup_usd=str(payment_price(request, "price_dns_lookup", "0.001")),
        blocklist_check_usd=str(
            payment_price(request, "price_dns_blocklist_check", "0.003")
        ),
        filtering_check_usd=str(
            payment_price(request, "price_dns_filtering_check", "0.01")
        ),
    )


@router.post("/lookup/quote", response_model=PaidEndpointQuote)
async def quote_dns_lookup(request: Request, body: DNSLookupRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_dns_lookup", "0.001"), "dns_lookup", "/v1/dns/lookup")


@router.get("/blocklists/sources", response_model=DNSBlocklistSourcesResponse)
async def dns_blocklist_sources(request: Request) -> DNSBlocklistSourcesResponse:
    return _blocklist_service(request).sources_response()


@router.get("/filtering/resolvers", response_model=DNSFilteringResolversResponse)
async def dns_filtering_resolvers(request: Request) -> DNSFilteringResolversResponse:
    service = _filtering_service(request)
    if service is not None:
        return service.resolver_catalog()
    return filtering_resolver_catalog(_filtering_config(request))


@router.post("/blocklists/check/quote", response_model=PaidEndpointQuote)
async def quote_dns_blocklist_check(
    request: Request, body: DNSDomainCheckRequest
) -> PaidEndpointQuote:
    try:
        normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not _blocklist_service(request).is_ready():
        raise HTTPException(503, "blocklist catalog does not meet minimum coverage")
    return quote(
        payment_price(request, "price_dns_blocklist_check", "0.003"),
        "dns_blocklist_check",
        "/v1/dns/blocklists/check",
    )


@router.post("/filtering/check/quote", response_model=PaidEndpointQuote)
async def quote_dns_filtering_check(
    request: Request, body: DNSDomainCheckRequest
) -> PaidEndpointQuote:
    try:
        normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not _filtering_config(request).enabled:
        raise HTTPException(503, "DNS filtering checks are disabled")
    return quote(
        payment_price(request, "price_dns_filtering_check", "0.01"),
        "dns_filtering_check",
        "/v1/dns/filtering/check",
    )


@router.post("/blocklists/check", response_model=DNSBlocklistCheckResponse)
async def dns_blocklist_check(
    request: Request, body: DNSDomainCheckRequest
) -> DNSBlocklistCheckResponse | Response:
    try:
        normalized = normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    service = _blocklist_service(request)
    if not service.is_ready():
        raise HTTPException(503, "blocklist catalog does not meet minimum coverage")
    amount = payment_price(request, "price_dns_blocklist_check", "0.003")
    async with _authorization_guard(request):
        verified = await _verify_deferred(
            request,
            amount=amount,
            description="Hyrule DNS blocklist check",
            domain=normalized,
        )
        if isinstance(verified, Response):
            return verified
        try:
            result = await service.check(body.domain)
        except BlocklistUnavailableError as exc:
            raise HTTPException(503, str(exc)) from exc
        if not await _settle_deferred(request, verified):
            raise HTTPException(402, "payment settlement failed")
        return result


@router.post("/filtering/check", response_model=DNSFilteringCheckResponse)
async def dns_filtering_check(
    request: Request, body: DNSDomainCheckRequest
) -> DNSFilteringCheckResponse | Response:
    try:
        normalized = normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not _filtering_config(request).enabled:
        raise HTTPException(503, "DNS filtering checks are disabled")
    amount = payment_price(request, "price_dns_filtering_check", "0.01")
    async with _authorization_guard(request):
        verified = await _verify_deferred(
            request,
            amount=amount,
            description="Hyrule live DNS filtering check",
            domain=normalized,
        )
        if isinstance(verified, Response):
            return verified
        service = _filtering_service(request)
        if service is None:
            raise HTTPException(503, "DNS filtering service is unavailable")
        try:
            result = await service.check(body.domain)
        except DomainNotResolvableError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not service.meets_quality_floor(result):
            raise HTTPException(
                503,
                "fewer than the required DNS filtering profiles returned conclusive evidence",
            )
        if not await _settle_deferred(request, verified):
            raise HTTPException(402, "payment settlement failed")
        return result


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
