"""Contract-first RDAP and WHOIS registry lookup API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import payment_price, quote, require_payment
from hyrule_cloud.models import (
    CapabilityEndpoint,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    RDAPLookupRequest,
    RDAPLookupResponse,
    RegistryPricingResponse,
    RegistrySubject,
    RegistrySubjectType,
    WhoisLookupRequest,
    WhoisLookupResponse,
)
from hyrule_cloud.services.registry.lookup import rdap_lookup as rdap_lookup_service
from hyrule_cloud.services.registry.lookup import whois_lookup as whois_lookup_service

router = APIRouter(prefix="/v1", tags=["Registry intelligence"])


@router.get("/rdap/capabilities", response_model=ProductCapabilityResponse)
async def get_rdap_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="rdap",
        purpose="Structured registry data for domains, IPs, prefixes/network blocks, ASNs, and entities using IANA RDAP bootstrap.",
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/rdap/lookup", method="POST", paid=True, description="Canonical RDAP lookup"),
            CapabilityEndpoint(path="/v1/rdap/domain/{domain}", method="GET", paid=True, description="Domain RDAP lookup"),
            CapabilityEndpoint(path="/v1/rdap/ip/{address}", method="GET", paid=True, description="IP RDAP lookup"),
            CapabilityEndpoint(path="/v1/rdap/prefix", method="GET", paid=True, description="Prefix/network block RDAP lookup"),
            CapabilityEndpoint(path="/v1/rdap/asn/{asn}", method="GET", paid=True, description="ASN RDAP lookup"),
            CapabilityEndpoint(path="/v1/rdap/entity/{handle}", method="GET", paid=True, description="Entity RDAP lookup"),
        ],
    )


@router.get("/whois/capabilities", response_model=ProductCapabilityResponse)
async def get_whois_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="whois",
        purpose="Legacy WHOIS lookup for domains, IPs, prefixes/network blocks, and ASNs with parsed and optional raw output.",
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/whois/lookup", method="POST", paid=True, description="Canonical WHOIS lookup"),
            CapabilityEndpoint(path="/v1/whois/domain/{domain}", method="GET", paid=True, description="Domain WHOIS lookup"),
            CapabilityEndpoint(path="/v1/whois/ip/{address}", method="GET", paid=True, description="IP WHOIS lookup"),
            CapabilityEndpoint(path="/v1/whois/prefix", method="GET", paid=True, description="Prefix/network block WHOIS lookup"),
            CapabilityEndpoint(path="/v1/whois/asn/{asn}", method="GET", paid=True, description="ASN WHOIS lookup"),
        ],
    )


@router.get("/registry/pricing", response_model=RegistryPricingResponse)
async def get_registry_pricing(request: Request) -> RegistryPricingResponse:
    return RegistryPricingResponse(
        rdap_lookup_usd=str(payment_price(request, "price_rdap_lookup", "0.003")),
        whois_lookup_usd=str(payment_price(request, "price_whois_lookup", "0.005")),
    )


@router.post("/rdap/lookup/quote", response_model=PaidEndpointQuote)
async def quote_rdap_lookup(request: Request, body: RDAPLookupRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_rdap_lookup", "0.003"), "rdap_lookup", "/v1/rdap/lookup")


@router.post("/whois/lookup/quote", response_model=PaidEndpointQuote)
async def quote_whois_lookup(request: Request, body: WhoisLookupRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_whois_lookup", "0.005"), "whois_lookup", "/v1/whois/lookup")


async def _paid_rdap(request: Request) -> Response | None:
    amount = payment_price(request, "price_rdap_lookup", "0.003")
    result = await require_payment(request, amount, "Hyrule RDAP lookup")
    return result if isinstance(result, Response) else None


async def _paid_whois(request: Request) -> Response | None:
    amount = payment_price(request, "price_whois_lookup", "0.005")
    result = await require_payment(request, amount, "Hyrule WHOIS lookup")
    return result if isinstance(result, Response) else None


@router.post("/rdap/lookup", response_model=RDAPLookupResponse)
async def rdap_lookup(request: Request, body: RDAPLookupRequest) -> RDAPLookupResponse | Response:
    if payment := await _paid_rdap(request):
        return payment
    return await rdap_lookup_service(body)


@router.get("/rdap/domain/{domain}", response_model=RDAPLookupResponse)
async def rdap_domain(request: Request, domain: str) -> RDAPLookupResponse | Response:
    if payment := await _paid_rdap(request):
        return payment
    return await rdap_lookup_service(RDAPLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.DOMAIN, value=domain)))


@router.get("/rdap/ip/{address}", response_model=RDAPLookupResponse)
async def rdap_ip(request: Request, address: str) -> RDAPLookupResponse | Response:
    if payment := await _paid_rdap(request):
        return payment
    return await rdap_lookup_service(RDAPLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.IP, value=address)))


@router.get("/rdap/prefix", response_model=RDAPLookupResponse)
async def rdap_prefix(request: Request, prefix: str) -> RDAPLookupResponse | Response:
    if payment := await _paid_rdap(request):
        return payment
    return await rdap_lookup_service(RDAPLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.PREFIX, value=prefix)))


@router.get("/rdap/asn/{asn}", response_model=RDAPLookupResponse)
async def rdap_asn(request: Request, asn: int) -> RDAPLookupResponse | Response:
    if payment := await _paid_rdap(request):
        return payment
    return await rdap_lookup_service(RDAPLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.ASN, value=asn)))


@router.get("/rdap/entity/{handle}", response_model=RDAPLookupResponse)
async def rdap_entity(request: Request, handle: str) -> RDAPLookupResponse | Response:
    if payment := await _paid_rdap(request):
        return payment
    return await rdap_lookup_service(RDAPLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.ENTITY, value=handle)))


@router.post("/whois/lookup", response_model=WhoisLookupResponse)
async def whois_lookup(request: Request, body: WhoisLookupRequest) -> WhoisLookupResponse | Response:
    if payment := await _paid_whois(request):
        return payment
    return await whois_lookup_service(body)


@router.get("/whois/domain/{domain}", response_model=WhoisLookupResponse)
async def whois_domain(request: Request, domain: str) -> WhoisLookupResponse | Response:
    if payment := await _paid_whois(request):
        return payment
    return await whois_lookup_service(WhoisLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.DOMAIN, value=domain)))


@router.get("/whois/ip/{address}", response_model=WhoisLookupResponse)
async def whois_ip(request: Request, address: str) -> WhoisLookupResponse | Response:
    if payment := await _paid_whois(request):
        return payment
    return await whois_lookup_service(WhoisLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.IP, value=address)))


@router.get("/whois/prefix", response_model=WhoisLookupResponse)
async def whois_prefix(request: Request, prefix: str) -> WhoisLookupResponse | Response:
    if payment := await _paid_whois(request):
        return payment
    return await whois_lookup_service(WhoisLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.PREFIX, value=prefix)))


@router.get("/whois/asn/{asn}", response_model=WhoisLookupResponse)
async def whois_asn(request: Request, asn: int) -> WhoisLookupResponse | Response:
    if payment := await _paid_whois(request):
        return payment
    return await whois_lookup_service(WhoisLookupRequest(subject=RegistrySubject(type=RegistrySubjectType.ASN, value=asn)))
