"""Server-only NAT/CGNAT diagnostic API."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import diagnostic_quote, payment_price, require_paid_diagnostic
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DiagnosticResponse,
    NATIPResponse,
    NATPortForwardCheckRequest,
    NATPricingResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.nat import classify_address
from hyrule_cloud.services.ports.checks import run_port_check

router = APIRouter(prefix="/v1/nat", tags=["NAT/CGNAT"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_nat_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="nat",
        purpose="Free server-observed public IP with CGNAT/scope classification, plus paid outside-in port-forward reachability. Browser/WebRTC/STUN NAT typing is deferred.",
        separation_of_concerns="/v1/nat reports what this server observes about the caller; /v1/ports performs outside-in service reachability.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/nat/ip", method="GET", description="Return caller-observed public IP, CGNAT/scope classification, and selected headers"),
            CapabilityEndpoint(path="/v1/nat/capabilities", method="GET", description="NAT diagnostic capabilities"),
            CapabilityEndpoint(path="/v1/nat/pricing", method="GET", description="NAT diagnostic pricing"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/nat/port-forward/check", method="POST", paid=True, description="Check a declared port-forward from outside"),
        ],
    )


@router.get("/ip", response_model=NATIPResponse)
async def nat_ip(request: Request) -> NATIPResponse:
    client_host = request.client.host if request.client else "0.0.0.0"
    headers = {key.lower(): value for key, value in request.headers.items()}
    ip_version = ipaddress.ip_address(client_host).version
    classification, cgnat_likely = classify_address(client_host)
    return NATIPResponse(
        ip=client_host,
        ip_version=ip_version,
        classification=classification,
        cgnat_likely=cgnat_likely,
        headers_seen={
            "x_forwarded_for": headers.get("x-forwarded-for"),
            "x_real_ip": headers.get("x-real-ip"),
            "cf_connecting_ip": headers.get("cf-connecting-ip"),
        },
    )


@router.get("/pricing", response_model=NATPricingResponse)
async def get_nat_pricing(request: Request) -> NATPricingResponse:
    return NATPricingResponse(
        port_forward_check_usd=str(payment_price(request, "price_nat_port_forward_check", "0.005")),
    )


@router.post("/port-forward/check/quote", response_model=PaidEndpointQuote)
async def quote_nat_port_forward(request: Request, body: NATPortForwardCheckRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_nat_port_forward_check", default="0.005", name="nat_port_forward_check", paid_endpoint="/v1/nat/port-forward/check")


@router.post("/port-forward/check", response_model=DiagnosticResponse)
async def nat_port_forward_check(request: Request, body: NATPortForwardCheckRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_nat_port_forward_check", default="0.005", description="Hyrule NAT port-forward outside-in check"):
        return payment
    return await run_port_check(body)
