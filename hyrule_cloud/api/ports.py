"""Outside-in single-service port reachability API."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import diagnostic_quote, payment_price, require_paid_diagnostic
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DiagnosticResponse,
    PaidEndpointQuote,
    PortAllowedResponse,
    PortCheckRequest,
    PortPricingResponse,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.ports.checks import run_port_check
from hyrule_cloud.services.safety import allowed_tcp_ports

router = APIRouter(prefix="/v1/ports", tags=["Port reachability"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_ports_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="ports",
        purpose="Paid outside-in reachability for one declared public TCP/UDP service. This is not a general port scanner.",
        separation_of_concerns="/v1/ports checks one declared service; /v1/web diagnoses HTTP/TLS; /v1/path diagnoses network paths.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/ports/capabilities", method="GET", description="Port diagnostic capabilities"),
            CapabilityEndpoint(path="/v1/ports/allowed", method="GET", description="Allowed public diagnostic ports"),
            CapabilityEndpoint(path="/v1/ports/pricing", method="GET", description="Port diagnostic pricing"),
            CapabilityEndpoint(path="/v1/ports/check/quote", method="POST", description="Quote one service check"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/ports/check", method="POST", paid=True, description="Run one declared service reachability check"),
        ],
    )


@router.get("/allowed", response_model=PortAllowedResponse)
async def get_allowed_ports() -> PortAllowedResponse:
    return PortAllowedResponse(tcp_ports=allowed_tcp_ports())


@router.get("/pricing", response_model=PortPricingResponse)
async def get_ports_pricing(request: Request) -> PortPricingResponse:
    return PortPricingResponse(check_usd=str(payment_price(request, "price_port_check", "0.003")))


@router.post("/check/quote", response_model=PaidEndpointQuote)
async def quote_port_check(request: Request, body: PortCheckRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_port_check", default="0.003", name="port_check", paid_endpoint="/v1/ports/check")


@router.post("/check", response_model=DiagnosticResponse)
async def port_check(request: Request, body: PortCheckRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_port_check", default="0.003", description="Hyrule outside-in port reachability check"):
        return payment
    return await run_port_check(body)
