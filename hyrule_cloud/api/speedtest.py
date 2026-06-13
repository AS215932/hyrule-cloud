"""Hyrule/AS215932 speedtest diagnostics API."""

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
    DiagnosticJobKind,
    DiagnosticJobResponse,
    DiagnosticResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    SpeedtestPricingResponse,
    SpeedtestRequest,
)
from hyrule_cloud.services.diagnostics.jobs import build_job_response
from hyrule_cloud.services.speedtest import speedtest_contract

router = APIRouter(prefix="/v1/speedtest", tags=["Speedtest"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_speedtest_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="speedtest",
        purpose="Paid throughput, latency, jitter, and path evidence to Hyrule/AS215932 endpoints.",
        separation_of_concerns="/v1/speedtest measures client-to-Hyrule throughput; /v1/path diagnoses routing/packet-loss evidence.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/speedtest/capabilities", method="GET", description="Speedtest capabilities"),
            CapabilityEndpoint(path="/v1/speedtest/pricing", method="GET", description="Speedtest pricing"),
            CapabilityEndpoint(path="/v1/speedtest/quote", method="POST", description="Quote a speedtest evidence pack"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/speedtest", method="POST", paid=True, description="Create/return speedtest evidence contract"),
            CapabilityEndpoint(path="/v1/speedtest/jobs", method="POST", paid=True, description="Create async speedtest job"),
            CapabilityEndpoint(path="/v1/speedtest/jobs/{job_id}", method="GET", paid=True, description="Fetch speedtest job status/results"),
        ],
    )


@router.get("/pricing", response_model=SpeedtestPricingResponse)
async def get_speedtest_pricing(request: Request) -> SpeedtestPricingResponse:
    return SpeedtestPricingResponse(test_usd=str(payment_price(request, "price_speedtest", "0.10")))


@router.post("/quote", response_model=PaidEndpointQuote)
async def quote_speedtest(request: Request, body: SpeedtestRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_speedtest", default="0.10", name="speedtest", paid_endpoint="/v1/speedtest")


@router.post("", response_model=DiagnosticResponse)
async def create_speedtest(request: Request, body: SpeedtestRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_speedtest", default="0.10", description="Hyrule/AS215932 speedtest evidence pack"):
        return payment
    return speedtest_contract(body)


@router.post("/jobs", response_model=DiagnosticJobResponse)
async def create_speedtest_job(request: Request, body: SpeedtestRequest) -> DiagnosticJobResponse | Response:
    amount = payment_price(request, "price_speedtest", "0.10")
    if payment := await require_paid_diagnostic(request, price_attr="price_speedtest", default="0.10", description="Hyrule async speedtest evidence pack"):
        return payment
    return build_job_response(service="speedtest", kind=DiagnosticJobKind.SPEEDTEST, charged_amount_usd=amount)


@router.get("/jobs/{job_id}", response_model=DiagnosticJobResponse)
async def get_speedtest_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("speedtest.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_speedtest_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("speedtest.jobs.download")
