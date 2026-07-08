"""Hyrule/AS215932 speedtest diagnostics API."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import (
    not_implemented,
    payment_price,
)
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DiagnosticJobResponse,
    DiagnosticResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    SpeedtestPricingResponse,
    SpeedtestRequest,
)

router = APIRouter(prefix="/v1/speedtest", tags=["Speedtest"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_speedtest_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="speedtest",
        purpose="Throughput, latency, jitter, and path evidence to Hyrule/AS215932 endpoints. Not yet purchasable: the measurement backend is under construction.",
        separation_of_concerns="/v1/speedtest measures client-to-Hyrule throughput; /v1/path diagnoses routing/packet-loss evidence.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/speedtest/capabilities", method="GET", description="Speedtest capabilities"),
            CapabilityEndpoint(path="/v1/speedtest/pricing", method="GET", description="Speedtest pricing"),
        ],
        paid_endpoints=[],
    )


@router.get("/pricing", response_model=SpeedtestPricingResponse)
async def get_speedtest_pricing(request: Request) -> SpeedtestPricingResponse:
    return SpeedtestPricingResponse(test_usd=str(payment_price(request, "price_speedtest", "0.10")))


@router.post("/quote", response_model=PaidEndpointQuote)
async def quote_speedtest(request: Request, body: SpeedtestRequest) -> Response:
    # The paid endpoint this quotes is 501 while the measurement backend is
    # unbuilt; a payable-looking quote for it would send agents into a dead end.
    return not_implemented("speedtest.quote")


@router.post("", response_model=DiagnosticResponse)
async def create_speedtest(request: Request, body: SpeedtestRequest) -> DiagnosticResponse | Response:
    # The payload/upload endpoints the contract references are not routed yet:
    # refuse before charging.
    return not_implemented("speedtest.create")


@router.post("/jobs", response_model=DiagnosticJobResponse)
async def create_speedtest_job(request: Request, body: SpeedtestRequest) -> DiagnosticJobResponse | Response:
    # Async report jobs have no retrieval backend yet: refuse before charging.
    return not_implemented("speedtest.jobs.create")


@router.get("/jobs/{job_id}", response_model=DiagnosticJobResponse)
async def get_speedtest_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("speedtest.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_speedtest_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("speedtest.jobs.download")
