"""Routing/path diagnostics API."""

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
    DiagnosticVantage,
    PaidEndpointQuote,
    PathPricingResponse,
    PathProbeKind,
    PathProbeRequest,
    PathReportRequest,
    PathVantagesResponse,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.diagnostics.jobs import build_job_response
from hyrule_cloud.services.path.diagnostics import path_probe, path_report

router = APIRouter(prefix="/v1/path", tags=["Path diagnostics"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_path_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="path",
        purpose="Paid routing/path diagnostics using extmon, AS215932, public BGP/RPKI, router-table snapshots, and optional Globalping/RIPE Atlas evidence.",
        separation_of_concerns="/v1/path diagnoses reachability paths; /v1/bgp diagnoses routing control-plane state; /v1/ports checks one declared service port.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/path/capabilities", method="GET", description="Path diagnostic capabilities"),
            CapabilityEndpoint(path="/v1/path/vantages", method="GET", description="Supported diagnostic vantages"),
            CapabilityEndpoint(path="/v1/path/pricing", method="GET", description="Path diagnostic pricing"),
            CapabilityEndpoint(path="/v1/path/report/quote", method="POST", description="Quote a path evidence pack"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/path/ping", method="POST", paid=True, description="Run/queue ping evidence from approved vantages"),
            CapabilityEndpoint(path="/v1/path/trace", method="POST", paid=True, description="Run/queue traceroute evidence"),
            CapabilityEndpoint(path="/v1/path/mtr", method="POST", paid=True, description="Run/queue MTR packet-loss evidence"),
            CapabilityEndpoint(path="/v1/path/asymmetry", method="POST", paid=True, description="Collect path asymmetry evidence where possible"),
            CapabilityEndpoint(path="/v1/path/report", method="POST", paid=True, description="Create synchronous path report"),
            CapabilityEndpoint(path="/v1/path/jobs", method="POST", paid=True, description="Create async path evidence-pack job"),
        ],
    )


@router.get("/vantages", response_model=PathVantagesResponse)
async def get_path_vantages() -> PathVantagesResponse:
    return PathVantagesResponse(
        vantages=[
            {"id": DiagnosticVantage.EXTMON.value, "owner": "hyrule", "role": "external neutral monitor", "status": "supported"},
            {"id": DiagnosticVantage.AS215932.value, "owner": "hyrule", "role": "AS215932 internal/router perspective", "status": "supported"},
            {"id": DiagnosticVantage.GLOBALPING.value, "owner": "third_party", "role": "public multi-vantage active probes", "status": "token_ready"},
            {"id": DiagnosticVantage.RIPE_ATLAS.value, "owner": "third_party", "role": "RIPE Atlas measurements", "status": "token_ready"},
        ]
    )


@router.get("/pricing", response_model=PathPricingResponse)
async def get_path_pricing(request: Request) -> PathPricingResponse:
    return PathPricingResponse(
        probe_usd=str(payment_price(request, "price_path_probe", "0.005")),
        report_usd=str(payment_price(request, "price_path_report", "0.05")),
    )


@router.post("/report/quote", response_model=PaidEndpointQuote)
async def quote_path_report(request: Request, body: PathReportRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_path_report", default="0.05", name="path_report", paid_endpoint="/v1/path/report")


async def _paid_probe(request: Request) -> Response | None:
    return await require_paid_diagnostic(request, price_attr="price_path_probe", default="0.005", description="Hyrule path diagnostic probe")


@router.post("/ping", response_model=DiagnosticResponse)
async def path_ping(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request):
        return payment
    body.probe = PathProbeKind.PING
    return await path_probe(body)


@router.post("/trace", response_model=DiagnosticResponse)
async def path_trace(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request):
        return payment
    body.probe = PathProbeKind.TRACE
    return await path_probe(body)


@router.post("/mtr", response_model=DiagnosticResponse)
async def path_mtr(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request):
        return payment
    body.probe = PathProbeKind.MTR
    return await path_probe(body)


@router.post("/asymmetry", response_model=DiagnosticResponse)
async def path_asymmetry(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request):
        return payment
    body.probe = PathProbeKind.ASYMMETRY
    return await path_probe(body)


@router.post("/report", response_model=DiagnosticResponse)
async def create_path_report(request: Request, body: PathReportRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_path_report", default="0.05", description="Hyrule routing/path evidence pack"):
        return payment
    return await path_report(body)


@router.post("/jobs", response_model=DiagnosticJobResponse)
async def create_path_job(request: Request, body: PathReportRequest) -> DiagnosticJobResponse | Response:
    amount = payment_price(request, "price_path_report", "0.05")
    if payment := await require_paid_diagnostic(request, price_attr="price_path_report", default="0.05", description="Hyrule async routing/path evidence pack"):
        return payment
    return build_job_response(service="path", kind=DiagnosticJobKind.PATH_REPORT, charged_amount_usd=amount)


@router.get("/jobs/{job_id}", response_model=DiagnosticJobResponse)
async def get_path_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("path.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_path_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("path.jobs.download")
