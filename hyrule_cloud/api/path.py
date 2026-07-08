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
from hyrule_cloud.services.path.diagnostics import (
    path_active_probe_enabled,
    path_probe,
    path_report,
)

router = APIRouter(prefix="/v1/path", tags=["Path diagnostics"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_path_capabilities() -> ProductCapabilityResponse:
    # Advertise each paid path endpoint only when ITS default request would
    # actually probe. The ping-family defaults to [extmon] (never an active
    # vantage) so its default body 501s even with a prober configured, while
    # /v1/path/report defaults to a set that includes globalping. Mirror the
    # manifest's per-endpoint gate so capabilities never list a route whose
    # default request 501s.
    probe_enabled = path_active_probe_enabled(
        PathProbeRequest.model_fields["vantages"].default_factory()
    )
    report_enabled = path_active_probe_enabled(
        PathReportRequest.model_fields["vantages"].default_factory()
    )
    _free_endpoints = [
        CapabilityEndpoint(path="/v1/path/capabilities", method="GET", description="Path diagnostic capabilities"),
        CapabilityEndpoint(path="/v1/path/vantages", method="GET", description="Supported diagnostic vantages"),
        CapabilityEndpoint(path="/v1/path/pricing", method="GET", description="Path diagnostic pricing"),
    ]
    _paid_endpoints: list[CapabilityEndpoint] = []
    if probe_enabled:
        _paid_endpoints.extend([
            CapabilityEndpoint(path="/v1/path/ping", method="POST", paid=True, description="Run/queue ping evidence from approved vantages"),
            CapabilityEndpoint(path="/v1/path/trace", method="POST", paid=True, description="Run/queue traceroute evidence"),
            CapabilityEndpoint(path="/v1/path/mtr", method="POST", paid=True, description="Run/queue MTR packet-loss evidence"),
            CapabilityEndpoint(path="/v1/path/asymmetry", method="POST", paid=True, description="Collect path asymmetry evidence where possible"),
        ])
    if report_enabled:
        _free_endpoints.append(
            CapabilityEndpoint(path="/v1/path/report/quote", method="POST", description="Quote a path evidence pack")
        )
        _paid_endpoints.append(
            CapabilityEndpoint(path="/v1/path/report", method="POST", paid=True, description="Create synchronous path report")
        )
    return ProductCapabilityResponse(
        service="path",
        purpose="Paid routing/path diagnostics using extmon, AS215932, public BGP/RPKI, router-table snapshots, and optional Globalping/RIPE Atlas evidence.",
        separation_of_concerns="/v1/path diagnoses reachability paths; /v1/bgp diagnoses routing control-plane state; /v1/ports checks one declared service port.",
        free_endpoints=_free_endpoints,
        paid_endpoints=_paid_endpoints,
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
async def quote_path_report(request: Request, body: PathReportRequest) -> PaidEndpointQuote | Response:
    # Don't hand out a payable quote for a diagnostic that will 501 on execute.
    if not path_active_probe_enabled(body.vantages):
        return not_implemented("path.report")
    return diagnostic_quote(request, price_attr="price_path_report", default="0.05", name="path_report", paid_endpoint="/v1/path/report")


async def _paid_probe(request: Request, vantages: list[DiagnosticVantage]) -> Response | None:
    # No active-probe vantage among the requested set is configured, so a probe
    # would only return a "probe accepted" acknowledgement with no reachability
    # data. Refuse before charging until Globalping/RIPE Atlas is wired up.
    if not path_active_probe_enabled(vantages):
        return not_implemented("path.probe")
    return await require_paid_diagnostic(request, price_attr="price_path_probe", default="0.005", description="Hyrule path diagnostic probe")


@router.post("/ping", response_model=DiagnosticResponse)
async def path_ping(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request, body.vantages):
        return payment
    body.probe = PathProbeKind.PING
    return await path_probe(body)


@router.post("/trace", response_model=DiagnosticResponse)
async def path_trace(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request, body.vantages):
        return payment
    body.probe = PathProbeKind.TRACE
    return await path_probe(body)


@router.post("/mtr", response_model=DiagnosticResponse)
async def path_mtr(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request, body.vantages):
        return payment
    body.probe = PathProbeKind.MTR
    return await path_probe(body)


@router.post("/asymmetry", response_model=DiagnosticResponse)
async def path_asymmetry(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    if payment := await _paid_probe(request, body.vantages):
        return payment
    body.probe = PathProbeKind.ASYMMETRY
    return await path_probe(body)


@router.post("/report", response_model=DiagnosticResponse)
async def create_path_report(request: Request, body: PathReportRequest) -> DiagnosticResponse | Response:
    # The evidence pack is inconclusive without active-probe vantages; refuse
    # before charging until one of the requested vantages is configured.
    if not path_active_probe_enabled(body.vantages):
        return not_implemented("path.report")
    if payment := await require_paid_diagnostic(request, price_attr="price_path_report", default="0.05", description="Hyrule routing/path evidence pack"):
        return payment
    return await path_report(body)


@router.post("/jobs", response_model=DiagnosticJobResponse)
async def create_path_job(request: Request, body: PathReportRequest) -> DiagnosticJobResponse | Response:
    # Async report jobs have no retrieval backend yet: refuse before charging.
    # Use POST /v1/path/report for the synchronous evidence pack.
    return not_implemented("path.jobs.create")


@router.get("/jobs/{job_id}", response_model=DiagnosticJobResponse)
async def get_path_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("path.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_path_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("path.jobs.download")
