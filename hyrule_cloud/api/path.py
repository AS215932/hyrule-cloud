"""Routing/path diagnostics API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from hyrule_cloud.api._contract import (
    diagnostic_quote,
    not_implemented,
    payment_price,
)
from hyrule_cloud.models import (
    PATH_PROBE_DEFAULT_VANTAGES,
    PATH_REPORT_DEFAULT_VANTAGES,
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
from hyrule_cloud.providers.prober_client import (
    ProbeRejectedError,
    ProberProvider,
    ProbeUnavailableError,
)
from hyrule_cloud.services.path.diagnostics import (
    path_active_probe_enabled,
    path_probe,
    path_report,
)
from hyrule_cloud.state import AppState

router = APIRouter(prefix="/v1/path", tags=["Path diagnostics"])


def _typed_state(request: Request) -> AppState | None:
    return getattr(request.app.state, "_typed_state", None)


def _prober(request: Request) -> ProberProvider | None:
    return getattr(_typed_state(request), "prober_provider", None)


async def _charge_then_deliver(
    request: Request,
    *,
    price_attr: str,
    default: str,
    description: str,
    deliver: Callable[[], Awaitable[DiagnosticResponse]],
) -> DiagnosticResponse | Response:
    """Deliver-then-settle: verify the payment, run the measurement, and settle
    only if the prober actually produced evidence. A prober outage (or a target
    that resolves to nothing) never moves the customer's money."""
    state = _typed_state(request)
    gate = getattr(state, "payment_gate", None)
    amount = payment_price(request, price_attr, default)
    if gate is None:
        # App state not wired (tests / OpenAPI import): closed, never free.
        return JSONResponse(
            status_code=402,
            content={"payment_required": True, "amount": str(amount), "description": description},
        )
    verified = await gate.verify_only(request, amount, description=description)
    if isinstance(verified, Response):
        return verified
    try:
        result = await deliver()
    except ProbeRejectedError as exc:
        # Prober defense-in-depth rejected the target as unsafe/invalid.
        raise HTTPException(400, str(exc)) from exc
    except ProbeUnavailableError as exc:
        # Never delivered a measurement — do not settle.
        raise HTTPException(502, str(exc)) from exc
    if not await gate.settle_verified(request, verified):
        raise HTTPException(402, "payment settlement failed")
    return result


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_path_capabilities() -> ProductCapabilityResponse:
    # Advertise each paid path endpoint only when ITS default request would
    # actually probe. Mirror the manifest's per-endpoint gate so capabilities
    # never list a route whose default request 501s.
    probe_enabled = path_active_probe_enabled(PATH_PROBE_DEFAULT_VANTAGES)
    report_enabled = path_active_probe_enabled(PATH_REPORT_DEFAULT_VANTAGES)
    _free_endpoints = [
        CapabilityEndpoint(path="/v1/path/capabilities", method="GET", description="Path diagnostic capabilities"),
        CapabilityEndpoint(path="/v1/path/vantages", method="GET", description="Supported diagnostic vantages"),
        CapabilityEndpoint(path="/v1/path/pricing", method="GET", description="Path diagnostic pricing"),
    ]
    _paid_endpoints: list[CapabilityEndpoint] = []
    if probe_enabled:
        # Only ping and traceroute are truly delivered by the prober. MTR
        # (per-hop loss) and reverse-path asymmetry have no honest backend yet,
        # so they are not advertised and 501 before charging.
        _paid_endpoints.extend([
            CapabilityEndpoint(path="/v1/path/ping", method="POST", paid=True, description="Ping reachability (loss/RTT) from AS215932 vantages"),
            CapabilityEndpoint(path="/v1/path/trace", method="POST", paid=True, description="Traceroute path from AS215932 vantages"),
        ])
    if report_enabled:
        _free_endpoints.append(
            CapabilityEndpoint(path="/v1/path/report/quote", method="POST", description="Quote a path evidence pack")
        )
        _paid_endpoints.append(
            CapabilityEndpoint(path="/v1/path/report", method="POST", paid=True, description="Create synchronous path report (ping + traceroute + classification)")
        )
    return ProductCapabilityResponse(
        service="path",
        purpose="Paid routing/path diagnostics: ping and traceroute evidence from AS215932 vantages, with control-plane context from /v1/bgp and router-table snapshots.",
        separation_of_concerns="/v1/path diagnoses reachability paths; /v1/bgp diagnoses routing control-plane state; /v1/ports checks one declared service port.",
        free_endpoints=_free_endpoints,
        paid_endpoints=_paid_endpoints,
    )


@router.get("/vantages", response_model=PathVantagesResponse)
async def get_path_vantages() -> PathVantagesResponse:
    prober_up = path_active_probe_enabled([DiagnosticVantage.AS215932])
    prober_status = "supported" if prober_up else "not_configured"
    return PathVantagesResponse(
        vantages=[
            {"id": DiagnosticVantage.EXTMON.value, "owner": "hyrule", "role": "external neutral monitor", "status": prober_status},
            {"id": DiagnosticVantage.AS215932.value, "owner": "hyrule", "role": "AS215932 internal/router perspective", "status": prober_status},
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


async def _run_probe(request: Request, body: PathProbeRequest, kind: PathProbeKind) -> DiagnosticResponse | Response:
    if not path_active_probe_enabled(body.vantages):
        return not_implemented("path.probe")
    body.probe = kind
    return await _charge_then_deliver(
        request,
        price_attr="price_path_probe",
        default="0.005",
        description=f"Hyrule path {kind.value} probe",
        deliver=lambda: path_probe(body, _prober(request)),
    )


@router.post("/ping", response_model=DiagnosticResponse)
async def path_ping(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    return await _run_probe(request, body, PathProbeKind.PING)


@router.post("/trace", response_model=DiagnosticResponse)
async def path_trace(request: Request, body: PathProbeRequest) -> DiagnosticResponse | Response:
    return await _run_probe(request, body, PathProbeKind.TRACE)


@router.post("/mtr", response_model=DiagnosticResponse)
async def path_mtr(request: Request, body: PathProbeRequest) -> Response:
    # Per-hop packet loss (MTR) needs many probes per hop; the prober does not
    # collect it. Refuse before charging rather than relabel a traceroute.
    return not_implemented("path.mtr", "Per-hop MTR loss is not collected; use /v1/path/ping and /v1/path/trace.")


@router.post("/asymmetry", response_model=DiagnosticResponse)
async def path_asymmetry(request: Request, body: PathProbeRequest) -> Response:
    # Reverse-path evidence requires a probe originating at the target; not
    # available without a RIPE Atlas / reverse-traceroute source.
    return not_implemented("path.asymmetry", "Reverse-path asymmetry evidence is not available; only forward traceroute is offered via /v1/path/trace.")


@router.post("/report", response_model=DiagnosticResponse)
async def create_path_report(request: Request, body: PathReportRequest) -> DiagnosticResponse | Response:
    # The evidence pack is inconclusive without active-probe vantages; refuse
    # before charging until one of the requested vantages is configured.
    if not path_active_probe_enabled(body.vantages):
        return not_implemented("path.report")
    return await _charge_then_deliver(
        request,
        price_attr="price_path_report",
        default="0.05",
        description="Hyrule routing/path evidence pack",
        deliver=lambda: path_report(body, _prober(request)),
    )


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
