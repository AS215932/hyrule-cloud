"""Free, short-lived network observations for autonomous agents and browsers."""

from __future__ import annotations

import ipaddress
from typing import cast

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.api._contract import config_from_request, not_implemented
from hyrule_cloud.models import (
    IPCheckAgentFingerprintReport,
    IPCheckAgentFingerprintRequest,
    IPCheckBrowserFingerprintReport,
    IPCheckBrowserFingerprintRequest,
    IPCheckBrowserObservationRequest,
    IPCheckDNSObservationRequest,
    IPCheckHTTPSObservationResponse,
    IPCheckNetworkObservationRequest,
    IPCheckSessionCreateRequest,
    IPCheckSessionCreateResponse,
    IPCheckSessionReport,
)
from hyrule_cloud.services.ip_check import (
    IPCheckSessionNotFoundError,
    create_ip_check_session,
    get_ip_check_report,
    ip_check_ready,
    observe_agent_fingerprint,
    observe_browser_candidates,
    observe_browser_fingerprint,
    observe_dns_resolver,
    observe_https_address,
    observe_network_addresses,
    verify_dns_observer_signature,
)

router = APIRouter(prefix="/v1/ip-check", tags=["Network environment check"])
internal_router = APIRouter(prefix="/v1/internal/ip-check", tags=["Internal IP check"])


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession] | None:
    state = getattr(request.app.state, "_typed_state", None)
    factory = getattr(state, "session_factory", None)
    return cast(async_sessionmaker[AsyncSession] | None, factory)


def _readiness_refusal(request: Request) -> Response | None:
    if ip_check_ready(config_from_request(request).ip_check):
        return None
    return not_implemented(
        "ip_check",
        "Network checks are disabled until the dual-stack, DNS-observer, and STUN canaries are ready.",
    )


def _bearer(request: Request) -> str | None:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not value or len(value) > 128:
        return None
    return value


def _missing_session() -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "ip_check_session_not_found"})


@router.post("/sessions", response_model=IPCheckSessionCreateResponse)
async def create_session(
    request: Request,
    body: IPCheckSessionCreateRequest,
) -> IPCheckSessionCreateResponse | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    factory = _session_factory(request)
    if factory is None:
        return JSONResponse(status_code=503, content={"error": "session_store_unavailable"})
    config = config_from_request(request).ip_check
    return await create_ip_check_session(factory, config, body)


@router.post(
    "/sessions/{session_id}/observe/http",
    response_model=IPCheckHTTPSObservationResponse,
)
async def observe_http(
    request: Request,
    session_id: str,
) -> IPCheckHTTPSObservationResponse | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    token = _bearer(request)
    if token is None:
        return _missing_session()
    factory = _session_factory(request)
    if factory is None:
        return JSONResponse(status_code=503, content={"error": "session_store_unavailable"})
    client_host = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(client_host)
    except ValueError:
        return JSONResponse(status_code=503, content={"error": "observer_address_unavailable"})
    if not address.is_global:
        return JSONResponse(status_code=503, content={"error": "observer_proxy_misconfigured"})
    host = (request.url.hostname or "").lower()
    if host == "v4.check.hyrule.host" and address.version != 4:
        return JSONResponse(status_code=409, content={"error": "ipv4_probe_family_mismatch"})
    if host == "v6.check.hyrule.host" and address.version != 6:
        return JSONResponse(status_code=409, content={"error": "ipv6_probe_family_mismatch"})
    try:
        return await observe_https_address(
            factory,
            session_id=session_id,
            token=token,
            address=str(address),
        )
    except IPCheckSessionNotFoundError:
        return _missing_session()


@router.post("/sessions/{session_id}/observe/browser", response_model=IPCheckSessionReport)
async def observe_browser(
    request: Request,
    session_id: str,
    body: IPCheckBrowserObservationRequest,
) -> IPCheckSessionReport | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    token = _bearer(request)
    factory = _session_factory(request)
    if token is None or factory is None:
        return _missing_session()
    config = config_from_request(request).ip_check
    try:
        await observe_browser_candidates(
            factory,
            session_id=session_id,
            token=token,
            observation=body,
        )
        return await get_ip_check_report(
            factory,
            config,
            session_id=session_id,
            token=token,
        )
    except IPCheckSessionNotFoundError:
        return _missing_session()


@router.post("/sessions/{session_id}/observe/network", response_model=IPCheckSessionReport)
async def observe_network(
    request: Request,
    session_id: str,
    body: IPCheckNetworkObservationRequest,
) -> IPCheckSessionReport | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    token = _bearer(request)
    factory = _session_factory(request)
    if token is None:
        return _missing_session()
    if factory is None:
        return JSONResponse(status_code=503, content={"error": "session_store_unavailable"})
    config = config_from_request(request).ip_check
    try:
        await observe_network_addresses(
            factory,
            session_id=session_id,
            token=token,
            observation=body,
        )
        return await get_ip_check_report(
            factory,
            config,
            session_id=session_id,
            token=token,
        )
    except IPCheckSessionNotFoundError:
        return _missing_session()


@router.post(
    "/sessions/{session_id}/fingerprints/browser",
    response_model=IPCheckBrowserFingerprintReport,
)
async def browser_fingerprint(
    request: Request,
    session_id: str,
    body: IPCheckBrowserFingerprintRequest,
) -> IPCheckBrowserFingerprintReport | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    token = _bearer(request)
    factory = _session_factory(request)
    if token is None:
        return _missing_session()
    if factory is None:
        return JSONResponse(status_code=503, content={"error": "session_store_unavailable"})
    try:
        return await observe_browser_fingerprint(
            factory,
            session_id=session_id,
            token=token,
            observation=body,
            observed_headers={
                "user_agent": request.headers.get("user-agent"),
                "accept_language": request.headers.get("accept-language"),
                "sec_ch_ua": request.headers.get("sec-ch-ua"),
                "sec_ch_ua_platform": request.headers.get("sec-ch-ua-platform"),
                "tls_ja4": request.headers.get("x-hyrule-observed-tls-ja4"),
            },
        )
    except IPCheckSessionNotFoundError:
        return _missing_session()


@router.post(
    "/sessions/{session_id}/fingerprints/agent",
    response_model=IPCheckAgentFingerprintReport,
)
async def agent_fingerprint(
    request: Request,
    session_id: str,
    body: IPCheckAgentFingerprintRequest,
) -> IPCheckAgentFingerprintReport | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    token = _bearer(request)
    factory = _session_factory(request)
    if token is None:
        return _missing_session()
    if factory is None:
        return JSONResponse(status_code=503, content={"error": "session_store_unavailable"})
    try:
        return await observe_agent_fingerprint(
            factory,
            session_id=session_id,
            token=token,
            observation=body,
        )
    except IPCheckSessionNotFoundError:
        return _missing_session()


@router.get("/sessions/{session_id}", response_model=IPCheckSessionReport)
async def session_report(request: Request, session_id: str) -> IPCheckSessionReport | Response:
    if refusal := _readiness_refusal(request):
        return refusal
    token = _bearer(request)
    factory = _session_factory(request)
    if token is None or factory is None:
        return _missing_session()
    try:
        return await get_ip_check_report(
            factory,
            config_from_request(request).ip_check,
            session_id=session_id,
            token=token,
        )
    except IPCheckSessionNotFoundError:
        return _missing_session()


@internal_router.post("/dns-observations", status_code=202)
async def dns_observation(
    request: Request,
    body: IPCheckDNSObservationRequest,
) -> Response:
    config = config_from_request(request).ip_check
    if not ip_check_ready(config):
        return JSONResponse(status_code=404, content={"error": "not_found"})
    raw_body = await request.body()
    if not verify_dns_observer_signature(
        config,
        timestamp=request.headers.get("x-hyrule-timestamp", ""),
        signature=request.headers.get("x-hyrule-signature", ""),
        body=raw_body,
    ):
        return JSONResponse(status_code=401, content={"error": "invalid_observer_signature"})
    factory = _session_factory(request)
    if factory is None:
        return JSONResponse(status_code=503, content={"error": "session_store_unavailable"})
    accepted = await observe_dns_resolver(factory, body)
    if not accepted:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    return Response(status_code=202)
