"""Contract-first BGP/routing intelligence API routes."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import select

from hyrule_cloud.api._contract import (
    not_implemented,
    now_utc,
    payment_price,
    quote,
    require_payment,
)
from hyrule_cloud.db import BGPJobRow, BGPSnapshotRow
from hyrule_cloud.models import (
    BGPDataset,
    BGPJobResponse,
    BGPJobStatus,
    BGPLookupRequest,
    BGPLookupResponse,
    BGPPricingResponse,
    BGPSnapshotListResponse,
    BGPSnapshotSummary,
    BGPSourcesResponse,
    BGPStatusResponse,
    BGPStreamJobRequest,
    CapabilityEndpoint,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    SourceHealth,
)
from hyrule_cloud.services.bgp.lookup import as215932_status, lookup_bgp
from hyrule_cloud.services.bgp.stream import bgpstream_worker_enabled

router = APIRouter(prefix="/v1/bgp", tags=["BGP intelligence"])


def _state(request: Request) -> Any | None:
    return getattr(request.app.state, "_typed_state", None)


def _session_factory(request: Request) -> Any | None:
    return getattr(_state(request), "session_factory", None)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.get("/status", response_model=BGPStatusResponse)
async def get_bgp_status() -> BGPStatusResponse:
    """Free Hyrule/AS215932 BGP status.

    This endpoint is intentionally scoped to Hyrule's own monitored network.
    Arbitrary prefix/IP/ASN investigation belongs to /v1/bgp/lookup.
    """
    return await as215932_status()


@router.get("/sources", response_model=BGPSourcesResponse)
async def get_bgp_sources() -> BGPSourcesResponse:
    sources = {
        name: SourceHealth(status="not_configured")
        for name in [
            "ripestat",
            "cloudflare_radar",
            "bgp_tools",
            "peeringdb",
            "routinator",
            "bgpalerter",
            "bgpstream",
            "as215932_router_tables",
        ]
    }
    return BGPSourcesResponse(sources=sources, updated_at=now_utc())


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_bgp_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="bgp",
        purpose="BGP/routing intelligence for AS215932 status, public routing lookup, RPKI, BGPStream jobs, and router snapshots.",
        separation_of_concerns="Use /v1/dns for DNS, /v1/ip for IP intelligence, and /v1/mx for mail diagnostics.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/bgp/status", method="GET", description="AS215932 monitored BGP status"),
            CapabilityEndpoint(path="/v1/bgp/sources", method="GET", description="BGP data source health"),
            CapabilityEndpoint(path="/v1/bgp/pricing", method="GET", description="BGP product pricing"),
            CapabilityEndpoint(path="/v1/bgp/lookup/quote", method="POST", description="Quote a synchronous BGP lookup"),
            CapabilityEndpoint(path="/v1/bgp/snapshots/router", method="GET", description="List AS215932 router snapshot metadata"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/bgp/lookup", method="POST", paid=True, description="Lookup by prefix, IP, or ASN; prefix/IP do not require ASN input"),
            # Don't advertise BGPStream jobs while no processing worker is
            # deployed — creation 501s before charging. Mirrors the threat/voip
            # gated-capabilities pattern.
            *(
                [CapabilityEndpoint(path="/v1/bgp/jobs", method="POST", paid=True, description="Create historical BGPStream job")]
                if bgpstream_worker_enabled()
                else []
            ),
            CapabilityEndpoint(path="/v1/bgp/snapshots/router/{snapshot_id}/download", method="GET", paid=True, description="Download paid router table snapshot"),
        ],
    )


@router.get("/pricing", response_model=BGPPricingResponse)
async def get_bgp_pricing(request: Request) -> BGPPricingResponse:
    return BGPPricingResponse(
        public_latest_lookup_usd=str(payment_price(request, "price_bgp_lookup", "0.005")),
        router_table_lookup_usd=str(payment_price(request, "price_bgp_router_query", "0.01")),
        bgpstream_update_hour_usd=str(payment_price(request, "price_bgpstream_hour", "0.05")),
        bgpstream_rib_usd=str(payment_price(request, "price_bgpstream_rib", "0.10")),
        router_snapshot_download_usd=str(payment_price(request, "price_bgp_router_table", "0.10")),
        router_snapshot_bundle_usd=str(payment_price(request, "price_bgp_router_table_all", "0.25")),
    )


@router.post("/lookup/quote", response_model=PaidEndpointQuote)
async def quote_bgp_lookup(request: Request, body: BGPLookupRequest) -> PaidEndpointQuote:
    price_attr = "price_bgp_router_query" if BGPDataset.AS215932_ROUTER_TABLES in body.datasets else "price_bgp_lookup"
    default = "0.01" if price_attr == "price_bgp_router_query" else "0.005"
    return quote(payment_price(request, price_attr, default), "bgp_lookup", "/v1/bgp/lookup")


@router.get("/snapshots/router", response_model=BGPSnapshotListResponse)
async def list_bgp_router_snapshots(request: Request) -> BGPSnapshotListResponse:
    factory = _session_factory(request)
    if factory is None:
        return BGPSnapshotListResponse()
    async with factory() as session:
        rows = (
            await session.execute(
                select(BGPSnapshotRow)
                .where(BGPSnapshotRow.kind == "router_table")
                .order_by(BGPSnapshotRow.created_at.desc())
                .limit(100)
            )
        ).scalars().all()
    return BGPSnapshotListResponse(
        snapshots=[
            BGPSnapshotSummary(
                snapshot_id=row.snapshot_id,
                kind=row.kind,
                router=row.router,
                created_at=row.created_at,
                expires_at=row.expires_at,
                formats=[row.artifact_format or "normalized_jsonl.gz"],
                size_bytes=row.compressed_size_bytes,
                sha256=row.sha256,
            )
            for row in rows
        ]
    )


async def _paid_lookup(request: Request, body: BGPLookupRequest | None = None) -> Response | None:
    router_query = body is not None and BGPDataset.AS215932_ROUTER_TABLES in body.datasets
    attr = "price_bgp_router_query" if router_query else "price_bgp_lookup"
    default = "0.01" if router_query else "0.005"
    amount = payment_price(request, attr, default)
    result = await require_payment(request, amount, "Hyrule BGP/routing lookup")
    return result if isinstance(result, Response) else None


@router.post("/lookup", response_model=BGPLookupResponse)
async def bgp_lookup(request: Request, body: BGPLookupRequest) -> BGPLookupResponse | Response:
    amount = payment_price(
        request,
        "price_bgp_router_query" if BGPDataset.AS215932_ROUTER_TABLES in body.datasets else "price_bgp_lookup",
        "0.01" if BGPDataset.AS215932_ROUTER_TABLES in body.datasets else "0.005",
    )
    if payment := await _paid_lookup(request, body):
        return payment
    result = await lookup_bgp(body)
    result.charged_amount_usd = str(amount)
    return result


@router.get("/prefix", response_model=BGPLookupResponse)
async def bgp_prefix(request: Request, prefix: str) -> BGPLookupResponse | Response:
    if payment := await _paid_lookup(request):
        return payment
    body = BGPLookupRequest.model_validate({"subject": {"type": "prefix", "value": prefix}})
    result = await lookup_bgp(body)
    result.charged_amount_usd = str(payment_price(request, "price_bgp_lookup", "0.005"))
    return result


@router.get("/ip", response_model=BGPLookupResponse)
async def bgp_ip(request: Request, address: str) -> BGPLookupResponse | Response:
    if payment := await _paid_lookup(request):
        return payment
    body = BGPLookupRequest.model_validate({"subject": {"type": "ip", "value": address}})
    result = await lookup_bgp(body)
    result.charged_amount_usd = str(payment_price(request, "price_bgp_lookup", "0.005"))
    return result


@router.get("/asn/{asn}", response_model=BGPLookupResponse)
async def bgp_asn(request: Request, asn: str) -> BGPLookupResponse | Response:
    if payment := await _paid_lookup(request):
        return payment
    body = BGPLookupRequest.model_validate({"subject": {"type": "asn", "value": asn}})
    result = await lookup_bgp(body)
    result.charged_amount_usd = str(payment_price(request, "price_bgp_lookup", "0.005"))
    return result


@router.post("/jobs", response_model=BGPJobResponse)
async def create_bgpstream_job(request: Request, body: BGPStreamJobRequest) -> BGPJobResponse | Response:
    # Queued jobs are only fulfilled by an external BGPStream worker. Until one
    # is deployed, refuse before charging rather than bill for a job that would
    # sit queued forever. Existing job status/download routes stay reachable.
    if not bgpstream_worker_enabled():
        return not_implemented(
            "bgp.jobs.create",
            "Historical BGPStream jobs are temporarily unavailable; no processing worker is deployed.",
        )
    attr = "price_bgpstream_rib" if body.record_type.value == "ribs" else "price_bgpstream_hour"
    default = "0.10" if attr == "price_bgpstream_rib" else "0.05"
    amount = payment_price(request, attr, default)
    payment = await require_payment(request, amount, "Hyrule BGPStream historical job")
    if isinstance(payment, Response):
        return payment
    job_id = "bgpj_" + secrets.token_urlsafe(16)
    token = "hyr_bgp_job_" + secrets.token_urlsafe(24)
    created = now_utc()
    expires = created + timedelta(days=7)
    factory = _session_factory(request)
    if factory is not None:
        async with factory() as session:
            session.add(
                BGPJobRow(
                    job_id=job_id,
                    status="queued",
                    owner_wallet=str(payment),
                    payment_tx=getattr(request.state, "payment_tx", None),
                    access_token_hash=_hash_token(token),
                    query=body.model_dump(mode="json"),
                    price_usd=amount,
                    created_at=created,
                    expires_at=expires,
                )
            )
            await session.commit()
    return BGPJobResponse(
        job_id=job_id,
        job_access_token=token,
        status=BGPJobStatus.QUEUED,
        charged_amount_usd=str(amount),
        status_url=f"/v1/bgp/jobs/{job_id}",
        download_url=f"/v1/bgp/jobs/{job_id}/download",
        created_at=created,
        expires_at=expires,
    )


@router.get("/jobs/{job_id}", response_model=BGPJobResponse)
async def get_bgp_job(request: Request, job_id: str, token: str | None = None) -> BGPJobResponse:
    factory = _session_factory(request)
    if factory is None:
        raise HTTPException(404, "job not found")
    async with factory() as session:
        row = await session.get(BGPJobRow, job_id)
    if row is None or (row.access_token_hash and _hash_token(token or "") != row.access_token_hash):
        raise HTTPException(404, "job not found")
    return BGPJobResponse(
        job_id=row.job_id,
        status=BGPJobStatus(row.status),
        charged_amount_usd=str(row.price_usd) if row.price_usd is not None else None,
        status_url=f"/v1/bgp/jobs/{row.job_id}",
        download_url=f"/v1/bgp/jobs/{row.job_id}/download",
        error=row.error,
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_bgp_job(request: Request, job_id: str, token: str | None = None) -> Response:
    factory = _session_factory(request)
    if factory is None:
        raise HTTPException(404, "job not found")
    async with factory() as session:
        row = await session.get(BGPJobRow, job_id)
        if row is None or (row.access_token_hash and _hash_token(token or "") != row.access_token_hash):
            raise HTTPException(404, "job not found")
        snapshot = await session.get(BGPSnapshotRow, row.artifact_snapshot_id) if row.artifact_snapshot_id else None
    if snapshot is None or not snapshot.artifact_path:
        raise HTTPException(409, "job artifact is not ready")
    path = Path(snapshot.artifact_path)
    if not path.exists():
        raise HTTPException(410, "job artifact expired")
    return FileResponse(path, media_type="application/gzip", filename=path.name)


@router.get(
    "/snapshots/router/{snapshot_id}/download",
    response_model=None,
    responses={
        200: {
            "description": "Gzip-compressed normalized router-table snapshot",
            "content": {
                "application/gzip": {
                    "schema": {"type": "string", "format": "binary"}
                }
            },
        }
    },
)
async def download_bgp_router_snapshot(request: Request, snapshot_id: str, format: str = "normalized_jsonl") -> Response:
    result = await require_payment(
        request,
        payment_price(request, "price_bgp_router_table", "0.10"),
        "Hyrule AS215932 router table snapshot download",
    )
    if isinstance(result, Response):
        return result
    factory = _session_factory(request)
    if factory is None:
        raise HTTPException(404, "snapshot not found")
    async with factory() as session:
        row = await session.get(BGPSnapshotRow, snapshot_id)
    if row is None or not row.artifact_path:
        raise HTTPException(404, "snapshot not found")
    path = Path(row.artifact_path)
    if not path.exists():
        raise HTTPException(410, "snapshot artifact expired")
    return FileResponse(path, media_type="application/gzip", filename=path.name)
