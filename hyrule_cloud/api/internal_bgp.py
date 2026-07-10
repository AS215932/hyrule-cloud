"""Internal token-protected BGP ingest/job endpoints for extmon and noc."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from hyrule_cloud.db import BGPJobRow, BGPSnapshotRow, BGPSourceStatusRow

router = APIRouter(prefix="/v1/internal/bgp", tags=["Internal BGP ingest"])


class BGPSourceStatusIngest(BaseModel):
    source_name: str = Field(min_length=1, max_length=64)
    status: str = "ok"
    payload: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class BGPSnapshotIngest(BaseModel):
    snapshot_id: str
    kind: str = "router_table"
    source: str = "noc"
    router: str | None = None
    asn: int | None = 215932
    prefix: str | None = None
    artifact_path: str | None = None
    artifact_format: str | None = None
    sha256: str | None = None
    compressed_size_bytes: int | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    expires_at: datetime | None = None


class BGPJobHeartbeat(BaseModel):
    claimed_by: str | None = None
    status: str | None = None
    error: str | None = None
    artifact_snapshot_id: str | None = None


def _state(request: Request) -> Any | None:
    return getattr(request.app.state, "_typed_state", None)


def _require_token(request: Request) -> None:
    state = _state(request)
    cfg = getattr(state, "config", None)
    expected = getattr(cfg, "bgp_ingest_token", "") if cfg is not None else ""
    supplied = request.headers.get("X-Hyrule-BGP-Ingest-Token") or ""
    if not expected or supplied != expected:
        raise HTTPException(status_code=403, detail="invalid BGP ingest token")


async def _session(request: Request) -> Any | None:
    state = _state(request)
    factory = getattr(state, "session_factory", None)
    if factory is None:
        return None
    return factory()


@router.post("/ingest/status")
async def ingest_bgp_status(request: Request, body: BGPSourceStatusIngest) -> dict[str, str]:
    _require_token(request)
    now = datetime.now(UTC)
    session_cm = await _session(request)
    if session_cm is not None:
        async with session_cm as session:
            row = BGPSourceStatusRow(
                source_name=body.source_name,
                status=body.status,
                last_success_at=now if body.status == "ok" else None,
                last_error_at=now if body.status != "ok" else None,
                last_error=body.error,
                payload=body.payload,
                updated_at=now,
            )
            await session.merge(row)
            await session.commit()
    return {"status": "accepted"}


@router.post("/ingest/snapshot")
async def ingest_bgp_snapshot(request: Request, body: BGPSnapshotIngest) -> dict[str, str]:
    _require_token(request)
    session_cm = await _session(request)
    if session_cm is not None:
        async with session_cm as session:
            row = BGPSnapshotRow(
                snapshot_id=body.snapshot_id,
                kind=body.kind,
                source=body.source,
                router=body.router,
                asn=body.asn,
                prefix=body.prefix,
                artifact_path=body.artifact_path,
                artifact_format=body.artifact_format,
                sha256=body.sha256,
                compressed_size_bytes=body.compressed_size_bytes,
                payload=body.payload,
                created_at=body.created_at or datetime.now(UTC),
                expires_at=body.expires_at,
            )
            await session.merge(row)
            await session.commit()
    return {"status": "accepted", "snapshot_id": body.snapshot_id}


@router.post("/jobs/claim")
async def claim_bgp_job(request: Request, body: BGPJobHeartbeat | None = None) -> dict[str, object]:
    _require_token(request)
    session_cm = await _session(request)
    if session_cm is None:
        return {"job": None}
    async with session_cm as session:
        row = (
            await session.execute(
                select(BGPJobRow)
                .where(BGPJobRow.status == "queued")
                .order_by(BGPJobRow.created_at.asc())
                .limit(1)
            )
        ).scalars().first()
        if row is None:
            return {"job": None}
        row.status = "claimed"
        row.claimed_by = body.claimed_by if body else "extmon"
        row.claimed_at = datetime.now(UTC)
        row.heartbeat_at = row.claimed_at
        await session.commit()
        return {"job": {"job_id": row.job_id, "query": row.query}}


@router.post("/jobs/{job_id}/heartbeat")
async def heartbeat_bgp_job(request: Request, job_id: str, body: BGPJobHeartbeat) -> dict[str, str]:
    _require_token(request)
    session_cm = await _session(request)
    if session_cm is not None:
        async with session_cm as session:
            row = await session.get(BGPJobRow, job_id)
            if row is not None:
                row.heartbeat_at = datetime.now(UTC)
                if body.status:
                    row.status = body.status
                if body.error:
                    row.error = body.error
                await session.commit()
    return {"status": "accepted"}


@router.post("/jobs/{job_id}/complete")
async def complete_bgp_job(request: Request, job_id: str, body: BGPJobHeartbeat) -> dict[str, str]:
    _require_token(request)
    session_cm = await _session(request)
    job_payer: str | None = None
    job_tx: str | None = None
    job_price = None
    completed = False
    if session_cm is not None:
        async with session_cm as session:
            row = await session.get(BGPJobRow, job_id)
            if row is not None:
                row.status = "completed"
                row.artifact_snapshot_id = body.artifact_snapshot_id
                row.completed_at = datetime.now(UTC)
                job_payer, job_tx, job_price = row.owner_wallet, row.payment_tx, row.price_usd
                completed = True
                await session.commit()
    if completed:
        # Trust layer: fulfillment receipt attesting the exact artifact
        # delivered for the paid job (payment receipt was minted at create).
        state = getattr(request.app.state, "_typed_state", None)
        trust = getattr(state, "trust", None)
        receipts = getattr(trust, "receipts", None)
        if receipts is not None:
            from hyrule_cloud.trust.models import ReceiptKind

            dev = bool(job_tx and job_tx.startswith("dev_bypass"))
            await receipts.mint(
                kind=ReceiptKind.FULFILLMENT,
                outcome="delivered",
                resource_path="/v1/bgp/jobs",
                method="POST",
                rail="dev-bypass" if dev else "x402-exact-evm",
                amount_usd=job_price,
                payer=None if dev else job_payer,
                tx_hash=None if dev else job_tx,
                job_id=job_id,
                evidence=(
                    {"artifact_snapshot_id": str(body.artifact_snapshot_id)}
                    if body.artifact_snapshot_id
                    else None
                ),
            )
    return {"status": "accepted"}


@router.post("/jobs/{job_id}/fail")
async def fail_bgp_job(request: Request, job_id: str, body: BGPJobHeartbeat) -> dict[str, str]:
    _require_token(request)
    session_cm = await _session(request)
    if session_cm is not None:
        async with session_cm as session:
            row = await session.get(BGPJobRow, job_id)
            if row is not None:
                row.status = "failed"
                row.error = body.error
                row.completed_at = datetime.now(UTC)
                await session.commit()
    return {"status": "accepted"}
