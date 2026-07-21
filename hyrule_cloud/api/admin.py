"""Browser-session-only Hyrule administration API.

The router is intentionally excluded from the public x402/OpenAPI catalog.
It exposes operational fields only; authentication material and provider
payloads never enter a response model.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, exists, func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.db import (
    AccountRow,
    AccountWalletRow,
    AdminAuditRow,
    AdminOperationRow,
    ApiKeyRow,
    DiagnosticJobRow,
    DomainJobRow,
    DomainOperationRow,
    DomainRow,
    MailAccountRow,
    PaymentEventRow,
    RefundResolutionRow,
    SessionRow,
    VMRow,
)
from hyrule_cloud.domains.models import (
    DNSChangesetRequest,
    DNSSECUpdateRequest,
    NameserverUpdateRequest,
)
from hyrule_cloud.middleware.auth import (
    derive_ip_prefix_hash,
    require_admin_csrf,
    require_admin_session,
    require_admin_step_up,
)
from hyrule_cloud.models import VMStatus
from hyrule_cloud.services.passwords import verify_password
from hyrule_cloud.state import AppState, get_app_state

router = APIRouter(
    prefix="/v1/admin",
    tags=["administration"],
    include_in_schema=False,
)

_ADMIN_STEP_UP_ATTEMPT_LIMIT = 5
_ADMIN_STEP_UP_ATTEMPT_WINDOW = timedelta(minutes=15)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _factory(state: AppState) -> async_sessionmaker[AsyncSession]:
    if state.session_factory is None:
        raise HTTPException(503, "Database not available")
    return cast(async_sessionmaker[AsyncSession], state.session_factory)


def _audit(
    session: AsyncSession,
    request: Request,
    actor: AccountRow,
    action: str,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> AdminAuditRow:
    row = AdminAuditRow(
        audit_id=str(uuid.uuid4()),
        actor_account_id=actor.account_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        reason=reason,
        details=details,
        ip_prefix_hash=derive_ip_prefix_hash(_client_ip(request)),
    )
    session.add(row)
    return row


async def _audit_before_dispatch(
    state: AppState,
    request: Request,
    actor: AccountRow,
    action: str,
    *,
    target_type: str,
    target_id: str,
    reason: str,
    details: dict[str, Any] | None = None,
) -> str:
    """Durably record a privileged request before its external side effect."""
    async with _factory(state)() as session:
        row = _audit(
            session,
            request,
            actor,
            f"{action}.requested",
            target_type=target_type,
            target_id=target_id,
            reason=reason,
            details=details,
        )
        audit_id = row.audit_id
        await session.commit()
    return audit_id


class StepUpRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class RoleRequest(ReasonRequest):
    is_admin: bool


class OwnershipTransferRequest(ReasonRequest):
    target_account_id: str = Field(min_length=11, max_length=11)


class NameserverAdminRequest(ReasonRequest):
    request: NameserverUpdateRequest


class DNSAdminRequest(ReasonRequest):
    expected_revision: int = Field(ge=1)
    request: DNSChangesetRequest


class DNSSECAdminRequest(ReasonRequest):
    request: DNSSECUpdateRequest


class RefundResolutionRequest(ReasonRequest):
    status: Literal["resolved", "rejected"]
    external_reference: str | None = Field(default=None, max_length=256)
    transaction_hash: str | None = Field(default=None, max_length=128)


def _account_payload(row: AccountRow) -> dict[str, Any]:
    return {
        "account_id": row.account_id,
        "is_admin": row.is_admin,
        "disabled": row.disabled_at is not None,
        "disabled_at": row.disabled_at,
        "disabled_reason": row.disabled_reason,
        "created_at": row.created_at,
        "last_login_at": row.last_login_at,
        "password_changed_at": row.password_changed_at,
    }


def _vm_payload(row: VMRow) -> dict[str, Any]:
    return {
        "vm_id": row.vm_id,
        "owner_account_id": row.owner_account_id,
        "owner_wallet": row.owner_wallet,
        "status": str(row.status),
        "xcpng_uuid": row.xcpng_uuid,
        "hostname": row.hostname,
        "ipv6": row.ipv6,
        "ipv6_prefix": row.ipv6_prefix,
        "os": row.os,
        "size": str(row.size),
        "vcpu": row.vcpu,
        "memory_mb": row.memory_mb,
        "disk_gb": row.disk_gb,
        "ssh_pubkey": row.ssh_pubkey,
        "domain": row.domain,
        "billing_mode": row.billing_mode,
        "charged_usd": row.cost_total,
        "retail_usd": row.retail_cost_total,
        "payment_tx": row.payment_tx,
        "suspension_reason": row.suspension_reason,
        "created_at": row.created_at,
        "provisioned_at": row.provisioned_at,
        "expires_at": row.expires_at,
        "error": row.error,
    }


def _domain_payload(row: DomainRow) -> dict[str, Any]:
    return {
        "domain": row.fqdn,
        "owner_account_id": row.owner_account_id,
        "owner_wallet": row.owner_wallet,
        "status": str(row.status),
        "provider_status": row.provider_status,
        "provider_domain_id": row.openprovider_id,
        "provider_operation_id": row.provider_operation_id,
        "linked_vm_id": row.vm_id,
        "nameserver_mode": row.nameserver_mode,
        "nameservers": row.nameservers,
        "dnssec_mode": row.dnssec_mode,
        "dnssec_status": row.dnssec_status,
        "zone_revision": row.zone_revision,
        "registered_at": row.registered_at,
        "expires_at": row.expires_at,
        "payment_tx": row.payment_tx,
        "error": row.error,
    }


@router.post("/step-up")
async def step_up(
    body: StepUpRequest,
    request: Request,
    account: AccountRow = Depends(require_admin_csrf),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    token_hash = getattr(request.state, "session_token_hash", None)
    if not token_hash:
        raise HTTPException(401, "Browser session required")
    now = _now()
    async with _factory(state)() as session:
        row = (
            await session.execute(
                select(SessionRow)
                .where(SessionRow.token_hash == token_hash)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None or row.account_id != account.account_id:
            raise HTTPException(401, "Session expired")
        window_started_at = row.admin_step_up_window_started_at
        if (
            window_started_at is None
            or now - _aware(window_started_at) >= _ADMIN_STEP_UP_ATTEMPT_WINDOW
        ):
            row.admin_step_up_attempts = 0
            row.admin_step_up_window_started_at = now
        if row.admin_step_up_attempts >= _ADMIN_STEP_UP_ATTEMPT_LIMIT:
            raise HTTPException(429, "Too many step-up attempts; try again later")

        # Hold the session row lock across Argon verification so concurrent
        # requests cannot each slip through the same pre-verification limit.
        row.admin_step_up_attempts += 1
        if not verify_password(account.password_hash, body.password):
            _audit(
                session,
                request,
                account,
                "admin.step_up_failed",
                target_type="session",
            )
            await session.commit()
            raise HTTPException(401, "Password is incorrect")

        row.admin_step_up_attempts = 0
        row.admin_step_up_window_started_at = None
        row.admin_elevated_at = now
        _audit(session, request, account, "admin.step_up", target_type="session")
        await session.commit()
    request.state.admin_elevated_at = now
    return {
        "status": "ok",
        "elevated_until": now + timedelta(seconds=state.config.admin_step_up_seconds),
    }


@router.get("/overview")
async def overview(
    window: Literal["24h", "7d", "30d"] = "24h",
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    delta = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[window]
    since = _now() - delta
    async with _factory(state)() as session:
        accounts = int(await session.scalar(select(func.count()).select_from(AccountRow)) or 0)
        disabled = int(
            await session.scalar(
                select(func.count())
                .select_from(AccountRow)
                .where(AccountRow.disabled_at.is_not(None))
            )
            or 0
        )
        admins = int(
            await session.scalar(
                select(func.count()).select_from(AccountRow).where(AccountRow.is_admin.is_(True))
            )
            or 0
        )
        vms = int(await session.scalar(select(func.count()).select_from(VMRow)) or 0)
        running_vms = int(
            await session.scalar(
                select(func.count())
                .select_from(VMRow)
                .where(VMRow.status.in_([VMStatus.READY.value, VMStatus.RUNNING.value]))
            )
            or 0
        )
        domains = int(await session.scalar(select(func.count()).select_from(DomainRow)) or 0)
        mailboxes = int(await session.scalar(select(func.count()).select_from(MailAccountRow)) or 0)
        settled_count, revenue = (
            await session.execute(
                select(func.count(), func.coalesce(func.sum(PaymentEventRow.amount_usd), 0)).where(
                    PaymentEventRow.event_type == "settled",
                    PaymentEventRow.created_at >= since,
                )
            )
        ).one()
        waived_count, waived_retail = (
            await session.execute(
                select(func.count(), func.coalesce(func.sum(PaymentEventRow.amount_usd), 0)).where(
                    PaymentEventRow.event_type == "admin_bypass",
                    PaymentEventRow.created_at >= since,
                )
            )
        ).one()
        refund_owed = int(
            await session.scalar(
                select(func.count())
                .select_from(PaymentEventRow)
                .where(
                    PaymentEventRow.event_type == "refund_owed",
                    PaymentEventRow.created_at >= since,
                    ~exists(
                        select(RefundResolutionRow.resolution_id).where(
                            RefundResolutionRow.payment_event_id == PaymentEventRow.event_id
                        )
                    ),
                )
            )
            or 0
        )
        failed_jobs = int(
            await session.scalar(
                select(func.count())
                .select_from(DomainJobRow)
                .where(DomainJobRow.status == "failed")
            )
            or 0
        )
    return {
        "window": window,
        "generated_at": _now(),
        "accounts": {
            "total": accounts,
            "enabled": accounts - disabled,
            "disabled": disabled,
            "admins": admins,
        },
        "resources": {
            "vms": vms,
            "running_vms": running_vms,
            "domains": domains,
            "mailboxes": mailboxes,
        },
        "payments": {
            "settled_count": int(settled_count),
            "revenue_usd": Decimal(revenue),
            "admin_waiver_count": int(waived_count),
            "admin_waived_retail_usd": Decimal(waived_retail),
            "refund_owed_count": refund_owed,
        },
        "waivers": {
            "enabled": bool(getattr(state.config, "admin_payment_bypass_enabled", False)),
            "diagnostic_limit_per_minute": int(
                getattr(state.config, "admin_diagnostic_bypass_per_minute", 120)
            ),
            "real_cost_limit_per_hour": int(
                getattr(state.config, "admin_cost_bypass_per_hour", 10)
            ),
            "step_up_seconds": int(getattr(state.config, "admin_step_up_seconds", 600)),
        },
        "operations": {"failed_jobs": failed_jobs},
    }


@router.get("/accounts")
async def list_accounts(
    q: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    stmt = select(AccountRow).order_by(AccountRow.created_at.desc()).limit(limit).offset(offset)
    if q:
        stmt = stmt.where(AccountRow.account_id.ilike(f"%{q.strip()}%"))
    async with _factory(state)() as session:
        rows = list(await session.scalars(stmt))
    return {"items": [_account_payload(row) for row in rows], "limit": limit, "offset": offset}


@router.get("/vms")
async def list_vms(
    q: str | None = Query(default=None, max_length=256),
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    stmt = select(VMRow).order_by(VMRow.created_at.desc()).limit(limit).offset(offset)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                VMRow.vm_id.ilike(like),
                VMRow.owner_account_id.ilike(like),
                VMRow.hostname.ilike(like),
            )
        )
    if status:
        stmt = stmt.where(VMRow.status == status)
    async with _factory(state)() as session:
        rows = list(await session.scalars(stmt))
    return {"items": [_vm_payload(row) for row in rows], "limit": limit, "offset": offset}


@router.get("/domains")
async def list_domains(
    q: str | None = Query(default=None, max_length=256),
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    stmt = select(DomainRow).order_by(DomainRow.registered_at.desc()).limit(limit).offset(offset)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(DomainRow.fqdn.ilike(like), DomainRow.owner_account_id.ilike(like)))
    if status:
        stmt = stmt.where(DomainRow.status == status)
    async with _factory(state)() as session:
        rows = list(await session.scalars(stmt))
    return {"items": [_domain_payload(row) for row in rows], "limit": limit, "offset": offset}


@router.get("/payment-events")
async def list_payment_events(
    event_type: str | None = Query(default=None, max_length=24),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    stmt = (
        select(PaymentEventRow)
        .order_by(PaymentEventRow.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if event_type:
        stmt = stmt.where(PaymentEventRow.event_type == event_type)
    async with _factory(state)() as session:
        rows = list(await session.scalars(stmt))
    return {
        "items": [
            {
                "event_id": row.event_id,
                "created_at": row.created_at,
                "event_type": row.event_type,
                "resource_path": row.resource_path,
                "method": row.method,
                "service_group": row.service_group,
                "amount_usd": row.amount_usd,
                "network": row.network,
                "asset": row.asset,
                "payer_wallet": row.payer_wallet,
                "tx_hash": row.tx_hash,
                "actor_account_id": row.actor_account_id,
                "error": row.error_reason,
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
    }


@router.get("/refunds")
async def list_refunds(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        owed = list(
            await session.scalars(
                select(PaymentEventRow)
                .where(PaymentEventRow.event_type == "refund_owed")
                .order_by(PaymentEventRow.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        ids = [row.event_id for row in owed]
        resolutions = {
            row.payment_event_id: row
            for row in (
                list(
                    await session.scalars(
                        select(RefundResolutionRow).where(
                            RefundResolutionRow.payment_event_id.in_(ids)
                        )
                    )
                )
                if ids
                else []
            )
        }
    return {
        "items": [
            {
                "event_id": row.event_id,
                "created_at": row.created_at,
                "resource_path": row.resource_path,
                "amount_usd": row.amount_usd,
                "network": row.network,
                "asset": row.asset,
                "payer_wallet": row.payer_wallet,
                "original_tx": row.tx_hash,
                "reason": row.error_reason,
                "resolution": (
                    {
                        "status": resolutions[row.event_id].status,
                        "external_reference": resolutions[row.event_id].external_reference,
                        "transaction_hash": resolutions[row.event_id].transaction_hash,
                        "resolved_at": resolutions[row.event_id].created_at,
                        "actor_account_id": resolutions[row.event_id].actor_account_id,
                    }
                    if row.event_id in resolutions
                    else None
                ),
            }
            for row in owed
        ],
        "limit": limit,
        "offset": offset,
    }


@router.get("/jobs")
async def list_jobs(
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    domain_stmt = select(DomainJobRow).order_by(DomainJobRow.created_at.desc()).limit(limit)
    diagnostic_stmt = (
        select(DiagnosticJobRow).order_by(DiagnosticJobRow.created_at.desc()).limit(limit)
    )
    if status:
        domain_stmt = domain_stmt.where(DomainJobRow.status == status)
        diagnostic_stmt = diagnostic_stmt.where(DiagnosticJobRow.status == status)
    async with _factory(state)() as session:
        domain_rows = list(await session.scalars(domain_stmt))
        diagnostic_rows = list(await session.scalars(diagnostic_stmt))
    items: list[dict[str, Any]] = [
        {
            "job_id": row.job_id,
            "source": "domain",
            "kind": row.kind,
            "resource_id": row.resource_id,
            "status": row.status,
            "attempts": row.attempts,
            "last_error": row.last_error,
            "created_at": row.created_at,
            "completed_at": row.completed_at,
        }
        for row in domain_rows
    ] + [
        {
            "job_id": row.job_id,
            "source": "diagnostic",
            "kind": row.kind,
            "service": row.service,
            "target": row.target,
            "status": row.status,
            "last_error": row.error,
            "created_at": row.created_at,
            "completed_at": row.completed_at,
        }
        for row in diagnostic_rows
    ]
    items.sort(key=lambda item: _aware(item["created_at"]), reverse=True)
    return {"items": items[:limit]}


@router.get("/audit")
async def list_audit(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        rows = list(
            await session.scalars(
                select(AdminAuditRow)
                .order_by(AdminAuditRow.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
    return {
        "items": [
            {
                "audit_id": row.audit_id,
                "actor_account_id": row.actor_account_id,
                "action": row.action,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "reason": row.reason,
                "details": row.details,
                "succeeded": row.succeeded,
                "created_at": row.created_at,
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
    }


@router.get("/operations")
async def list_operations(
    limit: int = Query(default=100, ge=1, le=500),
    _admin: AccountRow = Depends(require_admin_session),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        rows = list(
            await session.scalars(
                select(AdminOperationRow).order_by(AdminOperationRow.created_at.desc()).limit(limit)
            )
        )
    return {
        "items": [
            {
                "operation_id": row.operation_id,
                "kind": row.kind,
                "account_id": row.account_id,
                "actor_account_id": row.actor_account_id,
                "status": row.status,
                "reason": row.reason,
                "progress": row.progress,
                "error": row.error,
                "created_at": row.created_at,
                "started_at": row.started_at,
                "completed_at": row.completed_at,
            }
            for row in rows
        ]
    }


async def _enabled_admin_count(session: AsyncSession, *, lock: bool = False) -> int:
    predicate = (AccountRow.is_admin.is_(True), AccountRow.disabled_at.is_(None))
    if lock:
        # Serialize the last-Admin invariant across concurrent disable/demote
        # requests. PostgreSQL READ COMMITTED refreshes the blocked statement's
        # view after the first transaction commits.
        rows = list(
            await session.scalars(
                select(AccountRow.account_id)
                .where(*predicate)
                .order_by(AccountRow.account_id)
                .with_for_update()
            )
        )
        return len(rows)
    return int(
        await session.scalar(select(func.count()).select_from(AccountRow).where(*predicate)) or 0
    )


async def _locked_account(session: AsyncSession, account_id: str) -> AccountRow | None:
    return (
        await session.execute(
            select(AccountRow)
            .where(AccountRow.account_id == account_id)
            .with_for_update()
        )
    ).scalar_one_or_none()


@router.post("/accounts/{account_id}/disable")
async def disable_account(
    account_id: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    if account_id == actor.account_id:
        raise HTTPException(409, "You cannot disable your current Admin account")
    async with _factory(state)() as session:
        target = await _locked_account(session, account_id)
        if target is None:
            raise HTTPException(404, "Account not found")
        if (
            target.is_admin
            and target.disabled_at is None
            and await _enabled_admin_count(session, lock=True) <= 1
        ):
            raise HTTPException(409, "At least one enabled Admin must remain")
        now = _now()
        target.disabled_at = now
        target.disabled_reason = body.reason
        target.disabled_by_account_id = actor.account_id
        await session.execute(delete(SessionRow).where(SessionRow.account_id == account_id))
        await session.execute(
            update(ApiKeyRow)
            .where(ApiKeyRow.account_id == account_id, ApiKeyRow.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        operation = AdminOperationRow(
            operation_id=str(uuid.uuid4()),
            kind="suspend_account_resources",
            account_id=account_id,
            actor_account_id=actor.account_id,
            reason=body.reason,
            created_at=now,
        )
        session.add(operation)
        _audit(
            session,
            request,
            actor,
            "account.disable",
            target_type="account",
            target_id=account_id,
            reason=body.reason,
        )
        await session.commit()
    return {"status": "disabled", "operation_id": operation.operation_id}


@router.post("/accounts/{account_id}/enable")
async def enable_account(
    account_id: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        target = await _locked_account(session, account_id)
        if target is None:
            raise HTTPException(404, "Account not found")
        now = _now()
        target.disabled_at = None
        target.disabled_reason = None
        target.disabled_by_account_id = None
        operation = AdminOperationRow(
            operation_id=str(uuid.uuid4()),
            kind="resume_account_resources",
            account_id=account_id,
            actor_account_id=actor.account_id,
            reason=body.reason,
            created_at=now,
        )
        session.add(operation)
        _audit(
            session,
            request,
            actor,
            "account.enable",
            target_type="account",
            target_id=account_id,
            reason=body.reason,
        )
        await session.commit()
    return {"status": "enabled", "operation_id": operation.operation_id}


@router.post("/accounts/{account_id}/role")
async def set_account_role(
    account_id: str,
    body: RoleRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    if account_id == actor.account_id and not body.is_admin:
        raise HTTPException(409, "You cannot demote your current Admin account")
    async with _factory(state)() as session:
        target = await session.get(AccountRow, account_id)
        if target is None:
            raise HTTPException(404, "Account not found")
        if (
            target.is_admin
            and not body.is_admin
            and target.disabled_at is None
            and await _enabled_admin_count(session, lock=True) <= 1
        ):
            raise HTTPException(409, "At least one enabled Admin must remain")
        target.is_admin = body.is_admin
        _audit(
            session,
            request,
            actor,
            "account.promote" if body.is_admin else "account.demote",
            target_type="account",
            target_id=account_id,
            reason=body.reason,
        )
        await session.commit()
    return {"account_id": account_id, "is_admin": body.is_admin}


@router.post("/accounts/{account_id}/revoke-sessions")
async def revoke_account_sessions(
    account_id: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        if await session.get(AccountRow, account_id) is None:
            raise HTTPException(404, "Account not found")
        result = cast(
            CursorResult[Any],
            await session.execute(delete(SessionRow).where(SessionRow.account_id == account_id)),
        )
        _audit(
            session,
            request,
            actor,
            "account.revoke_sessions",
            target_type="account",
            target_id=account_id,
            reason=body.reason,
        )
        await session.commit()
    return {"revoked": int(result.rowcount or 0)}


@router.post("/accounts/{account_id}/revoke-keys")
async def revoke_account_keys(
    account_id: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    now = _now()
    async with _factory(state)() as session:
        if await session.get(AccountRow, account_id) is None:
            raise HTTPException(404, "Account not found")
        result = cast(
            CursorResult[Any],
            await session.execute(
                update(ApiKeyRow)
                .where(
                    ApiKeyRow.account_id == account_id,
                    ApiKeyRow.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            ),
        )
        _audit(
            session,
            request,
            actor,
            "account.revoke_keys",
            target_type="account",
            target_id=account_id,
            reason=body.reason,
        )
        await session.commit()
    return {"revoked": int(result.rowcount or 0)}


@router.post("/vms/{vm_id}/actions/{action}")
async def vm_action(
    vm_id: str,
    action: Literal["start", "reboot", "shutdown", "suspend", "destroy"],
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    orch = state.orchestrator
    async with _factory(state)() as session:
        row = await session.get(VMRow, vm_id)
        if row is None:
            raise HTTPException(404, "VM not found")
        xcpng_uuid = row.xcpng_uuid
        if action == "start" and row.expires_at is not None and _aware(row.expires_at) <= _now():
            raise HTTPException(409, "Expired VMs cannot be started")
        if action not in {"reboot", "destroy"} and not xcpng_uuid:
            raise HTTPException(409, "VM has no provider instance")
    await _audit_before_dispatch(
        state,
        request,
        actor,
        f"vm.{action}",
        target_type="vm",
        target_id=vm_id,
        reason=body.reason,
    )
    if action == "reboot":
        if not await orch.reboot_vm(vm_id):
            raise HTTPException(409, "VM cannot be rebooted")
    elif action == "destroy":
        if not await orch.destroy_vm(vm_id):
            raise HTTPException(409, "VM cannot be destroyed")
    else:
        assert xcpng_uuid is not None
        if action == "start":
            await orch.xcpng.start_vm(xcpng_uuid)
        elif action == "shutdown":
            await orch.xcpng.shutdown_vm(xcpng_uuid)
        else:
            await orch.xcpng.suspend_vm(xcpng_uuid)
        async with _factory(state)() as session:
            current = await session.get(VMRow, vm_id)
            if current is not None:
                current.status = VMStatus.RUNNING if action == "start" else VMStatus.SUSPENDED
                current.suspension_reason = None if action == "start" else "manual_admin"
                current.suspended_by_account_id = None if action == "start" else actor.account_id
                await session.commit()
    return {"vm_id": vm_id, "action": action, "status": "accepted"}


async def _assert_transfer_target(session: AsyncSession, account_id: str) -> AccountRow:
    target = await session.get(AccountRow, account_id)
    if target is None or target.disabled_at is not None:
        raise HTTPException(409, "Target account is missing or disabled")
    return target


async def _transfer_wallet_identity(session: AsyncSession, account_id: str) -> str:
    """Use the transferee's wallet, or a non-signable account marker."""
    address = await session.scalar(
        select(AccountWalletRow.address)
        .where(AccountWalletRow.account_id == account_id)
        .limit(1)
    )
    return address or f"account:{account_id}"


async def _resume_transferred_vm(state: AppState, vm_id: str) -> None:
    """Clear an old owner's account suspension after a successful transfer."""
    restart_provisioning = False
    async with _factory(state)() as session:
        current = (
            await session.execute(
                select(VMRow).where(VMRow.vm_id == vm_id).with_for_update()
            )
        ).scalar_one_or_none()
        if current is None or current.suspension_reason != "account_disabled":
            return
        if current.expires_at is not None and _aware(current.expires_at) <= _now():
            current.suspension_reason = "expired"
            current.suspended_by_account_id = None
            await session.commit()
            return

        status = str(current.status)
        if status in {VMStatus.DESTROYED.value, VMStatus.FAILED.value}:
            return
        if status == VMStatus.PROVISIONING.value:
            # The in-flight provisioner will observe the cleared marker and
            # complete normally for the enabled recipient.
            current.suspension_reason = None
            current.suspended_by_account_id = None
        elif status == VMStatus.SUSPENDED.value and current.xcpng_uuid:
            orchestrator = state.orchestrator
            if orchestrator is None:
                raise HTTPException(503, "VM service unavailable")
            # The transfer audit is committed before this provider call. Keep
            # the row locked so no concurrent Admin action can overwrite it.
            await orchestrator.xcpng.start_vm(current.xcpng_uuid)
            current.status = VMStatus.RUNNING
            current.suspension_reason = None
            current.suspended_by_account_id = None
        elif status == VMStatus.SUSPENDED.value:
            orchestrator = state.orchestrator
            if orchestrator is None:
                raise HTTPException(503, "VM service unavailable")
            current.status = VMStatus.PROVISIONING
            current.suspension_reason = None
            current.suspended_by_account_id = None
            current.error = None
            restart_provisioning = True
        else:
            # A stale provenance marker on an already-live VM should not block
            # the recipient, but it does not require a provider transition.
            current.suspension_reason = None
            current.suspended_by_account_id = None
        await session.commit()

    if restart_provisioning:
        # The branch above validated the service before committing the queued
        # state; AppState does not replace a live orchestrator at runtime.
        orchestrator = state.orchestrator
        assert orchestrator is not None
        orchestrator.start_provisioning(vm_id)


async def _pending_domain_operation(session: AsyncSession, fqdn: str) -> bool:
    return (
        await session.scalar(
            select(DomainOperationRow.operation_id)
            .where(
                DomainOperationRow.fqdn == fqdn,
                DomainOperationRow.status.in_(["queued", "running", "waiting_provider"]),
            )
            .limit(1)
        )
    ) is not None


@router.post("/vms/{vm_id}/transfer")
async def transfer_vm(
    vm_id: str,
    body: OwnershipTransferRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        await _assert_transfer_target(session, body.target_account_id)
        new_owner_wallet = await _transfer_wallet_identity(session, body.target_account_id)
        vm = (
            await session.execute(select(VMRow).where(VMRow.vm_id == vm_id).with_for_update())
        ).scalar_one_or_none()
        if vm is None:
            raise HTTPException(404, "VM not found")
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.vm_id == vm_id).with_for_update()
            )
        ).scalar_one_or_none()
        if domain is not None and await _pending_domain_operation(session, domain.fqdn):
            raise HTTPException(409, "Attached domain has a pending operation")
        previous_account_id = vm.owner_account_id
        vm.owner_account_id = body.target_account_id
        vm.owner_wallet = new_owner_wallet
        vm.anon_management_token_hash = None
        if domain is not None:
            domain.owner_account_id = body.target_account_id
            domain.owner_wallet = new_owner_wallet
            domain.anon_management_token_hash = None
        _audit(
            session,
            request,
            actor,
            "vm.transfer",
            target_type="vm",
            target_id=vm_id,
            reason=body.reason,
            details={
                "target_account_id": body.target_account_id,
                "previous_account_id": previous_account_id,
                "attached_domain": domain.fqdn if domain else None,
            },
        )
        await session.commit()
    await _resume_transferred_vm(state, vm_id)
    return {"vm_id": vm_id, "owner_account_id": body.target_account_id}


@router.post("/domains/{fqdn}/transfer")
async def transfer_domain(
    fqdn: str,
    body: OwnershipTransferRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    fqdn = fqdn.lower().rstrip(".")
    attached_vm_id: str | None = None
    async with _factory(state)() as session:
        await _assert_transfer_target(session, body.target_account_id)
        new_owner_wallet = await _transfer_wallet_identity(session, body.target_account_id)
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn).with_for_update())
        ).scalar_one_or_none()
        if domain is None:
            raise HTTPException(404, "Domain not found")
        if await _pending_domain_operation(session, fqdn):
            raise HTTPException(409, "Domain has a pending operation")
        previous_account_id = domain.owner_account_id
        domain.owner_account_id = body.target_account_id
        domain.owner_wallet = new_owner_wallet
        domain.anon_management_token_hash = None
        if domain.vm_id:
            attached_vm_id = domain.vm_id
            vm = (
                await session.execute(
                    select(VMRow).where(VMRow.vm_id == domain.vm_id).with_for_update()
                )
            ).scalar_one_or_none()
            if vm is not None:
                vm.owner_account_id = body.target_account_id
                vm.owner_wallet = new_owner_wallet
                vm.anon_management_token_hash = None
        _audit(
            session,
            request,
            actor,
            "domain.transfer",
            target_type="domain",
            target_id=fqdn,
            reason=body.reason,
            details={
                "target_account_id": body.target_account_id,
                "previous_account_id": previous_account_id,
                "attached_vm": domain.vm_id,
            },
        )
        await session.commit()
    if attached_vm_id is not None:
        await _resume_transferred_vm(state, attached_vm_id)
    return {"domain": fqdn, "owner_account_id": body.target_account_id}


async def _domain_owner(state: AppState, fqdn: str) -> str:
    async with _factory(state)() as session:
        row = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == fqdn.lower().rstrip("."))
            )
        ).scalar_one_or_none()
    if row is None or row.owner_account_id is None:
        raise HTTPException(404, "Managed account-owned domain not found")
    return row.owner_account_id


@router.put("/domains/{fqdn}/nameservers")
async def admin_nameservers(
    fqdn: str,
    body: NameserverAdminRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> Any:
    if state.domains is None:
        raise HTTPException(503, "Domain service unavailable")
    owner = await _domain_owner(state, fqdn)
    idempotency_key = str(uuid.uuid4())
    await _audit_before_dispatch(
        state,
        request,
        actor,
        "domain.nameservers",
        target_type="domain",
        target_id=fqdn,
        reason=body.reason,
        details={"idempotency_key": idempotency_key},
    )
    result = await state.domains.enqueue_nameserver_update(
        owner, fqdn, body.request, idempotency_key
    )
    return result


@router.post("/domains/{fqdn}/dns")
async def admin_dns(
    fqdn: str,
    body: DNSAdminRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> Any:
    if state.domains is None:
        raise HTTPException(503, "Domain service unavailable")
    owner = await _domain_owner(state, fqdn)
    idempotency_key = str(uuid.uuid4())
    await _audit_before_dispatch(
        state,
        request,
        actor,
        "domain.dns",
        target_type="domain",
        target_id=fqdn,
        reason=body.reason,
        details={
            "idempotency_key": idempotency_key,
            "expected_revision": body.expected_revision,
        },
    )
    result = await state.domains.apply_changeset(
        owner,
        fqdn,
        body.expected_revision,
        body.request,
        idempotency_key=idempotency_key,
    )
    return result


@router.put("/domains/{fqdn}/dnssec")
async def admin_dnssec(
    fqdn: str,
    body: DNSSECAdminRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> Any:
    if state.domains is None:
        raise HTTPException(503, "Domain service unavailable")
    owner = await _domain_owner(state, fqdn)
    idempotency_key = str(uuid.uuid4())
    await _audit_before_dispatch(
        state,
        request,
        actor,
        "domain.dnssec",
        target_type="domain",
        target_id=fqdn,
        reason=body.reason,
        details={"idempotency_key": idempotency_key},
    )
    result = await state.domains.enqueue_dnssec_update(
        owner,
        fqdn,
        body.request,
        idempotency_key,
    )
    return result


@router.post("/domains/{fqdn}/reconcile")
async def reconcile_domain(
    fqdn: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    fqdn = fqdn.lower().rstrip(".")
    async with _factory(state)() as session:
        if await session.scalar(select(DomainRow.id).where(DomainRow.fqdn == fqdn)) is None:
            raise HTTPException(404, "Domain not found")
        job = DomainJobRow(
            job_id=f"djob_{uuid.uuid4().hex[:22]}",
            kind="reconcile_domain",
            resource_id=fqdn,
            dedupe_key=f"admin-reconcile:{fqdn}:{uuid.uuid4()}",
            payload={"admin_requested": True},
        )
        session.add(job)
        _audit(
            session,
            request,
            actor,
            "domain.reconcile",
            target_type="domain",
            target_id=fqdn,
            reason=body.reason,
        )
        await session.commit()
    return {"job_id": job.job_id, "status": "queued"}


@router.post("/jobs/{job_id}/retry")
async def retry_job(
    job_id: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        job = await session.get(DomainJobRow, job_id)
        if job is None:
            raise HTTPException(404, "Retry is supported only for domain jobs")
        if job.status != "failed":
            raise HTTPException(409, "Only failed jobs can be retried")
        job.status = "queued"
        job.available_at = _now()
        job.locked_at = None
        job.locked_by = None
        job.last_error = None
        job.completed_at = None
        _audit(
            session,
            request,
            actor,
            "job.retry",
            target_type="job",
            target_id=job_id,
            reason=body.reason,
        )
        await session.commit()
    return {"job_id": job_id, "status": "queued"}


@router.post("/operations/{operation_id}/retry")
async def retry_admin_operation(
    operation_id: str,
    body: ReasonRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        operation = await session.get(AdminOperationRow, operation_id)
        if operation is None:
            raise HTTPException(404, "Operation not found")
        if operation.status != "failed":
            raise HTTPException(409, "Only failed operations can be retried")
        account = await session.get(AccountRow, operation.account_id)
        if account is None:
            raise HTTPException(409, "Operation account no longer exists")
        if operation.kind == "suspend_account_resources" and account.disabled_at is None:
            raise HTTPException(409, "Cannot retry suspension while the account is enabled")
        if operation.kind == "resume_account_resources" and account.disabled_at is not None:
            raise HTTPException(409, "Cannot retry resumption while the account is disabled")
        operation.status = "queued"
        operation.error = None
        operation.started_at = None
        operation.completed_at = None
        _audit(
            session,
            request,
            actor,
            "admin_operation.retry",
            target_type="operation",
            target_id=operation_id,
            reason=body.reason,
        )
        await session.commit()
    return {"operation_id": operation_id, "status": "queued"}


@router.post("/refunds/{event_id}/resolve")
async def resolve_refund(
    event_id: str,
    body: RefundResolutionRequest,
    request: Request,
    actor: AccountRow = Depends(require_admin_step_up()),
    state: AppState = Depends(get_app_state),
) -> dict[str, Any]:
    async with _factory(state)() as session:
        event = await session.get(PaymentEventRow, event_id)
        if event is None or event.event_type != "refund_owed":
            raise HTTPException(404, "Refund obligation not found")
        existing = await session.scalar(
            select(RefundResolutionRow.resolution_id).where(
                RefundResolutionRow.payment_event_id == event_id
            )
        )
        if existing is not None:
            raise HTTPException(409, "Refund obligation is already resolved")
        extra = event.extra if isinstance(event.extra, dict) else {}
        resource_id = str(
            extra.get("vm_id") or extra.get("order_id") or event.tx_hash or event.event_id
        )
        resource_type = (
            "vm" if extra.get("vm_id") else "domain" if extra.get("order_id") else "payment"
        )
        resolution = RefundResolutionRow(
            resolution_id=str(uuid.uuid4()),
            payment_event_id=event.event_id,
            resource_type=resource_type,
            resource_id=resource_id[:128],
            status=body.status,
            amount_usd=event.amount_usd,
            network=event.network,
            payer_wallet=event.payer_wallet,
            external_reference=body.external_reference,
            transaction_hash=body.transaction_hash,
            reason=body.reason,
            actor_account_id=actor.account_id,
        )
        session.add(resolution)
        _audit(
            session,
            request,
            actor,
            "refund.resolve",
            target_type="payment_event",
            target_id=event_id,
            reason=body.reason,
            details={
                "status": body.status,
                "external_reference": body.external_reference,
                "transaction_hash": body.transaction_hash,
            },
        )
        await session.commit()
    return {"resolution_id": resolution.resolution_id, "status": resolution.status}
