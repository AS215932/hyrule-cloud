"""Durable resource suspension/resumption for administrator account actions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import case, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.db import AccountRow, AdminOperationRow, MailAccountRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.orchestrator import Orchestrator

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


async def process_admin_operations(
    session_factory: async_sessionmaker[AsyncSession],
    orchestrator: Orchestrator,
    *,
    limit: int = 10,
) -> int:
    """Claim and execute queued account suspend/resume operations."""
    processed = 0
    for _ in range(limit):
        async with session_factory() as session:
            stale_before = _now() - timedelta(minutes=15)
            if session.get_bind().dialect.name == "sqlite":
                stale_before = stale_before.replace(tzinfo=None)
            eligible = or_(
                AdminOperationRow.status == "queued",
                (
                    (AdminOperationRow.status == "running")
                    & or_(
                        AdminOperationRow.started_at.is_(None),
                        AdminOperationRow.started_at < stale_before,
                    )
                ),
            )

            # Lock the account before selecting its oldest operation. Locking
            # only an operation row lets a second worker skip that row and run
            # the next enable/disable operation for the same account out of
            # order. The account lock provides a stable per-account queue while
            # still allowing different accounts to progress concurrently.
            pending_for_account = exists(
                select(AdminOperationRow.operation_id).where(
                    AdminOperationRow.account_id == AccountRow.account_id,
                    eligible,
                )
            )
            fresh_running_for_account = exists(
                select(AdminOperationRow.operation_id).where(
                    AdminOperationRow.account_id == AccountRow.account_id,
                    AdminOperationRow.status == "running",
                    AdminOperationRow.started_at.is_not(None),
                    AdminOperationRow.started_at >= stale_before,
                )
            )
            earliest_pending_at = (
                select(func.min(AdminOperationRow.created_at))
                .where(
                    AdminOperationRow.account_id == AccountRow.account_id,
                    eligible,
                )
                .scalar_subquery()
            )
            account = (
                await session.execute(
                    select(AccountRow)
                    .where(pending_for_account, ~fresh_running_for_account)
                    .order_by(earliest_pending_at, AccountRow.account_id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
            if account is None:
                break

            operation = (
                await session.execute(
                    select(AdminOperationRow)
                    .where(
                        AdminOperationRow.account_id == account.account_id,
                        eligible,
                    )
                    .order_by(
                        case((AdminOperationRow.status == "running", 0), else_=1),
                        AdminOperationRow.created_at,
                    )
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
            if operation is None:
                break
            operation.status = "running"
            operation.started_at = _now()
            operation.completed_at = None
            operation.error = None
            operation_id = operation.operation_id
            await session.commit()

        try:
            progress = await _apply_account_operation(session_factory, orchestrator, operation_id)
        except Exception as exc:
            log.exception("admin_operation_failed", operation_id=operation_id)
            async with session_factory() as session:
                current = await session.get(AdminOperationRow, operation_id)
                if current is not None:
                    current.status = "failed"
                    current.error = str(exc)[:2000]
                    current.completed_at = _now()
                    await session.commit()
        else:
            async with session_factory() as session:
                current = await session.get(AdminOperationRow, operation_id)
                if current is not None:
                    current.status = "completed"
                    current.progress = progress
                    current.error = None
                    current.completed_at = _now()
                    await session.commit()
        processed += 1
    return processed


async def _apply_account_operation(
    session_factory: async_sessionmaker[AsyncSession],
    orchestrator: Orchestrator,
    operation_id: str,
) -> dict[str, int]:
    async with session_factory() as session:
        operation = await session.get(AdminOperationRow, operation_id)
        if operation is None:
            raise RuntimeError("admin operation disappeared")
        kind = operation.kind
        account_id = operation.account_id
        actor_id = operation.actor_account_id
        vms = list(await session.scalars(select(VMRow).where(VMRow.owner_account_id == account_id)))
        mailboxes = list(
            await session.scalars(
                select(MailAccountRow).where(MailAccountRow.owner_account_id == account_id)
            )
        )

    if kind not in {"suspend_account_resources", "resume_account_resources"}:
        raise RuntimeError(f"unsupported admin operation: {kind}")

    vm_count = 0
    mail_count = 0
    now = _now()
    if kind == "suspend_account_resources":
        for vm in vms:
            if str(vm.status) in {
                VMStatus.DESTROYED.value,
                VMStatus.FAILED.value,
                VMStatus.SUSPENDED.value,
            }:
                continue
            if vm.xcpng_uuid:
                await orchestrator.xcpng.suspend_vm(vm.xcpng_uuid)
            async with session_factory() as session:
                current = await session.get(VMRow, vm.vm_id)
                if current is not None and str(current.status) not in {
                    VMStatus.DESTROYED.value,
                    VMStatus.FAILED.value,
                    VMStatus.SUSPENDED.value,
                }:
                    current.status = VMStatus.SUSPENDED
                    current.suspension_reason = "account_disabled"
                    current.suspended_by_account_id = actor_id
                    await session.commit()
                    vm_count += 1
        async with session_factory() as session:
            for mailbox in mailboxes:
                current = await session.get(MailAccountRow, mailbox.mailbox_id)
                if current is not None and current.status != "suspended":
                    current.status = "suspended"
                    current.suspension_reason = "account_disabled"
                    current.suspended_by_account_id = actor_id
                    mail_count += 1
            await session.commit()
    else:
        for vm in vms:
            if vm.suspension_reason != "account_disabled":
                continue
            if vm.expires_at is not None and _aware(vm.expires_at) <= now:
                async with session_factory() as session:
                    current = await session.get(VMRow, vm.vm_id)
                    if current is not None:
                        current.suspension_reason = "expired"
                        current.suspended_by_account_id = None
                        await session.commit()
                continue
            if vm.xcpng_uuid:
                await orchestrator.xcpng.start_vm(vm.xcpng_uuid)
            async with session_factory() as session:
                current = await session.get(VMRow, vm.vm_id)
                if current is not None and current.suspension_reason == "account_disabled":
                    current.status = VMStatus.RUNNING
                    current.suspension_reason = None
                    current.suspended_by_account_id = None
                    await session.commit()
                    vm_count += 1
        async with session_factory() as session:
            for mailbox in mailboxes:
                current = await session.get(MailAccountRow, mailbox.mailbox_id)
                if current is not None and current.suspension_reason == "account_disabled":
                    current.status = "active"
                    current.suspension_reason = None
                    current.suspended_by_account_id = None
                    mail_count += 1
            await session.commit()
    return {"vms": vm_count, "mailboxes": mail_count}
