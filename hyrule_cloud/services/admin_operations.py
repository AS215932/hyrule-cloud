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
            await _apply_account_operation(session_factory, orchestrator, operation_id)
        except Exception as exc:
            log.exception("admin_operation_failed", operation_id=operation_id)
            # Validation failures that occur before the account lease is
            # acquired (or a failed terminal-status commit) still need a
            # durable failure marker. Normal provider failures are already
            # finalized under the lease and leave this branch as a no-op.
            async with session_factory() as session:
                current = (
                    await session.execute(
                        select(AdminOperationRow)
                        .where(AdminOperationRow.operation_id == operation_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if current is not None and current.status == "running":
                    current.status = "failed"
                    current.error = str(exc)[:2000]
                    current.completed_at = _now()
                    await session.commit()
        processed += 1
    return processed


async def _apply_account_operation(
    session_factory: async_sessionmaker[AsyncSession],
    orchestrator: Orchestrator,
    operation_id: str,
) -> dict[str, int]:
    # Retain the account row lock for the full provider/database operation. It
    # is both the account-state fence (enable/disable cannot change underneath
    # this worker) and the exclusive lease: another worker's SKIP LOCKED claim
    # cannot reclaim this operation merely because it legitimately runs longer
    # than the 15-minute crash-recovery threshold. A dead worker releases the
    # transaction lock when its connection closes, after which stale recovery
    # remains available.
    async with session_factory() as lease_session:
        operation = await lease_session.get(AdminOperationRow, operation_id)
        if operation is None:
            raise RuntimeError("admin operation disappeared")
        kind = operation.kind
        account_id = operation.account_id
        actor_id = operation.actor_account_id
        if kind not in {"suspend_account_resources", "resume_account_resources"}:
            raise RuntimeError(f"unsupported admin operation: {kind}")

        account = (
            await lease_session.execute(
                select(AccountRow)
                .where(AccountRow.account_id == account_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if account is None:
            raise RuntimeError("admin operation account disappeared")

        operation_matches_state = (
            kind == "suspend_account_resources" and account.disabled_at is not None
        ) or (kind == "resume_account_resources" and account.disabled_at is None)
        try:
            if not operation_matches_state:
                # A newer inverse operation won the account-state transition
                # before this queued operation ran. Completing it as a no-op
                # preserves queue ordering without acting against current state.
                progress = {"vms": 0, "mailboxes": 0}
            else:
                vms = list(
                    await lease_session.scalars(
                        select(VMRow).where(VMRow.owner_account_id == account_id)
                    )
                )
                mailboxes = list(
                    await lease_session.scalars(
                        select(MailAccountRow).where(
                            MailAccountRow.owner_account_id == account_id
                        )
                    )
                )
                progress = await _apply_locked_account_operation(
                    session_factory,
                    orchestrator,
                    kind=kind,
                    account_id=account_id,
                    actor_id=actor_id,
                    vms=vms,
                    mailboxes=mailboxes,
                )
        except Exception as exc:
            # Finalize while the account lease is still held. A second worker
            # cannot slip into the stale-claim window between the last provider
            # call and this durable terminal status.
            operation.status = "failed"
            operation.error = str(exc)[:2000]
            operation.completed_at = _now()
            await lease_session.commit()
            raise
        else:
            operation.status = "completed"
            operation.progress = progress
            operation.error = None
            operation.completed_at = _now()
            await lease_session.commit()
            return progress


async def _apply_locked_account_operation(
    session_factory: async_sessionmaker[AsyncSession],
    orchestrator: Orchestrator,
    *,
    kind: str,
    account_id: str,
    actor_id: str | None,
    vms: list[VMRow],
    mailboxes: list[MailAccountRow],
) -> dict[str, int]:
    vm_count = 0
    mail_count = 0
    now = _now()
    if kind == "suspend_account_resources":
        for vm in vms:
            async with session_factory() as session:
                current = (
                    await session.execute(
                        select(VMRow).where(VMRow.vm_id == vm.vm_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if current is None or current.owner_account_id != account_id:
                    continue
                if str(current.status) in {
                    VMStatus.DESTROYED.value,
                    VMStatus.FAILED.value,
                    VMStatus.SUSPENDED.value,
                }:
                    continue
                if str(current.status) != VMStatus.PROVISIONING.value and current.xcpng_uuid:
                    await orchestrator.xcpng.suspend_vm(current.xcpng_uuid)
                # A provisioner owns the PROVISIONING transition. Mark the
                # desired terminal state without making its initial guard exit;
                # finalization will suspend the new provider VM under the row lock.
                if str(current.status) != VMStatus.PROVISIONING.value:
                    current.status = VMStatus.SUSPENDED
                current.suspension_reason = "account_disabled"
                current.suspended_by_account_id = actor_id
                await session.commit()
                vm_count += 1
        async with session_factory() as session:
            for mailbox in mailboxes:
                mailbox_row = (
                    await session.execute(
                        select(MailAccountRow)
                        .where(MailAccountRow.mailbox_id == mailbox.mailbox_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    mailbox_row is not None
                    and mailbox_row.owner_account_id == account_id
                    and mailbox_row.status != "suspended"
                ):
                    mailbox_row.status = "suspended"
                    mailbox_row.suspension_reason = "account_disabled"
                    mailbox_row.suspended_by_account_id = actor_id
                    mail_count += 1
            await session.commit()
    else:
        for vm in vms:
            restart_provisioning = False
            async with session_factory() as session:
                current = (
                    await session.execute(
                        select(VMRow).where(VMRow.vm_id == vm.vm_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    current is None
                    or current.owner_account_id != account_id
                    or current.suspension_reason != "account_disabled"
                ):
                    continue
                if str(current.status) in {
                    VMStatus.DESTROYED.value,
                    VMStatus.FAILED.value,
                }:
                    # A provisioning failure can retain the disable marker and
                    # even a provider UUID. Terminal rows may already carry a
                    # refund obligation and must never be revived by enable.
                    continue
                if current.expires_at is not None and _aware(current.expires_at) <= now:
                    current.suspension_reason = "expired"
                    current.suspended_by_account_id = None
                    await session.commit()
                    continue
                if str(current.status) == VMStatus.PROVISIONING.value:
                    # The existing provisioner will observe the cleared marker
                    # and complete normally; do not invent a RUNNING row before
                    # a provider UUID exists.
                    current.suspension_reason = None
                    current.suspended_by_account_id = None
                elif current.xcpng_uuid:
                    await orchestrator.xcpng.start_vm(current.xcpng_uuid)
                    current.status = VMStatus.RUNNING
                    current.suspension_reason = None
                    current.suspended_by_account_id = None
                else:
                    # Recover a legacy row that was incorrectly suspended before
                    # provider creation by returning it to the provision queue.
                    current.status = VMStatus.PROVISIONING
                    current.suspension_reason = None
                    current.suspended_by_account_id = None
                    current.error = None
                    restart_provisioning = True
                await session.commit()
                vm_count += 1
            if restart_provisioning:
                orchestrator.start_provisioning(vm.vm_id)
        async with session_factory() as session:
            for mailbox in mailboxes:
                mailbox_row = (
                    await session.execute(
                        select(MailAccountRow)
                        .where(MailAccountRow.mailbox_id == mailbox.mailbox_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    mailbox_row is not None
                    and mailbox_row.owner_account_id == account_id
                    and mailbox_row.suspension_reason == "account_disabled"
                ):
                    if (
                        mailbox_row.expires_at is not None
                        and _aware(mailbox_row.expires_at) <= now
                    ):
                        mailbox_row.status = "suspended"
                        mailbox_row.suspension_reason = "expired"
                    else:
                        mailbox_row.status = "active"
                        mailbox_row.suspension_reason = None
                        mail_count += 1
                    mailbox_row.suspended_by_account_id = None
            await session.commit()
    return {"vms": vm_count, "mailboxes": mail_count}
