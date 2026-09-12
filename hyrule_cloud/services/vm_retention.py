"""Persist recovery evidence; no provider mutation or disk purging occurs here."""
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import VMRestoreRow, VMRetentionRow, VMRow
from hyrule_cloud.providers.xcpng import VMProtectionManifest


async def prepare_retention(
    session: AsyncSession, vm_id: str, manifest: VMProtectionManifest, retain_until: datetime,
) -> VMRetentionRow:
    """Lock the resource and stage an immutable manifest in the caller's transaction.

    The caller must commit before any provider delete and coordinate the expiry
    deletion claim. This function alone does not authorize a provider action.
    """
    vm = await session.scalar(select(VMRow).where(VMRow.vm_id == vm_id).with_for_update())
    if vm is None:
        raise ValueError("VM is unavailable for retention preparation")
    payload = {"version": 2, "mode": "whole_vm", **asdict(manifest)}
    payload = json.loads(json.dumps(payload))
    existing = await session.get(VMRetentionRow, vm_id)
    if existing is not None:
        if existing.manifest != payload:
            raise ValueError("Retention manifest cannot be replaced")
        return existing
    if vm.xcpng_uuid != manifest.vm_uuid or not manifest.disk_ids or not vm.owner_wallet:
        raise ValueError("Retention identity is incomplete or mismatched")
    if retain_until.tzinfo is None or retain_until <= datetime.now(UTC):
        raise ValueError("Retention requires a future timezone-aware deadline")
    record = VMRetentionRow(
        vm_id=vm_id, source_vm_uuid=manifest.vm_uuid,
        owner_account_id=vm.owner_account_id, owner_wallet=vm.owner_wallet,
        manifest=payload, retain_until=retain_until,
        restore_config={"os": vm.os, "vcpu": vm.vcpu, "memory_mb": vm.memory_mb,
                        "disk_gb": vm.disk_gb, "ssh_pubkey": vm.ssh_pubkey},
    )
    session.add(record)
    await session.flush()
    return record


def stored_manifest(record: VMRetentionRow) -> VMProtectionManifest:
    payload = record.manifest
    if (payload.get("version") != 2 or payload.get("mode") != "whole_vm"
            or payload.get("vm_uuid") != record.source_vm_uuid):
        raise ValueError("Unsupported or mismatched retention manifest")
    fields = {key: value for key, value in payload.items() if key not in {"version", "mode"}}
    for key in ("disk_ids", "snapshot_ids"):
        fields[key] = tuple(fields[key])
    fields["blocked_operations"] = tuple(tuple(pair) for pair in fields["blocked_operations"])
    manifest = VMProtectionManifest(**fields)
    if not manifest.disk_ids:
        raise ValueError("Empty retention manifest")
    return manifest


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


async def prepare_restore(
    session: AsyncSession, vm: VMRow, *, operation_id: str, actor_account_id: str,
    days: int, reason: str,
) -> VMRestoreRow:
    """Stage recovery under the caller's account/VM lock; audit and commit next.

    The fixed expiry and retained evidence make replay independent of wall time.
    No provider call is authorized until this transaction is committed.
    """
    existing = await session.get(VMRestoreRow, operation_id)
    if existing is not None:
        if (existing.vm_id, existing.days, existing.reason) != (vm.vm_id, days, reason):
            raise ValueError("Restore operation ID was already used for another request")
        return existing
    retained = await session.get(VMRetentionRow, vm.vm_id)
    if (retained is None or retained.state != "retained" or retained.restore_operation_id is not None
            or vm.deletion_started_at is None or vm.xcpng_uuid != retained.source_vm_uuid
            or vm.owner_account_id != retained.owner_account_id or vm.owner_wallet != retained.owner_wallet
            or vm.expires_at is None or not 1 <= days <= 365 or not reason.strip()):
        raise ValueError("VM is not eligible for retained recovery")
    snapshot = {
        "previous_expiry": _aware(vm.expires_at).isoformat(),
        "source_vm_uuid": retained.source_vm_uuid,
        "owner_account_id": retained.owner_account_id, "owner_wallet": retained.owner_wallet,
        "manifest": retained.manifest, "restore_config": retained.restore_config,
        "retain_until": _aware(retained.retain_until).isoformat(),
        "created_at": _aware(retained.created_at).isoformat(),
        "retained_at": _aware(retained.retained_at).isoformat() if retained.retained_at else None,
    }
    operation = VMRestoreRow(
        operation_id=operation_id, vm_id=vm.vm_id, actor_account_id=actor_account_id,
        days=days, reason=reason, retention_snapshot=snapshot,
        new_expiry=max(_aware(vm.expires_at), datetime.now(UTC)) + timedelta(days=days),
    )
    session.add(operation)
    retained.state = "restoring"
    retained.restore_operation_id = operation_id
    await session.flush()
    return operation


async def authorize_restore(session: AsyncSession, vm: VMRow, operation: VMRestoreRow) -> None:
    """Commit a usable expiry before allowing provider restart settings to change.

    Keep the deletion claim and active evidence until provider finalization.
    The caller must audit and commit this transition before any provider write.
    """
    retained = await session.get(VMRetentionRow, vm.vm_id)
    if (operation.state != "pending" or operation.vm_id != vm.vm_id or retained is None
            or retained.state != "restoring" or retained.restore_operation_id != operation.operation_id
            or vm.deletion_started_at is None or vm.xcpng_uuid != retained.source_vm_uuid
            or vm.owner_account_id != retained.owner_account_id or vm.owner_wallet != retained.owner_wallet
            or vm.expires_at is None
            or _aware(vm.expires_at) != _aware(datetime.fromisoformat(operation.retention_snapshot["previous_expiry"]))
            or _aware(operation.new_expiry) <= datetime.now(UTC)):
        raise ValueError("Recovery identity or authorization deadline changed")
    vm.expires_at = operation.new_expiry
    vm.suspension_reason = "manual_admin"
    vm.suspended_by_account_id = operation.actor_account_id
    operation.state = "authorized"
    await session.flush()


async def complete_restore(session: AsyncSession, vm: VMRow, operation: VMRestoreRow) -> None:
    """Finalize after provider verification, under the same lifecycle lock.

    Historical evidence stays in the operation; removing only the active record
    allows a later expiry cycle to capture fresh protection and deadlines.
    """
    retained = await session.get(VMRetentionRow, vm.vm_id)
    if (operation.state != "authorized" or operation.vm_id != vm.vm_id or retained is None
            or retained.state != "restoring" or retained.restore_operation_id != operation.operation_id
            or vm.deletion_started_at is None or vm.xcpng_uuid != retained.source_vm_uuid
            or vm.owner_account_id != retained.owner_account_id or vm.owner_wallet != retained.owner_wallet):
        raise ValueError("Recovery identity or state changed")
    vm.expires_at = operation.new_expiry
    vm.deletion_started_at = None
    # Recovery is deliberately stopped. A delayed account-enable job must not
    # interpret old disable provenance as permission to start this guest.
    vm.suspension_reason = "manual_admin"
    vm.suspended_by_account_id = operation.actor_account_id
    operation.state = "completed"
    operation.completed_at = datetime.now(UTC)
    await session.delete(retained)
    await session.flush()
