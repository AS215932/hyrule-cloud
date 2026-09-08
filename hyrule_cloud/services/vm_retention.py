"""Persist recovery evidence; no provider mutation or disk purging occurs here."""
from dataclasses import asdict
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import VMRetentionRow, VMRow
from hyrule_cloud.providers.xcpng import RetainedDisk, VMRetentionManifest


async def prepare_retention(
    session: AsyncSession, vm_id: str, manifest: VMRetentionManifest, retain_until: datetime,
) -> VMRetentionRow:
    """Lock the resource and stage an immutable manifest in the caller's transaction.

    The caller must commit before any provider delete and coordinate the expiry
    deletion claim. This function alone does not authorize a provider action.
    """
    vm = await session.scalar(select(VMRow).where(VMRow.vm_id == vm_id).with_for_update())
    if vm is None:
        raise ValueError("VM is unavailable for retention preparation")
    payload = {"version": 1, "vm_uuid": manifest.vm_uuid,
               "disks": [asdict(disk) for disk in manifest.disks]}
    existing = await session.get(VMRetentionRow, vm_id)
    if existing is not None:
        if existing.manifest != payload:
            raise ValueError("Retention manifest cannot be replaced")
        return existing
    if vm.xcpng_uuid != manifest.vm_uuid or not manifest.disks or not vm.owner_wallet:
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


def stored_manifest(record: VMRetentionRow) -> VMRetentionManifest:
    payload = record.manifest
    if payload.get("version") != 1 or payload.get("vm_uuid") != record.source_vm_uuid:
        raise ValueError("Unsupported or mismatched retention manifest")
    disks = tuple(RetainedDisk(**disk) for disk in payload["disks"])
    if not disks:
        raise ValueError("Empty retention manifest")
    return VMRetentionManifest(record.source_vm_uuid, disks)
