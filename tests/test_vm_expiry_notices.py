"""Owner-facing expiry notices (issue #110).

A paid VM must never be suspended or (irreversibly) deleted without the owner
being warned first. These tests pin the pre-expiry warning, the suspend notice
and the pre-deletion last-call emitted by the expiry sweep onto the
customer-visible VM event log, and that each fires at most once per deadline.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import Base, VMEventRow, VMRow
from hyrule_cloud.models import VMEventKey, VMStatus
from hyrule_cloud.orchestrator import Orchestrator


def _config(**overrides):
    base = dict(
        vm_grace_period_hours=48,
        vm_expiry_warning_hours=[72, 24],
        vm_deletion_warning_hours=12,
        vm_expiry_retention_enabled=False,
        vm_retention_days=30,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


async def _orchestrator():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    orch = object.__new__(Orchestrator)
    orch.db = sessions
    orch.config = _config()
    orch.xcpng = SimpleNamespace(suspend_vm=AsyncMock(), destroy_vm=AsyncMock())
    return orch, sessions, engine


async def _events(sessions, vm_id, event):
    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(VMEventRow).where(
                    VMEventRow.vm_id == vm_id, VMEventRow.event == str(event)
                )
            )
        )
    return rows


@pytest.mark.asyncio
async def test_pre_expiry_warning_fires_once_per_deadline():
    orch, sessions, engine = await _orchestrator()
    now = datetime.now(UTC)
    vm_id = "vm_warn"
    async with sessions() as session:
        session.add(VMRow(
            vm_id=vm_id, owner_wallet="w", status=VMStatus.RUNNING,
            xcpng_uuid="g", ssh_pubkey="ssh-ed25519 t",
            expires_at=now + timedelta(hours=20),
        ))
        await session.commit()
    try:
        await orch._warn_upcoming_expiries(datetime.now(UTC))
        await orch._warn_upcoming_expiries(datetime.now(UTC))
        events = await _events(sessions, vm_id, VMEventKey.EXPIRY_WARNING)
        assert len(events) == 1
        assert events[0].detail["hours_remaining"] <= 20
        # Marker is keyed on the 24h threshold (most urgent crossed).
        async with sessions() as session:
            row = await session.get(VMRow, vm_id)
            assert "warn:24" in (row.metadata_ or {}).get("expiry_notices", {})
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_no_warning_before_window():
    orch, sessions, engine = await _orchestrator()
    now = datetime.now(UTC)
    async with sessions() as session:
        session.add(VMRow(
            vm_id="vm_far", owner_wallet="w", status=VMStatus.RUNNING,
            xcpng_uuid="g", ssh_pubkey="ssh-ed25519 t",
            expires_at=now + timedelta(hours=100),
        ))
        await session.commit()
    try:
        await orch._warn_upcoming_expiries(datetime.now(UTC))
        assert await _events(sessions, "vm_far", VMEventKey.EXPIRY_WARNING) == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_renewal_rearms_warning():
    orch, sessions, engine = await _orchestrator()
    now = datetime.now(UTC)
    vm_id = "vm_renew_warn"
    async with sessions() as session:
        session.add(VMRow(
            vm_id=vm_id, owner_wallet="w", status=VMStatus.RUNNING,
            xcpng_uuid="g", ssh_pubkey="ssh-ed25519 t",
            expires_at=now + timedelta(hours=20),
        ))
        await session.commit()
    try:
        await orch._warn_upcoming_expiries(datetime.now(UTC))
        assert len(await _events(sessions, vm_id, VMEventKey.EXPIRY_WARNING)) == 1
        # Renew: move the deadline out, then back near a new 20h expiry.
        async with sessions() as session:
            row = await session.get(VMRow, vm_id)
            row.expires_at = datetime.now(UTC) + timedelta(hours=20, minutes=5)
            await session.commit()
        await orch._warn_upcoming_expiries(datetime.now(UTC))
        # A new deadline re-arms the warning: a second event is emitted.
        assert len(await _events(sessions, vm_id, VMEventKey.EXPIRY_WARNING)) == 2
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_suspend_emits_notice():
    orch, sessions, engine = await _orchestrator()
    now = datetime.now(UTC)
    vm_id = "vm_suspend"
    async with sessions() as session:
        session.add(VMRow(
            vm_id=vm_id, owner_wallet="w", status=VMStatus.RUNNING,
            xcpng_uuid="g", ssh_pubkey="ssh-ed25519 t",
            expires_at=now - timedelta(hours=1),
        ))
        await session.commit()
    try:
        await orch.check_expiries()
        async with sessions() as session:
            row = await session.get(VMRow, vm_id)
            assert row.status == VMStatus.SUSPENDED
            assert row.suspension_reason == "expired"
        orch.xcpng.suspend_vm.assert_awaited_once_with("g")
        orch.xcpng.destroy_vm.assert_not_awaited()
        events = await _events(sessions, vm_id, VMEventKey.EXPIRY_SUSPENDED)
        assert len(events) == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_deletion_warning_inside_window_once():
    orch, sessions, engine = await _orchestrator()
    now = datetime.now(UTC)
    vm_id = "vm_predelete"
    # Grace is 48h; put us 6h from grace end (within the 12h warning window).
    async with sessions() as session:
        session.add(VMRow(
            vm_id=vm_id, owner_wallet="w", status=VMStatus.SUSPENDED,
            suspension_reason="expired", xcpng_uuid="g", ssh_pubkey="ssh-ed25519 t",
            expires_at=now - timedelta(hours=42),
        ))
        await session.commit()
    try:
        await orch.check_expiries()
        await orch.check_expiries()
        orch.xcpng.destroy_vm.assert_not_awaited()
        events = await _events(sessions, vm_id, VMEventKey.DELETION_WARNING)
        assert len(events) == 1
        assert events[0].detail["hours_remaining"] <= 12
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_no_deletion_warning_before_window():
    orch, sessions, engine = await _orchestrator()
    now = datetime.now(UTC)
    vm_id = "vm_early_suspended"
    # Just expired (46h to grace end) — outside the 12h deletion window.
    async with sessions() as session:
        session.add(VMRow(
            vm_id=vm_id, owner_wallet="w", status=VMStatus.SUSPENDED,
            suspension_reason="expired", xcpng_uuid="g", ssh_pubkey="ssh-ed25519 t",
            expires_at=now - timedelta(hours=2),
        ))
        await session.commit()
    try:
        await orch.check_expiries()
        assert await _events(sessions, vm_id, VMEventKey.DELETION_WARNING) == []
    finally:
        await engine.dispose()
