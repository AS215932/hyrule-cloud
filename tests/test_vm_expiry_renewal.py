"""Renewal must win over an expiry sweep that read an older deadline."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.orchestrator import Orchestrator


@pytest.mark.asyncio
@pytest.mark.parametrize("expired_days", [1, 3])
async def test_committed_renewal_is_rechecked_before_expiry_action(expired_days):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    vm_id = "vm_renewed_before_action"
    async with sessions() as session:
        session.add(VMRow(
            vm_id=vm_id, owner_wallet="test-owner", status=VMStatus.RUNNING,
            xcpng_uuid="test-guest", ssh_pubkey="ssh-ed25519 test",
            expires_at=now - timedelta(days=expired_days),
        ))
        await session.commit()

    # Commit a renewal as the sweep closes the transaction that selected its
    # candidates. This models a separate API process, without touching a guest.
    class RenewAfterSelection:
        def __init__(self):
            self.session = sessions()
            self.selected = False

        async def __aenter__(self):
            await self.session.__aenter__()
            original_execute = self.session.execute

            async def execute(statement, *args, **kwargs):
                result = await original_execute(statement, *args, **kwargs)
                if "vms.expires_at <" in str(statement):
                    self.selected = True
                return result

            self.session.execute = execute
            return self.session

        async def __aexit__(self, *args):
            await self.session.__aexit__(*args)
            if self.selected:
                async with sessions() as renewal:
                    row = await renewal.get(VMRow, vm_id)
                    row.expires_at = now + timedelta(days=30)
                    await renewal.commit()

    orch = object.__new__(Orchestrator)
    orch.db = RenewAfterSelection
    orch.config = SimpleNamespace(vm_grace_period_hours=48)
    orch.xcpng = SimpleNamespace(suspend_vm=AsyncMock(), destroy_vm=AsyncMock())
    try:
        await orch.check_expiries()
        orch.xcpng.suspend_vm.assert_not_awaited()
        orch.xcpng.destroy_vm.assert_not_awaited()
        async with sessions() as session:
            row = await session.get(VMRow, vm_id)
            assert row.status == VMStatus.RUNNING
    finally:
        await engine.dispose()


async def _stored_vm(status=VMStatus.RUNNING):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        session.add(VMRow(
            vm_id="vm_lifecycle", owner_wallet="test-owner", status=status,
            xcpng_uuid="test-guest", ssh_pubkey="ssh-ed25519 test",
            expires_at=datetime.now(UTC) - timedelta(days=3),
        ))
        await session.commit()
    orch = object.__new__(Orchestrator)
    orch.db = sessions
    orch.config = SimpleNamespace(vm_grace_period_hours=48)
    orch.xcpng = SimpleNamespace(
        destroy_vm=AsyncMock(), suspend_vm=AsyncMock(),
        get_vm_power_state=AsyncMock(return_value="Halted"), start_vm=AsyncMock(),
    )
    return orch, engine


@pytest.mark.asyncio
async def test_failed_delete_retains_claim_and_refuses_renewal_after_restart():
    orch, engine = await _stored_vm()
    orch.xcpng.destroy_vm.side_effect = RuntimeError("provider unavailable")
    try:
        with pytest.raises(RuntimeError, match="provider unavailable"):
            await orch.destroy_vm("vm_lifecycle")
        restarted = object.__new__(Orchestrator)
        restarted.db = orch.db
        async with restarted.locked_vm("vm_lifecycle") as (_, row):
            assert row.deletion_started_at is not None
            assert not restarted.vm_can_extend(row)
        assert await restarted.extend_vm("vm_lifecycle", 5) is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_failed_resume_preserves_committed_extension():
    orch, engine = await _stored_vm(VMStatus.SUSPENDED)
    orch.xcpng.start_vm.side_effect = RuntimeError("provider unavailable")
    before = datetime.now(UTC)
    try:
        updated = await orch.extend_vm("vm_lifecycle", 5)
        assert updated is not None and updated.status == VMStatus.SUSPENDED
        async with orch.db() as session:
            row = await session.get(VMRow, "vm_lifecycle")
            assert row.expires_at.replace(tzinfo=UTC) >= before + timedelta(days=5)
            assert row.status == VMStatus.SUSPENDED
            assert row.deletion_started_at is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_failed_suspend_is_not_recorded_as_suspended():
    orch, engine = await _stored_vm()
    async with orch.db() as session:
        row = await session.get(VMRow, "vm_lifecycle")
        row.expires_at = datetime.now(UTC) - timedelta(hours=1)
        await session.commit()
    orch.xcpng.suspend_vm.side_effect = RuntimeError("provider unavailable")
    try:
        await orch.check_expiries()
        async with orch.db() as session:
            row = await session.get(VMRow, "vm_lifecycle")
            assert row.status == VMStatus.RUNNING
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_destroyed_vm_retries_quarantined_dns_cleanup_without_deleting_again():
    orch, engine = await _stored_vm()
    orch.dns = SimpleNamespace(delete_aaaa=AsyncMock(side_effect=RuntimeError("DNS unavailable")))
    async with orch.db() as session:
        row = await session.get(VMRow, "vm_lifecycle")
        row.hostname = "test.deploy.hyrule.host"
        row.ipv6_prefix_index = 5
        row.ipv6_prefix = "2001:db8:5::/64"
        await session.commit()
    try:
        assert await orch.destroy_vm("vm_lifecycle")
        async with orch.db() as session:
            row = await session.get(VMRow, "vm_lifecycle")
            assert row.status == VMStatus.DESTROYED
            assert row.ipv6_prefix_index == 5
        orch.dns.delete_aaaa.side_effect = None
        assert await orch.destroy_vm("vm_lifecycle")
        orch.xcpng.destroy_vm.assert_awaited_once()
        async with orch.db() as session:
            row = await session.get(VMRow, "vm_lifecycle")
            assert row.ipv6_prefix_index is None
            assert row.ipv6_prefix is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_worker_resumes_claim_even_before_original_expiry():
    orch, engine = await _stored_vm()
    async with orch.db() as session:
        row = await session.get(VMRow, "vm_lifecycle")
        row.expires_at = datetime.now(UTC) + timedelta(days=30)
        await session.commit()
    orch.xcpng.destroy_vm.side_effect = RuntimeError("provider unavailable")
    try:
        with pytest.raises(RuntimeError):
            await orch.destroy_vm("vm_lifecycle")
        orch.xcpng.destroy_vm.side_effect = None
        await orch.check_expiries()
        assert orch.xcpng.destroy_vm.await_count == 2
        async with orch.db() as session:
            row = await session.get(VMRow, "vm_lifecycle")
            assert row.status == VMStatus.DESTROYED
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("committed", [False, True])
async def test_extension_reconciles_lost_commit_acknowledgment(committed):
    from sqlalchemy import select

    from hyrule_cloud.db import PaymentEventRow

    orch, engine = await _stored_vm()
    try:
        async with orch.locked_vm("vm_lifecycle") as (session, row):
            old_expiry = row.expires_at
            real_commit = session.commit

            async def broken_commit():
                if committed:
                    await real_commit()
                raise ConnectionError("simulated lost commit acknowledgment")

            session.commit = broken_commit
            updated = await orch.extend_vm("vm_lifecycle", 5, session=session)
        async with orch.db() as check:
            stored = await check.get(VMRow, "vm_lifecycle")
            receipts = list(await check.scalars(select(PaymentEventRow)))
            if committed:
                assert updated is not None
                assert stored.expires_at > old_expiry
                assert len(receipts) == 1
                assert receipts[0].event_type == "extend_applied"
                assert receipts[0].amount_usd == 0
                assert receipts[0].extra["days"] == 5
            else:
                assert updated is None
                assert stored.expires_at == old_expiry
                assert receipts == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_extension_does_not_authorize_refund_when_reconciliation_fails():
    from hyrule_cloud.orchestrator import ExtensionOutcomeUnknownError

    orch, engine = await _stored_vm()
    try:
        async with orch.locked_vm("vm_lifecycle") as (session, _row):
            session.commit = AsyncMock(side_effect=ConnectionError("commit outcome unknown"))
            session.rollback = AsyncMock(side_effect=ConnectionError("connection unavailable"))
            with pytest.raises(ExtensionOutcomeUnknownError):
                await orch.extend_vm("vm_lifecycle", 5, session=session)
        orch.xcpng.start_vm.assert_not_awaited()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_owner_transfer_after_paid_commit_does_not_resume_guest():
    orch, engine = await _stored_vm(VMStatus.SUSPENDED)
    try:
        async with orch.locked_vm("vm_lifecycle") as (session, _row):
            commit = session.commit

            async def commit_then_transfer():
                await commit()
                async with orch.db() as transfer:
                    row = await transfer.get(VMRow, "vm_lifecycle")
                    row.owner_wallet = "new-owner"
                    await transfer.commit()

            session.commit = commit_then_transfer
            updated = await orch.extend_vm("vm_lifecycle", 5, session=session)
        assert updated is not None
        expiry = updated.expires_at.replace(tzinfo=UTC)
        assert expiry > datetime.now(UTC) + timedelta(days=4)
        assert updated.owner_wallet == "new-owner"
        orch.xcpng.start_vm.assert_not_awaited()
        assert updated.status == VMStatus.SUSPENDED
    finally:
        await engine.dispose()
