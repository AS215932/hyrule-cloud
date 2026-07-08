"""Refund obligations for paid VMs that fail to provision.

The x402 charge settles at create time; provisioning can fail minutes later. A
paid VM that never came up owes the customer a refund, and that obligation must
be recorded (payer + amount + original tx) so it is actually paid back rather
than left as an empty "will be refunded" promise.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, PaymentEventRow, VMRow
from hyrule_cloud.models import VMSize, VMStatus
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.services.refunds import RefundService


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _events(factory) -> list[PaymentEventRow]:
    async with factory() as session:
        return list((await session.execute(select(PaymentEventRow))).scalars())


@pytest.mark.asyncio
async def test_refund_service_records_owed(session_factory) -> None:
    svc = RefundService(PaymentLedger(session_factory))

    recorded = await svc.record_owed(
        resource_path="/v1/vm/create",
        payer="0xPayer",
        amount=Decimal("0.05"),
        original_tx="0xCHARGE",
        reason="MEMORY_CONSTRAINT_VIOLATION_ORDER",
        vm_id="vm_x",
    )

    assert recorded is True
    events = await _events(session_factory)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "refund_owed"
    assert event.service_group == "vm"
    assert event.payer_wallet == "0xPayer"
    assert event.amount_usd == Decimal("0.05")
    assert event.tx_hash == "0xCHARGE"
    assert event.extra["vm_id"] == "vm_x"


@pytest.mark.asyncio
async def test_refund_service_skips_when_unpaid(session_factory) -> None:
    svc = RefundService(PaymentLedger(session_factory))

    # No wallet, zero amount, or missing amount => nothing was charged.
    assert (
        await svc.record_owed(
            resource_path="/v1/vm/create",
            payer="",
            amount=Decimal("0"),
            original_tx=None,
            reason="boom",
        )
        is False
    )
    assert (
        await svc.record_owed(
            resource_path="/v1/vm/create",
            payer=None,
            amount=Decimal("0.05"),
            original_tx=None,
            reason="boom",
        )
        is False
    )
    assert await _events(session_factory) == []


def _paid_provisioning_vm(vm_id: str, *, wallet: str, tx: str | None, cost: str) -> VMRow:
    return VMRow(
        vm_id=vm_id,
        owner_wallet=wallet,
        status=VMStatus.PROVISIONING,
        size=VMSize.XS,
        os="nonexistent-template",  # forces "Unknown OS template" -> provision failure
        ssh_pubkey="ssh-ed25519 AAAA test",
        open_ports=[22],
        cost_total=Decimal(cost),
        payment_tx=tx,
    )


@pytest.mark.asyncio
async def test_failed_paid_vm_records_refund_owed(session_factory, monkeypatch) -> None:
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_refundme", wallet="0xPayer", tx="0xCHARGE", cost="0.05"))
        await session.commit()

    await orch._provision_vm("vm_refundme")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_refundme")
        assert row.status == VMStatus.FAILED
    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].payer_wallet == "0xPayer"
    assert owed[0].amount_usd == Decimal("0.05")
    assert owed[0].tx_hash == "0xCHARGE"
    assert owed[0].service_group == "vm"


@pytest.mark.asyncio
async def test_failed_free_vm_records_no_refund(session_factory, monkeypatch) -> None:
    """A free subdomain VM (no wallet, nothing charged) must not create a
    phantom refund obligation when it fails."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_free", wallet="", tx=None, cost="0"))
        await session.commit()

    await orch._provision_vm("vm_free")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_free")
        assert row.status == VMStatus.FAILED
    assert [e for e in await _events(session_factory) if e.event_type == "refund_owed"] == []
