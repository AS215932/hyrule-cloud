"""Refund obligations for paid VMs that fail to provision.

The x402 charge settles at create time; provisioning can fail minutes later. A
paid VM that never came up owes the customer a refund, and that obligation must
be recorded (payer + amount + original tx) so it is actually paid back rather
than left as an empty "will be refunded" promise.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, CryptoIntentRow, PaymentEventRow, VMRow
from hyrule_cloud.models import CryptoIntentStatus, VMSize, VMStatus
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


EVM_WALLET = "0x" + "ab" * 20  # 0x + 40 hex == a real EVM refund address
NATIVE_DEPOSIT_ADDR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BTC, not a refund dest


def _looks_like_evm_wallet_import():
    from hyrule_cloud.orchestrator import _looks_like_evm_wallet

    return _looks_like_evm_wallet


def test_looks_like_evm_wallet() -> None:
    is_evm = _looks_like_evm_wallet_import()
    assert is_evm(EVM_WALLET) is True
    assert is_evm(NATIVE_DEPOSIT_ADDR) is False  # native deposit address
    assert is_evm("0xPayer") is False  # too short
    assert is_evm("0x" + "zz" * 20) is False  # not hex
    assert is_evm("") is False
    assert is_evm(None) is False


async def _seed_settled(factory, *, tx: str, amount: str, network: str, asset: str, payer: str) -> None:
    """Write the settled x402 event that check_payment records at VM create."""
    await PaymentLedger(factory).record_event(
        event_type="settled",
        resource_path="/v1/vm/create",
        method="POST",
        amount=Decimal(amount),
        network=network,
        asset=asset,
        payer=payer,
        tx_hash=tx,
    )


@pytest.mark.asyncio
async def test_failed_paid_vm_refunds_from_settled_ledger(session_factory, monkeypatch) -> None:
    """The refund uses the authoritative settled charge (amount + network +
    asset + payer wallet), NOT the recomputed VMRow.cost_total."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    await _seed_settled(
        session_factory,
        tx="0xCHARGE",
        amount="0.05",
        network="base-sepolia",
        asset="USDC",
        payer=EVM_WALLET,
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        # cost_total deliberately differs from the settled amount (e.g. a price
        # change between charge and failure) — the refund must follow the charge.
        session.add(_paid_provisioning_vm("vm_refundme", wallet=EVM_WALLET, tx="0xCHARGE", cost="0.10"))
        await session.commit()

    await orch._provision_vm("vm_refundme")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_refundme")
        assert row.status == VMStatus.FAILED
    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].payer_wallet == EVM_WALLET
    assert owed[0].amount_usd == Decimal("0.05")  # settled amount, not cost_total 0.10
    assert owed[0].network == "base-sepolia"
    assert owed[0].asset == "USDC"
    assert owed[0].tx_hash == "0xCHARGE"
    assert owed[0].service_group == "vm"


@pytest.mark.asyncio
async def test_failed_native_intent_vm_records_manual_refund(session_factory, monkeypatch) -> None:
    """A native BTC/XMR intent VM that fails AFTER being marked PROVISIONED must
    flip its intent to REFUND_MANUAL and record the owed refund (network=native,
    asset+amount from the intent). The x402 skip must not silently drop the debt
    of a paying native customer."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(
            _paid_provisioning_vm("vm_native", wallet=NATIVE_DEPOSIT_ADDR, tx="btc-txid-abc", cost="0.05")
        )
        session.add(
            CryptoIntentRow(
                intent_id="int_native1",
                asset="BTC",
                amount_crypto=Decimal("0.0001"),
                amount_usd=Decimal("0.05"),
                address=NATIVE_DEPOSIT_ADDR,
                status=CryptoIntentStatus.PROVISIONED,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                vm_id="vm_native",
                tx_hash="btc-txid-abc",
            )
        )
        await session.commit()

    await orch._provision_vm("vm_native")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_native")
        assert row.status == VMStatus.FAILED
        intent = await session.get(CryptoIntentRow, "int_native1")
        assert intent.status == CryptoIntentStatus.REFUND_MANUAL
    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].network == "native"
    assert owed[0].asset == "BTC"
    assert owed[0].amount_usd == Decimal("0.05")
    assert owed[0].payer_wallet == NATIVE_DEPOSIT_ADDR


@pytest.mark.asyncio
async def test_failed_evm_vm_without_settled_row_falls_back_to_cost(session_factory, monkeypatch) -> None:
    """If the settled ledger write was lost, an EVM payer still gets a refund
    obligation from the VM's recorded cost (best-effort, never lose the debt)."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_evm", wallet=EVM_WALLET, tx="0xLOST", cost="0.05"))
        await session.commit()

    await orch._provision_vm("vm_evm")

    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].payer_wallet == EVM_WALLET
    assert owed[0].amount_usd == Decimal("0.05")
    assert owed[0].tx_hash == "0xLOST"


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
