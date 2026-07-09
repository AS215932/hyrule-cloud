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
from hyrule_cloud.db import Base, CryptoIntentRow, PaymentEventRow, VMQuoteRow, VMRow
from hyrule_cloud.models import (
    CryptoIntentStatus,
    QuoteStatus,
    VMCreateRequest,
    VMSize,
    VMStatus,
)
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
    # payer is the bounded intent_id (deposit addresses — esp. XMR — can exceed
    # payer_wallet's width); the deposit address rides in extra.
    assert owed[0].payer_wallet == "int_native1"
    assert owed[0].extra["native_deposit_address"] == NATIVE_DEPOSIT_ADDR
    assert owed[0].extra["intent_id"] == "int_native1"


@pytest.mark.asyncio
async def test_long_xmr_deposit_address_records_refund(session_factory, monkeypatch) -> None:
    """A 95-char XMR deposit address must not overflow payer_wallet and silently
    drop the refund row — it goes in extra, with the bounded intent_id as payer."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    xmr_addr = "4" + "A" * 94  # 95 chars, longer than payer_wallet String(64)
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_xmr", wallet=xmr_addr, tx="xmr-txid", cost="0.05"))
        session.add(
            CryptoIntentRow(
                intent_id="int_xmr1",
                asset="XMR",
                amount_crypto=Decimal("0.0003"),
                amount_usd=Decimal("0.05"),
                address=xmr_addr,
                status=CryptoIntentStatus.PROVISIONED,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                vm_id="vm_xmr",
                tx_hash="xmr-txid",
            )
        )
        await session.commit()

    await orch._provision_vm("vm_xmr")

    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].payer_wallet == "int_xmr1"  # bounded, not the 95-char address
    assert owed[0].extra["native_deposit_address"] == xmr_addr


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


@pytest.mark.asyncio
async def test_create_vm_can_defer_provisioning(session_factory, monkeypatch) -> None:
    """create_vm(start_provisioning=False) inserts the row WITHOUT spawning the
    background task, so a native intent can link its vm_id before provisioning
    can fail; start_provisioning(vm_id) then kicks it off explicitly."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: False
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    spawned: list[str] = []
    monkeypatch.setattr(orch, "_spawn_provisioning", lambda vm_id: spawned.append(vm_id))
    order = VMCreateRequest(duration_days=1, size=VMSize.XS, os="debian-13", ssh_pubkey="ssh-ed25519 AAAA test")

    row, _ = await orch.create_vm(order, owner_wallet=EVM_WALLET, start_provisioning=False)
    assert spawned == []  # deferred — nothing provisioning yet

    orch.start_provisioning(row.vm_id)
    assert spawned == [row.vm_id]  # explicit start works


@pytest.mark.asyncio
async def test_native_refund_surfaces_received_crypto_amount(session_factory, monkeypatch) -> None:
    """A native intent accepted via overpayment stores amount_received_crypto
    (what the customer actually sent on-chain). A manual refund would be short if
    the worklist showed only the quote, so the received amount rides in extra."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(
            _paid_provisioning_vm("vm_over", wallet=NATIVE_DEPOSIT_ADDR, tx="btc-over", cost="0.05")
        )
        session.add(
            CryptoIntentRow(
                intent_id="int_over1",
                asset="BTC",
                amount_crypto=Decimal("0.0001"),  # quoted
                amount_received_crypto=Decimal("0.00025"),  # customer overpaid on-chain
                amount_usd=Decimal("0.05"),
                address=NATIVE_DEPOSIT_ADDR,
                status=CryptoIntentStatus.PROVISIONED,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                vm_id="vm_over",
                tx_hash="btc-over",
            )
        )
        await session.commit()

    await orch._provision_vm("vm_over")

    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    # The actual on-chain amount, not just the quote, is available to the operator
    # (stored as a string; DB Numeric(24,12) pads scale, so compare numerically).
    assert Decimal(owed[0].extra["amount_received_crypto"]) == Decimal("0.00025")


@pytest.mark.asyncio
async def test_evm_fallback_prefers_quote_amount_over_cost_total(session_factory, monkeypatch) -> None:
    """When the settled ledger row was lost, a quote-bound VM's refund must use
    the locked quote amount actually charged, not the VM's recomputed cost_total
    (they diverge if pricing changed during the quote TTL)."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    order = VMCreateRequest(
        duration_days=1, size=VMSize.XS, os="debian-13", ssh_pubkey="ssh-ed25519 AAAA test"
    )
    async with session_factory() as session:
        # cost_total (recomputed) is 0.10, but the locked quote charged 0.05.
        session.add(_paid_provisioning_vm("vm_q", wallet=EVM_WALLET, tx="0xLOST2", cost="0.10"))
        session.add(
            VMQuoteRow(
                quote_id="q_locked",
                order_payload=order.model_dump(mode="json"),
                amount_usd=Decimal("0.05"),
                status=QuoteStatus.CREATED,
                vm_id="vm_q",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        await session.commit()

    await orch._provision_vm("vm_q")

    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].amount_usd == Decimal("0.05")  # locked quote, not cost_total 0.10


@pytest.mark.asyncio
async def test_settled_refund_without_payer_still_records(session_factory, monkeypatch) -> None:
    """If the SDK settles but exposes no payer address, the settled charge (with
    tx + network metadata) must still land on the refund worklist for manual
    investigation rather than being dropped."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    await _seed_settled(
        session_factory,
        tx="0xNOPAYER",
        amount="0.05",
        network="base-sepolia",
        asset="USDC",
        payer="",  # SDK settled but did not expose a payer
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_np", wallet=EVM_WALLET, tx="0xNOPAYER", cost="0.05"))
        await session.commit()

    await orch._provision_vm("vm_np")

    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1  # not dropped
    assert owed[0].payer_wallet == "unknown"
    assert owed[0].tx_hash == "0xNOPAYER"
    assert owed[0].amount_usd == Decimal("0.05")


@pytest.mark.asyncio
async def test_charged_vm_without_ledger_or_payer_still_records(session_factory, monkeypatch) -> None:
    """A settled charge whose best-effort ledger row was lost AND whose payer the
    SDK never exposed (owner_wallet='unknown', but payment_tx set) must still land
    on the refund worklist rather than being dropped as a 'free' VM."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_unk", wallet="unknown", tx="0xCHARGED", cost="0.05"))
        await session.commit()

    await orch._provision_vm("vm_unk")

    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1  # not dropped
    assert owed[0].payer_wallet == "unknown"
    assert owed[0].tx_hash == "0xCHARGED"
    assert owed[0].amount_usd == Decimal("0.05")


@pytest.mark.asyncio
async def test_activate_reservation_can_defer_provisioning(session_factory, monkeypatch) -> None:
    """The create route links a quote to the VM before provisioning starts, so a
    fast failure can find the locked quote amount (get_quote_for_vm otherwise
    races link_quote_vm). activate_vm_reservation must honor
    start_provisioning=False and only spawn on the explicit start."""
    orch = Orchestrator(HyruleConfig(), session_factory)
    spawned: list[str] = []
    monkeypatch.setattr(orch, "_spawn_provisioning", lambda vm_id: spawned.append(vm_id))
    async with session_factory() as session:
        session.add(_paid_provisioning_vm("vm_res", wallet="", tx=None, cost="0.05"))
        await session.commit()

    row = await orch.activate_vm_reservation(
        "vm_res", owner_wallet=EVM_WALLET, payment_tx="0xTX", start_provisioning=False
    )
    assert row is not None
    assert spawned == []  # deferred until the quote is linked

    orch.start_provisioning("vm_res")
    assert spawned == ["vm_res"]


@pytest.mark.asyncio
async def test_dev_bypass_vm_failure_records_no_refund(session_factory, monkeypatch) -> None:
    """A dev-bypass 'payment' (tx=dev_bypass_*, non-EVM test wallet) charged
    nothing, so a failed VM must NOT create a phantom refund_owed row that would
    pollute the operator worklist and payment metrics."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(
            _paid_provisioning_vm("vm_dev", wallet="0xDEV_TEST_WALLET", tx="dev_bypass_0x0", cost="0.05")
        )
        await session.commit()

    await orch._provision_vm("vm_dev")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_dev")
        assert row.status == VMStatus.FAILED
    assert [e for e in await _events(session_factory) if e.event_type == "refund_owed"] == []


@pytest.mark.asyncio
async def test_record_native_intent_refund_without_vm(session_factory) -> None:
    """If create_vm fails before a vm_id is linked, the settled native intent
    must still get a refund_owed row — recorded by intent_id with no VM. And it
    is idempotent so a later _provision_vm failure can't double-owe."""
    orch = Orchestrator(HyruleConfig(), session_factory)
    xmr_addr = "8" + "B" * 94
    async with session_factory() as session:
        session.add(
            CryptoIntentRow(
                intent_id="int_novm",
                asset="XMR",
                amount_crypto=Decimal("0.0003"),
                amount_usd=Decimal("0.05"),
                address=xmr_addr,
                status=CryptoIntentStatus.PROVISIONING,  # never reached PROVISIONED
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                tx_hash="xmr-tx",
            )
        )
        await session.commit()

    recorded = await orch.record_native_intent_refund("int_novm", reason="provisioning_failed")
    assert recorded is True

    async with session_factory() as session:
        intent = await session.get(CryptoIntentRow, "int_novm")
        assert intent.status == CryptoIntentStatus.REFUND_MANUAL
    owed = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed) == 1
    assert owed[0].payer_wallet == "int_novm"  # bounded, not the 95-char address
    assert owed[0].network == "native"
    assert owed[0].extra["native_deposit_address"] == xmr_addr

    # Idempotent: a second call (e.g. a later _provision_vm failure) doesn't
    # record a duplicate obligation.
    assert await orch.record_native_intent_refund("int_novm", reason="again") is False
    owed2 = [e for e in await _events(session_factory) if e.event_type == "refund_owed"]
    assert len(owed2) == 1
