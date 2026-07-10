"""Trust-layer fulfillment + refund receipts (M2).

Asynchronous outcomes must produce receipts too: VM provisioned (real or
simulated), VM failed → refund obligation, native intent SETTLED, extend,
and job completion. Native rails must never disclose payment details, and
refund receipts must soft-link the ledger obligation they attest.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    Base,
    CryptoIntentRow,
    FulfillmentReceiptRow,
    PaymentEventRow,
    VMQuoteRow,
    VMRow,
)
from hyrule_cloud.models import (
    CryptoIntentStatus,
    QuoteStatus,
    VMSize,
    VMStatus,
)
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.services.intents import create_intent, poll_one_intent
from hyrule_cloud.trust import TrustServices
from hyrule_cloud.trust.receipts import ReceiptService, load_signing_keys
from tests.test_api import (
    _TEST_TOKEN,
    MockConfig,
    MockGate,
    MockNetworkProvider,
    MockOrchestrator,
)
from tests.test_intent_engine import (
    AddressScanResult,
    _StubNativeProvider,
    _StubOrchestrator,
    _StubRateProvider,
    _vm_create_request,
)
from tests.test_trust_receipts import _trust_config

PAYER = "0xFBD95291e4b9C901E084a8856eA184d3F7A232ed"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _receipts_for(factory) -> ReceiptService:
    config = _trust_config()
    return ReceiptService(
        config,
        factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=load_signing_keys(config),
    )


async def _receipt_rows(factory) -> list[FulfillmentReceiptRow]:
    async with factory() as session:
        return list(
            (
                await session.execute(
                    select(FulfillmentReceiptRow).order_by(FulfillmentReceiptRow.created_at)
                )
            ).scalars()
        )


def _vm_row(vm_id: str, **overrides) -> VMRow:
    values = dict(
        vm_id=vm_id,
        owner_wallet=PAYER,
        status=VMStatus.PROVISIONING,
        size=VMSize.XS,
        os="debian-13",
        ssh_pubkey="ssh-ed25519 AAAA...",
        open_ports=[22, 80],
        expires_at=datetime.now(UTC) + timedelta(days=1),
        cost_total=Decimal("0.05"),
        payment_tx="0xSETTLED",
        provision_started_at=datetime.now(UTC) - timedelta(seconds=5),
    )
    values.update(overrides)
    return VMRow(**values)


@pytest.mark.asyncio
async def test_simulated_provisioning_mints_fulfillment_receipt(session_factory) -> None:
    receipts = _receipts_for(session_factory)
    orch = Orchestrator(HyruleConfig(), session_factory, receipts=receipts)
    async with session_factory() as session:
        session.add(_vm_row("vm_sim1"))
        session.add(
            VMQuoteRow(
                quote_id="q_sim1",
                order_payload={},
                amount_usd=Decimal("0.05"),
                status=QuoteStatus.CONSUMED,
                vm_id="vm_sim1",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        await session.commit()

    await orch._simulate_provisioning("vm_sim1")

    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    receipt = rows[0]
    assert receipt.kind == "fulfillment"
    assert receipt.outcome == "provisioned"
    assert receipt.rail == "x402-exact-evm"
    assert receipt.vm_id == "vm_sim1"
    assert receipt.quote_id == "q_sim1"
    assert receipt.amount_usd == Decimal("0.05")
    assert receipt.payload["outcome"]["simulated"] is True
    # provision_started_at was set and simulate stamped provisioned_at.
    assert receipt.payload["timing"]["provision_seconds"] is not None


@pytest.mark.asyncio
async def test_failed_provision_mints_refund_and_failed_receipts(
    session_factory, monkeypatch
) -> None:
    """_provision_vm in real mode with no template config fails → refund
    obligation + refund receipt (linked to the ledger event) + failed
    fulfillment receipt."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    receipts = _receipts_for(session_factory)
    orch = Orchestrator(HyruleConfig(), session_factory, receipts=receipts)
    async with session_factory() as session:
        session.add(_vm_row("vm_fail1"))
        session.add(
            PaymentEventRow(
                event_id="evt-settled-1",
                event_type="settled",
                resource_path="/v1/vm/create",
                method="POST",
                service_group="vm",
                amount_usd=Decimal("0.05"),
                network="eip155:8453",
                asset="USDC",
                payer_wallet=PAYER,
                tx_hash="0xSETTLED",
            )
        )
        await session.commit()

    await orch._provision_vm("vm_fail1")

    async with session_factory() as session:
        refund_events = list(
            (
                await session.execute(
                    select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
                )
            ).scalars()
        )
    assert len(refund_events) == 1

    rows = await _receipt_rows(session_factory)
    by_kind = {r.kind: r for r in rows}
    assert set(by_kind) == {"refund", "fulfillment"}
    refund = by_kind["refund"]
    assert refund.outcome == "refund_owed"
    assert refund.payer_wallet == PAYER
    assert refund.tx_hash == "0xSETTLED"
    assert refund.payment_event_id == refund_events[0].event_id
    failed = by_kind["fulfillment"]
    assert failed.outcome == "failed"
    assert failed.vm_id == "vm_fail1"
    assert failed.payload["outcome"]["detail"]


@pytest.mark.asyncio
async def test_create_failure_refund_mints_receipt(session_factory) -> None:
    receipts = _receipts_for(session_factory)
    orch = Orchestrator(HyruleConfig(), session_factory, receipts=receipts)
    async with session_factory() as session:
        session.add(
            PaymentEventRow(
                event_id="evt-settled-2",
                event_type="settled",
                resource_path="/v1/vm/create",
                method="POST",
                service_group="vm",
                amount_usd=Decimal("0.10"),
                network="eip155:8453",
                asset="USDC",
                payer_wallet=PAYER,
                tx_hash="0xCHARGE",
            )
        )
        await session.commit()

    await orch.record_create_failure_refund(
        owner_wallet=PAYER,
        payment_tx="0xCHARGE",
        charged_amount=Decimal("0.10"),
        reason="capacity exhausted",
        vm_id="vm_gone",
    )

    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    assert rows[0].kind == "refund"
    assert rows[0].amount_usd == Decimal("0.10")
    assert rows[0].network == "eip155:8453"
    assert rows[0].vm_id == "vm_gone"


@pytest.mark.asyncio
async def test_dev_bypass_create_failure_mints_nothing(session_factory) -> None:
    receipts = _receipts_for(session_factory)
    orch = Orchestrator(HyruleConfig(), session_factory, receipts=receipts)

    await orch.record_create_failure_refund(
        owner_wallet="0xDEV_TEST_WALLET",
        payment_tx="dev_bypass_0x0",
        charged_amount=Decimal("0.05"),
        reason="boom",
        vm_id="vm_dev",
    )

    assert await _receipt_rows(session_factory) == []


@pytest.mark.asyncio
async def test_native_intent_refund_receipt_is_private_and_idempotent(session_factory) -> None:
    receipts = _receipts_for(session_factory)
    orch = Orchestrator(HyruleConfig(), session_factory, receipts=receipts)
    async with session_factory() as session:
        session.add(
            CryptoIntentRow(
                intent_id="int_xmr_refund",
                asset="XMR",
                amount_crypto=Decimal("0.0003"),
                amount_usd=Decimal("0.05"),
                address="4Ahyrule_xmr_deposit_subaddress_example",
                status=CryptoIntentStatus.SETTLED,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                tx_hash="xmr-txid-abc",
            )
        )
        await session.commit()

    assert await orch.record_native_intent_refund("int_xmr_refund", reason="provision failed")

    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    receipt = rows[0]
    assert receipt.kind == "refund"
    assert receipt.rail == "native-xmr"
    assert receipt.intent_id == "int_xmr_refund"
    assert receipt.payer_wallet is None
    assert receipt.tx_hash is None
    blob = json.dumps(receipt.payload)
    assert "4Ahyrule_xmr_deposit_subaddress_example" not in blob
    assert "xmr-txid-abc" not in blob
    assert receipt.payment_event_id is not None

    # Idempotent: re-recording an already-owed intent mints no second receipt.
    assert await orch.record_native_intent_refund("int_xmr_refund", reason="again") is False
    assert len(await _receipt_rows(session_factory)) == 1


@pytest.mark.asyncio
async def test_first_settled_native_intent_mints_payment_receipt(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/intents.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        orch = _StubOrchestrator(factory)
        orch.receipts = _receipts_for(factory)
        provider = _StubNativeProvider()
        rates = _StubRateProvider()

        row = await create_intent(
            session_factory=factory,
            provider=provider,
            rates=rates,
            asset="BTC",
            order_payload=_vm_create_request(),
            amount_usd=Decimal("0.05"),
            client_order_id=None,
            owner_account_id=None,
        )
        provider.scan_results[row.address] = AddressScanResult(
            address=row.address,
            received_total=row.amount_crypto,
            confirmations=6,
            tx_hash="btc-txid-settled",
        )

        updated = await poll_one_intent(
            intent_id=row.intent_id,
            session_factory=factory,
            provider=provider,
            rates=rates,
            orch=orch,
        )
        assert updated is not None

        rows = await _receipt_rows(factory)
        payment_rows = [r for r in rows if r.kind == "payment"]
        assert len(payment_rows) == 1
        receipt = payment_rows[0]
        assert receipt.rail == "native-btc"
        assert receipt.outcome == "settled"
        assert receipt.intent_id == row.intent_id
        assert receipt.payer_wallet is None and receipt.tx_hash is None
        blob = json.dumps(receipt.payload)
        assert row.address not in blob
        assert "btc-txid-settled" not in blob

        # A second poll of the (now terminal) intent mints no duplicate.
        await poll_one_intent(
            intent_id=row.intent_id,
            session_factory=factory,
            provider=provider,
            rates=rates,
            orch=orch,
        )
        assert len([r for r in await _receipt_rows(factory) if r.kind == "payment"]) == 1
    finally:
        await engine.dispose()


# --- Route-level: extend fulfillment receipt ---


class _ExtendOrchestrator(MockOrchestrator):
    async def get_vm(self, vm_id):
        row = await super().get_vm(vm_id)
        if row is not None:
            row.size = VMSize.XS  # the extend route prices on row.size
        return row

    async def extend_vm(self, vm_id, days):
        return SimpleNamespace(
            expires_at=datetime(2026, 8, 1, tzinfo=UTC), status=VMStatus.RUNNING
        )


@pytest_asyncio.fixture
async def extend_app_state(session_factory):
    from hyrule_cloud.state import AppState

    og_state = getattr(app.state, "_typed_state", None)
    state = AppState(
        config=MockConfig(),
        orchestrator=_ExtendOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider(),
        trust=TrustServices(receipts=_receipts_for(session_factory)),
    )
    app.state._typed_state = state
    yield state
    if og_state:
        app.state._typed_state = og_state


@pytest.mark.asyncio
async def test_extend_route_mints_fulfillment_receipt(extend_app_state, session_factory) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/vm/vm_test123/extend",
            json={"days": 3},
            headers={
                "X-Mock-Wallet": PAYER,
                "Authorization": f"Bearer {_TEST_TOKEN}",
            },
        )
        assert res.status_code == 200

    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    receipt = rows[0]
    assert receipt.kind == "fulfillment"
    assert receipt.outcome == "extended"
    assert receipt.vm_id == "vm_test123"
    assert receipt.payload["evidence"]["extension_days"] == "3"


@pytest.mark.asyncio
async def test_vm_receipts_endpoint_is_management_gated(extend_app_state, session_factory) -> None:
    service = extend_app_state.trust.receipts
    from hyrule_cloud.trust.models import ReceiptKind

    await service.mint(
        kind=ReceiptKind.PAYMENT,
        outcome="settled",
        resource_path="/v1/vm/create",
        method="POST",
        rail="x402-exact-evm",
        amount_usd=Decimal("0.05"),
        payer=PAYER,
        tx_hash="0xSETTLED",
        vm_id="vm_test123",
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        unauthorized = await client.get("/v1/vm/vm_test123/receipts")
        assert unauthorized.status_code == 404

        res = await client.get(
            "/v1/vm/vm_test123/receipts",
            headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["vm_id"] == "vm_test123"
        assert len(body["receipts"]) == 1
        assert body["receipts"][0]["url"].startswith("/v1/receipts/hyr_rcpt_")
