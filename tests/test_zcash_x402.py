from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from x402.schemas import PaymentPayload

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.db import Base, ZcashInvoiceRow, ZcashPaymentRow
from hyrule_cloud.payments.zcash import (
    ZCASH_ASSET,
    ZCASH_TESTNET,
    ZcashPaymentService,
    build_invoice_memo_hex,
    normalize_txid,
    resource_hash,
    usd_to_zatoshis,
    zatoshis_to_zec_decimal_string,
)
from hyrule_cloud.state import AppState

TXID = "ab" * 32


class _FakeRates:
    async def get_usd_per(self, asset: str) -> Decimal:
        assert asset == "ZEC"
        return Decimal("25")


class _FakeZcashRpc:
    def __init__(self) -> None:
        self.txs: dict[str, dict[str, Any]] = {}
        self.address_calls: list[tuple[int, list[str]]] = []
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def close(self) -> None:
        self.closed = True

    async def get_address_for_account(
        self,
        account: int,
        receiver_types: list[str],
    ) -> dict[str, Any]:
        self.address_calls.append((account, receiver_types))
        return {"address": "utest1merchantinvoice", "diversifier_index": 17}

    async def view_transaction(self, txid: str) -> dict[str, Any]:
        if txid not in self.txs:
            raise RuntimeError("not visible")
        return self.txs[txid]


@pytest_asyncio.fixture
async def zcash_service():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    rpc = _FakeZcashRpc()
    service = ZcashPaymentService(
        config=PaymentConfig(
            payment_networks=[],
            receiver_address="",
            zcash_enabled=True,
            zcash_network="testnet",
            zcash_min_confirmations=1,
            zcash_invoice_ttl_seconds=180,
            zcash_merchant="example.net",
        ),
        session_factory=factory,
        rates=_FakeRates(),
        rpc=rpc,  # type: ignore[arg-type]
    )
    try:
        yield service, rpc, factory
    finally:
        await engine.dispose()


def test_zec_zatoshi_helpers_are_decimal_safe() -> None:
    assert usd_to_zatoshis(Decimal("0.05"), Decimal("25")) == 200_000
    assert zatoshis_to_zec_decimal_string(200_000) == "0.00200000"
    assert normalize_txid(TXID.upper()) == TXID
    assert normalize_txid("not-a-txid") is None


def test_invoice_memo_binds_resource_amount_and_merchant() -> None:
    res_hash = resource_hash("https://api.example.net/v1/report")
    memo_hex = build_invoice_memo_hex(
        invoice_id="inv_test",
        resource_hash_value=res_hash,
        amount_zat="50000",
        merchant="example.net",
    )

    memo = json.loads(bytes.fromhex(memo_hex).decode("utf-8"))
    assert memo == {
        "amountZat": "50000",
        "invoice": "inv_test",
        "merchant": "example.net",
        "proto": "x402-zcash",
        "resourceHash": res_hash,
        "v": 1,
    }


@pytest.mark.asyncio
async def test_create_invoice_builds_exact_zcash_requirement(zcash_service) -> None:
    service, rpc, _factory = zcash_service

    invoice = await service.create_invoice(
        resource_url="https://api.example.net/v1/report",
        amount_usd=Decimal("0.05"),
    )
    requirement = service.requirement_for_invoice(invoice)

    assert rpc.address_calls == [(0, ["orchard"])]
    assert invoice.network == ZCASH_TESTNET
    assert invoice.amount_zat == "200000"
    assert requirement.scheme == "exact"
    assert requirement.network == ZCASH_TESTNET
    assert requirement.asset == ZCASH_ASSET
    assert requirement.amount == "200000"
    assert requirement.pay_to == "utest1merchantinvoice"
    assert requirement.extra["invoiceId"] == invoice.invoice_id
    assert requirement.extra["memoHex"] == invoice.memo_hex
    assert requirement.extra["broadcastMode"] == "client"


@pytest.mark.asyncio
async def test_verify_and_settle_wallet_visible_shielded_payment(zcash_service) -> None:
    service, rpc, factory = zcash_service
    invoice = await service.create_invoice(
        resource_url="https://api.example.net/v1/report",
        amount_usd=Decimal("0.05"),
    )
    requirement = service.requirement_for_invoice(invoice)
    rpc.txs[TXID] = {
        "confirmations": 1,
        "outputs": [
            {
                "address": invoice.pay_to,
                "valueZat": int(invoice.amount_zat),
                "memo": invoice.memo_hex,
                "pool": "orchard",
            }
        ],
    }
    payload = PaymentPayload(
        x402_version=2,
        accepted=requirement,
        payload={"txid": TXID, "invoiceId": invoice.invoice_id},
    )

    verification = await service.verify(payload, requirement)
    settlement = await service.settle(payload, requirement)

    assert verification.is_valid is True
    assert settlement.success is True
    assert settlement.transaction == TXID
    async with factory() as db:
        stored_invoice = await db.get(ZcashInvoiceRow, invoice.invoice_id)
        payment = (
            await db.execute(
                select(ZcashPaymentRow).where(
                    ZcashPaymentRow.invoice_id == invoice.invoice_id
                )
            )
        ).scalar_one()
    assert stored_invoice is not None
    assert stored_invoice.status == "settled"
    assert stored_invoice.txid == TXID
    assert payment.txid == TXID


@pytest.mark.asyncio
async def test_verify_rejects_txid_without_matching_memo(zcash_service) -> None:
    service, rpc, _factory = zcash_service
    invoice = await service.create_invoice(
        resource_url="https://api.example.net/v1/report",
        amount_usd=Decimal("0.05"),
    )
    requirement = service.requirement_for_invoice(invoice)
    rpc.txs[TXID] = {
        "confirmations": 1,
        "outputs": [
            {
                "address": invoice.pay_to,
                "valueZat": int(invoice.amount_zat),
                "memo": "00",
                "pool": "orchard",
            }
        ],
    }
    payload = PaymentPayload(
        x402_version=2,
        accepted=requirement,
        payload={"txid": TXID, "invoiceId": invoice.invoice_id},
    )

    verification = await service.verify(payload, requirement)

    assert verification.is_valid is False
    assert verification.invalid_reason == "no_matching_output"


@pytest.mark.asyncio
async def test_zcash_facilitator_supported_route_advertises_slip44_asset(
    zcash_service,
) -> None:
    service, _rpc, _factory = zcash_service
    cfg = HyruleConfig()
    cfg.payment = service.config
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=cfg,
        orchestrator=None,
        payment_gate=None,
        network_provider=None,
        zcash_payment=service,
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            body = (await client.get("/x402/zcash/supported")).json()
    finally:
        if prev is not None:
            app.state._typed_state = prev
        else:
            try:
                del app.state._typed_state
            except AttributeError:
                pass

    assert body["kinds"][0]["scheme"] == "exact"
    assert body["kinds"][0]["network"] == ZCASH_TESTNET
    assert body["kinds"][0]["extra"]["asset"] == ZCASH_ASSET
    assert body["kinds"][0]["extra"]["unit"] == "zatoshi"


@pytest.mark.asyncio
async def test_zcash_facilitator_verify_and_settle_routes(zcash_service) -> None:
    service, rpc, _factory = zcash_service
    invoice = await service.create_invoice(
        resource_url="https://api.example.net/v1/report",
        amount_usd=Decimal("0.05"),
    )
    requirement = service.requirement_for_invoice(invoice)
    rpc.txs[TXID] = {
        "confirmations": 1,
        "outputs": [
            {
                "address": invoice.pay_to,
                "valueZat": int(invoice.amount_zat),
                "memo": invoice.memo_hex,
                "pool": "orchard",
            }
        ],
    }
    payload = PaymentPayload(
        x402_version=2,
        accepted=requirement,
        payload={"txid": TXID, "invoiceId": invoice.invoice_id},
    )
    cfg = HyruleConfig()
    cfg.payment = service.config
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=cfg,
        orchestrator=None,
        payment_gate=None,
        network_provider=None,
        zcash_payment=service,
    )
    request_body = {
        "x402Version": 2,
        "paymentPayload": payload.model_dump(by_alias=True),
        "paymentRequirements": requirement.model_dump(by_alias=True),
    }
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            verify_body = (await client.post("/x402/zcash/verify", json=request_body)).json()
            settle_body = (await client.post("/x402/zcash/settle", json=request_body)).json()
    finally:
        if prev is not None:
            app.state._typed_state = prev
        else:
            try:
                del app.state._typed_state
            except AttributeError:
                pass

    assert verify_body["isValid"] is True
    assert settle_body["success"] is True
    assert settle_body["transaction"] == TXID
