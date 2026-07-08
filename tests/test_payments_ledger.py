"""Payments ledger (Phase 2 of the x402 launch plan).

Every payment-gate outcome must land in payment_events, ledger failures must
never break the payment flow, and /metrics must aggregate the ledger behind
its bearer token.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from x402.http import PAYMENT_SIGNATURE_HEADER

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, PaymentEventRow, VMRow
from hyrule_cloud.models import VMSize, VMStatus
from hyrule_cloud.services.payments_ledger import PaymentLedger, service_group_for_path
from tests.test_payment_gate_x402 import (
    PAYER,
    _FakeServer,
    _gate,
    _payment_header,
    _request,
)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _events(factory) -> list[PaymentEventRow]:
    async with factory() as session:
        return list((await session.execute(select(PaymentEventRow))).scalars())


def test_service_group_for_path() -> None:
    assert service_group_for_path("/v1/vm/create") == "vm"
    assert service_group_for_path("/v1/domain/register") == "domain"
    assert service_group_for_path("/v1/zone/record") == "domain"
    assert service_group_for_path("/v1/network/request") == "network_proxy"
    assert service_group_for_path("/v1/dns/lookup") == "network_intel"
    assert service_group_for_path("/v1/bgp/lookup") == "network_intel"
    assert service_group_for_path("/v1/mail/accounts") == "mail"
    assert service_group_for_path("/v1/pricing") == "other"
    # Prefix matching must not swallow sibling paths.
    assert service_group_for_path("/v1/vmx/whatever") == "other"


@pytest.mark.asyncio
async def test_settled_payment_writes_ledger_row(session_factory) -> None:
    server = _FakeServer()
    gate = _gate(server)
    gate.ledger = PaymentLedger(session_factory)
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == PAYER
    events = await _events(session_factory)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "settled"
    assert event.service_group == "vm"
    assert event.resource_path == "/v1/vm/create"
    assert event.payer_wallet == PAYER
    assert event.tx_hash == "0xSETTLED"
    assert event.network == "eip155:8453"
    assert event.amount_usd == Decimal("0.05")
    assert event.facilitator_host == "facilitator.payai.network"


@pytest.mark.asyncio
async def test_no_payment_writes_required_402(session_factory) -> None:
    gate = _gate(_FakeServer())
    gate.ledger = PaymentLedger(session_factory)

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["required_402"]
    assert events[0].payer_wallet is None


@pytest.mark.asyncio
async def test_verify_failure_writes_verify_failed(session_factory) -> None:
    server = _FakeServer(valid=False)
    gate = _gate(server)
    gate.ledger = PaymentLedger(session_factory)
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["verify_failed"]
    assert events[0].error_reason == "invalid_signature"


@pytest.mark.asyncio
async def test_settle_failure_writes_settle_failed(session_factory) -> None:
    server = _FakeServer(settle_success=False)
    gate = _gate(server)
    gate.ledger = PaymentLedger(session_factory)
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["settle_failed"]
    assert events[0].error_reason == "insufficient_funds"


@pytest.mark.asyncio
async def test_dev_bypass_writes_dev_bypass(session_factory) -> None:
    gate = _gate(_FakeServer())
    gate.config.dev_bypass_secret = "sekrit"
    gate.ledger = PaymentLedger(session_factory)
    req = _request({"X-DEV-BYPASS": "sekrit"})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == "0xDEV_TEST_WALLET"
    events = await _events(session_factory)
    assert [e.event_type for e in events] == ["dev_bypass"]


@pytest.mark.asyncio
async def test_broken_ledger_never_breaks_payment_flow() -> None:
    class _ExplodingFactory:
        def __call__(self):
            raise RuntimeError("db down")

    server = _FakeServer()
    gate = _gate(server)
    gate.ledger = PaymentLedger(_ExplodingFactory())  # type: ignore[arg-type]
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == PAYER  # payment still settles even though the ledger is down


# --- /metrics exporter ---


def _metrics_state(session_factory, token: str) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(metrics_token=token),
        session_factory=session_factory,
    )


@pytest_asyncio.fixture
async def metrics_app_state(session_factory):
    from hyrule_cloud.api import metrics as metrics_module

    metrics_module._cache.clear()
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = _metrics_state(session_factory, "scrape-token")
    yield session_factory
    if old_state is not None:
        app.state._typed_state = old_state
    else:
        delattr(app.state, "_typed_state")


@pytest.mark.asyncio
async def test_metrics_requires_bearer_token(metrics_app_state) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        missing = await client.get("/metrics")
        wrong = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
    assert missing.status_code == 401
    assert wrong.status_code == 401


@pytest.mark.asyncio
async def test_metrics_disabled_without_token(session_factory) -> None:
    from hyrule_cloud.api import metrics as metrics_module

    metrics_module._cache.clear()
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = _metrics_state(session_factory, "")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/metrics", headers={"Authorization": "Bearer anything"})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        else:
            delattr(app.state, "_typed_state")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_metrics_renders_ledger_and_fleet_counters(metrics_app_state) -> None:
    session_factory = metrics_app_state
    ledger = PaymentLedger(session_factory)
    server = _FakeServer()
    gate = _gate(server)
    gate.ledger = ledger

    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})
    assert await gate.check_payment(req, Decimal("0.05"), "VM creation") == PAYER
    assert isinstance(await gate.check_payment(_request(), Decimal("0.10"), "quote"), Response)

    async with session_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_metrics_test",
                owner_wallet=PAYER,
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                hostname="m.deploy.hyrule.host",
                cost_total=Decimal("0.05"),
                provisioned_at=None,
            )
        )
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/metrics", headers={"Authorization": "Bearer scrape-token"})

    assert res.status_code == 200
    body = res.text
    assert (
        'hyrule_payment_events_total{event_type="settled",service_group="vm",network="eip155:8453"} 1'
        in body
    )
    assert (
        'hyrule_payment_events_total{event_type="required_402",service_group="vm",network=""} 1'
        in body
    )
    assert 'hyrule_payment_revenue_usd_total{service_group="vm",network="eip155:8453"} 0.05' in body
    assert "hyrule_payment_unique_payers 1" in body
    assert "hyrule_payment_unique_payers_24h 1" in body
    assert 'hyrule_vms_active{status="ready"} 1' in body
    assert 'hyrule_vm_provision_total{result="ready"} 0' in body
    assert 'hyrule_vm_provision_total{result="failed"} 0' in body
