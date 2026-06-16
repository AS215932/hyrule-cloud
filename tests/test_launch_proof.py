"""Issue #28: launch-proof contract over the existing VM path.

Covers the full state journey (quote → payment_required → provisioning →
provisioned) and the failed → safe-message path.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, VMQuoteRow, VMRow
from hyrule_cloud.models import (
    LaunchProofStatus,
    PaymentStatus,
    SSHSmokeStatus,
    VMSize,
    VMStatus,
)
from hyrule_cloud.services import quotes as quotes_service


def _now() -> datetime:
    return datetime.now(UTC)


class _StubNetwork:
    key = "base"
    caip2 = "eip155:8453"
    asset = "USDC"
    chain_id = 8453


class _StubPayment:
    def enabled_networks(self):
        return [_StubNetwork()]


class _StubCfg:
    payment = _StubPayment()
    blocked_ports = [25]
    deploy_domain = "deploy.hyrule.host"
    max_paid_active_vms = 0
    vm_grace_period_hours = 1


class _StubOrchestrator:
    """Owns the session factory + the compute_price/create_vm contract routes use."""

    def __init__(self, session_factory: async_sessionmaker) -> None:
        self.db = session_factory
        self.created_vms: list[str] = []

    def compute_price(self, request):
        from hyrule_cloud.models import CostBreakdown

        total = Decimal("0.05") * request.duration_days
        return total, CostBreakdown(
            vm_cost=f"${total:.2f}",
            domain_cost="$0.00",
            total=f"${total:.2f}",
        )

    async def create_vm(self, request, owner_wallet: str, owner_account_id: str | None = None):
        from hyrule_cloud.middleware.anon_token import hash_anon_token
        from hyrule_cloud.models import generate_anon_management_token, generate_vm_id

        vm_id = generate_vm_id()
        anon_token = generate_anon_management_token()
        hostname = f"{vm_id[:8]}.deploy.hyrule.host"
        async with self.db() as session:
            row = VMRow(
                vm_id=vm_id,
                owner_wallet=owner_wallet,
                owner_account_id=owner_account_id,
                anon_management_token_hash=hash_anon_token(anon_token),
                status=VMStatus.PROVISIONING,
                size=VMSize(request.size),
                os=request.os,
                hostname=hostname,
                ssh_pubkey=request.ssh_pubkey,
                open_ports=[22, 80, 443],
                expires_at=_now() + timedelta(days=request.duration_days),
                cost_total=Decimal("0.05"),
            )
            session.add(row)
            await session.commit()
        self.created_vms.append(vm_id)
        return row, anon_token

    async def get_vm(self, vm_id: str) -> VMRow | None:
        async with self.db() as session:
            return await session.get(VMRow, vm_id)

    async def get_quote_for_vm(self, vm_id: str) -> VMQuoteRow | None:
        async with self.db() as session:
            from sqlalchemy import select

            result = await session.execute(
                select(VMQuoteRow).where(VMQuoteRow.vm_id == vm_id)
            )
            return result.scalar_one_or_none()


@pytest_asyncio.fixture
async def lp_state():
    from hyrule_cloud.state import AppState

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    orch = _StubOrchestrator(factory)
    gate = AsyncMock()

    state = AppState(
        config=_StubCfg(),
        orchestrator=orch,
        payment_gate=gate,
        network_provider=None,
        session_factory=factory,
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev
        await engine.dispose()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        yield c


def _order(**overrides) -> dict:
    base = {
        "duration_days": 1,
        "size": "xs",
        "os": "debian-13",
        "ssh_pubkey": "ssh-ed25519 AAAA test",
    }
    base.update(overrides)
    return base


# --- Happy path: quote → provisioning → provisioned ---


@pytest.mark.asyncio
async def test_quote_create_then_status_shows_provisioning(lp_state, client):
    lp_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 200, res.text
    vm_id = res.json()["vm_id"]

    status = await client.get(f"/v1/vm/{vm_id}/status")
    assert status.status_code == 200
    body = status.json()
    assert body["launch_proof_status"] == LaunchProofStatus.PROVISIONING
    assert body["payment_status"] == PaymentStatus.PAID
    assert body["dns_aaaa_verified"] is False  # simulated, ipv6 not yet set
    assert body["ssh_smoke_status"] == SSHSmokeStatus.NOT_RUN
    assert body["rollback_available"] is False
    assert body["customer_message"] is not None


@pytest.mark.asyncio
async def test_provisioned_vm_shows_launch_proof_fields(lp_state, client):
    lp_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    vm_id = res.json()["vm_id"]

    # Simulate the orchestrator finishing provisioning
    async with lp_state.orchestrator.db() as session:
        row = await session.get(VMRow, vm_id)
        row.status = VMStatus.READY
        row.ipv6 = "2001:db8::42"
        row.provisioned_at = _now()
        await session.commit()

    status = await client.get(f"/v1/vm/{vm_id}/status")
    assert status.status_code == 200
    body = status.json()
    assert body["launch_proof_status"] == LaunchProofStatus.PROVISIONED
    assert body["payment_status"] == PaymentStatus.PAID
    assert body["dns_aaaa_verified"] is True
    assert body["ssh_smoke_status"] == SSHSmokeStatus.PASSED
    assert body["rollback_available"] is False
    assert body["customer_message"] == "Your VM is ready."


# --- Payment-required state (controlled simulation) ---


@pytest.mark.asyncio
async def test_payment_required_state_on_status(lp_state, client):
    """Controlled simulation: a VM row linked to a CREATED quote shows
    payment_required so the contract can be exercised end-to-end."""
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    # Insert a placeholder VM linked to the still-created quote
    async with lp_state.orchestrator.db() as session:
        vm = VMRow(
            vm_id="vm_placeholder_001",
            owner_wallet="",
            status=VMStatus.PROVISIONING,
            size=VMSize.XS,
            os="debian-13",
            ssh_pubkey="ssh-ed25519 AAAA test",
            open_ports=[22, 80, 443],
            expires_at=_now() + timedelta(days=1),
            cost_total=Decimal("0.05"),
            metadata_={
                "launch_proof": {
                    "payment_status": PaymentStatus.PAYMENT_REQUIRED,
                }
            },
        )
        session.add(vm)
        quote_row = await session.get(VMQuoteRow, quote["quote_id"])
        quote_row.vm_id = vm.vm_id
        await session.commit()

    status = await client.get("/v1/vm/vm_placeholder_001/status")
    assert status.status_code == 200
    body = status.json()
    assert body["launch_proof_status"] == LaunchProofStatus.PAYMENT_REQUIRED
    assert body["payment_status"] == PaymentStatus.PAYMENT_REQUIRED


# --- Failed path with customer-safe message ---


@pytest.mark.asyncio
async def test_failed_vm_shows_safe_message_and_rollback(lp_state, client):
    async with lp_state.orchestrator.db() as session:
        vm = VMRow(
            vm_id="vm_failed_001",
            owner_wallet="0xwallet",
            status=VMStatus.FAILED,
            size=VMSize.XS,
            os="debian-13",
            ssh_pubkey="ssh-ed25519 AAAA test",
            open_ports=[22, 80, 443],
            expires_at=_now() + timedelta(days=1),
            cost_total=Decimal("0.05"),
            error="XCP-NG template clone failed: sr_not_found on UUID deadbeef",
        )
        session.add(vm)
        await session.commit()

    status = await client.get("/v1/vm/vm_failed_001/status")
    assert status.status_code == 200
    body = status.json()
    assert body["launch_proof_status"] == LaunchProofStatus.FAILED
    assert body["payment_status"] == PaymentStatus.PAID
    assert body["dns_aaaa_verified"] is False
    assert body["ssh_smoke_status"] == SSHSmokeStatus.FAILED
    assert body["rollback_available"] is True
    # Operator sees the raw error
    assert "sr_not_found" in (body["operator_message"] or "")
    # Customer message is safe — no internal detail leaked
    customer = body["customer_message"]
    assert customer is not None
    assert "sr_not_found" not in customer
    assert "deadbeef" not in customer
    assert "refunded" in customer.lower() or "notified" in customer.lower()


# --- Rolled-back path ---


@pytest.mark.asyncio
async def test_rolled_back_vm_shows_rolled_back(lp_state, client):
    async with lp_state.orchestrator.db() as session:
        vm = VMRow(
            vm_id="vm_rollback_001",
            owner_wallet="0xwallet",
            status=VMStatus.DESTROYED,
            size=VMSize.XS,
            os="debian-13",
            ssh_pubkey="ssh-ed25519 AAAA test",
            open_ports=[22, 80, 443],
            expires_at=_now() + timedelta(days=1),
            cost_total=Decimal("0.05"),
            metadata_={
                "launch_proof": {
                    "previous_launch_proof_status": LaunchProofStatus.FAILED,
                }
            },
        )
        session.add(vm)
        await session.commit()

    status = await client.get("/v1/vm/vm_rollback_001/status")
    assert status.status_code == 200
    body = status.json()
    assert body["launch_proof_status"] == LaunchProofStatus.ROLLED_BACK
    assert body["rollback_available"] is False


# --- Quote/create 402 still leaves quote created ---


@pytest.mark.asyncio
async def test_create_with_quote_no_payment_402(lp_state, client):
    lp_state.payment_gate.check_payment = AsyncMock(return_value=Response(status_code=402))
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 402

    row = await quotes_service.get_quote(lp_state.orchestrator.db, quote["quote_id"])
    assert row is not None
    assert row.status == "created"
