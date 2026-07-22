"""Issue #14: durable VM order quotes.

Covers the quote lifecycle (create / get / expiry), idempotency (same key + same
spec → return; same key + different spec → 409), price-lock consistency, and the
quote-bound POST /v1/vm/create path (paid, 402-no-payment, expired, body
mismatch, idempotent replay of a consumed quote). Mirrors the in-memory SQLite +
AppState fixture style of test_intent_engine.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, VMQuoteRow, VMRow
from hyrule_cloud.models import CostBreakdown, QuoteStatus, VMSize, VMStatus
from hyrule_cloud.services import quotes as quotes_service


def _now() -> datetime:
    return datetime.now(UTC)


# --- Stubs ---


class _StubNetwork:
    key = "base"
    caip2 = "eip155:8453"
    asset = "USDC"
    chain_id = 8453


class _StubPayment:
    price_vm_xs = Decimal("0.20")
    price_vm_sm = Decimal("0.40")
    price_vm_md = Decimal("0.60")
    price_vm_lg = Decimal("0.80")
    price_vm_addon_vcpu = Decimal("0.10")
    price_vm_addon_ram_gb = Decimal("0.15")
    price_vm_addon_disk_10gb = Decimal("0.05")

    def enabled_networks(self):
        return [_StubNetwork()]


class _StubCfg:
    payment = _StubPayment()
    blocked_ports = [25]
    deploy_domain = "deploy.hyrule.host"
    xcpng = type("XCPNG", (), {"templates": {"debian-13": "template-debian-13"}})()


class _StubOrchestrator:
    """Owns the session factory + the compute_price/create_vm contract routes use."""

    def __init__(self, session_factory: async_sessionmaker) -> None:
        self.db = session_factory
        self.created_vms: list[str] = []
        self.provisioning_started: list[str] = []
        self.charged_amounts: dict[str, Decimal] = {}
        self.create_failure_refunds: list[tuple[str | None, str | None]] = []
        self.capacity_error: Exception | None = None

    def compute_price(self, request):
        total = Decimal("0.20") * request.duration_days
        return total, CostBreakdown(vm_cost=f"${total}", domain_cost="$0.00", total=f"${total}")

    async def ensure_vm_capacity(self, _request) -> None:
        if self.capacity_error is not None:
            raise self.capacity_error

    def start_provisioning(self, vm_id: str) -> None:
        self.provisioning_started.append(vm_id)

    async def create_vm(
        self,
        request,
        owner_wallet: str,
        owner_account_id: str | None = None,
        start_provisioning: bool = True,
        **kwargs,
    ):
        from hyrule_cloud.middleware.anon_token import hash_anon_token
        from hyrule_cloud.models import generate_anon_management_token, generate_vm_id

        vm_id = generate_vm_id()
        anon_token = generate_anon_management_token()
        snapshot = kwargs.get("pricing_snapshot") or {}
        async with self.db() as session:
            row = VMRow(
                vm_id=vm_id,
                owner_wallet=owner_wallet,
                owner_account_id=owner_account_id,
                anon_management_token_hash=hash_anon_token(anon_token),
                status=VMStatus.PROVISIONING,
                size=VMSize(request.size),
                vcpu=request.resources.vcpu,
                memory_mb=request.resources.ram_mb,
                disk_gb=request.resources.disk_gb,
                billing_addon_vcpu=snapshot.get("addon_vcpu", 0),
                billing_addon_ram_mb=snapshot.get("addon_ram_mb", 0),
                billing_addon_disk_gb=snapshot.get("addon_disk_gb", 0),
                os=request.os,
                ssh_pubkey=request.ssh_pubkey,
                open_ports=[22, 80, 443],
                expires_at=_now() + timedelta(days=request.duration_days),
                cost_total=Decimal("0.20"),
            )
            session.add(row)
            await session.commit()
        self.created_vms.append(vm_id)
        return row, anon_token

    async def persist_charged_amount(self, vm_id: str, amount: Decimal) -> None:
        self.charged_amounts[vm_id] = amount
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None:
                row.cost_total = amount
                await session.commit()

    async def persist_payment_billing(
        self,
        vm_id: str,
        retail_amount: Decimal,
        *,
        admin_waived: bool,
        payment_tx: str | None = None,
    ) -> None:
        self.charged_amounts[vm_id] = Decimal("0") if admin_waived else retail_amount
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None:
                row.retail_cost_total = retail_amount
                row.cost_total = Decimal("0") if admin_waived else retail_amount
                row.billing_mode = "admin_waived" if admin_waived else "charged"
                row.payment_tx = payment_tx
                await session.commit()

    async def record_create_failure_refund(
        self, *, owner_wallet, payment_tx, charged_amount, reason, vm_id=None
    ) -> None:
        self.create_failure_refunds.append((vm_id, payment_tx))

    async def mark_vm_failed(self, vm_id: str, error: str) -> None:
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None:
                row.status = VMStatus.FAILED
                row.error = error
                await session.commit()


@pytest_asyncio.fixture
async def quote_state():
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


# --- POST /v1/vm/quote ---


@pytest.mark.asyncio
async def test_create_quote_returns_quote(quote_state, client):
    res = await client.post("/v1/vm/quote", json={"order_payload": _order()})
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["quote_id"].startswith("q_")
    assert body["status"] == "created"
    assert body["amount_usd"] == "0.200000"  # Numeric(12,6) round-trip
    assert body["resources"] == {"vcpu": 1, "ram_mb": 1024, "disk_gb": 10}
    assert body["pricing"]["daily_price_usd"] == "0.20"
    assert body["accepted_payment_methods"]["evm"][0]["caip2"] == "eip155:8453"
    assert body["accepted_payment_methods"]["native"] == []  # no native rail wired
    assert body["order_payload"]["size"] == "xs"
    assert "expires_at" in body


@pytest.mark.asyncio
async def test_create_quote_price_matches_compute_price(quote_state, client):
    res = await client.post("/v1/vm/quote", json={"order_payload": _order(duration_days=7)})
    assert res.status_code == 201
    # 0.20/day * 7 days
    assert Decimal(res.json()["amount_usd"]) == Decimal("1.40")


@pytest.mark.asyncio
async def test_custom_quote_rebases_to_cheapest_exact_profile(quote_state, client):
    res = await client.post(
        "/v1/vm/quote",
        json={
            "order_payload": _order(
                size="xs",
                resources={"vcpu": 1, "ram_mb": 2048, "disk_gb": 20},
            )
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["order_payload"]["size"] == "sm"
    assert body["resources"] == {"vcpu": 1, "ram_mb": 2048, "disk_gb": 20}
    assert Decimal(body["amount_usd"]) == Decimal("0.40")
    assert body["pricing"]["base_profile"] == "sm"
    assert body["pricing"]["addon_ram_mb"] == 0


@pytest.mark.asyncio
async def test_maximum_custom_quote_has_locked_addon_breakdown(quote_state, client):
    res = await client.post(
        "/v1/vm/quote",
        json={
            "order_payload": _order(
                resources={"vcpu": 4, "ram_mb": 8192, "disk_gb": 40}
            )
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["order_payload"]["size"] == "lg"
    assert Decimal(body["amount_usd"]) == Decimal("1.40")
    assert body["pricing"]["addon_ram_mb"] == 4096
    assert body["pricing"]["addon_ram_usd_day"] == "0.60"


@pytest.mark.asyncio
async def test_custom_quote_rejects_resources_above_order_cap(quote_state, client):
    res = await client.post(
        "/v1/vm/quote",
        json={
            "order_payload": _order(
                resources={"vcpu": 4, "ram_mb": 8192, "disk_gb": 50}
            )
        },
    )
    assert res.status_code == 422
    assert "disk_gb must be between 10 and 40" in res.json()["detail"]


@pytest.mark.asyncio
async def test_idempotency_canonicalizes_original_profile_choice(quote_state, client):
    resources = {"vcpu": 3, "ram_mb": 6144, "disk_gb": 30}
    first = await client.post(
        "/v1/vm/quote",
        json={
            "order_payload": _order(size="xs", resources=resources),
            "client_order_id": "same-resources",
        },
    )
    replay = await client.post(
        "/v1/vm/quote",
        json={
            "order_payload": _order(size="lg", resources=resources),
            "client_order_id": "same-resources",
        },
    )
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["quote_id"] == first.json()["quote_id"]


@pytest.mark.asyncio
async def test_create_quote_custom_domain_requires_domain(quote_state, client):
    res = await client.post(
        "/v1/vm/quote", json={"order_payload": _order(domain_mode="custom")}
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_create_quote_blocked_port_rejected(quote_state, client):
    res = await client.post(
        "/v1/vm/quote", json={"order_payload": _order(open_ports=[25])}
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_real_mode_quote_rejects_unsupported_os(quote_state, client, monkeypatch):
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)

    res = await client.post(
        "/v1/vm/quote", json={"order_payload": _order(os="openbsd-7.8")}
    )
    assert res.status_code == 400
    assert "not supported" in res.text


@pytest.mark.asyncio
async def test_real_mode_quote_returns_503_when_live_capacity_is_exhausted(
    quote_state, client, monkeypatch
):
    from hyrule_cloud.orchestrator import VMCapacityError
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)
    quote_state.orchestrator.capacity_error = VMCapacityError("insufficient RAM capacity")

    res = await client.post("/v1/vm/quote", json={"order_payload": _order()})

    assert res.status_code == 503
    assert res.json()["detail"] == "The requested VM does not fit current host capacity"
    async with quote_state.orchestrator.db() as session:
        quotes = list((await session.scalars(select(VMQuoteRow))).all())
    assert quotes == []


# --- Idempotency ---


@pytest.mark.asyncio
async def test_quote_idempotent_same_key_same_spec_returns_existing(quote_state, client):
    payload = {"order_payload": _order(), "client_order_id": "cli-1"}
    first = await client.post("/v1/vm/quote", json=payload)
    second = await client.post("/v1/vm/quote", json=payload)
    assert first.status_code == 201
    assert second.status_code == 200  # idempotent replay
    assert first.json()["quote_id"] == second.json()["quote_id"]


@pytest.mark.asyncio
async def test_quote_idempotent_conflict_same_key_different_spec(quote_state, client):
    await client.post(
        "/v1/vm/quote", json={"order_payload": _order(), "client_order_id": "cli-2"}
    )
    conflict = await client.post(
        "/v1/vm/quote",
        json={"order_payload": _order(duration_days=30), "client_order_id": "cli-2"},
    )
    assert conflict.status_code == 409


# --- GET /v1/vm/quote/{id} ---


@pytest.mark.asyncio
async def test_get_quote_round_trips(quote_state, client):
    created = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()
    got = await client.get(f"/v1/vm/quote/{created['quote_id']}")
    assert got.status_code == 200
    assert got.json()["quote_id"] == created["quote_id"]
    assert got.json()["status"] == "created"


@pytest.mark.asyncio
async def test_get_unknown_quote_404(quote_state, client):
    assert (await client.get("/v1/vm/quote/q_does_not_exist")).status_code == 404


@pytest.mark.asyncio
async def test_get_expired_quote_surfaces_expired_status(quote_state, client):
    created = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()
    await _expire(quote_state, created["quote_id"])
    got = await client.get(f"/v1/vm/quote/{created['quote_id']}")
    assert got.status_code == 200
    assert got.json()["status"] == "expired"


# --- POST /v1/vm/create with quote_id ---


@pytest.mark.asyncio
async def test_create_with_quote_paid_provisions_and_consumes(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 202, res.text
    assert res.json()["vm_id"]
    assert res.json()["management_token"] is not None
    # Quote is now consumed and linked to the VM.
    row = await quotes_service.get_quote(quote_state.orchestrator.db, quote["quote_id"])
    assert QuoteStatus(row.status) == QuoteStatus.CONSUMED
    assert row.vm_id == res.json()["vm_id"]


@pytest.mark.asyncio
async def test_create_preserves_quoted_profile_after_catalog_price_change(
    quote_state,
    client,
    monkeypatch,
):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (
        await client.post(
            "/v1/vm/quote",
            json={
                "order_payload": _order(
                    size="md",
                    resources={"vcpu": 2, "ram_mb": 4096, "disk_gb": 20},
                )
            },
        )
    ).json()
    assert quote["order_payload"]["size"] == "md"

    # These resources now price cheapest from SM. The durable quote must keep
    # MD as the VM's billing base so later extensions use the quoted profile.
    monkeypatch.setattr(quote_state.config.payment, "price_vm_sm", Decimal("0.01"))
    monkeypatch.setattr(quote_state.config.payment, "price_vm_md", Decimal("5.00"))
    order = dict(quote["order_payload"])
    order["quote_id"] = quote["quote_id"]
    response = await client.post("/v1/vm/create", json=order)

    assert response.status_code == 202, response.text
    async with quote_state.orchestrator.db() as session:
        vm = await session.get(VMRow, response.json()["vm_id"])
    assert VMSize(vm.size) is VMSize.MD
    assert (
        vm.billing_addon_vcpu,
        vm.billing_addon_ram_mb,
        vm.billing_addon_disk_gb,
    ) == (0, 0, 0)


@pytest.mark.asyncio
async def test_create_accepts_original_custom_shortcut_after_quote_rebases_profile(
    quote_state,
    client,
):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    original = _order(
        size="xs",
        resources={"vcpu": 1, "ram_mb": 2048, "disk_gb": 20},
    )
    quote = (
        await client.post("/v1/vm/quote", json={"order_payload": original})
    ).json()
    assert quote["order_payload"]["size"] == "sm"

    response = await client.post(
        "/v1/vm/create",
        json={**original, "quote_id": quote["quote_id"]},
    )

    assert response.status_code == 202, response.text
    async with quote_state.orchestrator.db() as session:
        vm = await session.get(VMRow, response.json()["vm_id"])
    assert VMSize(vm.size) is VMSize.SM


@pytest.mark.asyncio
async def test_link_quote_failure_still_starts_provisioning(quote_state, client, monkeypatch):
    """A post-charge link_quote_vm failure must NOT strand the paid VM: since
    provisioning is now deferred until after the link, a link exception would
    otherwise leave the VM in PROVISIONING with no background task and no refund
    path. The create still succeeds and provisioning is started."""
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    async def _boom(*args, **kwargs):
        raise RuntimeError("transient DB error while linking quote")

    monkeypatch.setattr("hyrule_cloud.api.routes.link_quote_vm", _boom)

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 202, res.text
    vm_id = res.json()["vm_id"]
    assert vm_id in quote_state.orchestrator.provisioning_started


@pytest.mark.asyncio
async def test_post_charge_failure_records_refund_and_fails_row(quote_state, client, monkeypatch):
    """A post-charge failure before the background provisioner is scheduled (here
    start_provisioning raises) must (a) record a refund and (b) terminally fail
    the VM row so it doesn't sit in PROVISIONING pinning its customer /64."""
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    def _boom(vm_id):
        raise RuntimeError("scheduler down")

    monkeypatch.setattr(quote_state.orchestrator, "start_provisioning", _boom)

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 500
    # A refund was recorded for the charged-but-failed create.
    assert quote_state.orchestrator.create_failure_refunds
    # The half-created row is terminally FAILED, not stranded in PROVISIONING.
    vm_id = quote_state.orchestrator.created_vms[-1]
    async with quote_state.orchestrator.db() as session:
        row = await session.get(VMRow, vm_id)
    assert row.status == VMStatus.FAILED


@pytest.mark.asyncio
async def test_link_quote_retries_then_succeeds(quote_state, client, monkeypatch):
    """A transient link failure is retried; once it succeeds the quote carries
    its vm_id so the paid VM stays rediscoverable via the consumed quote."""
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    calls = {"n": 0}
    real_link = quotes_service.link_quote_vm

    async def _flaky(db, quote_id, vm_id):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("transient DB error while linking quote")
        await real_link(db, quote_id, vm_id)

    monkeypatch.setattr("hyrule_cloud.api.routes.link_quote_vm", _flaky)

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 202, res.text
    assert calls["n"] == 2  # failed once, retried, succeeded
    row = await quotes_service.get_quote(quote_state.orchestrator.db, quote["quote_id"])
    assert row.vm_id == res.json()["vm_id"]  # linked on retry — rediscoverable


@pytest.mark.asyncio
async def test_create_with_quote_no_payment_402_leaves_quote_created(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value=Response(status_code=402))
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 402
    row = await quotes_service.get_quote(quote_state.orchestrator.db, quote["quote_id"])
    assert QuoteStatus(row.status) == QuoteStatus.CREATED  # unconsumed, retry-able


@pytest.mark.asyncio
async def test_create_with_expired_quote_409(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()
    await _expire(quote_state, quote["quote_id"])
    res = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_create_with_mismatched_body_422(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()
    # Body differs from the stored spec (duration 30 vs quoted 1).
    res = await client.post(
        "/v1/vm/create", json=_order(duration_days=30, quote_id=quote["quote_id"])
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_create_rejects_resource_tampering_against_quote(quote_state, client):
    quoted_order = _order(resources={"vcpu": 3, "ram_mb": 6144, "disk_gb": 30})
    quote = (
        await client.post("/v1/vm/quote", json={"order_payload": quoted_order})
    ).json()
    tampered = dict(quote["order_payload"])
    tampered["quote_id"] = quote["quote_id"]
    tampered["resources"] = {"vcpu": 4, "ram_mb": 6144, "disk_gb": 30}

    res = await client.post("/v1/vm/create", json=tampered)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_custom_create_persists_exact_resources_and_billing_addons(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (
        await client.post(
            "/v1/vm/quote",
            json={
                "order_payload": _order(
                    resources={"vcpu": 4, "ram_mb": 8192, "disk_gb": 40}
                )
            },
        )
    ).json()
    order = dict(quote["order_payload"])
    order["quote_id"] = quote["quote_id"]

    created = await client.post("/v1/vm/create", json=order)
    assert created.status_code == 202, created.text
    async with quote_state.orchestrator.db() as session:
        row = await session.get(VMRow, created.json()["vm_id"])
    assert (row.vcpu, row.memory_mb, row.disk_gb) == (4, 8192, 40)
    assert (row.billing_addon_vcpu, row.billing_addon_ram_mb, row.billing_addon_disk_gb) == (
        0,
        4096,
        0,
    )


@pytest.mark.asyncio
async def test_create_idempotent_replay_of_consumed_quote(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()
    first = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    second = await client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"]))
    assert first.status_code == 202
    assert second.status_code == 200
    assert first.json()["vm_id"] == second.json()["vm_id"]
    # The one-shot management token is only revealed on first provision.
    assert second.json()["management_token"] is None
    # Exactly one VM was provisioned despite two create posts.
    assert len(quote_state.orchestrator.created_vms) == 1


@pytest.mark.asyncio
async def test_concurrent_paid_creates_provision_at_most_one_vm(quote_state, client):
    """Sourcery (#16): the quote is claimed atomically BEFORE provisioning, so two
    concurrent paid creates for the same quote provision exactly one VM."""
    import asyncio

    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    quote = (await client.post("/v1/vm/quote", json={"order_payload": _order()})).json()

    r1, r2 = await asyncio.gather(
        client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"])),
        client.post("/v1/vm/create", json=_order(quote_id=quote["quote_id"])),
    )
    # The invariant: at most one VM regardless of how the two interleave.
    assert len(quote_state.orchestrator.created_vms) == 1
    statuses = {r1.status_code, r2.status_code}
    # Winner → 202 (accepted); loser → 200 (existing VM) or 409 (mid-provision).
    assert 202 in statuses
    assert statuses.issubset({200, 202, 409})


@pytest.mark.asyncio
async def test_create_unknown_quote_404(quote_state, client):
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    res = await client.post("/v1/vm/create", json=_order(quote_id="q_nope"))
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_legacy_create_without_quote_id_still_works(quote_state, client):
    """Backward-compat: the legacy compute-price-from-body path is unchanged."""
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")
    res = await client.post("/v1/vm/create", json=_order())
    assert res.status_code == 202, res.text
    assert res.json()["vm_id"]


@pytest.mark.asyncio
async def test_real_mode_create_rejects_unsupported_os_before_payment(
    quote_state, client, monkeypatch
):
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)
    quote_state.payment_gate.check_payment = AsyncMock(return_value="0xWALLET")

    res = await client.post("/v1/vm/create", json=_order(os="openbsd-7.8"))
    assert res.status_code == 400
    quote_state.payment_gate.check_payment.assert_not_awaited()


# --- Migration 008 linkage / schema validity ---


def test_migration_008_chains_to_007():
    import importlib.util
    from pathlib import Path

    # Alembic versions are loaded by file path (the module name starts with a
    # digit and the dir isn't a package), so load it the same way here.
    path = Path(__file__).resolve().parent.parent / "alembic" / "versions" / "008_vm_quotes.py"
    spec = importlib.util.spec_from_file_location("migration_008", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "008"
    assert mod.down_revision == "007"
    assert callable(mod.upgrade) and callable(mod.downgrade)


def test_vm_quotes_table_in_metadata():
    assert "vm_quotes" in Base.metadata.tables
    cols = Base.metadata.tables["vm_quotes"].columns
    assert {"quote_id", "order_payload", "amount_usd", "status", "expires_at"} <= set(cols.keys())


def test_migration_012_chains_to_011():
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).resolve().parent.parent
        / "alembic"
        / "versions"
        / "012_vm_customer_ipv6_prefixes.py"
    )
    spec = importlib.util.spec_from_file_location("migration_012", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "012"
    assert mod.down_revision == "011"
    assert callable(mod.upgrade) and callable(mod.downgrade)


def test_vms_table_has_customer_ipv6_prefix_columns():
    cols = Base.metadata.tables["vms"].columns
    assert {"ipv6_prefix_index", "ipv6_prefix"} <= set(cols.keys())


# --- helpers ---


async def _expire(state, quote_id: str) -> None:
    async with state.orchestrator.db() as db:
        await db.execute(
            update(VMQuoteRow)
            .where(VMQuoteRow.quote_id == quote_id)
            .values(expires_at=_now() - timedelta(minutes=1))
        )
        await db.commit()
