"""Issue #28: launch-proof contract over the existing VM path.

Covers the full state journey (quote → payment_required → provisioning →
provisioned) and the failed → safe-message path.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import partial
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, VMQuoteRow, VMRow
from hyrule_cloud.models import (
    DNSResolutionStatus,
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
        self.provisioning_started: list[str] = []
        self.create_failure_refunds: list[tuple[str | None, str | None]] = []

    def compute_price(self, request):
        from hyrule_cloud.models import CostBreakdown

        total = Decimal("0.05") * request.duration_days
        return total, CostBreakdown(
            vm_cost=f"${total:.2f}",
            domain_cost="$0.00",
            total=f"${total:.2f}",
        )

    async def start_provisioning(self, vm_id: str) -> None:
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

    async def persist_charged_amount(self, vm_id: str, amount: Decimal) -> None:
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None:
                row.cost_total = amount
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
    assert res.status_code == 202, res.text
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


# --- HYRULE_REQUIRE_REAL_PROVISIONING startup guard ---


def _guard_config(*, require: bool, dev_bypass: str = "") -> object:
    from hyrule_cloud.config import HyruleConfig, PaymentConfig

    return HyruleConfig(
        require_real_provisioning=require,
        payment=PaymentConfig(dev_bypass_secret=dev_bypass),
    )


def test_guard_noop_when_not_required(monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", False)
    launch_proof.enforce_real_provisioning_guard(_guard_config(require=False, dev_bypass="x"))


def test_guard_rejects_simulation_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", False)
    with pytest.raises(RuntimeError, match="HCP_LAUNCH_PROOF_REAL_XCPNG"):
        launch_proof.enforce_real_provisioning_guard(_guard_config(require=True))


def test_guard_rejects_dev_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)
    with pytest.raises(RuntimeError, match="PAYMENT_DEV_BYPASS_SECRET"):
        launch_proof.enforce_real_provisioning_guard(_guard_config(require=True, dev_bypass="x"))


def test_guard_passes_in_real_mode_without_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)
    launch_proof.enforce_real_provisioning_guard(_guard_config(require=True))


# --- Real-mode launch-proof evidence helpers (Phase 3d) ---


@pytest.mark.asyncio
async def test_probe_ssh_detects_listening_port() -> None:
    from hyrule_cloud.orchestrator import Orchestrator

    async def _handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        ok = await Orchestrator._probe_ssh(
            object(), "127.0.0.1", timeout_seconds=5, interval_seconds=1, port=port
        )
    finally:
        server.close()
        await server.wait_closed()
    assert ok is True


@pytest.mark.asyncio
async def test_probe_ssh_fails_closed_when_unreachable() -> None:
    from hyrule_cloud.orchestrator import Orchestrator

    # Port 1 on localhost: connection refused immediately, loop must give up.
    ok = await Orchestrator._probe_ssh(
        object(), "127.0.0.1", timeout_seconds=2, interval_seconds=1, port=1
    )
    assert ok is False


@pytest.mark.asyncio
async def test_verify_aaaa_fails_closed_without_dns_server() -> None:
    from hyrule_cloud.config import HyruleConfig
    from hyrule_cloud.providers.dns import DNSProvider

    provider = DNSProvider(HyruleConfig(dns_server="", dns_tsig_key="dGVzdA=="))
    assert await provider.verify_aaaa("vm123", "2a0c:b641:b51::2") is False


# --- Customer-side DNS resolution proof ---
#
# A real paid VM (vm_bDRgKbVbxsUcraNvVuSbxA) shipped as status=ready,
# launch_proof_status=provisioned, ssh_smoke=passed, dns_aaaa_verified=true
# while unable to resolve a single hostname: the inbound proofs never look at
# whether the guest's own resolver answers.


async def _ready_vm(state, vm_id: str, launch_proof: dict) -> None:
    async with state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id=vm_id,
                owner_wallet="0xwallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                hostname="a37e2372.deploy.hyrule.host",
                ipv6="2a0c:b641:b51:d0f8::2",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                expires_at=_now() + timedelta(days=1),
                cost_total=Decimal("0.05"),
                metadata_={"launch_proof": launch_proof},
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_dns_resolution_failure_reports_degraded_not_ready(lp_state, client):
    """The live defect: reachable + correct AAAA, but resolves nothing."""
    await _ready_vm(
        lp_state,
        "vm_dns_broken",
        {
            "ssh_smoke_status": "passed",
            "dns_aaaa_verified": True,
            "dns_resolution_status": DNSResolutionStatus.FAILED.value,
        },
    )

    body = (await client.get("/v1/vm/vm_dns_broken/status")).json()

    assert body["dns_resolution_status"] == DNSResolutionStatus.FAILED
    # NOT a clean provisioned — but the VM is delivered, so not `failed`
    # either (that state promises a refund).
    assert body["launch_proof_status"] == LaunchProofStatus.DEGRADED
    assert body["status"] == VMStatus.READY
    assert body["ssh_smoke_status"] == SSHSmokeStatus.PASSED
    assert body["dns_aaaa_verified"] is True
    customer = body["customer_message"]
    assert customer != "Your VM is ready."
    assert "resolve" in customer.lower()
    # The customer can unblock themselves while the operator fixes the fleet.
    assert "resolv.conf" in customer
    assert "HYRULE_CUSTOMER_IPV6_DNS" in (body["operator_message"] or "")


@pytest.mark.asyncio
async def test_dns_resolution_failure_overrides_stale_ready_message(lp_state, client):
    """A persisted "Your VM is ready." must not outrank the degraded message."""
    await _ready_vm(
        lp_state,
        "vm_dns_stale_msg",
        {
            "ssh_smoke_status": "passed",
            "dns_resolution_status": DNSResolutionStatus.FAILED.value,
            "customer_message": "Your VM is ready.",
        },
    )

    body = (await client.get("/v1/vm/vm_dns_stale_msg/status")).json()

    assert body["launch_proof_status"] == LaunchProofStatus.DEGRADED
    assert body["customer_message"] != "Your VM is ready."


@pytest.mark.asyncio
async def test_dns_resolution_passed_stays_provisioned(lp_state, client):
    await _ready_vm(
        lp_state,
        "vm_dns_ok",
        {
            "ssh_smoke_status": "passed",
            "dns_aaaa_verified": True,
            "dns_resolution_status": DNSResolutionStatus.PASSED.value,
        },
    )

    body = (await client.get("/v1/vm/vm_dns_ok/status")).json()

    assert body["dns_resolution_status"] == DNSResolutionStatus.PASSED
    assert body["launch_proof_status"] == LaunchProofStatus.PROVISIONED
    assert body["customer_message"] == "Your VM is ready."


@pytest.mark.asyncio
async def test_dns_resolution_unmeasured_reports_not_run(lp_state, client):
    """Rows provisioned before the probe existed say "not checked" — the
    status is never inferred from the VM being READY, which is the class of
    guess that shipped the broken VM."""
    await _ready_vm(lp_state, "vm_dns_unmeasured", {"ssh_smoke_status": "passed"})

    body = (await client.get("/v1/vm/vm_dns_unmeasured/status")).json()

    assert body["dns_resolution_status"] == DNSResolutionStatus.NOT_RUN
    assert body["launch_proof_status"] == LaunchProofStatus.PROVISIONED


# --- The probe itself ---


class _StubResolverProtocol(asyncio.DatagramProtocol):
    """Minimal UDP DNS responder: answers every query with `answer` (or NODATA)."""

    def __init__(self, answer: str | None) -> None:
        self.answer = answer
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        import dns.message
        import dns.rrset

        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        if self.answer is not None:
            response.answer.append(
                dns.rrset.from_text(
                    query.question[0].name, 60, "IN", "AAAA", self.answer
                )
            )
        assert self.transport is not None
        self.transport.sendto(response.to_wire(), addr)


def _probe_orchestrator(dns_servers: str, hostname: str = "deb.debian.org"):
    """Minimal `self` for the probe helpers (mirrors the _probe_ssh tests)."""
    from types import SimpleNamespace

    from hyrule_cloud.orchestrator import Orchestrator

    orch = SimpleNamespace(
        config=SimpleNamespace(
            customer_ipv6_dns=dns_servers,
            customer_dns_probe_hostname=hostname,
        )
    )
    orch._query_customer_resolver = partial(Orchestrator._query_customer_resolver, orch)
    orch._probe_customer_dns_resolution = partial(
        Orchestrator._probe_customer_dns_resolution, orch
    )
    return orch


async def _stub_resolver(answer: str | None) -> tuple[asyncio.DatagramTransport, int]:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _StubResolverProtocol(answer), local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("socket").getsockname()[1]
    return transport, port


@pytest.mark.asyncio
async def test_dns_probe_passes_when_resolver_answers() -> None:
    # A DNS64-synthesized AAAA for an IPv4-only host: what NAT64 needs.
    transport, port = await _stub_resolver("64:ff9b::9765:8b1e")
    try:
        result = await _probe_orchestrator("127.0.0.1")._probe_customer_dns_resolution(
            timeout_seconds=2, port=port
        )
    finally:
        transport.close()
    assert result is DNSResolutionStatus.PASSED


@pytest.mark.asyncio
async def test_dns_probe_fails_when_resolver_returns_no_address() -> None:
    """NOERROR/NODATA: the resolver answers but synthesises nothing, so an
    IPv6-only guest still cannot reach the name."""
    transport, port = await _stub_resolver(None)
    try:
        result = await _probe_orchestrator("127.0.0.1")._probe_customer_dns_resolution(
            timeout_seconds=2, port=port
        )
    finally:
        transport.close()
    assert result is DNSResolutionStatus.FAILED


@pytest.mark.asyncio
async def test_dns_probe_fails_when_nothing_listens() -> None:
    """The live outage: the address routes traffic and refuses port 53."""
    transport, port = await _stub_resolver("64:ff9b::1")
    transport.close()
    await asyncio.sleep(0)

    result = await _probe_orchestrator("127.0.0.1")._probe_customer_dns_resolution(
        timeout_seconds=1, port=port
    )
    assert result is DNSResolutionStatus.FAILED


@pytest.mark.asyncio
async def test_dns_probe_falls_back_to_second_resolver() -> None:
    transport, port = await _stub_resolver("2606:4700:4700::1111")
    try:
        # 127.0.0.2:port has no listener; the second resolver answers.
        result = await _probe_orchestrator(
            "127.0.0.2, 127.0.0.1"
        )._probe_customer_dns_resolution(timeout_seconds=1, port=port)
    finally:
        transport.close()
    assert result is DNSResolutionStatus.PASSED


@pytest.mark.asyncio
async def test_dns_probe_not_run_without_configuration() -> None:
    assert (
        await _probe_orchestrator("")._probe_customer_dns_resolution(timeout_seconds=1)
        is DNSResolutionStatus.NOT_RUN
    )
    assert (
        await _probe_orchestrator("127.0.0.1", hostname="")._probe_customer_dns_resolution(
            timeout_seconds=1
        )
        is DNSResolutionStatus.NOT_RUN
    )


@pytest.mark.asyncio
async def test_dns_probe_swallows_unexpected_errors() -> None:
    """An internal probe bug must not crash provisioning (that would fail a
    paid VM) and must not mark a healthy fleet degraded — it reports not_run."""
    orch = _probe_orchestrator("127.0.0.1")

    async def _boom(*args, **kwargs):
        raise RuntimeError("probe exploded")

    orch._query_customer_resolver = _boom

    assert (
        await orch._probe_customer_dns_resolution(timeout_seconds=1)
        is DNSResolutionStatus.NOT_RUN
    )


def test_explicit_dns_verification_failure_is_not_papered_over() -> None:
    """A measured dns_aaaa_verified=False must win over the ipv6+hostname
    inference — otherwise a failed authoritative check reports verified."""
    from hyrule_cloud.services.launch_proof import build_launch_proof

    class _Row:
        status = VMStatus.READY
        ipv6 = "2a0c:b641:b51:1::2"
        hostname = "abc.deploy.hyrule.host"
        payment_tx = "0xSETTLED"
        cost_total = Decimal("0.05")
        error = None
        metadata_ = {"launch_proof": {"dns_aaaa_verified": False, "ssh_smoke_status": "passed"}}

    proof = build_launch_proof(_Row())
    assert proof["dns_aaaa_verified"] is False
    # Without a measurement, inference from ipv6+hostname still applies.
    _Row.metadata_ = {}
    proof = build_launch_proof(_Row())
    assert proof["dns_aaaa_verified"] is True
