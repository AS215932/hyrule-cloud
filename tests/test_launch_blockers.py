from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.api.routes import _enforce_paid_vm_cap
from hyrule_cloud.app import app
from hyrule_cloud.db import Base, CryptoIntentRow, VMQuoteRow, VMRow
from hyrule_cloud.models import (
    CryptoIntentStatus,
    NetworkRequest,
    QuoteStatus,
    VMSize,
    VMStatus,
)
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.network_client import NetworkProvider


def _now() -> datetime:
    return datetime.now(UTC)


class _Payment:
    price_vm_xs = Decimal("0.05")
    price_vm_sm = Decimal("0.10")
    price_vm_md = Decimal("0.20")
    price_vm_lg = Decimal("0.40")
    price_domain_markup = Decimal("1.00")
    price_proxy_direct = Decimal("0.01")
    price_proxy_tor = Decimal("0.05")
    price_proxy_i2p = Decimal("0.05")
    price_proxy_yggdrasil = Decimal("0.03")
    dev_bypass_secret = ""

    def enabled_networks(self):
        return []


class _Cfg:
    payment = _Payment()
    deploy_domain = "deploy.hyrule.host"
    blocked_ports = [25]
    max_paid_active_vms = 0
    vm_grace_period_hours = 1


class _Gate:
    async def check_payment(self, request, amount, description, extra_body):
        if request.headers.get("X-Mock-Paid"):
            request.state.payment_tx = "0xpaid"
            return "0xwallet"
        return Response(status_code=402)


class _Openprovider:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, str, str]] = []
        self.registrations: list[tuple[str, str]] = []
        self.fail_register = False

    async def check_domain(self, name, extension):
        return {
            "status": "free",
            "price": Decimal("8.50"),
            "currency": "USD",
            "is_premium": False,
        }

    async def register_domain(self, name, extension, period=1):
        if self.fail_register:
            raise RuntimeError("registrar unavailable")
        self.registrations.append((name, extension))
        return {"id": 42}

    async def create_zone(self, name):
        return {"name": name}

    async def list_zone_records(self, zone_name):
        return [{"name": "", "type": "AAAA", "value": "2001:db8::42", "ttl": 300}]

    async def create_zone_record(self, zone_name, name, rtype, value, ttl=300, prio=None):
        self.records.append((zone_name, name, rtype, value))
        return {}

    async def delete_zone_record(self, zone_name, name, rtype):
        return {}


class _Orch:
    def __init__(self, factory):
        self.db = factory
        self.openprovider = _Openprovider()

    async def get_vm(self, vm_id):
        async with self.db() as session:
            return await session.get(VMRow, vm_id)

    def compute_price(self, request):
        from hyrule_cloud.models import CostBreakdown

        total = Decimal("0.05") * request.duration_days
        return total, CostBreakdown(
            vm_cost=f"${total:.2f}",
            domain_cost="$0.00",
            total=f"${total:.2f}",
        )


@pytest_asyncio.fixture
async def launch_state():
    from hyrule_cloud.state import AppState

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    cfg = _Cfg()
    orch = _Orch(factory)
    state = AppState(
        config=cfg,
        orchestrator=orch,
        payment_gate=_Gate(),
        network_provider=None,
        native_crypto=object(),
        rate_provider=object(),
        native_payment_assets=[],
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev
        await engine.dispose()


@pytest.mark.asyncio
async def test_native_intent_rejected_until_asset_advertised(launch_state):
    payload = {
        "asset": "BTC",
        "order_payload": {
            "duration_days": 1,
            "size": "xs",
            "os": "debian-13",
            "ssh_pubkey": "ssh-ed25519 AAAA test",
            "domain_mode": "auto",
            "open_ports": [80, 443],
        },
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/v1/intent/create", json=payload)
    assert res.status_code == 503


@pytest.mark.asyncio
async def test_legacy_singular_domain_and_zone_routes_are_removed(launch_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        check = await client.get("/v1/domain/check", params={"domain": "example.test"})
        register = await client.post(
            "/v1/domain/register",
            json={"domain": "example.test", "client_order_id": "domain-1"},
            headers={"X-Mock-Paid": "1"},
        )
        records = await client.get("/v1/zone/records", params={"zone": "example.test"})

    assert [check.status_code, register.status_code, records.status_code] == [404, 404, 404]


@pytest.mark.asyncio
async def test_vm_quote_custom_domain_does_not_bundle_domain_registration(launch_state):
    payload = {
        "order_payload": {
            "duration_days": 1,
            "size": "xs",
            "os": "debian-13",
            "ssh_pubkey": "ssh-ed25519 AAAA test",
            "domain_mode": "custom",
            "domain": "quoted.test",
            "open_ports": [80, 443],
        }
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/v1/vm/quote", json=payload)
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["amount_usd"] == "0.050000"


@pytest.mark.asyncio
async def test_paid_vm_cap_counts_active_paid_vms(launch_state):
    launch_state.config.max_paid_active_vms = 1
    async with launch_state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id="vm_cap",
                owner_wallet="0xwallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                expires_at=_now() + timedelta(days=1),
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()

    with pytest.raises(Exception) as exc:
        await _enforce_paid_vm_cap(launch_state.orchestrator, launch_state.config)
    assert getattr(exc.value, "status_code", None) == 503


@pytest.mark.asyncio
async def test_network_provider_blocks_unsafe_contract_edges():
    provider = NetworkProvider()
    try:
        bad_method = await provider.execute_request(
            NetworkRequest(
                url="https://example.com",
                method="PUT",
            )
        )
        assert bad_method.status_code == 400

        direct_onion = await provider.execute_request(
            NetworkRequest(
                url="http://exampleonion.onion",
                proxy_mode="direct",
            )
        )
        assert direct_onion.status_code == 400

        localhost = await provider.execute_request(
            NetworkRequest(
                url="http://127.0.0.1/",
                proxy_mode="direct",
            )
        )
        assert localhost.status_code == 403
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_expiry_suspend_and_destroy_paths_are_exercised(launch_state):
    class _XCPNG:
        def __init__(self):
            self.suspended: list[str] = []

        async def suspend_vm(self, uuid):
            self.suspended.append(uuid)

    class _Fake:
        config = launch_state.config
        db = launch_state.orchestrator.db
        xcpng = _XCPNG()
        destroyed: list[str] = []

        async def destroy_vm(self, vm_id):
            self.destroyed.append(vm_id)
            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                row.status = VMStatus.DESTROYED
                await session.commit()
            return True

    now = _now()
    async with launch_state.orchestrator.db() as session:
        session.add_all(
            [
                VMRow(
                    vm_id="vm_suspend",
                    owner_wallet="0xwallet",
                    xcpng_uuid="uuid-suspend",
                    status=VMStatus.READY,
                    size=VMSize.XS,
                    os="debian-13",
                    ssh_pubkey="ssh-ed25519 AAAA test",
                    open_ports=[22],
                    expires_at=now - timedelta(minutes=5),
                    cost_total=Decimal("0.05"),
                ),
                VMRow(
                    vm_id="vm_destroy",
                    owner_wallet="0xwallet",
                    xcpng_uuid="uuid-destroy",
                    status=VMStatus.SUSPENDED,
                    size=VMSize.XS,
                    os="debian-13",
                    ssh_pubkey="ssh-ed25519 AAAA test",
                    open_ports=[22],
                    expires_at=now - timedelta(hours=2),
                    cost_total=Decimal("0.05"),
                ),
            ]
        )
        await session.commit()

    fake = _Fake()
    await Orchestrator.check_expiries(fake)
    assert fake.xcpng.suspended == ["uuid-suspend"]
    assert fake.destroyed == ["vm_destroy"]


# --- Paid VM service is closed while provisioning is simulated (Phase 1) ---
#
# The app boots in simulation to serve the intel/proxy/domain services, but the
# live x402 gate must never charge (or hand out a crypto deposit address) for a
# VM it can only fake. The gate opens at the Phase-3d real-provisioning flip.

_VM_ORDER = {
    "duration_days": 1,
    "size": "xs",
    "os": "debian-13",
    "ssh_pubkey": "ssh-ed25519 AAAA test",
    "domain_mode": "auto",
    "open_ports": [80, 443],
}


def _real_gate():
    """A real x402 PaymentGate (not a test double) — the live-money path.

    Construction is network-free; the facilitator is only contacted lazily.
    """
    from hyrule_cloud.config import PaymentConfig
    from hyrule_cloud.middleware.x402 import PaymentGate

    return PaymentGate(
        PaymentConfig(
            receiver_address="0xFf4555af30A1066A889324a3Fe88c76796159f15",
            facilitator_url="https://facilitator.payai.network",
        )
    )


def test_vm_service_open_truth_table(monkeypatch):
    from hyrule_cloud.api import routes

    real_gate = _real_gate()
    monkeypatch.setattr(routes, "_real_provisioning_enabled", lambda: False)
    # Live gate + simulation → closed; a test double is always treated as open.
    assert routes._vm_service_open(real_gate) is False
    assert routes._vm_service_open(object()) is True
    # Real provisioning enabled → the live gate may take money.
    monkeypatch.setattr(routes, "_real_provisioning_enabled", lambda: True)
    assert routes._vm_service_open(real_gate) is True


@pytest.mark.asyncio
async def test_vm_create_refuses_before_charging_while_simulated(launch_state):
    launch_state.payment_gate = _real_gate()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/vm/create", json=_VM_ORDER, headers={"X-Mock-Paid": "1"}
        )
    assert res.status_code == 503
    assert "not yet generally available" in res.json()["detail"]
    # Refused at the top of the handler — no row was ever written.
    async with launch_state.orchestrator.db() as session:
        count = (await session.execute(select(func.count()).select_from(VMRow))).scalar()
    assert count == 0


@pytest.mark.asyncio
async def test_vm_quote_refused_while_simulated(launch_state):
    launch_state.payment_gate = _real_gate()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/v1/vm/quote", json={"order_payload": _VM_ORDER})
    assert res.status_code == 503
    assert "not yet generally available" in res.json()["detail"]


@pytest.mark.asyncio
async def test_vm_crypto_intent_refused_while_simulated(launch_state):
    launch_state.payment_gate = _real_gate()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/intent/create", json={"asset": "BTC", "order_payload": _VM_ORDER}
        )
    assert res.status_code == 503
    assert "not yet generally available" in res.json()["detail"]


@pytest.mark.asyncio
async def test_manifest_hides_vm_create_until_real_provisioning(launch_state, monkeypatch):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        sim = await client.get("/.well-known/x402.json")
        assert sim.status_code == 200
        sim_paths = {r["path"] for r in sim.json()["resources"]}
        assert "/v1/vm/create" not in sim_paths
        # Other paid services stay advertised while VMs are held back.
        assert "/v1/network/request" in sim_paths

        monkeypatch.setattr(
            "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
        )
        real = await client.get("/.well-known/x402.json")
        real_paths = {r["path"] for r in real.json()["resources"]}
    assert "/v1/vm/create" in real_paths


@pytest.mark.asyncio
async def test_consumed_quote_replay_survives_closed_service(launch_state):
    # A paid, already-provisioned quote must still return its VM even while the
    # service is closed — don't strand a customer who already paid (the guard
    # sits after the consumed-quote replay).
    launch_state.payment_gate = _real_gate()
    async with launch_state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id="vm_consumed",
                owner_wallet="0xwallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                expires_at=_now() + timedelta(days=1),
                cost_total=Decimal("0.05"),
            )
        )
        session.add(
            VMQuoteRow(
                quote_id="q_consumed",
                order_payload=_VM_ORDER,
                amount_usd=Decimal("0.05"),
                status=QuoteStatus.CONSUMED,
                vm_id="vm_consumed",
                expires_at=_now() + timedelta(minutes=30),
            )
        )
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/vm/create", json={"quote_id": "q_consumed", **_VM_ORDER}
        )
    assert res.status_code == 200, res.text
    assert res.json()["vm_id"] == "vm_consumed"


@pytest.mark.asyncio
async def test_extend_refused_while_simulated(launch_state):
    from hyrule_cloud.middleware.anon_token import hash_anon_token
    from hyrule_cloud.models import generate_anon_management_token

    launch_state.payment_gate = _real_gate()
    token = generate_anon_management_token()
    async with launch_state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id="vm_ext",
                owner_wallet="0xwallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                expires_at=_now() + timedelta(days=1),
                cost_total=Decimal("0.05"),
                anon_management_token_hash=hash_anon_token(token),
            )
        )
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/vm/vm_ext/extend",
            json={"days": 3},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert res.status_code == 503
    assert "not yet generally available" in res.json()["detail"]


def test_intent_awaiting_payment_truth_table():
    from hyrule_cloud.api import routes

    class _Row:
        def __init__(self, status, amount_received_crypto=None, tx_hash=None):
            self.status = status
            self.amount_received_crypto = amount_received_crypto
            self.tx_hash = tx_hash

    # No funds in flight → awaiting (safe to refuse while closed).
    for awaiting in (
        CryptoIntentStatus.CREATED,
        CryptoIntentStatus.WAITING_PAYMENT,
        CryptoIntentStatus.PENDING,
    ):
        assert routes._intent_awaiting_payment(_Row(awaiting)) is True
    # Committed / provisioning / terminal → always resolves.
    for committed in (
        CryptoIntentStatus.SETTLED,
        CryptoIntentStatus.UNDERPAID,
        CryptoIntentStatus.OVERPAID,
        CryptoIntentStatus.LATE_PAID,
        CryptoIntentStatus.PROVISIONING,
        CryptoIntentStatus.PROVISIONED,
        CryptoIntentStatus.FAILED,
        CryptoIntentStatus.EXPIRED,
        CryptoIntentStatus.REFUND_MANUAL,
        CryptoIntentStatus.PAID,
    ):
        assert routes._intent_awaiting_payment(_Row(committed)) is False
    # WAITING_PAYMENT with an unconfirmed deposit already seen is NOT awaiting —
    # the customer has sent crypto, so the replay must resolve.
    assert (
        routes._intent_awaiting_payment(
            _Row(CryptoIntentStatus.WAITING_PAYMENT, amount_received_crypto=Decimal("0.0005"))
        )
        is False
    )
    assert (
        routes._intent_awaiting_payment(
            _Row(CryptoIntentStatus.WAITING_PAYMENT, tx_hash="deadbeef")
        )
        is False
    )
    # A zero received amount is still awaiting.
    assert (
        routes._intent_awaiting_payment(
            _Row(CryptoIntentStatus.WAITING_PAYMENT, amount_received_crypto=Decimal("0"))
        )
        is True
    )


@pytest.mark.asyncio
async def test_intent_replay_respects_commitment_while_simulated(launch_state):
    # Funds already committed (SETTLED) → replay resolves so the deposit is not
    # orphaned. Still awaiting payment (CREATED) → the guard refuses, so a
    # closed service never re-hands-out a deposit address for a simulated VM.
    launch_state.payment_gate = _real_gate()
    async with launch_state.orchestrator.db() as session:
        session.add(
            CryptoIntentRow(
                intent_id="int_settled",
                asset="BTC",
                amount_crypto=Decimal("0.001"),
                address="bc1qsettled",
                status=CryptoIntentStatus.SETTLED,
                expires_at=_now() + timedelta(hours=1),
                client_order_id="settled-1",
                order_payload=_VM_ORDER,
            )
        )
        session.add(
            CryptoIntentRow(
                intent_id="int_created",
                asset="BTC",
                amount_crypto=Decimal("0.001"),
                address="bc1qcreated",
                status=CryptoIntentStatus.CREATED,
                expires_at=_now() + timedelta(hours=1),
                client_order_id="created-1",
                order_payload=_VM_ORDER,
            )
        )
        # WAITING_PAYMENT but the poller has already seen an unconfirmed deposit:
        # funds are in flight, so this must replay even while closed.
        session.add(
            CryptoIntentRow(
                intent_id="int_unconfirmed",
                asset="BTC",
                amount_crypto=Decimal("0.001"),
                amount_received_crypto=Decimal("0.0005"),
                address="bc1qunconfirmed",
                status=CryptoIntentStatus.WAITING_PAYMENT,
                expires_at=_now() + timedelta(hours=1),
                client_order_id="unconfirmed-1",
                order_payload=_VM_ORDER,
            )
        )
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        settled = await client.post(
            "/v1/intent/create",
            json={"asset": "BTC", "order_payload": _VM_ORDER, "client_order_id": "settled-1"},
        )
        created = await client.post(
            "/v1/intent/create",
            json={"asset": "BTC", "order_payload": _VM_ORDER, "client_order_id": "created-1"},
        )
        unconfirmed = await client.post(
            "/v1/intent/create",
            json={"asset": "BTC", "order_payload": _VM_ORDER, "client_order_id": "unconfirmed-1"},
        )
    assert settled.status_code == 200, settled.text
    assert settled.json()["intent_id"] == "int_settled"
    assert created.status_code == 503
    assert "not yet generally available" in created.json()["detail"]
    # Funds already sent (unconfirmed) → recoverable, not stranded.
    assert unconfirmed.status_code == 200, unconfirmed.text
    assert unconfirmed.json()["intent_id"] == "int_unconfirmed"
