from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.api.routes import _enforce_paid_vm_cap
from hyrule_cloud.app import app
from hyrule_cloud.db import Base, DomainRow, VMRow
from hyrule_cloud.models import DomainStatus, NetworkRequest, VMSize, VMStatus
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.network_client import NetworkProvider


def _now() -> datetime:
    return datetime.now(UTC)


class _Payment:
    price_vm_xs = Decimal("0.05")
    price_vm_sm = Decimal("0.10")
    price_vm_md = Decimal("0.20")
    price_vm_lg = Decimal("0.40")
    price_vpn = Decimal("0.02")
    price_domain_markup = Decimal("1.00")
    price_proxy_direct = Decimal("0.01")
    price_proxy_tor = Decimal("0.05")
    price_proxy_residential = Decimal("0.20")
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

    def compute_price(self, request):
        from hyrule_cloud.models import CostBreakdown

        total = Decimal("0.05") * request.duration_days
        domain_cost = Decimal("0")
        if request.domain_mode == "custom" and request.domain:
            domain_cost = Decimal("1.00")
        total += domain_cost
        return total, CostBreakdown(
            vm_cost=f"${total - domain_cost:.2f}",
            domain_cost=f"${domain_cost:.2f}" if domain_cost else "$0.00",
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
async def test_domain_register_persists_ownerless_token_and_gates_records(launch_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        check = await client.get("/v1/domain/check", params={"domain": "example.test"})
        assert check.status_code == 200
        assert check.json()["total"] == "9.50"

        unpaid = await client.post("/v1/domain/register", json={"domain": "example.test"})
        assert unpaid.status_code == 402

        paid = await client.post(
            "/v1/domain/register",
            json={"domain": "example.test", "client_order_id": "domain-1"},
            headers={"X-Mock-Paid": "1"},
        )
        assert paid.status_code == 200, paid.text
        body = paid.json()
        assert body["status"] == "active"
        token = body["management_token"]
        assert token.startswith("hyr_dom_")
        assert body["management_url"] == "/v1/zone/records?zone=example.test"

        denied = await client.get("/v1/zone/records", params={"zone": "example.test"})
        assert denied.status_code == 404

        allowed = await client.get(
            "/v1/zone/records",
            params={"zone": "example.test"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert allowed.status_code == 200
        assert allowed.json()["records"][0]["type"] == "AAAA"

    async with launch_state.orchestrator.db() as session:
        row = (await session.get(DomainRow, 1))
        assert row.fqdn == "example.test"
        assert row.status == DomainStatus.ACTIVE
        assert row.owner_wallet == "0xwallet"


@pytest.mark.asyncio
async def test_domain_register_failure_after_payment_persists_failed_row(launch_state):
    launch_state.orchestrator.openprovider.fail_register = True
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        paid = await client.post(
            "/v1/domain/register",
            json={"domain": "broken.test", "client_order_id": "domain-fail-1"},
            headers={"X-Mock-Paid": "1"},
        )
        assert paid.status_code == 502

    async with launch_state.orchestrator.db() as session:
        row = (await session.get(DomainRow, 1))
        assert row.fqdn == "broken.test"
        assert row.status == DomainStatus.FAILED
        assert row.payment_tx == "0xpaid"
        assert "registrar unavailable" in row.error


@pytest.mark.asyncio
async def test_vm_quote_custom_domain_includes_registrar_price_and_markup(launch_state):
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
    assert body["amount_usd"] == "9.550000"


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
