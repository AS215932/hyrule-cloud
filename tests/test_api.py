import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI, Response
from hyrule_cloud.app import app
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.models import VMSize, VMStatus, ProxyMode
from datetime import datetime
from decimal import Decimal

# Block A0: known token used by the mock VM. Tests that exercise the
# management-gated routes pass this as Authorization: Bearer / ?token=.
_TEST_TOKEN = "hyr_vm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

class MockConfig:
    class Payment:
        price_vm_xs = Decimal("0.05")
        price_vm_sm = Decimal("0.10")
        price_vm_md = Decimal("0.20")
        price_vm_lg = Decimal("0.40")
        price_vpn = Decimal("0.02")
        price_domain_markup = Decimal("1.00")
        price_proxy_direct = Decimal("0.01")
        price_proxy_tor = Decimal("0.05")
        price_proxy_residential = Decimal("0.20")
        asset = "USDC"
        network = "eip155:8453"
        dev_bypass_secret = ""
    
    class XCPNG:
        templates = {}

    payment = Payment()
    xcpng = XCPNG()
    deploy_domain = "deploy.hyrule.host"
    blocked_ports = [25]

class MockOrchestrator:
    async def get_vm(self, vm_id):
        if vm_id == "vm_test123":
            class MockRow:
                vm_id = "vm_test123"
                status = VMStatus.READY
                ipv6 = "2001:db8::1"
                hostname = "test.deploy.hyrule.host"
                expires_at = datetime.utcnow()
                error = None
                open_ports = [22, 80]
                created_at = datetime.utcnow()
                # Block A0: matches _TEST_TOKEN, so the management routes
                # accept the bearer header / ?token= param in tests.
                anon_management_token_hash = hash_anon_token(_TEST_TOKEN)
            return MockRow()
        return None

class MockGate:
    async def check_payment(self, request, amount, description, extra_body):
        # Allow requests with X-Mock-Wallet header to mimic paid requests
        if request.headers.get("X-Mock-Wallet"):
            request.state.payment_tx = "0xMockHash"
            return request.headers.get("X-Mock-Wallet")
        return Response(status_code=402)

class MockNetworkProvider:
    pass

@pytest.fixture
def override_state():
    from hyrule_cloud.state import AppState
    og_state = getattr(app.state, "_typed_state", None)
    app_state = AppState(
        config=MockConfig(),
        orchestrator=MockOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider()
    )
    app.state._typed_state = app_state
    yield app_state
    if og_state:
        app.state._typed_state = og_state

@pytest.mark.asyncio
async def test_get_pricing(override_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/pricing")
        assert res.status_code == 200
        data = res.json()
        assert data["vm_prices"]["xs (1vCPU/512MB/10GB)"] == "$0.05/day"
        assert data["domain_auto"] == "$0.00 (subdomain under deploy.hyrule.host)"

@pytest.mark.asyncio
async def test_get_pricing_uses_configured_deploy_domain(override_state):
    override_state.config.deploy_domain = "custom.example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/pricing")
        assert res.status_code == 200
        data = res.json()
        assert data["domain_auto"] == "$0.00 (subdomain under custom.example.com)"

@pytest.mark.asyncio
async def test_get_os_list(override_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/os/list")
        assert res.status_code == 200
        data = res.json()
        assert len(data["templates"]) > 0

@pytest.mark.asyncio
async def test_get_vm_status(override_state):
    """Block A0: the old `/v1/vm/{id}` URL is now management-gated. With
    the correct anon token it still returns the full management view.
    Without a token it returns 404 (not 403) so vm_id existence does not
    leak to random guessers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            "/v1/vm/vm_test123",
            headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["ipv6"] == "2001:db8::1"

        # Without the token: 404, same shape as "VM not found".
        res_no_token = await client.get("/v1/vm/vm_test123")
        assert res_no_token.status_code == 404

        res_404 = await client.get(
            "/v1/vm/vm_missing",
            headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
        )
        assert res_404.status_code == 404

@pytest.mark.asyncio
async def test_network_request_402(override_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/v1/network/request", json={
            "url": "http://example.com",
            "proxy_mode": "direct"
        })
        assert res.status_code == 402
