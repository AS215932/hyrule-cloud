from datetime import datetime
from decimal import Decimal

import pytest
from fastapi import Response
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.middleware.x402 import VerifiedPayment
from hyrule_cloud.models import NetworkResponse, ProxyMode, VMStatus

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
        price_proxy_i2p = Decimal("0.05")
        price_proxy_yggdrasil = Decimal("0.03")
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
                metadata_ = None
                payment_tx = None
                cost_total = Decimal("0.05")
                # Block A0: matches _TEST_TOKEN, so the management routes
                # accept the bearer header / ?token= param in tests.
                anon_management_token_hash = hash_anon_token(_TEST_TOKEN)
            return MockRow()
        return None

    async def get_quote_for_vm(self, vm_id):
        return None

class MockGate:
    def __init__(self):
        self.settled = 0

    async def check_payment(self, request, amount, description, extra_body):
        # Allow requests with X-Mock-Wallet header to mimic paid requests
        if request.headers.get("X-Mock-Wallet"):
            request.state.payment_tx = "0xMockHash"
            return request.headers.get("X-Mock-Wallet")
        return Response(status_code=402)

    async def verify_only(self, request, amount, description="", extra_body=None):
        # Two-phase flow (verify now, settle after delivery) for the proxy route.
        wallet = request.headers.get("X-Mock-Wallet")
        if wallet:
            return VerifiedPayment(payer=wallet, amount=amount)
        return Response(status_code=402)

    async def settle_verified(self, request, verified):
        self.settled += 1
        request.state.payment_tx = "0xMockHash"
        return True

class MockNetworkProvider:
    def __init__(self):
        self.available = True
        self.reason = None
        self.requests = []
        self.next_response = None  # per-test override (e.g. simulate a failure)

    async def mode_status(self, mode):
        provider = self
        class Status:
            available = provider.available
            reason = provider.reason
        return Status()

    async def execute_request(self, req):
        self.requests.append(req)
        if self.next_response is not None:
            return self.next_response
        return NetworkResponse(
            status_code=200,
            headers={"content-type": "text/plain"},
            body="ok",
            elapsed_seconds=0.01,
            proxy_mode=req.proxy_mode,
        )

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
        assert data["proxy_prices"] == {
            "direct": "$0.01/request",
            "tor": "$0.05/request",
            "i2p": "$0.05/request",
            "yggdrasil": "$0.03/request",
        }
        # VPN has no endpoint yet — it must not be priced until it exists.
        assert "vpn_per_day" not in data

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
async def test_real_mode_os_list_only_advertises_supported_templates(override_state, monkeypatch):
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/os/list")
        assert res.status_code == 200
        assert [template["name"] for template in res.json()["templates"]] == ["debian-13"]

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


@pytest.mark.asyncio
async def test_network_request_paid_calls_sidecar_provider(override_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            headers={"X-Mock-Wallet": "0xWallet"},
            json={"url": "http://example.com", "proxy_mode": "i2p"},
        )
        assert res.status_code == 200
        assert res.json()["body"] == "ok"
        assert len(override_state.network_provider.requests) == 1
        assert override_state.network_provider.requests[0].proxy_mode == "i2p"


@pytest.mark.asyncio
async def test_network_request_unavailable_mode_returns_503_before_payment(override_state):
    override_state.network_provider.available = False
    override_state.network_provider.reason = "tor SOCKS listener unavailable"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            json={"url": "http://example.com", "proxy_mode": "tor"},
        )
        assert res.status_code == 503
        assert "tor SOCKS listener unavailable" in res.text


@pytest.mark.asyncio
async def test_network_request_proxy_failure_is_not_charged(override_state):
    """A dead tor circuit / gateway failure (mode_status said available, the
    fetch then failed) must return an error WITHOUT settling — the canary was
    charged $0.05 for a 504 here."""
    override_state.network_provider.next_response = NetworkResponse(
        status_code=502,
        headers={},
        body="",
        elapsed_seconds=0.0,
        proxy_mode=ProxyMode.TOR,
        error="Network proxy error: HTTP 504",
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            headers={"X-Mock-Wallet": "0xWallet"},
            json={"url": "http://example.com", "proxy_mode": "tor"},
        )
    assert res.status_code == 502
    # The request was attempted, but the payment must not have settled.
    assert len(override_state.network_provider.requests) == 1
    assert override_state.payment_gate.settled == 0


@pytest.mark.asyncio
async def test_network_request_client_error_is_not_charged(override_state):
    """A validation rejection (400/403) is the caller's mistake — surface it,
    but never settle for a request we refused to run."""
    override_state.network_provider.next_response = NetworkResponse(
        status_code=403,
        headers={},
        body="",
        elapsed_seconds=0.0,
        proxy_mode=ProxyMode.DIRECT,
        error="Host is disallowed",
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            headers={"X-Mock-Wallet": "0xWallet"},
            json={"url": "http://example.com", "proxy_mode": "direct"},
        )
    assert res.status_code == 403
    assert override_state.payment_gate.settled == 0


@pytest.mark.asyncio
async def test_network_request_delivered_response_settles(override_state):
    """A delivered answer (even a target 4xx) settles exactly once."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            headers={"X-Mock-Wallet": "0xWallet"},
            json={"url": "http://example.com", "proxy_mode": "direct"},
        )
    assert res.status_code == 200
    assert res.json()["body"] == "ok"
    assert override_state.payment_gate.settled == 1


@pytest.mark.asyncio
async def test_network_request_settlement_failure_withholds_response(override_state, monkeypatch):
    """If settlement is declined after the fetch (e.g. a reused authorization),
    the caller must get a payment error, NOT the fetched body for free."""
    async def fail_settle(request, verified):
        return False

    monkeypatch.setattr(override_state.payment_gate, "settle_verified", fail_settle)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            headers={"X-Mock-Wallet": "0xWallet"},
            json={"url": "http://example.com", "proxy_mode": "direct"},
        )
    assert res.status_code == 402
    assert res.json().get("body") != "ok"  # the paid content was withheld


@pytest.mark.asyncio
async def test_network_request_rejects_concurrent_authorization_reuse(override_state):
    """Two concurrent requests reusing the same x402 authorization must not both
    reach the sidecar — the second is rejected while the first is in flight."""
    import asyncio

    entered = asyncio.Event()
    release = asyncio.Event()
    orig_execute = override_state.network_provider.execute_request

    async def blocking_execute(req):
        entered.set()
        await release.wait()
        return await orig_execute(req)

    override_state.network_provider.execute_request = blocking_execute
    headers = {"X-Mock-Wallet": "0xWallet", "X-PAYMENT": "sig-abc"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        async def call():
            return await client.post(
                "/v1/network/request",
                headers=headers,
                json={"url": "http://example.com", "proxy_mode": "direct"},
            )

        first = asyncio.create_task(call())
        await entered.wait()  # first is now blocked in the fetch, holding the guard
        second = await call()  # same authorization, still in flight
        release.set()
        first_res = await first

    assert second.status_code == 409
    assert first_res.status_code == 200
    # Only one fetch actually ran for the shared authorization.
    assert len(override_state.network_provider.requests) == 1


@pytest.mark.asyncio
async def test_network_request_post_settles_before_forwarding(override_state):
    """A POST is non-idempotent — it must be paid BEFORE forwarding, so a
    payment failure never triggers the upstream side effect."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            json={"url": "http://example.com", "proxy_mode": "direct", "method": "POST"},
        )
    assert res.status_code == 402
    # The unpaid POST must NOT have been forwarded to the sidecar.
    assert override_state.network_provider.requests == []


@pytest.mark.asyncio
async def test_network_request_post_forwards_after_atomic_payment(override_state):
    """A paid POST forwards via the atomic (settle-first) path, not the deferred
    settle-after-delivery path used for idempotent GET/HEAD."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/network/request",
            headers={"X-Mock-Wallet": "0xWallet"},
            json={"url": "http://example.com", "proxy_mode": "direct", "method": "POST"},
        )
    assert res.status_code == 200
    assert len(override_state.network_provider.requests) == 1
    # Atomic check_payment was used, not the deferred settle_verified path.
    assert override_state.payment_gate.settled == 0
