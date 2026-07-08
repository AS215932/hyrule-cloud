"""Block A0 authorization matrix.

These tests are the regression suite for the security hotfix that
gates `/logs`, `/reboot`, `/extend`, `DELETE /vm/{id}`, and the
non-sanitized `GET /vm/{id}` behind a one-time anon management token.
Public sanitized status remains at `GET /vm/{id}/status`.

Coverage:
  - Sanitized status view is public for any vm_id (200; no ssh/firewall
    fields leak).
  - Pre-A0 legacy rows (anon_management_token_hash IS NULL) deny all
    management routes regardless of presented token.
  - Token via Authorization: Bearer is accepted.
  - Token via ?token= query param is accepted.
  - Wrong token returns 404 (NOT 403 — vm_id existence must not leak).
  - Missing token on management routes returns 404.
  - `POST /v1/vm/create` response includes management_token +
    management_url exactly once.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from fastapi import Response
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.middleware.anon_token import (
    can_manage_vm,
    can_view_public_status,
    hash_anon_token,
)
from hyrule_cloud.models import (
    VMStatus,
    generate_anon_management_token,
    generate_vm_id,
)

_TOKEN_OK = "hyr_vm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_TOKEN_WRONG = "hyr_vm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


# --- Generator + helper unit tests (no app boot needed) ---


def test_generate_vm_id_format_and_entropy():
    ids = {generate_vm_id() for _ in range(1000)}
    assert len(ids) == 1000, "1000 generations collided — entropy too low"
    for vm_id in list(ids)[:10]:
        assert vm_id.startswith("vm_")
        assert len(vm_id) == 25  # "vm_" + 22 chars
        suffix = vm_id[3:]
        assert all(c.isalnum() for c in suffix)


def test_generate_anon_management_token_format_and_entropy():
    toks = {generate_anon_management_token() for _ in range(1000)}
    assert len(toks) == 1000
    for tok in list(toks)[:10]:
        assert tok.startswith("hyr_vm_")
        assert len(tok) == 39  # "hyr_vm_" + 32 chars
        assert all(c.isalnum() for c in tok[7:])


def test_hash_anon_token_is_deterministic_sha256_hex():
    assert hash_anon_token("hello") == hash_anon_token("hello")
    assert hash_anon_token("hello") != hash_anon_token("world")
    assert len(hash_anon_token("hello")) == 64
    assert all(c in "0123456789abcdef" for c in hash_anon_token("hello"))


def test_can_view_public_status_is_unconditional():
    class _Row:
        pass
    # Always True regardless of row shape — sanitization is the route's job.
    assert can_view_public_status(_Row()) is True


def test_can_manage_vm_rejects_missing_token():
    class _Row:
        anon_management_token_hash = hash_anon_token(_TOKEN_OK)
    assert can_manage_vm(_Row(), None) is False
    assert can_manage_vm(_Row(), "") is False


def test_can_manage_vm_rejects_legacy_pre_a0_rows():
    class _LegacyRow:
        anon_management_token_hash = None
    assert can_manage_vm(_LegacyRow(), _TOKEN_OK) is False


def test_can_manage_vm_accepts_correct_token():
    class _Row:
        anon_management_token_hash = hash_anon_token(_TOKEN_OK)
    assert can_manage_vm(_Row(), _TOKEN_OK) is True


def test_can_manage_vm_rejects_wrong_token():
    class _Row:
        anon_management_token_hash = hash_anon_token(_TOKEN_OK)
    assert can_manage_vm(_Row(), _TOKEN_WRONG) is False


# --- Route-level tests ---


class _Cfg:
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


def _row_with_hash(hash_hex: str | None):
    class _Row:
        vm_id = "vm_abcDEF0123456789ABCDEF"
        status = VMStatus.READY
        ipv6 = "2001:db8::1"
        hostname = "abc.deploy.hyrule.host"
        ssh_pubkey = "ssh-ed25519 AAAA"
        expires_at = datetime.now(UTC)
        created_at = datetime.now(UTC)
        error = None
        open_ports = [22, 80]
        anon_management_token_hash = hash_hex
    return _Row()


class _OrchOK:
    """An A0-issued VM with token=_TOKEN_OK."""

    def __init__(self):
        self.rebooted: list[str] = []
        self.destroyed: list[str] = []

    async def get_vm(self, vm_id):
        if vm_id == "vm_abcDEF0123456789ABCDEF":
            return _row_with_hash(hash_anon_token(_TOKEN_OK))
        return None

    async def reboot_vm(self, vm_id):
        self.rebooted.append(vm_id)
        return True

    async def destroy_vm(self, vm_id):
        self.destroyed.append(vm_id)
        return True


class _OrchLegacy:
    """A pre-A0 VM with no token hash (legacy ownerless)."""

    async def get_vm(self, vm_id):
        if vm_id == "vm_legacy123abc":
            return _row_with_hash(None)
        return None

    async def reboot_vm(self, vm_id):
        return True


class _MockGate:
    async def check_payment(self, request, amount, description, extra_body):
        if request.headers.get("X-Mock-Wallet"):
            request.state.payment_tx = "0xMock"
            return request.headers.get("X-Mock-Wallet")
        return Response(status_code=402)


class _MockNetwork:
    pass


@pytest.fixture
def _state_ok():
    from hyrule_cloud.state import AppState
    orig = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_Cfg(),
        orchestrator=_OrchOK(),
        payment_gate=_MockGate(),
        network_provider=_MockNetwork(),
    )
    yield app.state._typed_state
    app.state._typed_state = orig


@pytest.fixture
def _state_legacy():
    from hyrule_cloud.state import AppState
    orig = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_Cfg(),
        orchestrator=_OrchLegacy(),
        payment_gate=_MockGate(),
        network_provider=_MockNetwork(),
    )
    yield app.state._typed_state
    app.state._typed_state = orig


# --- Public sanitized status ---


@pytest.mark.asyncio
async def test_public_status_no_auth_required(_state_ok):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/v1/vm/vm_abcDEF0123456789ABCDEF/status")
    assert res.status_code == 200
    data = res.json()
    assert data["vm_id"] == "vm_abcDEF0123456789ABCDEF"
    assert data["ipv6"] == "2001:db8::1"
    # Sanitized: no ssh, no firewall, no error.
    assert "ssh" not in data
    assert "firewall" not in data
    assert "error" not in data


@pytest.mark.asyncio
async def test_public_status_404_for_unknown_vm(_state_ok):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/v1/vm/vm_doesnotexist/status")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_public_status_works_for_legacy_pre_a0_rows(_state_legacy):
    """Legacy VMs keep their status page — only management is disabled."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/v1/vm/vm_legacy123abc/status")
    assert res.status_code == 200


# --- Management gating: full status route, logs, reboot, delete ---


@pytest.mark.parametrize("path,method", [
    ("/v1/vm/vm_abcDEF0123456789ABCDEF", "GET"),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF/logs", "GET"),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF/reboot", "POST"),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF", "DELETE"),
])
@pytest.mark.asyncio
async def test_management_routes_404_without_token(_state_ok, path, method):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.request(method, path)
    # 404 (NOT 403) — vm_id existence must not leak to random guessers.
    assert res.status_code == 404
    # No orchestrator side effects on rejection. A 404 with rebooted/
    # destroyed still mutated would be the worst-of-both-worlds outcome.
    assert _state_ok.orchestrator.rebooted == []
    assert _state_ok.orchestrator.destroyed == []


@pytest.mark.parametrize("path,method", [
    ("/v1/vm/vm_abcDEF0123456789ABCDEF", "GET"),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF/logs", "GET"),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF/reboot", "POST"),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF", "DELETE"),
])
@pytest.mark.asyncio
async def test_management_routes_404_with_wrong_token(_state_ok, path, method):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.request(
            method, path,
            headers={"Authorization": f"Bearer {_TOKEN_WRONG}"},
        )
    assert res.status_code == 404
    assert _state_ok.orchestrator.rebooted == []
    assert _state_ok.orchestrator.destroyed == []


@pytest.mark.parametrize("path,method,want", [
    ("/v1/vm/vm_abcDEF0123456789ABCDEF", "GET", 200),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF/logs", "GET", 200),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF/reboot", "POST", 200),
    ("/v1/vm/vm_abcDEF0123456789ABCDEF", "DELETE", 200),
])
@pytest.mark.asyncio
async def test_management_routes_accept_bearer_token(_state_ok, path, method, want):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.request(
            method, path,
            headers={"Authorization": f"Bearer {_TOKEN_OK}"},
        )
    assert res.status_code == want, res.text


@pytest.mark.asyncio
async def test_reboot_route_records_orchestrator_call_on_success(_state_ok):
    """Block A0: positive side-effect counterpart to the rejection tests
    above. When the token is valid, the orchestrator actually receives
    the call — proving that successful authorization is not a no-op."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.post(
            "/v1/vm/vm_abcDEF0123456789ABCDEF/reboot",
            headers={"Authorization": f"Bearer {_TOKEN_OK}"},
        )
    assert res.status_code == 200
    assert _state_ok.orchestrator.rebooted == ["vm_abcDEF0123456789ABCDEF"]
    assert _state_ok.orchestrator.destroyed == []


@pytest.mark.asyncio
async def test_management_routes_accept_query_token(_state_ok):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get(
            f"/v1/vm/vm_abcDEF0123456789ABCDEF?token={_TOKEN_OK}",
        )
    assert res.status_code == 200


@pytest.mark.parametrize("auth_header", [
    f"bearer {_TOKEN_OK}",          # lowercase scheme (RFC 7235 §2.1)
    f"BEARER {_TOKEN_OK}",          # uppercase scheme
    f"BeArEr {_TOKEN_OK}",          # mixed case
    f"  Bearer   {_TOKEN_OK}  ",    # surrounding + internal whitespace
])
@pytest.mark.asyncio
async def test_management_accepts_case_insensitive_bearer(_state_ok, auth_header):
    """Per RFC 7235 §2.1 the HTTP auth scheme is case-insensitive. Some
    clients (curl variants, older proxies, embedded HTTP libs) send
    'bearer' / 'BEARER' / mixed case. We must accept all of them."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get(
            "/v1/vm/vm_abcDEF0123456789ABCDEF",
            headers={"Authorization": auth_header},
        )
    assert res.status_code == 200, res.text


@pytest.mark.parametrize("path,method", [
    ("/v1/vm/vm_legacy123abc", "GET"),
    ("/v1/vm/vm_legacy123abc/logs", "GET"),
    ("/v1/vm/vm_legacy123abc/reboot", "POST"),
    ("/v1/vm/vm_legacy123abc", "DELETE"),
])
@pytest.mark.asyncio
async def test_legacy_pre_a0_rows_deny_all_management(_state_legacy, path, method):
    """Legacy ownerless VMs (anon_management_token_hash IS NULL) refuse
    management even with a syntactically-valid token. They are status-
    only until claimed via the future Wave 2 claim flow."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.request(
            method, path,
            headers={"Authorization": f"Bearer {_TOKEN_OK}"},
        )
    assert res.status_code == 404


# --- POST /v1/vm/create surfaces management_token + management_url once ---


class _OrchForCreate:
    """Mock orchestrator that records create_vm calls and returns a row +
    cleartext token, matching the real signature post-A0."""

    def __init__(self):
        self.last_row = None
        self.last_token = None

    def compute_price(self, request):
        from hyrule_cloud.models import CostBreakdown
        return Decimal("1.00"), CostBreakdown(
            vm_cost="$1.00", domain_cost="$0.00", total="$1.00",
        )

    def start_provisioning(self, vm_id):
        self.provisioning_started = getattr(self, "provisioning_started", [])
        self.provisioning_started.append(vm_id)

    async def create_vm(self, request, owner_wallet, owner_account_id=None, start_provisioning=True):
        from hyrule_cloud.models import generate_anon_management_token, generate_vm_id

        class _Row:
            vm_id = generate_vm_id()
            status = VMStatus.PROVISIONING
            payment_tx = None
        self.last_row = _Row()
        self.last_token = generate_anon_management_token()
        return self.last_row, self.last_token


@pytest.fixture
def _state_create():
    from hyrule_cloud.state import AppState
    orig = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_Cfg(),
        orchestrator=_OrchForCreate(),
        payment_gate=_MockGate(),
        network_provider=_MockNetwork(),
    )
    yield app.state._typed_state
    app.state._typed_state = orig


@pytest.mark.asyncio
async def test_vm_create_surfaces_management_token_and_url(_state_create):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.post(
            "/v1/vm/create",
            headers={"X-Mock-Wallet": "0xMockWallet"},
            json={
                "duration_days": 7,
                "size": "xs",
                "ssh_pubkey": "ssh-ed25519 AAAA",
            },
        )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["management_token"].startswith("hyr_vm_")
    assert data["management_url"].endswith(f"?token={data['management_token']}")
    # status_url points at the sanitized public route.
    assert data["status_url"].endswith("/status")
