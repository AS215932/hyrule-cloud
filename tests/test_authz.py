"""Block A0 authorization matrix tests.

Covers the security hotfix: anonymous (ownerless) VMs get a one-time
management token at creation; without it, /logs /reboot /extend DELETE
all return 404. Legacy VMs (created before A0, no token hash) cannot be
managed until claimed (claim flow lands in A1).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi import Response
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.models import (
    VMSize,
    VMStatus,
    generate_anon_management_token,
    generate_vm_id,
    hash_anon_management_token,
)


def _now() -> datetime:
    return datetime.now(UTC)


class _MockPaymentConfig:
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


class _MockXCPNG:
    templates = {"debian-13": "uuid-debian-13"}


class _MockConfig:
    payment = _MockPaymentConfig()
    xcpng = _MockXCPNG()
    deploy_domain = "deploy.hyrule.host"
    blocked_ports = [25]


class _MockRow:
    """Mimics enough of VMRow to satisfy the route handlers and helpers."""

    def __init__(
        self,
        vm_id: str,
        anon_management_token_hash: str | None,
        *,
        status: VMStatus = VMStatus.READY,
        owner_account_id: str | None = None,
    ) -> None:
        self.vm_id = vm_id
        self.anon_management_token_hash = anon_management_token_hash
        self.owner_account_id = owner_account_id
        self.status = status
        self.os = "debian-13"
        self.size = VMSize.XS
        self.ipv6 = "2a0c:b641:b51::abcd"
        self.hostname = "abcdef12.deploy.hyrule.host"
        self.ssh_pubkey = "ssh-ed25519 AAAA..."
        self.open_ports = [22, 80, 443]
        self.created_at = _now()
        self.expires_at = _now() + timedelta(days=7)
        self.error = None
        self.cost_total = Decimal("0.35")
        self.owner_wallet = "0xPayerWallet"
        self.payment_tx = "0xMockTx"
        self.xcpng_uuid = "fake-xcpng-uuid"


class _MockOrchestrator:
    def __init__(self) -> None:
        self._rows: dict[str, _MockRow] = {}
        self.reboot_called: list[str] = []
        self.destroy_called: list[str] = []
        self.extend_called: list[tuple[str, int]] = []

    def add(self, row: _MockRow) -> None:
        self._rows[row.vm_id] = row

    async def get_vm(self, vm_id: str):
        return self._rows.get(vm_id)

    async def reboot_vm(self, vm_id: str) -> bool:
        self.reboot_called.append(vm_id)
        return vm_id in self._rows

    async def destroy_vm(self, vm_id: str) -> bool:
        self.destroy_called.append(vm_id)
        return vm_id in self._rows

    async def extend_vm(self, vm_id: str, days: int):
        self.extend_called.append((vm_id, days))
        row = self._rows.get(vm_id)
        if row and row.expires_at:
            row.expires_at = row.expires_at + timedelta(days=days)
        return row


class _MockGate:
    async def check_payment(self, request, amount, description, extra_body):
        # Always settle when the bypass header is set, never otherwise (so
        # tests for unauthorized extend never reach payment in the first place).
        if request.headers.get("X-Mock-Wallet"):
            request.state.payment_tx = "0xMockTxExtend"
            return request.headers.get("X-Mock-Wallet")
        return Response(status_code=402)


@pytest.fixture
def authz_state():
    from hyrule_cloud.state import AppState

    orch = _MockOrchestrator()
    state = AppState(
        config=_MockConfig(),
        orchestrator=orch,
        payment_gate=_MockGate(),
        network_provider=None,
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev


# --- Test: anon ownerless VM, with management token ---


@pytest.mark.asyncio
async def test_anon_vm_status_public_with_token(authz_state):
    """An anon VM's /status is reachable by anyone holding the vm_id."""
    token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get(f"/v1/vm/{vm_id}/status")
        assert res.status_code == 200
        body = res.json()
        assert body["vm_id"] == vm_id
        assert body["ipv6"] == "2a0c:b641:b51::abcd"
        # Sanitized response must NOT leak management fields
        assert "ssh_pubkey" not in body
        assert "firewall" not in body
        assert "owner_wallet" not in body


@pytest.mark.asyncio
async def test_anon_vm_management_routes_succeed_with_token(authz_state):
    token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        headers = {"Authorization": f"Bearer {token}"}
        # full detail
        res = await c.get(f"/v1/vm/{vm_id}", headers=headers)
        assert res.status_code == 200
        body = res.json()
        assert body["ssh_pubkey"] == "ssh-ed25519 AAAA..."
        assert body["owner_wallet"] == "0xPayerWallet"
        assert body["has_anon_management_token"] is True
        assert body["is_legacy"] is False
        # logs
        res = await c.get(f"/v1/vm/{vm_id}/logs", headers=headers)
        assert res.status_code == 200
        # reboot
        res = await c.post(f"/v1/vm/{vm_id}/reboot", headers=headers)
        assert res.status_code == 200
        assert vm_id in authz_state.orchestrator.reboot_called
        # delete
        res = await c.delete(f"/v1/vm/{vm_id}", headers=headers)
        assert res.status_code == 200
        assert vm_id in authz_state.orchestrator.destroy_called


@pytest.mark.asyncio
async def test_anon_vm_management_via_query_token_works(authz_state):
    token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get(f"/v1/vm/{vm_id}?token={token}")
        assert res.status_code == 200


# --- Test: anon ownerless VM, WITHOUT the token (the dangerous case) ---


@pytest.mark.asyncio
async def test_anon_vm_management_routes_blocked_without_token(authz_state):
    token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        for path in (f"/v1/vm/{vm_id}", f"/v1/vm/{vm_id}/logs"):
            res = await c.get(path)
            assert res.status_code == 404, f"GET {path} should 404 without token"
        res = await c.post(f"/v1/vm/{vm_id}/reboot")
        assert res.status_code == 404
        # reboot must NOT execute without auth
        assert vm_id not in authz_state.orchestrator.reboot_called
        res = await c.delete(f"/v1/vm/{vm_id}")
        assert res.status_code == 404
        assert vm_id not in authz_state.orchestrator.destroy_called


@pytest.mark.asyncio
async def test_anon_vm_management_routes_reject_wrong_token(authz_state):
    real_token = generate_anon_management_token()
    fake_token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(real_token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        headers = {"Authorization": f"Bearer {fake_token}"}
        res = await c.delete(f"/v1/vm/{vm_id}", headers=headers)
        assert res.status_code == 404
        assert vm_id not in authz_state.orchestrator.destroy_called


# --- Test: extend requires token AND payment ---


@pytest.mark.asyncio
async def test_extend_blocked_without_token_even_with_payment(authz_state):
    """A stranger cannot pay to keep someone else's VM alive."""
    token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        # Provide payment (X-Mock-Wallet) but NO token — extend must reject before payment
        res = await c.post(
            f"/v1/vm/{vm_id}/extend",
            headers={"X-Mock-Wallet": "0xStranger"},
            json={"days": 7},
        )
        assert res.status_code == 404
        assert authz_state.orchestrator.extend_called == []


@pytest.mark.asyncio
async def test_extend_succeeds_with_token_and_payment(authz_state):
    token = generate_anon_management_token()
    vm_id = generate_vm_id()
    authz_state.orchestrator.add(
        _MockRow(vm_id=vm_id, anon_management_token_hash=hash_anon_management_token(token))
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.post(
            f"/v1/vm/{vm_id}/extend",
            headers={"X-Mock-Wallet": "0xPayerWallet", "Authorization": f"Bearer {token}"},
            json={"days": 7},
        )
        assert res.status_code == 200
        assert authz_state.orchestrator.extend_called == [(vm_id, 7)]


# --- Test: legacy ownerless VM (created before A0, no token hash) ---


@pytest.mark.asyncio
async def test_legacy_vm_status_works(authz_state):
    """Old vm_<12hex> rows whose token hash is NULL still serve /status."""
    vm_id = "vm_abc123def456"  # legacy ID shape
    authz_state.orchestrator.add(_MockRow(vm_id=vm_id, anon_management_token_hash=None))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get(f"/v1/vm/{vm_id}/status")
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_legacy_vm_management_disabled_until_claimed(authz_state):
    """Legacy VMs reject ALL management ops, even when a token is presented."""
    vm_id = "vm_abc123def456"
    authz_state.orchestrator.add(_MockRow(vm_id=vm_id, anon_management_token_hash=None))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        any_token = generate_anon_management_token()
        headers = {"Authorization": f"Bearer {any_token}"}
        for path in (f"/v1/vm/{vm_id}", f"/v1/vm/{vm_id}/logs"):
            res = await c.get(path, headers=headers)
            assert res.status_code == 404
        res = await c.post(f"/v1/vm/{vm_id}/reboot", headers=headers)
        assert res.status_code == 404
        res = await c.delete(f"/v1/vm/{vm_id}", headers=headers)
        assert res.status_code == 404


# --- Test: missing VM returns 404 (sanity) ---


@pytest.mark.asyncio
async def test_missing_vm_returns_404(authz_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        for path in ("/v1/vm/vm_missing/status", "/v1/vm/vm_missing", "/v1/vm/vm_missing/logs"):
            res = await c.get(path)
            assert res.status_code == 404


# --- Test: vm_id generator produces correct shape ---


def test_generate_vm_id_shape():
    vm_id = generate_vm_id()
    assert vm_id.startswith("vm_")
    body = vm_id[len("vm_"):]
    assert len(body) == 22
    assert all(c.isalnum() for c in body)


def test_generate_anon_management_token_shape():
    tok = generate_anon_management_token()
    assert tok.startswith("hyr_vm_")
    body = tok[len("hyr_vm_"):]
    assert len(body) == 32
    assert all(c.isalnum() for c in body)


def test_token_verify_constant_time():
    """Hash/verify round-trip works and rejects mismatches."""
    from hyrule_cloud.models import verify_anon_management_token

    tok = generate_anon_management_token()
    h = hash_anon_management_token(tok)
    assert verify_anon_management_token(tok, h) is True
    assert verify_anon_management_token("hyr_vm_wrong", h) is False
    assert verify_anon_management_token(None, h) is False
    assert verify_anon_management_token(tok, None) is False
