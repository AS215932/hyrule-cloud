"""Block A1 auth + account-ownership + claim tests.

Uses an in-process SQLite database with a minimal orchestrator stub so the
real auth code (argon2id hashing, session cookies, ownership helpers, claim
flow) runs end-to-end.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.middleware.anon_token import hash_anon_token as hash_anon_management_token
from hyrule_cloud.models import (
    VMSize,
    VMStatus,
    generate_anon_management_token,
    generate_vm_id,
)

# --- Fixtures: in-process DB + orchestrator stub ---


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


class _StubOrchestrator:
    """Tiny orchestrator-ish object that gives current_account a real DB session factory.

    For tests that need to create VMs, callers can insert directly via this
    orch's session factory rather than going through the heavy provision path.
    """

    def __init__(self, session_factory: async_sessionmaker) -> None:
        self.db = session_factory
        self.reboot_called: list[str] = []
        self.destroy_called: list[str] = []

    async def get_vm(self, vm_id: str) -> VMRow | None:
        async with self.db() as session:
            return await session.get(VMRow, vm_id)

    async def reboot_vm(self, vm_id: str) -> bool:
        self.reboot_called.append(vm_id)
        async with self.db() as session:
            vm = await session.get(VMRow, vm_id)
        return vm is not None

    async def destroy_vm(self, vm_id: str) -> bool:
        self.destroy_called.append(vm_id)
        async with self.db() as session:
            vm = await session.get(VMRow, vm_id)
            if vm is None:
                return False
            vm.status = VMStatus.DESTROYED
            vm.destroyed_at = _now()
            await session.commit()
        return True


class _MockGate:
    async def check_payment(self, request, amount, description, extra_body):
        if request.headers.get("X-Mock-Wallet"):
            request.state.payment_tx = "0xMockTxA1"
            return request.headers.get("X-Mock-Wallet")
        return Response(status_code=402)


@pytest_asyncio.fixture
async def auth_state():
    """Spin up an in-process SQLite DB, wire it through the orchestrator slot.

    Also clears the per-IP rate-limit caches so tests don't cross-contaminate.
    """
    from hyrule_cloud.api.auth import _RATE_LOGIN, _RATE_RECOVER, _RATE_REGISTER
    from hyrule_cloud.state import AppState

    _RATE_REGISTER.clear()
    _RATE_LOGIN.clear()
    _RATE_RECOVER.clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    orch = _StubOrchestrator(factory)
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
        await engine.dispose()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        yield c


# --- Test: registration → login → logout → relogin ---


@pytest.mark.asyncio
async def test_register_returns_account_id_and_recovery_code(auth_state, client):
    res = await client.post("/v1/auth/register", json={"password": "correct horse battery staple"})
    assert res.status_code == 200
    body = res.json()
    assert body["account_id"].startswith("H") and len(body["account_id"]) == 11
    assert body["recovery_code"].startswith("hyr-rec-")
    # Cookie was set
    assert "hyr_sess" in res.cookies


@pytest.mark.asyncio
async def test_register_rejects_short_password(auth_state, client):
    res = await client.post("/v1/auth/register", json={"password": "short"})
    assert res.status_code == 422


# Block D (Wave 3) will add:
#   - test_register_without_api_key_omits_key_fields
#   - test_register_with_api_key_returns_usable_bearer
#   - test_register_with_api_key_default_name_when_omitted
# These exercise the agent-bootstrap path (POST /v1/auth/register with
# with_api_key=true returning a cleartext hyr_sk_ bearer). Wave 2 ships
# without ApiKeyRow / api_keys endpoints, so the path is intentionally
# absent here.


@pytest.mark.asyncio
async def test_login_with_wrong_password_returns_generic_401(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "correct horse battery staple"})
    account_id = reg.json()["account_id"]
    await client.post("/v1/auth/logout")

    res = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "wrong horse battery staple"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_with_unknown_account_returns_same_generic_401(auth_state, client):
    res = await client.post(
        "/v1/auth/login",
        json={"account_id": "H0000000000", "password": "any password here"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_register_login_me_logout_flow(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "correct horse battery staple"})
    account_id = reg.json()["account_id"]

    me = await client.get("/v1/me")
    assert me.status_code == 200
    assert me.json()["account_id"] == account_id
    assert me.json()["vm_count"] == 0

    logout = await client.post("/v1/auth/logout")
    assert logout.status_code == 200

    me_after = await client.get("/v1/me")
    assert me_after.status_code == 401

    login = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "correct horse battery staple"},
    )
    assert login.status_code == 200
    assert login.json()["account_id"] == account_id

    me_back = await client.get("/v1/me")
    assert me_back.status_code == 200


# --- Test: recovery code is single-use + rotates ---


@pytest.mark.asyncio
async def test_recovery_code_resets_password_and_issues_new_code(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "old password long enough"})
    account_id = reg.json()["account_id"]
    old_recovery_code = reg.json()["recovery_code"]

    recover = await client.post(
        "/v1/auth/recover/code",
        json={
            "account_id": account_id,
            "recovery_code": old_recovery_code,
            "new_password": "brand new long password 123",
        },
    )
    assert recover.status_code == 200
    new_recovery_code = recover.json()["new_recovery_code"]
    assert new_recovery_code != old_recovery_code
    assert new_recovery_code.startswith("hyr-rec-")

    # Old session was revoked
    me = await client.get("/v1/me")
    assert me.status_code == 401

    # Can log in with new password
    login = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "brand new long password 123"},
    )
    assert login.status_code == 200

    # Old password is dead
    await client.post("/v1/auth/logout")
    bad = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "old password long enough"},
    )
    assert bad.status_code == 401


@pytest.mark.asyncio
async def test_recovery_code_cannot_be_reused(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "long enough pass word"})
    account_id = reg.json()["account_id"]
    code = reg.json()["recovery_code"]

    first = await client.post(
        "/v1/auth/recover/code",
        json={"account_id": account_id, "recovery_code": code, "new_password": "pw two long enough"},
    )
    assert first.status_code == 200

    # Use the SAME code again — should fail (it was burned)
    again = await client.post(
        "/v1/auth/recover/code",
        json={"account_id": account_id, "recovery_code": code, "new_password": "pw three long enough"},
    )
    assert again.status_code == 401


# --- Test: change password from inside session ---


@pytest.mark.asyncio
async def test_change_password_keeps_current_session_revokes_others(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "old password long enough"})
    account_id = reg.json()["account_id"]

    # Open a second session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c2:
        login2 = await c2.post(
            "/v1/auth/login",
            json={"account_id": account_id, "password": "old password long enough"},
        )
        assert login2.status_code == 200

        # Change password in client 1
        cp = await client.post(
            "/v1/me/password",
            json={"current_password": "old password long enough", "new_password": "fresh pw long enough"},
        )
        assert cp.status_code == 200

        # Client 1's session still works
        me1 = await client.get("/v1/me")
        assert me1.status_code == 200

        # Client 2's session was revoked
        me2 = await c2.get("/v1/me")
        assert me2.status_code == 401


@pytest.mark.asyncio
async def test_change_password_rejects_wrong_current_password(auth_state, client):
    await client.post("/v1/auth/register", json={"password": "old password long enough"})
    res = await client.post(
        "/v1/me/password",
        json={"current_password": "wrong", "new_password": "newer than ever long pw"},
    )
    assert res.status_code == 401


# --- Test: account-owned VM ownership enforcement ---


async def _seed_owned_vm(state, account_id: str) -> str:
    """Insert a VM owned by `account_id` directly via the DB factory."""
    vm_id = generate_vm_id()
    async with state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id=vm_id,
                owner_wallet="0xPayer",
                owner_account_id=account_id,
                anon_management_token_hash=None,
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ipv6="2a0c:b641:b51::1",
                hostname=f"{vm_id[3:11]}.deploy.hyrule.host",
                ssh_pubkey="ssh-ed25519 AAAA...",
                open_ports=[22, 80],
                expires_at=_now() + timedelta(days=7),
                cost_total=Decimal("0.35"),
            )
        )
        await session.commit()
    return vm_id


@pytest.mark.asyncio
async def test_account_owner_can_manage_their_vm(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "pw correct horse staple"})
    account_id = reg.json()["account_id"]

    vm_id = await _seed_owned_vm(auth_state, account_id)

    # status (sanitized) works
    res = await client.get(f"/v1/vm/{vm_id}/status")
    assert res.status_code == 200

    # full detail works
    res = await client.get(f"/v1/vm/{vm_id}")
    assert res.status_code == 200
    assert res.json()["vm_id"] == vm_id

    # reboot works (no token needed; account auth is sufficient)
    res = await client.post(f"/v1/vm/{vm_id}/reboot")
    assert res.status_code == 200

    # destroy works
    res = await client.delete(f"/v1/vm/{vm_id}")
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_cross_account_access_returns_404_not_403(auth_state, client):
    # Account A creates a VM
    reg_a = await client.post("/v1/auth/register", json={"password": "alice long pw 123"})
    account_a = reg_a.json()["account_id"]
    vm_id = await _seed_owned_vm(auth_state, account_a)
    await client.post("/v1/auth/logout")

    # Account B (different session) tries to access A's VM
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as cb:
        await cb.post("/v1/auth/register", json={"password": "bob long pw 1234567"})

        # Sanitized /status is intentionally public per Block A0 — anyone
        # who knows the vm_id can see status/ipv6/hostname/expires_at, no
        # ssh/firewall/error. That's the explicit tradeoff so order-status
        # pages work without auth. Confirm here, then confirm all
        # MANAGEMENT routes 404 (NOT 403) for cross-account callers.
        res = await cb.get(f"/v1/vm/{vm_id}/status")
        assert res.status_code == 200

        for path in (f"/v1/vm/{vm_id}", f"/v1/vm/{vm_id}/logs"):
            res = await cb.get(path)
            assert res.status_code == 404, f"{path} should 404 for cross-account"
        res = await cb.post(f"/v1/vm/{vm_id}/reboot")
        assert res.status_code == 404
        res = await cb.delete(f"/v1/vm/{vm_id}")
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_anon_token_is_not_accepted_on_account_owned_vm(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "carol long pw 1234567"})
    account_id = reg.json()["account_id"]
    vm_id = await _seed_owned_vm(auth_state, account_id)

    # Even if someone presents a (fake) management token, the VM is account-owned;
    # they need account auth, not token auth.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as cx:
        bogus = generate_anon_management_token()
        res = await cx.delete(f"/v1/vm/{vm_id}", headers={"Authorization": f"Bearer {bogus}"})
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_me_vms_lists_only_owned_vms(auth_state, client):
    reg_a = await client.post("/v1/auth/register", json={"password": "alice long pw 1234"})
    account_a = reg_a.json()["account_id"]
    vm_a_1 = await _seed_owned_vm(auth_state, account_a)
    vm_a_2 = await _seed_owned_vm(auth_state, account_a)
    await client.post("/v1/auth/logout")

    reg_b = await client.post("/v1/auth/register", json={"password": "bob long pw 1234567"})
    account_b = reg_b.json()["account_id"]
    vm_b_1 = await _seed_owned_vm(auth_state, account_b)

    res = await client.get("/v1/me/vms")
    assert res.status_code == 200
    vm_ids = sorted(v["vm_id"] for v in res.json()["vms"])
    assert vm_ids == sorted([vm_b_1])
    assert vm_a_1 not in vm_ids
    assert vm_a_2 not in vm_ids


# --- Test: claim flow ---


@pytest.mark.asyncio
async def test_claim_anon_vm_with_management_token(auth_state, client):
    # Create an anon VM directly (with a real token)
    cleartext_token = generate_anon_management_token()
    vm_id = generate_vm_id()
    async with auth_state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id=vm_id,
                owner_wallet="0xAnonPayer",
                owner_account_id=None,
                anon_management_token_hash=hash_anon_management_token(cleartext_token),
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ipv6="2a0c:b641:b51::2",
                hostname=f"{vm_id[3:11]}.deploy.hyrule.host",
                ssh_pubkey="ssh-ed25519 ABCD...",
                open_ports=[22],
                expires_at=_now() + timedelta(days=7),
                cost_total=Decimal("0.35"),
            )
        )
        await session.commit()

    # Sign up + claim
    await client.post("/v1/auth/register", json={"password": "dan long pw 12345678"})
    claim = await client.post(
        f"/v1/me/vms/{vm_id}/claim",
        json={"proof": "management_token", "token": cleartext_token},
    )
    assert claim.status_code == 200
    assert claim.json()["vm_id"] == vm_id

    # Now appears in /me/vms
    res = await client.get("/v1/me/vms")
    assert res.status_code == 200
    assert any(v["vm_id"] == vm_id for v in res.json()["vms"])

    # And the old token no longer works — the anon hash was burned
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as cx:
        res = await cx.delete(f"/v1/vm/{vm_id}", headers={"Authorization": f"Bearer {cleartext_token}"})
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_claim_rejects_wrong_token(auth_state, client):
    cleartext_token = generate_anon_management_token()
    vm_id = generate_vm_id()
    async with auth_state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id=vm_id,
                owner_wallet="0xAnonPayer",
                anon_management_token_hash=hash_anon_management_token(cleartext_token),
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ssh_pubkey="",
                open_ports=[22],
                expires_at=_now() + timedelta(days=7),
                cost_total=Decimal("0.35"),
            )
        )
        await session.commit()

    await client.post("/v1/auth/register", json={"password": "eve long pw 12345678"})
    claim = await client.post(
        f"/v1/me/vms/{vm_id}/claim",
        json={"proof": "management_token", "token": generate_anon_management_token()},
    )
    assert claim.status_code == 403


@pytest.mark.asyncio
async def test_claim_rejects_already_claimed_vm(auth_state, client):
    # Account A owns the VM
    reg_a = await client.post("/v1/auth/register", json={"password": "alice long pw 1234"})
    account_a = reg_a.json()["account_id"]
    vm_id = await _seed_owned_vm(auth_state, account_a)
    await client.post("/v1/auth/logout")

    # Account B tries to claim it with any token
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as cb:
        await cb.post("/v1/auth/register", json={"password": "bob long pw 12345678"})
        res = await cb.post(
            f"/v1/me/vms/{vm_id}/claim",
            json={"proof": "management_token", "token": generate_anon_management_token()},
        )
        assert res.status_code == 409


# --- Test: account deletion (detach vs destroy) ---


@pytest.mark.asyncio
async def test_account_delete_detach_returns_fresh_tokens(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "frank long pw 12345"})
    account_id = reg.json()["account_id"]
    vm_id = await _seed_owned_vm(auth_state, account_id)

    res = await client.delete("/v1/me?vm_policy=detach")
    assert res.status_code == 200
    body = res.json()
    assert body["vm_policy"] == "detach"
    assert len(body["detached_vms"]) == 1
    detached = body["detached_vms"][0]
    assert detached["vm_id"] == vm_id
    assert detached["management_token"].startswith("hyr_vm_")

    # VM is still alive and can be managed with the new token.
    # VMStatusResponse intentionally doesn't expose a `has_anon_management_token`
    # flag (would leak token presence); we just confirm the management
    # route accepts the fresh token by returning the full row.
    fresh_token = detached["management_token"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as cx:
        res = await cx.get(f"/v1/vm/{vm_id}", headers={"Authorization": f"Bearer {fresh_token}"})
        assert res.status_code == 200
        assert res.json()["vm_id"] == vm_id


@pytest.mark.asyncio
async def test_account_delete_destroy_actually_destroys(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "gwen long pw 12345678"})
    account_id = reg.json()["account_id"]
    vm_id = await _seed_owned_vm(auth_state, account_id)

    res = await client.delete("/v1/me?vm_policy=destroy")
    assert res.status_code == 200
    assert res.json()["vm_policy"] == "destroy"
    assert vm_id in auth_state.orchestrator.destroy_called


@pytest.mark.asyncio
async def test_account_delete_rejects_invalid_vm_policy(auth_state, client):
    await client.post("/v1/auth/register", json={"password": "henry long pw 1234567"})
    res = await client.delete("/v1/me?vm_policy=feed_to_dragons")
    assert res.status_code == 400


# --- Test: rate limiting (lightweight check) ---


@pytest.mark.asyncio
async def test_register_rate_limit_kicks_in(auth_state, client):
    # 5/hr per IP; the 6th must 429.
    # Need to import and CLEAR the bucket since the cache is module-level
    from hyrule_cloud.api.auth import _RATE_REGISTER
    _RATE_REGISTER.clear()

    for _ in range(5):
        res = await client.post("/v1/auth/register", json={"password": "throwaway pw long enough"})
        assert res.status_code == 200
        await client.post("/v1/auth/logout")

    res = await client.post("/v1/auth/register", json={"password": "throwaway pw long enough"})
    assert res.status_code == 429


# --- Test: /me/recovery-code rotation ---


@pytest.mark.asyncio
async def test_rotate_recovery_code_invalidates_old_code(auth_state, client):
    reg = await client.post("/v1/auth/register", json={"password": "iris long pw 12345678"})
    account_id = reg.json()["account_id"]
    old_code = reg.json()["recovery_code"]

    res = await client.post(
        "/v1/me/recovery-code",
        json={"current_password": "iris long pw 12345678"},
    )
    assert res.status_code == 200
    new_code = res.json()["new_recovery_code"]
    assert new_code != old_code

    # Old code should no longer work
    bad = await client.post(
        "/v1/auth/recover/code",
        json={"account_id": account_id, "recovery_code": old_code, "new_password": "next long pw 1234"},
    )
    assert bad.status_code == 401

    # New code works
    good = await client.post(
        "/v1/auth/recover/code",
        json={"account_id": account_id, "recovery_code": new_code, "new_password": "next long pw 1234"},
    )
    assert good.status_code == 200
