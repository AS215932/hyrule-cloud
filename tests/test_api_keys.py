"""Block D — API key lifecycle, scope enforcement, no-escalation, forbidden-via-key.

Re-uses the in-process SQLite + stub orchestrator fixture pattern from
test_auth.py so the real middleware (bearer resolution, scope set, browser
session gate) runs end-to-end.
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
from hyrule_cloud.models import VMSize, VMStatus, generate_vm_id


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
            request.state.payment_tx = "0xMockTxD"
            return request.headers.get("X-Mock-Wallet")
        return Response(status_code=402)


@pytest_asyncio.fixture
async def keys_state():
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


async def _seed_owned_vm(state, account_id: str) -> str:
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
                ipv6="2a0c:b641:b51::42",
                hostname=f"{vm_id[3:11]}.deploy.hyrule.host",
                ssh_pubkey="ssh-ed25519 AAAA...",
                open_ports=[22],
                expires_at=_now() + timedelta(days=7),
                cost_total=Decimal("0.35"),
            )
        )
        await session.commit()
    return vm_id


async def _register(client: AsyncClient, password: str = "correct horse battery staple") -> str:
    res = await client.post("/v1/auth/register", json={"password": password})
    assert res.status_code == 200, res.text
    return res.json()["account_id"]


# --- Creation lifecycle ---


@pytest.mark.asyncio
async def test_create_key_returns_cleartext_once_then_only_summary(keys_state, client):
    await _register(client)
    res = await client.post(
        "/v1/me/api-keys", json={"name": "agent-A", "scopes": ["vm:read", "vm:power"]}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["key"].startswith("hyr_sk_")
    assert set(body["scopes"]) == {"vm:read", "vm:power"}
    cleartext = body["key"]
    key_id = body["key_id"]

    # List never reveals cleartext
    listing = await client.get("/v1/me/api-keys")
    assert listing.status_code == 200
    assert all("key" not in row for row in listing.json()["keys"])
    assert any(row["key_id"] == key_id for row in listing.json()["keys"])

    # The cleartext authenticates as Bearer. But this key has vm:read+vm:power,
    # NOT account:read, so /v1/me must 403 — proving the scope set was applied.
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost"
    ) as bearer_c:
        res = await bearer_c.get(
            "/v1/me", headers={"Authorization": f"Bearer {cleartext}"}
        )
        assert res.status_code == 403

    # A key WITH account:read can hit /v1/me.
    res = await client.post(
        "/v1/me/api-keys", json={"name": "agent-with-read", "scopes": ["account:read"]}
    )
    ct2 = res.json()["key"]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost"
    ) as bearer_c:
        me = await bearer_c.get("/v1/me", headers={"Authorization": f"Bearer {ct2}"})
        assert me.status_code == 200


@pytest.mark.asyncio
async def test_default_scopes_when_none_specified(keys_state, client):
    await _register(client)
    res = await client.post("/v1/me/api-keys", json={"name": "default-key"})
    assert res.status_code == 200
    body = res.json()
    # DEFAULT_API_KEY_SCOPES from models.py
    assert set(body["scopes"]) == {
        "vm:read",
        "vm:power",
        "vm:extend",
        "vm:logs",
        "account:read",
    }


@pytest.mark.asyncio
async def test_unknown_scope_rejected(keys_state, client):
    await _register(client)
    res = await client.post(
        "/v1/me/api-keys", json={"name": "bad", "scopes": ["vm:read", "vm:typo"]}
    )
    assert res.status_code == 400
    assert "vm:typo" in res.text


@pytest.mark.asyncio
async def test_revoke_key_disables_bearer(keys_state, client):
    await _register(client)
    res = await client.post(
        "/v1/me/api-keys", json={"name": "revoke-me", "scopes": ["account:read"]}
    )
    cleartext = res.json()["key"]
    key_id = res.json()["key_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        me = await bc.get("/v1/me", headers={"Authorization": f"Bearer {cleartext}"})
        assert me.status_code == 200

    revoked = await client.delete(f"/v1/me/api-keys/{key_id}")
    assert revoked.status_code == 200

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        me = await bc.get("/v1/me", headers={"Authorization": f"Bearer {cleartext}"})
        assert me.status_code == 401


@pytest.mark.asyncio
async def test_revoke_nonexistent_key_404(keys_state, client):
    await _register(client)
    res = await client.delete("/v1/me/api-keys/does-not-exist")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_cannot_revoke_another_accounts_key(keys_state, client):
    # A creates a key
    await _register(client, password="alice long pw 12345678")
    a_key = await client.post(
        "/v1/me/api-keys", json={"name": "a-key", "scopes": ["account:read"]}
    )
    a_key_id = a_key.json()["key_id"]
    await client.post("/v1/auth/logout")

    # B logs in and tries to revoke A's key by guessing the id
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as cb:
        await cb.post("/v1/auth/register", json={"password": "bob long pw 12345678"})
        res = await cb.delete(f"/v1/me/api-keys/{a_key_id}")
        assert res.status_code == 404  # scoped by account_id


# --- Scope enforcement on VM routes ---


@pytest.mark.asyncio
async def test_api_key_scope_enforced_on_reboot(keys_state, client):
    account = await _register(client)
    vm_id = await _seed_owned_vm(keys_state, account)

    # A key WITHOUT vm:power
    res = await client.post(
        "/v1/me/api-keys", json={"name": "read-only", "scopes": ["vm:read"]}
    )
    cleartext = res.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        # vm:read sufficient for status
        res = await bc.get(
            f"/v1/vm/{vm_id}/status",
            headers={"Authorization": f"Bearer {cleartext}"},
        )
        assert res.status_code == 200

        # vm:power MISSING — reboot 403s
        res = await bc.post(
            f"/v1/vm/{vm_id}/reboot",
            headers={"Authorization": f"Bearer {cleartext}"},
        )
        assert res.status_code == 403
        assert "vm:power" in res.text


@pytest.mark.asyncio
async def test_api_key_scope_enforced_on_logs(keys_state, client):
    account = await _register(client)
    vm_id = await _seed_owned_vm(keys_state, account)

    res = await client.post(
        "/v1/me/api-keys", json={"name": "no-logs", "scopes": ["vm:read", "vm:power"]}
    )
    cleartext = res.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.get(
            f"/v1/vm/{vm_id}/logs",
            headers={"Authorization": f"Bearer {cleartext}"},
        )
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_api_key_with_destroy_scope_can_destroy(keys_state, client):
    account = await _register(client)
    vm_id = await _seed_owned_vm(keys_state, account)

    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "destroyer", "scopes": ["vm:read", "vm:destroy"]},
    )
    cleartext = res.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.delete(
            f"/v1/vm/{vm_id}",
            headers={"Authorization": f"Bearer {cleartext}"},
        )
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_session_auth_unaffected_by_scopes(keys_state, client):
    """Sessions are unrestricted; scope deps must be a no-op on cookie auth."""
    account = await _register(client)
    vm_id = await _seed_owned_vm(keys_state, account)

    # Session user can do everything regardless of any scope vocabulary.
    res = await client.post(f"/v1/vm/{vm_id}/reboot")
    assert res.status_code == 200
    res = await client.get(f"/v1/vm/{vm_id}/logs")
    assert res.status_code == 200
    res = await client.delete(f"/v1/vm/{vm_id}")
    assert res.status_code == 200


# --- Forbidden via API key ---


@pytest.mark.asyncio
async def test_api_key_cannot_change_password(keys_state, client):
    await _register(client, password="alice long pw 12345678")
    # Create a key with the broadest possible scope set
    res = await client.post(
        "/v1/me/api-keys",
        json={
            "name": "broad",
            "scopes": [
                "vm:read", "vm:power", "vm:extend", "vm:destroy", "vm:logs",
                "vm:create", "api_keys:read", "api_keys:write", "account:read",
            ],
        },
    )
    cleartext = res.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.post(
            "/v1/me/password",
            headers={"Authorization": f"Bearer {cleartext}"},
            json={
                "current_password": "alice long pw 12345678",
                "new_password": "new very long password",
            },
        )
        assert res.status_code == 403
        assert "browser session" in res.text


@pytest.mark.asyncio
async def test_api_key_cannot_rotate_recovery_code(keys_state, client):
    await _register(client, password="alice long pw 12345678")
    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "broad", "scopes": ["api_keys:write", "account:read"]},
    )
    cleartext = res.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.post(
            "/v1/me/recovery-code",
            headers={"Authorization": f"Bearer {cleartext}"},
            json={"current_password": "alice long pw 12345678"},
        )
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_api_key_cannot_delete_account(keys_state, client):
    await _register(client, password="alice long pw 12345678")
    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "broad", "scopes": ["api_keys:write", "account:read"]},
    )
    cleartext = res.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.delete(
            "/v1/me?vm_policy=detach",
            headers={"Authorization": f"Bearer {cleartext}"},
        )
        assert res.status_code == 403


# --- No-escalation rule ---


@pytest.mark.asyncio
async def test_api_key_cannot_mint_scopes_it_does_not_hold(keys_state, client):
    """A key with api_keys:write must not grant scopes that exceed its own."""
    await _register(client)
    # Issue a narrow minting key: api_keys:write + vm:read only.
    minting = await client.post(
        "/v1/me/api-keys",
        json={"name": "minter", "scopes": ["api_keys:write", "vm:read"]},
    )
    mint_key = minting.json()["key"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        # Try to mint a key with vm:destroy — minter doesn't hold it.
        res = await bc.post(
            "/v1/me/api-keys",
            headers={"Authorization": f"Bearer {mint_key}"},
            json={"name": "child", "scopes": ["vm:destroy", "vm:read"]},
        )
        assert res.status_code == 403
        assert "vm:destroy" in res.text

        # Subset is fine.
        res = await bc.post(
            "/v1/me/api-keys",
            headers={"Authorization": f"Bearer {mint_key}"},
            json={"name": "child-ok", "scopes": ["vm:read"]},
        )
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_browser_session_can_mint_any_scope(keys_state, client):
    """Sessions are unrestricted and bypass the no-escalation rule."""
    await _register(client)
    res = await client.post(
        "/v1/me/api-keys",
        json={
            "name": "broad-from-session",
            "scopes": ["vm:destroy", "vm:create", "api_keys:write"],
        },
    )
    assert res.status_code == 200


# --- Invalid bearer hard-fails (does not silently fall through to anon) ---


@pytest.mark.asyncio
async def test_invalid_sk_bearer_returns_401(keys_state, client):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.get(
            "/v1/me",
            headers={"Authorization": "Bearer hyr_sk_thisdoesnotexist"},
        )
        assert res.status_code == 401


# --- A key cannot revoke itself ---


@pytest.mark.asyncio
async def test_key_cannot_revoke_itself(keys_state, client):
    await _register(client)
    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "self", "scopes": ["api_keys:write", "api_keys:read"]},
    )
    cleartext = res.json()["key"]
    key_id = res.json()["key_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as bc:
        res = await bc.delete(
            f"/v1/me/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {cleartext}"},
        )
        assert res.status_code == 403
        assert "cannot revoke itself" in res.text
