"""Block D (Wave 3) — scoped API keys: lifecycle, scope enforcement, no
self-escalation, no self-revocation, browser-only operations stay browser-only.

These tests run against the same SQLite-in-memory `auth_state` fixture as
test_auth.py so the wire-up stays consistent.
"""

from __future__ import annotations

import pytest

# Reuse the existing auth_state + client fixtures.
from tests.test_auth import auth_state, client  # noqa: F401


async def _register_with_bootstrap_key(c):
    """Helper: register a fresh account asking for a starter API key.
    Returns (account_id, cleartext_api_key, scopes)."""
    res = await c.post(
        "/v1/auth/register",
        json={"password": "alpha bravo charlie 1234", "with_api_key": True, "api_key_name": "test"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    # Log out immediately so subsequent calls use the API key, not the cookie.
    await c.post("/v1/auth/logout")
    return body["account_id"], body["api_key"], body["api_key_scopes"]


# --- Smoke: middleware resolves hyr_sk_ on the wire ---


@pytest.mark.asyncio
async def test_api_key_authenticates_me(auth_state, client):
    """Wave 3: Bearer hyr_sk_... resolves to the issuing account on /v1/me."""
    account_id, key, _scopes = await _register_with_bootstrap_key(client)
    res = await client.get("/v1/me", headers={"authorization": f"Bearer {key}"})
    assert res.status_code == 200
    assert res.json()["account_id"] == account_id


@pytest.mark.asyncio
async def test_invalid_api_key_returns_401_not_anon(auth_state, client):
    """Wave 3: a bad/revoked bearer must NOT silently fall through to the
    cookie path (would silently mask a revoked agent key). Always 401."""
    res = await client.get(
        "/v1/me",
        headers={"authorization": "Bearer hyr_sk_" + "x" * 32},
    )
    assert res.status_code == 401


# --- Scope enforcement on a routable endpoint ---


@pytest.mark.asyncio
async def test_create_key_with_narrow_scope_then_call_with_wrong_scope_403s(
    auth_state, client
):
    """Wave 3: mint a key with vm:read only; calling a vm:create-requiring
    endpoint with it must 403 — even though the account itself could do it
    via the cookie session."""
    res = await client.post(
        "/v1/auth/register",
        json={"password": "charlie delta echo 12345", "with_api_key": True},
    )
    body = res.json()
    bootstrap_key = body["api_key"]
    # The bootstrap key carries api_keys:read by default? No — only
    # vm:read/create + intent:read/create. So we need to mint a fresh key
    # using the cookie session.
    narrow = await client.post(
        "/v1/me/api-keys",
        json={"name": "read-only", "scopes": ["vm:read"]},
    )
    assert narrow.status_code == 200, narrow.text
    narrow_key = narrow.json()["api_key"]

    await client.post("/v1/auth/logout")

    # We don't have a vm:create endpoint that's currently gated by
    # require_scope in Wave 3 (orchestrator wiring deferred to Wave 4). For
    # now, exercise the policy via /v1/me/api-keys (api_keys:write).
    # vm:read-only key can list (api_keys:read is also missing, so it's 403).
    res = await client.get(
        "/v1/me/api-keys", headers={"authorization": f"Bearer {narrow_key}"},
    )
    assert res.status_code == 403
    # ...whereas the bootstrap key has neither api_keys:read nor :write
    # either, so it also 403s — confirming the scope wall, not just account
    # gating.
    res = await client.get(
        "/v1/me/api-keys", headers={"authorization": f"Bearer {bootstrap_key}"},
    )
    assert res.status_code == 403


# --- No self-escalation when minting via API-key auth ---


@pytest.mark.asyncio
async def test_api_key_cannot_mint_key_with_extra_scopes(auth_state, client):
    """Wave 3 (assert_key_scopes_subset): a key authenticated via API-key
    bearer cannot create a child key whose scopes exceed its own."""
    # Cookie-session mint a key with only api_keys:write (+ a read).
    await client.post(
        "/v1/auth/register",
        json={"password": "delta echo foxtrot 1234"},
    )
    minted = await client.post(
        "/v1/me/api-keys",
        json={"name": "issuer", "scopes": ["api_keys:write", "vm:read"]},
    )
    assert minted.status_code == 200
    issuer_key = minted.json()["api_key"]
    await client.post("/v1/auth/logout")

    # Now try to escalate: ask for vm:destroy via the bearer.
    bad = await client.post(
        "/v1/me/api-keys",
        json={"name": "bad", "scopes": ["vm:destroy"]},
        headers={"authorization": f"Bearer {issuer_key}"},
    )
    assert bad.status_code == 403
    assert "exceed" in bad.json()["detail"]

    # Subset is fine.
    ok = await client.post(
        "/v1/me/api-keys",
        json={"name": "subset", "scopes": ["vm:read"]},
        headers={"authorization": f"Bearer {issuer_key}"},
    )
    assert ok.status_code == 200


# --- API keys must not reach destructive account ops ---


@pytest.mark.asyncio
async def test_api_key_cannot_change_password(auth_state, client):
    """Wave 3 (require_browser_session): /v1/me/password is browser-only
    even with an API key that carries every scope in the vocabulary. A
    leaked agent key must never destroy the account it belongs to. See
    [[feedback_security_split]]."""
    reg = await client.post(
        "/v1/auth/register",
        json={"password": "echo foxtrot golf 12345", "with_api_key": True},
    )
    key = reg.json()["api_key"]
    # Mint a max-scope key via the cookie session before logging out.
    full = await client.post(
        "/v1/me/api-keys",
        json={
            "name": "full",
            "scopes": [
                "vm:read", "vm:create", "vm:reboot", "vm:extend", "vm:destroy",
                "intent:create", "intent:read",
                "domain:register",
                "api_keys:read", "api_keys:write",
            ],
        },
    )
    full_key = full.json()["api_key"]
    await client.post("/v1/auth/logout")

    for k in (key, full_key):
        res = await client.post(
            "/v1/me/password",
            json={"current_password": "echo foxtrot golf 12345", "new_password": "papa quebec romeo 1234"},
            headers={"authorization": f"Bearer {k}"},
        )
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_api_key_cannot_delete_account(auth_state, client):
    """Wave 3: /v1/me DELETE is browser-only (require_browser_session)."""
    reg = await client.post(
        "/v1/auth/register",
        json={"password": "foxtrot golf hotel 12345", "with_api_key": True},
    )
    key = reg.json()["api_key"]
    await client.post("/v1/auth/logout")
    res = await client.delete(
        "/v1/me?vm_policy=destroy",
        headers={"authorization": f"Bearer {key}"},
    )
    assert res.status_code == 403


# --- Listing + revocation ---


@pytest.mark.asyncio
async def test_list_keys_omits_revoked(auth_state, client):
    """Wave 3: revoked keys disappear from /v1/me/api-keys (still in DB for
    audit but not surfaced)."""
    await client.post(
        "/v1/auth/register",
        json={"password": "golf hotel india 12345"},
    )
    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "k1", "scopes": ["vm:read"]},
    )
    k1 = res.json()["key"]["key_id"]
    await client.post("/v1/me/api-keys", json={"name": "k2", "scopes": ["vm:read"]})

    # List shows 2.
    lst = await client.get("/v1/me/api-keys")
    assert lst.status_code == 200
    assert len(lst.json()["keys"]) == 2

    # Revoke k1.
    rev = await client.delete(f"/v1/me/api-keys/{k1}")
    assert rev.status_code == 200

    # Now list shows 1.
    lst = await client.get("/v1/me/api-keys")
    assert len(lst.json()["keys"]) == 1


@pytest.mark.asyncio
async def test_revoke_unknown_key_returns_404(auth_state, client):
    await client.post(
        "/v1/auth/register",
        json={"password": "hotel india juliet 12345"},
    )
    res = await client.delete("/v1/me/api-keys/nonexistent-key-id")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_api_key_cannot_revoke_itself(auth_state, client):
    """Wave 3: a key cannot revoke itself when authenticating via that key.
    Prevents an agent silent self-lockout — they must get a clear error and
    use a different key (or the dashboard) to revoke."""
    await client.post(
        "/v1/auth/register",
        json={"password": "india juliet kilo 12345"},
    )
    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "self-revoker", "scopes": ["api_keys:write"]},
    )
    body = res.json()
    self_key = body["api_key"]
    self_key_id = body["key"]["key_id"]
    await client.post("/v1/auth/logout")

    res = await client.delete(
        f"/v1/me/api-keys/{self_key_id}",
        headers={"authorization": f"Bearer {self_key}"},
    )
    assert res.status_code == 403
    assert "cannot revoke itself" in res.json()["detail"]


@pytest.mark.asyncio
async def test_unknown_scope_in_create_returns_400(auth_state, client):
    """Wave 3 (validate_scopes): a typo'd scope must surface as a 400
    rather than silently get accepted."""
    await client.post(
        "/v1/auth/register",
        json={"password": "juliet kilo lima 1234567"},
    )
    res = await client.post(
        "/v1/me/api-keys",
        json={"name": "typo", "scopes": ["vm:reed"]},
    )
    assert res.status_code == 400
    assert "vm:reed" in res.json()["detail"]
