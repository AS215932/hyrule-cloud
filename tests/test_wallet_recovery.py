"""Block F: wallet-signature recovery tests.

Covers the full /v1/auth/recover/wallet/{challenge,verify} flow against an
in-process SQLite DB. Signatures are produced by `eth_account` with a fixed
test private key so the ecrecover path is exercised end-to-end (no mocks).

Key assertions:
- Account with no payment history cannot recover (signer-match fails).
- Replay of the same signature is rejected after first use.
- Expired challenges are rejected.
- Challenge issuance does NOT reveal account existence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, RecoveryChallengeRow, VMRow
from hyrule_cloud.models import (
    VMSize,
    VMStatus,
    generate_vm_id,
)


def _now() -> datetime:
    return datetime.now(UTC)


# --- Fixtures (mirror test_auth.py) ---


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


class _MockGate:
    async def check_payment(self, request, amount, description, extra_body):
        return Response(status_code=402)


@pytest_asyncio.fixture
async def auth_state():
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
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost"
    ) as c:
        yield c


# --- Helpers ---


# Stable test wallet. Real signature; the address below is its checksum form.
TEST_PRIVKEY = (
    "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
)
TEST_ADDRESS = Account.from_key(TEST_PRIVKEY).address  # 0x...


def _sign(text: str) -> str:
    msg = encode_defunct(text=text)
    signed = Account.sign_message(msg, private_key=TEST_PRIVKEY)
    return signed.signature.hex()


async def _seed_owned_vm(
    state, account_id: str, *, owner_wallet: str = TEST_ADDRESS
) -> str:
    """Insert a VM owned by `account_id` and paid for by `owner_wallet`."""
    vm_id = generate_vm_id()
    async with state.orchestrator.db() as session:
        session.add(
            VMRow(
                vm_id=vm_id,
                owner_wallet=owner_wallet,
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


# --- Tests: challenge issuance ---


@pytest.mark.asyncio
async def test_challenge_returned_for_unknown_account_id(auth_state, client):
    """No leak of account existence: unknown IDs still get a challenge.

    Verification later will fail at the signer-match step.
    """
    res = await client.post(
        "/v1/auth/recover/wallet/challenge",
        json={"account_id": "H0000000000"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["nonce"]
    assert "H0000000000" in body["challenge_text"]
    assert "Origin: https://hyrule.host" in body["challenge_text"]
    assert "Nonce:" in body["challenge_text"]
    assert "Expires:" in body["challenge_text"]


@pytest.mark.asyncio
async def test_challenge_text_is_origin_and_time_bound(auth_state, client):
    res = await client.post(
        "/v1/auth/recover/wallet/challenge",
        json={"account_id": "H1234567890"},
    )
    assert res.status_code == 200
    body = res.json()
    text = body["challenge_text"]
    # All four binding fields must be in the signed string.
    assert text.startswith("Recover Hyrule account H1234567890")
    assert "Origin: https://hyrule.host" in text
    assert f"Nonce: {body['nonce']}" in text
    assert "Issued:" in text and "Expires:" in text


@pytest.mark.asyncio
async def test_challenge_persisted_with_expiry(auth_state, client):
    res = await client.post(
        "/v1/auth/recover/wallet/challenge",
        json={"account_id": "HABCDEF1234"},
    )
    nonce = res.json()["nonce"]
    async with auth_state.orchestrator.db() as db:
        row = await db.get(RecoveryChallengeRow, nonce)
    assert row is not None
    assert row.used_at is None
    # 5-minute TTL; allow some skew.
    ttl = (row.expires_at.replace(tzinfo=UTC) - row.issued_at.replace(tzinfo=UTC))
    assert timedelta(minutes=4) < ttl <= timedelta(minutes=6)


# --- Tests: verify happy path ---


@pytest.mark.asyncio
async def test_recovery_succeeds_when_signer_owns_a_vm_on_account(
    auth_state, client
):
    reg = await client.post(
        "/v1/auth/register", json={"password": "before-pw correct horse"}
    )
    account_id = reg.json()["account_id"]
    await _seed_owned_vm(auth_state, account_id, owner_wallet=TEST_ADDRESS)

    # Drop the registration session so we can prove session revoke happens.
    await client.post("/v1/auth/logout")

    # Open a second client to simulate a live session that should be revoked.
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://localhost"
    ) as live:
        login = await live.post(
            "/v1/auth/login",
            json={"account_id": account_id, "password": "before-pw correct horse"},
        )
        assert login.status_code == 200
        # The live session works before recovery.
        me = await live.get("/v1/me")
        assert me.status_code == 200

        # Issue challenge + sign + verify in a third (untrusted) client.
        chal = await client.post(
            "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
        )
        nonce = chal.json()["nonce"]
        text = chal.json()["challenge_text"]
        signature = _sign(text)

        verify = await client.post(
            "/v1/auth/recover/wallet/verify",
            json={
                "nonce": nonce,
                "signature": signature,
                "new_password": "after-pw-extra-entropy-here",
            },
        )
        assert verify.status_code == 200, verify.text
        assert verify.json()["account_id"] == account_id

        # The live session is now revoked.
        me_after = await live.get("/v1/me")
        assert me_after.status_code == 401

    # New password works.
    relogin = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "after-pw-extra-entropy-here"},
    )
    assert relogin.status_code == 200

    # Old password does NOT.
    bad = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "before-pw correct horse"},
    )
    assert bad.status_code == 401


# --- Tests: payment-history requirement (Block F's headline guarantee) ---


@pytest.mark.asyncio
async def test_recovery_rejects_account_with_no_payment_history(
    auth_state, client
):
    """An account that has never paid via x402 cannot recover by wallet sig."""
    reg = await client.post(
        "/v1/auth/register", json={"password": "no-vms-yet pw correct"}
    )
    account_id = reg.json()["account_id"]
    # Deliberately NO _seed_owned_vm — account has zero payment history.

    chal = await client.post(
        "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
    )
    text = chal.json()["challenge_text"]
    nonce = chal.json()["nonce"]
    signature = _sign(text)

    verify = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": nonce,
            "signature": signature,
            "new_password": "would-be-new-pw 123",
        },
    )
    assert verify.status_code == 401
    # Old password still works.
    relogin = await client.post(
        "/v1/auth/login",
        json={"account_id": account_id, "password": "no-vms-yet pw correct"},
    )
    assert relogin.status_code == 200


@pytest.mark.asyncio
async def test_recovery_rejects_signer_who_didnt_pay_for_this_account(
    auth_state, client
):
    """VM exists, but it was paid for by a DIFFERENT wallet than the signer."""
    reg = await client.post(
        "/v1/auth/register", json={"password": "different-payer pw correct"}
    )
    account_id = reg.json()["account_id"]
    # The account's VM was paid by some OTHER wallet.
    await _seed_owned_vm(
        auth_state, account_id, owner_wallet="0xdeadbeef00000000000000000000000000000000"
    )

    chal = await client.post(
        "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
    )
    signature = _sign(chal.json()["challenge_text"])

    verify = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": chal.json()["nonce"],
            "signature": signature,
            "new_password": "shouldnt-work pw 12345",
        },
    )
    assert verify.status_code == 401


# --- Tests: replay + expiry + tampering ---


@pytest.mark.asyncio
async def test_replay_of_same_signature_is_rejected(auth_state, client):
    reg = await client.post(
        "/v1/auth/register", json={"password": "replay-test pw correct"}
    )
    account_id = reg.json()["account_id"]
    await _seed_owned_vm(auth_state, account_id)

    chal = await client.post(
        "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
    )
    nonce = chal.json()["nonce"]
    signature = _sign(chal.json()["challenge_text"])

    first = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": nonce,
            "signature": signature,
            "new_password": "first-reset-pw 12345",
        },
    )
    assert first.status_code == 200

    second = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": nonce,
            "signature": signature,
            "new_password": "second-reset-pw 12345",
        },
    )
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_expired_challenge_is_rejected(auth_state, client):
    reg = await client.post(
        "/v1/auth/register", json={"password": "expiry-test pw correct"}
    )
    account_id = reg.json()["account_id"]
    await _seed_owned_vm(auth_state, account_id)

    chal = await client.post(
        "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
    )
    nonce = chal.json()["nonce"]
    text = chal.json()["challenge_text"]

    # Backdate the challenge row to before "now" so the freshness check fails.
    async with auth_state.orchestrator.db() as db:
        row = await db.get(RecoveryChallengeRow, nonce)
        row.expires_at = _now() - timedelta(minutes=1)
        await db.commit()

    signature = _sign(text)
    res = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": nonce,
            "signature": signature,
            "new_password": "after-expiry pw 1234",
        },
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_unknown_nonce_is_rejected(auth_state, client):
    res = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": "this-nonce-was-never-issued-aaaaa",
            "signature": "0x" + "00" * 65,
            "new_password": "would-be-new-pw 1234",
        },
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_malformed_signature_is_rejected(auth_state, client):
    reg = await client.post(
        "/v1/auth/register", json={"password": "garbage-sig pw correct"}
    )
    account_id = reg.json()["account_id"]
    await _seed_owned_vm(auth_state, account_id)

    chal = await client.post(
        "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
    )
    res = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": chal.json()["nonce"],
            "signature": "not-a-real-signature-at-all-just-text",
            "new_password": "would-be-new-pw 1234",
        },
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_signature_over_different_text_is_rejected(auth_state, client):
    """A signature minted for a different challenge string must not verify.

    Defends against attackers reusing a wallet signature from any other dApp's
    "Sign in to ..." prompt against this endpoint.
    """
    reg = await client.post(
        "/v1/auth/register", json={"password": "wrong-text pw correct"}
    )
    account_id = reg.json()["account_id"]
    await _seed_owned_vm(auth_state, account_id)

    chal = await client.post(
        "/v1/auth/recover/wallet/challenge", json={"account_id": account_id}
    )
    nonce = chal.json()["nonce"]
    # Sign a DIFFERENT message — not the one stored in challenge_text.
    bogus_signature = _sign("Some other dApp's login prompt")

    res = await client.post(
        "/v1/auth/recover/wallet/verify",
        json={
            "nonce": nonce,
            "signature": bogus_signature,
            "new_password": "would-be-new-pw 12345",
        },
    )
    assert res.status_code == 401
