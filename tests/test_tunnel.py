"""Reverse-SSH tunnel service + route tests.

Covers the daemon-backed lease lifecycle (provision/extend/revoke/sweep) with a
fake TunnelProvider over an in-memory SQLite store, and the route's x402 payment
ordering: gate-hidden until ready, verify->provision->settle on create,
revoke-on-settle-failure, settle-after-daemon-preflight on extend, config-bound
duration checks, strict daemon-confirmed revoke, and the hashed owner-token
management gate.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, ReverseTunnelRow
from hyrule_cloud.middleware.x402 import VerifiedPayment
from hyrule_cloud.providers.tunnel_client import LeaseResult, TunnelDaemonError
from hyrule_cloud.services.tunnel.service import TunnelService, new_tunnel_id


class FakeTunnelProvider:
    """In-memory stand-in for the Go daemon control API."""

    def __init__(self):
        self.leases: dict[str, dict] = {}
        self.next_port = 10000
        self.create_error: Exception | None = None
        self.revoked: list[str] = []
        self.revoke_ok = True  # set False to simulate a daemon revoke failure

    async def close(self):
        pass

    async def health_check(self):
        return True

    async def health_check_cached(self):
        return True

    async def create_lease(self, tunnel_id, duration_seconds, allowlist_cidrs):
        if self.create_error is not None:
            raise self.create_error
        if tunnel_id in self.leases:
            return LeaseResult.from_json(self.leases[tunnel_id])  # idempotent
        if getattr(self, "omit_token", False):
            rec = {"lease_id": tunnel_id, "token": None, "port": self.next_port,
                   "endpoint_host": "tun.hyrule.host", "ssh_port": 2222, "status": "active",
                   "expires_at": (datetime.now(UTC) + timedelta(seconds=duration_seconds)).isoformat()}
            self.next_port += 1
            self.leases[tunnel_id] = rec
            return LeaseResult.from_json(rec)
        port = self.next_port
        self.next_port += 1
        expires = datetime.now(UTC) + timedelta(seconds=duration_seconds)
        rec = {
            "lease_id": tunnel_id,
            "token": f"tok{tunnel_id[-6:]}",
            "port": port,
            "endpoint_host": "tun.hyrule.host",
            "ssh_port": 2222,
            "status": "active",
            "expires_at": expires.isoformat(),
            "connected": False,
            "visitor_conns": 0,
        }
        self.leases[tunnel_id] = rec
        return LeaseResult.from_json(rec)

    async def extend_lease(self, tunnel_id, duration_seconds):
        rec = self.leases.get(tunnel_id)
        if rec is None:
            raise TunnelDaemonError("lease not found")
        expires = datetime.now(UTC) + timedelta(seconds=duration_seconds)
        rec["expires_at"] = expires.isoformat()
        return LeaseResult.from_json(rec)

    async def revoke_lease(self, tunnel_id):
        self.revoked.append(tunnel_id)
        if not self.revoke_ok:
            return False
        self.leases.pop(tunnel_id, None)
        return True

    async def get_lease(self, tunnel_id):
        rec = self.leases.get(tunnel_id)
        return LeaseResult.from_json(rec) if rec else None

    async def list_leases(self):
        return [LeaseResult.from_json(r) for r in self.leases.values()]


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _config(**overrides) -> HyruleConfig:
    cfg = HyruleConfig()
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


# --------------------------------------------------------------------------- #
# Service-level tests (real TunnelService + SQLite + fake provider)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_provision_writes_row_and_allocates(session_factory):
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(), session_factory, provider)
    tid = new_tunnel_id()
    row, lease = await svc.provision(
        tunnel_id=tid, hours=1, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None
    )
    assert row.allocated_port == lease.port == 10000
    assert row.owner_wallet == "0xabc"
    assert row.payment_tx is None
    async with session_factory() as s:
        rows = list((await s.execute(select(ReverseTunnelRow))).scalars())
    assert len(rows) == 1 and rows[0].tunnel_id == tid


@pytest.mark.asyncio
async def test_mark_settled_and_revoke(session_factory):
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(), session_factory, provider)
    tid = new_tunnel_id()
    await svc.provision(tunnel_id=tid, hours=1, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None)
    await svc.mark_settled(tid, "0xTX")
    row = await svc.get(tid)
    assert row.payment_tx == "0xTX"

    await svc.revoke(tid)
    assert tid in provider.revoked
    assert await svc.get(tid) is None


@pytest.mark.asyncio
async def test_extend_pushes_expiry(session_factory):
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(), session_factory, provider)
    tid = new_tunnel_id()
    await svc.provision(tunnel_id=tid, hours=1, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None)
    # Read both endpoints from the DB so tz-awareness is consistent (SQLite
    # returns naive datetimes; Postgres keeps tz — the comparison must not care).
    before = (await svc.get(tid)).expires_at
    updated = await svc.extend(tid, 5)
    assert updated is not None
    assert updated.expires_at > before


@pytest.mark.asyncio
async def test_sweep_reaps_expired_past_grace(session_factory):
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(tunnel_grace_period_minutes=0), session_factory, provider)
    tid = new_tunnel_id()
    await svc.provision(tunnel_id=tid, hours=1, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None)
    # Force it into the past.
    async with session_factory() as s:
        r = await s.get(ReverseTunnelRow, tid)
        r.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await s.commit()
    reaped = await svc.sweep_expiries()
    assert reaped == 1
    assert tid in provider.revoked
    assert await svc.get(tid) is None


@pytest.mark.asyncio
async def test_extend_is_monotonic(session_factory):
    # A later extend then a "stale" shorter one must not regress the stored expiry.
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(), session_factory, provider)
    tid = new_tunnel_id()
    await svc.provision(tunnel_id=tid, hours=1, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None)
    await svc.extend(tid, 5)
    long_expiry = (await svc.get(tid)).expires_at
    # The fake returns now+duration, so a 1h extend is EARLIER than the 5h one.
    await svc.extend(tid, 1)
    assert (await svc.get(tid)).expires_at == long_expiry  # not regressed


@pytest.mark.asyncio
async def test_sweep_keeps_live_lease(session_factory):
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(), session_factory, provider)
    tid = new_tunnel_id()
    await svc.provision(tunnel_id=tid, hours=5, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None)
    assert await svc.sweep_expiries() == 0
    assert await svc.get(tid) is not None


# --------------------------------------------------------------------------- #
# Route-level tests (payment flow ordering + gate)
# --------------------------------------------------------------------------- #


class MockGate:
    def __init__(self, *, settle_ok=True):
        self.verified = 0
        self.settled = 0
        self.checked = 0
        self.settle_ok = settle_ok

    async def verify_only(self, request, amount, description="", extra_body=None):
        self.verified += 1
        wallet = request.headers.get("X-Mock-Wallet")
        if wallet:
            return VerifiedPayment(payer=wallet, amount=amount)
        return Response(status_code=402)

    async def settle_verified(self, request, verified):
        self.settled += 1
        if self.settle_ok:
            request.state.payment_tx = "0xMockHash"
            request.state.payment_response_headers = {"X-PAYMENT-RESPONSE": "proof"}
        return self.settle_ok

    async def check_payment(self, request, amount, description="", extra_body=None):
        self.checked += 1
        wallet = request.headers.get("X-Mock-Wallet")
        if wallet:
            request.state.payment_tx = "0xMockHash"
            return wallet
        return Response(status_code=402)


@pytest_asyncio.fixture
async def wired(session_factory, monkeypatch):
    from hyrule_cloud.state import AppState

    monkeypatch.setattr(
        "hyrule_cloud.api.tunnel.tunnel_service_ready", lambda: True
    )
    provider = FakeTunnelProvider()
    gate = MockGate()
    svc = TunnelService(_config(), session_factory, provider)
    og = getattr(app.state, "_typed_state", None)
    state = AppState(
        config=_config(),
        orchestrator=None,
        payment_gate=gate,
        network_provider=None,
        tunnel_provider=provider,
        tunnel_service=svc,
    )
    app.state._typed_state = state
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        yield client, state, provider, gate
    if og is not None:
        app.state._typed_state = og


@pytest.mark.asyncio
async def test_create_requires_payment(wired):
    client, _state, provider, gate = wired
    r = await client.post("/v1/tunnel/create", json={"hours": 1})
    assert r.status_code == 402
    assert gate.settled == 0
    assert provider.leases == {}


@pytest.mark.asyncio
async def test_create_verify_then_provision_then_settle(wired):
    client, _state, provider, gate = wired
    r = await client.post("/v1/tunnel/create", json={"hours": 2}, headers={"X-Mock-Wallet": "0xabc"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["public_port"] >= 10000
    assert body["token"].startswith("tok")
    assert body["endpoint_host"] == "tun.hyrule.host"
    assert body["ssh_command"].startswith("ssh -N -R 0:localhost:22")
    # Delivered before charge: verify happened, then settle.
    assert gate.verified == 1 and gate.settled == 1
    assert len(provider.leases) == 1


@pytest.mark.asyncio
async def test_create_settle_failure_revokes_lease(session_factory, monkeypatch):
    from hyrule_cloud.state import AppState

    monkeypatch.setattr(
        "hyrule_cloud.api.tunnel.tunnel_service_ready", lambda: True
    )
    provider = FakeTunnelProvider()
    gate = MockGate(settle_ok=False)
    svc = TunnelService(_config(), session_factory, provider)
    og = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_config(), orchestrator=None, payment_gate=gate,
        network_provider=None, tunnel_provider=provider, tunnel_service=svc,
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            r = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
        assert r.status_code == 402
        # Provisioned then settle failed -> lease revoked, no paid-for-free tunnel.
        assert provider.revoked  # daemon revoke called
        assert provider.leases == {}
        async with session_factory() as s:
            rows = list((await s.execute(select(ReverseTunnelRow))).scalars())
        assert rows == []
    finally:
        if og is not None:
            app.state._typed_state = og


@pytest.mark.asyncio
async def test_create_ports_exhausted_never_charges(wired):
    client, _state, provider, gate = wired
    provider.create_error = TunnelDaemonError("no free tunnel ports", ports_exhausted=True)
    r = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    assert r.status_code == 503
    assert gate.settled == 0  # provisioning failed before settle


@pytest.mark.asyncio
async def test_create_hidden_when_not_ready(session_factory, monkeypatch):
    from hyrule_cloud.state import AppState

    monkeypatch.setattr(
        "hyrule_cloud.api.tunnel.tunnel_service_ready", lambda: False
    )
    provider = FakeTunnelProvider()
    gate = MockGate()
    svc = TunnelService(_config(), session_factory, provider)
    og = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_config(), orchestrator=None, payment_gate=gate,
        network_provider=None, tunnel_provider=provider, tunnel_service=svc,
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            r = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
        assert r.status_code == 501  # not_implemented gate
        assert gate.verified == 0
    finally:
        if og is not None:
            app.state._typed_state = og


@pytest.mark.asyncio
async def test_extend_settles_after_preflight(wired):
    client, _state, _provider, gate = wired
    created = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    tid = created.json()["tunnel_id"]
    token = created.json()["token"]
    gate.checked = 0
    r = await client.post(
        f"/v1/tunnel/{tid}/extend",
        json={"hours": 3},
        headers={"X-Mock-Wallet": "0xabc", "X-Tunnel-Token": token},
    )
    assert r.status_code == 200, r.text
    # Settle-first after a daemon pre-flight: check_payment used once.
    assert gate.checked == 1


@pytest.mark.asyncio
async def test_extend_daemon_gone_does_not_charge(wired):
    client, _state, provider, gate = wired
    created = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    tid = created.json()["tunnel_id"]
    token = created.json()["token"]
    # Daemon has dropped the lease (e.g. expired-in-grace); the pre-flight must
    # fail the extend BEFORE any charge.
    provider.leases.pop(tid, None)
    gate.checked = 0
    r = await client.post(
        f"/v1/tunnel/{tid}/extend",
        json={"hours": 3},
        headers={"X-Mock-Wallet": "0xabc", "X-Tunnel-Token": token},
    )
    assert r.status_code == 404
    assert gate.checked == 0  # never charged for undelivered time


@pytest.mark.asyncio
async def test_create_rejects_out_of_config_bounds(session_factory, monkeypatch):
    from hyrule_cloud.state import AppState

    monkeypatch.setattr("hyrule_cloud.api.tunnel.tunnel_service_ready", lambda: True)
    provider = FakeTunnelProvider()
    gate = MockGate()
    cfg = _config(tunnel_max_hours=24)
    svc = TunnelService(cfg, session_factory, provider)
    og = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=cfg, orchestrator=None, payment_gate=gate,
        network_provider=None, tunnel_provider=provider, tunnel_service=svc,
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            # 48h exceeds the configured 24h max -> 422 before any payment.
            r = await client.post("/v1/tunnel/create", json={"hours": 48}, headers={"X-Mock-Wallet": "0xabc"})
        assert r.status_code == 422
        assert gate.verified == 0
        assert provider.leases == {}
    finally:
        if og is not None:
            app.state._typed_state = og


@pytest.mark.asyncio
async def test_revoke_fails_when_daemon_revoke_fails(wired):
    client, _state, provider, _gate = wired
    created = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    tid = created.json()["tunnel_id"]
    token = created.json()["token"]
    provider.revoke_ok = False
    r = await client.delete(f"/v1/tunnel/{tid}", headers={"X-Tunnel-Token": token})
    assert r.status_code == 502  # daemon revoke failed -> not reported as revoked
    # Row retained so the owner can retry.
    assert (await client.get(f"/v1/tunnel/{tid}/status", headers={"X-Tunnel-Token": token})).status_code == 200


@pytest.mark.asyncio
async def test_token_is_hashed_at_rest(session_factory):
    provider = FakeTunnelProvider()
    svc = TunnelService(_config(), session_factory, provider)
    tid = new_tunnel_id()
    _row, lease = await svc.provision(
        tunnel_id=tid, hours=1, allowlist_cidrs=None, owner_wallet="0xabc", owner_account_id=None, idempotency_key=None
    )
    from hyrule_cloud.middleware.anon_token import hash_anon_token

    stored = await svc.get(tid)
    assert stored.token_hash == hash_anon_token(lease.token)
    assert stored.token_hash != lease.token  # cleartext never persisted


@pytest.mark.asyncio
async def test_status_requires_owner_token(wired):
    client, _state, _provider, _gate = wired
    created = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    tid = created.json()["tunnel_id"]
    token = created.json()["token"]
    # No token -> 404 (never confirm existence to a non-owner).
    assert (await client.get(f"/v1/tunnel/{tid}/status")).status_code == 404
    assert (await client.get(f"/v1/tunnel/{tid}/status", headers={"X-Tunnel-Token": "wrong"})).status_code == 404
    ok = await client.get(f"/v1/tunnel/{tid}/status", headers={"X-Tunnel-Token": token})
    assert ok.status_code == 200
    assert ok.json()["tunnel_id"] == tid


@pytest.mark.asyncio
async def test_revoke_requires_owner_token_then_tears_down(wired):
    client, _state, provider, _gate = wired
    created = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    tid = created.json()["tunnel_id"]
    token = created.json()["token"]
    assert (await client.delete(f"/v1/tunnel/{tid}")).status_code == 404  # no token
    ok = await client.delete(f"/v1/tunnel/{tid}", headers={"X-Tunnel-Token": token})
    assert ok.status_code == 200 and ok.json()["status"] == "revoked"
    assert tid in provider.revoked
    # Gone now.
    assert (await client.get(f"/v1/tunnel/{tid}/status", headers={"X-Tunnel-Token": token})).status_code == 404


@pytest.mark.asyncio
async def test_create_is_idempotent_on_payment_auth(wired):
    client, _state, provider, gate = wired
    headers = {"X-Mock-Wallet": "0xabc", "x-payment": "auth-ABC-123"}
    first = await client.post("/v1/tunnel/create", json={"hours": 1}, headers=headers)
    assert first.status_code == 200
    tid1, tok1 = first.json()["tunnel_id"], first.json()["token"]
    settled_after_first = gate.settled

    # Retry with the SAME payment authorization: recovers the same tunnel+token,
    # does NOT settle again, does NOT allocate a second lease.
    second = await client.post("/v1/tunnel/create", json={"hours": 1}, headers=headers)
    assert second.status_code == 200
    assert second.json()["tunnel_id"] == tid1
    assert second.json()["token"] == tok1
    assert gate.settled == settled_after_first  # no double charge
    assert len(provider.leases) == 1
    # The replay carries the original settlement proof so an x402 client accepts it.
    assert second.headers.get("X-PAYMENT-RESPONSE") == "proof"


@pytest.mark.asyncio
async def test_create_rejects_empty_allowlist(wired):
    client, _state, provider, gate = wired
    # An explicit empty allowlist is rejected (422) before any payment, never
    # silently treated as open.
    r = await client.post(
        "/v1/tunnel/create",
        json={"hours": 1, "allowlist_cidrs": []},
        headers={"X-Mock-Wallet": "0xabc"},
    )
    assert r.status_code == 422
    assert gate.verified == 0
    assert provider.leases == {}


@pytest.mark.asyncio
async def test_create_rejects_missing_daemon_token(wired):
    client, _state, provider, gate = wired
    provider.omit_token = True
    r = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    assert r.status_code == 502
    assert gate.settled == 0  # never charged
    assert provider.leases == {}  # daemon lease revoked


@pytest.mark.asyncio
async def test_status_daemon_unavailable_is_503(wired):
    client, _state, provider, _gate = wired
    created = await client.post("/v1/tunnel/create", json={"hours": 1}, headers={"X-Mock-Wallet": "0xabc"})
    tid = created.json()["tunnel_id"]
    token = created.json()["token"]

    async def boom(_tid):
        raise TunnelDaemonError("daemon down")

    provider.get_lease = boom
    r = await client.get(f"/v1/tunnel/{tid}/status", headers={"X-Tunnel-Token": token})
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_quote_and_pricing_are_free(wired):
    client, _state, _provider, _gate = wired
    q = await client.post("/v1/tunnel/quote", json={"hours": 4})
    assert q.status_code == 200
    assert q.json()["amount_usd"] == str(Decimal("0.05") * 4)
    p = await client.get("/v1/tunnel/pricing")
    assert p.status_code == 200 and p.json()["hourly_usd"] == "0.05"
    # quote is NOT a catalog operation
    from hyrule_cloud.services.discovery import PAID_OPERATIONS
    paths = {op.path for op in PAID_OPERATIONS}
    assert "/v1/tunnel/quote" not in paths
    assert "/v1/tunnel/create" in paths
