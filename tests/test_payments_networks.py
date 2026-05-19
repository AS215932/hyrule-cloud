"""Block C (Wave 3) — /v1/payments/networks contract.

The frontend reads from this endpoint and renders the chain selector from
it (never hardcodes — see [[feedback_verified_payment_chains]]). The tests
below lock in the response shape so a future refactor can't quietly drop
a field the JS adapter depends on.

We use ASGITransport rather than TestClient so the lifespan hook (which
opens a Postgres connection) doesn't fire — these tests verify the route
in isolation. AppState is wired in manually via the `app.state._typed_state`
slot, mirroring the pattern in tests/test_api.py.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, PaymentConfig, PaymentNetwork
from hyrule_cloud.state import AppState


@pytest.fixture
def real_payment_state():
    """Pin the real PaymentConfig (Base/Polygon/Arbitrum defaults) onto the
    app for this test only. Restores any previously-installed state on
    teardown so we don't bleed into other test modules."""
    cfg = HyruleConfig()
    cfg.payment = PaymentConfig()
    state = AppState(
        config=cfg,
        orchestrator=None,
        payment_gate=None,
        network_provider=None,
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev
        else:
            try:
                del app.state._typed_state
            except AttributeError:
                pass


@pytest.mark.asyncio
async def test_payments_networks_returns_base_by_default(real_payment_state) -> None:
    """Default config: only Base mainnet is enabled out of the box because
    that's what the default facilitator (public x402.org) verifies against.
    Polygon and Arbitrum are coded but disabled; operators flip them on in
    Vault once they're pointed at Coinbase CDP."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/v1/payments/networks")
    assert res.status_code == 200
    keys = [n["key"] for n in res.json()["networks"]]
    assert keys == ["base"]


@pytest.mark.asyncio
async def test_payments_networks_omits_disabled_chains_by_default(
    real_payment_state,
) -> None:
    """Polygon and Arbitrum are present in PaymentConfig but enabled=False —
    the endpoint MUST NOT advertise them. Per [[feedback_verified_payment_chains]],
    advertising a chain implies the verify_facilitator gate passed for it."""
    cfg = PaymentConfig()
    polygon = next(n for n in cfg.payment_networks if n.key == "polygon")
    assert polygon.enabled is False
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()
    keys_on_wire = {n["key"] for n in body["networks"]}
    assert "polygon" not in keys_on_wire
    assert "arbitrum" not in keys_on_wire


@pytest.mark.asyncio
async def test_payments_networks_shape_locks_in_required_fields(
    real_payment_state,
) -> None:
    """Every network entry MUST carry the fields the EVM JS adapter signs an
    EIP-712 payment with — name, version, chain_id, token_address, decimals,
    asset. Plus CAIP-2 for x402 v2."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()
    for n in body["networks"]:
        assert n["family"] == "evm"
        assert n["caip2"].startswith("eip155:")
        assert isinstance(n["chain_id"], int) and n["chain_id"] > 0
        assert n["asset"] == "USDC"
        assert n["token_address"].startswith("0x")
        assert n["token_decimals"] == 6
        # eip712_domain must have name + version — frontend needs both.
        assert n["eip712_domain"]["name"]
        assert n["eip712_domain"]["version"]


@pytest.mark.asyncio
async def test_payments_networks_top_level_carries_receiver_and_facilitator(
    real_payment_state,
) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()
    assert "receiver_address" in body
    assert body["facilitator_url"] == "https://x402.org/facilitator"


def test_disabled_chain_drops_off_the_wire() -> None:
    """Wave 3: enabled_networks() filters; the wire format should mirror.
    Operators flip a chain off via Vault by re-rendering PAYMENT_PAYMENT_NETWORKS
    with `enabled=False` for the relevant entry. This is a pure config
    test — no FastAPI app state needed."""
    cfg = PaymentConfig(
        payment_networks=[
            PaymentNetwork(
                key="base", display_name="Base", caip2="eip155:8453", family="evm",
                chain_id=8453, asset="USDC",
                token_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                token_decimals=6, eip712_domain={"name": "USD Coin", "version": "2"},
                enabled=True,
            ),
            PaymentNetwork(
                key="polygon", display_name="Polygon", caip2="eip155:137", family="evm",
                chain_id=137, asset="USDC",
                token_address="0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
                token_decimals=6, eip712_domain={"name": "USD Coin", "version": "2"},
                enabled=False,  # disabled
            ),
        ]
    )
    assert [n.key for n in cfg.enabled_networks()] == ["base"]
