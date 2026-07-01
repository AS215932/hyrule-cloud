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
    cfg.payment = PaymentConfig(facilitator_url="https://pay.openfacilitator.io")
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
        # native_currency feeds wallet_addEthereumChain when the wallet
        # doesn't know the chain yet — must carry name/symbol/decimals.
        assert n["native_currency"]["name"]
        assert n["native_currency"]["symbol"]
        assert isinstance(n["native_currency"]["decimals"], int)


@pytest.mark.asyncio
async def test_payments_networks_top_level_carries_receiver_and_facilitator(
    real_payment_state,
) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()
    assert "receiver_address" in body
    assert body["facilitator_url"] == "https://pay.openfacilitator.io"


@pytest.mark.asyncio
async def test_payments_networks_native_empty_until_rail_wired(real_payment_state) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()
    assert body["native"] == []


@pytest.mark.asyncio
async def test_payments_networks_native_lists_btc_xmr_when_rail_wired(
    real_payment_state,
) -> None:
    real_payment_state.native_crypto = object()
    real_payment_state.rate_provider = object()
    real_payment_state.native_payment_assets = ["BTC", "XMR"]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()
    assert body["native"] == ["BTC", "XMR"]


@pytest.mark.asyncio
async def test_payments_networks_lists_zcash_when_enabled(real_payment_state) -> None:
    real_payment_state.config.payment.zcash_enabled = True
    real_payment_state.config.payment.zcash_network = "testnet"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        body = (await c.get("/v1/payments/networks")).json()

    zcash = next(n for n in body["networks"] if n["family"] == "zcash")
    assert zcash["key"] == "zcash-testnet"
    assert zcash["caip2"] == "bip122:05a60a92d99d85997cce3b87616c089f"
    assert zcash["asset"] == "ZEC"
    assert zcash["asset_id"] == "slip44:133"
    assert zcash["x402"]["modes"] == ["client-broadcast"]


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


def test_polygon_native_currency_is_pol_not_eth() -> None:
    """Block C: Polygon's native gas token is POL, not ETH. The JS adapter
    sources native_currency from the backend (never hardcodes ETH) so that
    wallet_addEthereumChain advertises the correct token when an operator
    enables Polygon via Vault. Guards the [[feedback_verified_payment_chains]]
    rule that chain metadata flows from one source of truth."""
    cfg = PaymentConfig()
    polygon = next(n for n in cfg.payment_networks if n.key == "polygon")
    assert polygon.native_currency["symbol"] == "POL"
    base = next(n for n in cfg.payment_networks if n.key == "base")
    assert base.native_currency["symbol"] == "ETH"
