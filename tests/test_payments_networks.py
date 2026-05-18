"""Block C: PaymentNetwork catalog + /v1/payments/networks endpoint.

The catalog is the single source of truth for chain configuration (see
feedback_verified_payment_chains.md). The endpoint exposes it to the
frontend so payment-evm.js never hardcodes chain metadata.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from fastapi import Response
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import (
    PAYMENT_NETWORKS_CATALOG,
    PaymentConfig,
    PaymentNetwork,
)

# --- Catalog static checks ---


def test_catalog_caip2_matches_chain_id_for_evm():
    """For every eip155:N entry, N must equal chain_id."""
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        if net.caip2.startswith("eip155:"):
            n = int(net.caip2.split(":", 1)[1])
            assert n == net.chain_id, f"{key}: caip2 {net.caip2} ≠ chain_id {net.chain_id}"


def test_catalog_no_duplicate_caip2():
    seen: dict[str, str] = {}
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        assert net.caip2 not in seen, f"{key}: duplicate caip2 with {seen[net.caip2]}"
        seen[net.caip2] = key


def test_catalog_no_duplicate_chain_id():
    """EVM-only: SVM entries have chain_id=None and can validly repeat across
    mainnet/devnet/testnet families."""
    seen: dict[int, str] = {}
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        if net.chain_id is None:
            continue
        assert net.chain_id not in seen, f"{key}: duplicate chain_id with {seen[net.chain_id]}"
        seen[net.chain_id] = key


def test_catalog_usdc_decimals_are_six():
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        if net.asset == "USDC":
            assert net.token_decimals == 6, f"{key}: USDC must be 6 decimals"


def test_catalog_required_fields_present():
    """Every network must have core metadata; EIP-712 only applies to EVM."""
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        assert net.token_address, f"{key}: token_address empty"
        assert net.rpc_url, f"{key}: rpc_url empty"
        assert net.block_explorer_url, f"{key}: block_explorer_url empty"
        if net.family == "evm":
            assert net.eip712_domain_name, f"{key}: eip712_domain_name empty (EVM)"
            assert net.eip712_domain_version, f"{key}: eip712_domain_version empty (EVM)"
            assert net.chain_id is not None, f"{key}: chain_id missing (EVM)"
        elif net.family == "svm":
            assert net.chain_id is None, f"{key}: SVM must have chain_id=None"
            assert net.eip712_domain_name is None, f"{key}: SVM must have no EIP-712 domain"


def test_catalog_keys_match_entry_keys():
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        assert net.key == key, f"catalog key {key!r} != entry.key {net.key!r}"


# --- PaymentConfig.networks property ---


def test_default_enabled_is_base_polygon_arbitrum():
    cfg = PaymentConfig()
    keys = [n.key for n in cfg.networks]
    assert keys == ["base", "polygon", "arbitrum"]


def test_enable_world_adds_world(monkeypatch):
    monkeypatch.setenv("PAYMENT_ENABLE_WORLD", "true")
    cfg = PaymentConfig()
    keys = [n.key for n in cfg.networks]
    assert "world" in keys
    assert keys[:3] == ["base", "polygon", "arbitrum"]


def test_enable_svm_adds_solana_mainnet(monkeypatch):
    """Block H: PAYMENT_ENABLE_SVM=true adds Solana mainnet to the network
    list. Catalog mirrors the EVM convention — mainnet only, no testnet
    entries in the production catalog."""
    monkeypatch.setenv("PAYMENT_ENABLE_SVM", "true")
    cfg = PaymentConfig()
    keys = [n.key for n in cfg.networks]
    assert "solana" in keys
    solana = next(n for n in cfg.networks if n.key == "solana")
    assert solana.family == "svm"
    assert solana.caip2 == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    assert solana.chain_id is None
    assert solana.eip712_domain_name is None


def test_payment_network_family_classifier():
    """`family` derives "evm"/"svm" from the CAIP-2 prefix without state."""
    base = PAYMENT_NETWORKS_CATALOG["base"]
    solana = PAYMENT_NETWORKS_CATALOG["solana"]
    assert base.family == "evm"
    assert solana.family == "svm"


def test_networks_returns_typed_dataclasses():
    cfg = PaymentConfig()
    for n in cfg.networks:
        assert isinstance(n, PaymentNetwork)


# --- /v1/payments/networks endpoint ---


@pytest.fixture
def real_config_state():
    """Wire the live PaymentConfig (with its real catalog) into app.state.

    The other test modules stub the orchestrator, but for this endpoint we
    only need cfg.payment to be a real PaymentConfig.
    """
    from hyrule_cloud.state import AppState

    class _RealCfg:
        payment = PaymentConfig()

    class _NoopOrch:
        async def get_vm(self, vm_id): return None

    class _Gate:
        async def check_payment(self, *a, **k): return Response(status_code=402)

    state = AppState(
        config=_RealCfg(),
        orchestrator=_NoopOrch(),
        payment_gate=_Gate(),
        network_provider=None,
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev


@pytest.mark.asyncio
async def test_networks_endpoint_returns_default_three(real_config_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        res = await c.get("/v1/payments/networks")
    assert res.status_code == 200
    body = res.json()
    keys = [n["key"] for n in body["networks"]]
    assert keys == ["base", "polygon", "arbitrum"]


@pytest.mark.asyncio
async def test_networks_endpoint_shape_is_complete(real_config_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        res = await c.get("/v1/payments/networks")
    body = res.json()
    base = next(n for n in body["networks"] if n["key"] == "base")
    # All fields payment-evm.js needs to sign + switch chain
    assert base["caip2"] == "eip155:8453"
    assert base["chain_id"] == 8453
    assert base["asset"] == "USDC"
    assert base["token_address"].lower() == "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    assert base["token_decimals"] == 6
    assert base["eip712_domain"] == {"name": "USD Coin", "version": "2"}
    assert base["rpc_url"]
    assert base["block_explorer_url"]


@pytest.mark.asyncio
async def test_networks_endpoint_exposes_receiver(real_config_state):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        res = await c.get("/v1/payments/networks")
    body = res.json()
    assert "receiver_address" in body
    assert "facilitator_url" in body


# --- PaymentGate multi-network 402 body ---


@pytest.mark.asyncio
async def test_payment_gate_402_body_includes_all_enabled_networks():
    """When no payment header is present, the 402 response advertises every
    enabled chain in `accepts` with the per-chain EIP-712 + token metadata
    the browser needs to sign."""
    from fastapi import Request

    from hyrule_cloud.middleware.x402 import PaymentGate

    gate = PaymentGate(PaymentConfig())
    # Synthesize an ASGI request — only headers are inspected by build_402_response
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/vm/create",
        "headers": [],
        "query_string": b"",
        "url": b"http://localhost/v1/vm/create",
    }
    async def receive():  # pragma: no cover - never invoked
        return {"type": "http.disconnect"}

    request = Request(scope, receive)
    resp = await gate.check_payment(request, amount=Decimal("0.05"), description="test")
    assert resp.status_code == 402

    import base64
    import json
    header = resp.headers.get("X-PAYMENT-REQUIRED")
    assert header
    decoded = json.loads(base64.b64decode(header))
    assert decoded["x402Version"] == 2
    accepts = decoded["accepts"]
    caip2s = [a["network"] for a in accepts]
    assert "eip155:8453" in caip2s
    assert "eip155:137" in caip2s
    assert "eip155:42161" in caip2s
    # Per-chain metadata for signing
    base_entry = next(a for a in accepts if a["network"] == "eip155:8453")
    assert base_entry["chain_id"] == 8453
    assert base_entry["token_decimals"] == 6
    assert base_entry["eip712_domain"]["version"] == "2"
    assert base_entry["family"] == "evm"


# --- PaymentGate verify/settle bug regression (Block H) ---
#
# The prior PaymentGate.check_payment called self.server.verify(header, dict)
# and self.server.settle(header, dict) — but the SDK only exposes
# verify_payment / settle_payment with typed PaymentPayload + PaymentRequirements
# arguments. The prior call always raised AttributeError and was swallowed by
# the broad except, so production payments only succeeded via dev_bypass.
# This test exercises the verify/settle path end-to-end through a mocked
# facilitator client; if the wrong method names or untyped args reappear, the
# test fails because the SDK either raises or returns the wrong payer.


def _build_payment_header(network: str, payer: str, amount_int: int) -> str:
    """Build a valid v2 X-PAYMENT header for the given EVM network."""
    import base64

    from x402.schemas import PaymentPayload, PaymentRequirements

    accepted = PaymentRequirements(
        scheme="exact",
        network=network,
        asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # Base USDC
        amount=str(amount_int),
        pay_to="0x0000000000000000000000000000000000000ABC",
        max_timeout_seconds=60,
        extra={},
    )
    pp = PaymentPayload(
        x402_version=2,
        payload={
            "signature": "0x" + "00" * 65,
            "authorization": {
                "from": payer,
                "to": "0x0000000000000000000000000000000000000ABC",
                "value": str(amount_int),
                "validAfter": "0",
                "validBefore": "9999999999",
                "nonce": "0x" + "00" * 32,
            },
        },
        accepted=accepted,
    )
    body = pp.model_dump_json(by_alias=True, exclude_none=True)
    return base64.b64encode(body.encode()).decode()


@pytest.mark.asyncio
async def test_check_payment_uses_typed_verify_settle(monkeypatch):
    """Regression test: PaymentGate.check_payment must call the SDK's
    `verify_payment(PaymentPayload, PaymentRequirements)` and
    `settle_payment(...)`, not `verify(str, dict)` / `settle(str, dict)`.

    The prior implementation never reached production successfully because
    the wrong method names always raised AttributeError. This test mocks the
    facilitator client and asserts (a) the calls succeed, (b) the payer is
    extracted from the typed `SettleResponse.payer`, not a header-parsing
    helper, and (c) the tx hash from `SettleResponse.transaction` lands on
    request.state.payment_tx.
    """
    from fastapi import Request
    from x402.server import SettleResponse, VerifyResponse

    from hyrule_cloud.middleware.x402 import PaymentGate

    payer = "0x000000000000000000000000000000000000d00d"
    settled_tx = "0xfeedfacecafebeef"

    gate = PaymentGate(PaymentConfig())

    # Manually populate the SDK server's facilitator map and skip the
    # network-bound initialize() — we don't want the test reaching out to
    # https://x402.org/facilitator/supported.
    captured: dict[str, object] = {}

    class _MockFacilitatorClient:
        async def verify(self, payload, requirements):
            captured["verify_args"] = (payload, requirements)
            return VerifyResponse(is_valid=True, payer=payer)

        async def settle(self, payload, requirements):
            captured["settle_args"] = (payload, requirements)
            return SettleResponse(
                success=True,
                payer=payer,
                transaction=settled_tx,
                network=requirements.network,
                amount=requirements.amount,
            )

    mock_client = _MockFacilitatorClient()
    network = "eip155:8453"
    gate.server._facilitator_clients_map = {network: {"exact": mock_client}}
    # Bypass the SDK's initialize() (which would HTTP-fetch get_supported).
    gate.server._initialized = True

    header = _build_payment_header(network=network, payer=payer, amount_int=50_000)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/vm/create",
        "headers": [(b"x-payment", header.encode())],
        "query_string": b"",
        "url": b"http://localhost/v1/vm/create",
    }

    async def receive():  # pragma: no cover - never invoked
        return {"type": "http.disconnect"}

    request = Request(scope, receive)
    result = await gate.check_payment(
        request, amount=Decimal("0.05"), description="vm-create"
    )

    # If anyone reverts to `self.server.verify(header, dict)`, this assertion
    # fails because that method doesn't exist on x402ResourceServer and the
    # broad except returns a 502 Response instead of the payer string.
    assert isinstance(result, str), f"expected payer str, got {type(result).__name__}: {result!r}"
    assert result == payer
    assert request.state.payment_tx == settled_tx

    # Typed args proof: verify and settle each received a PaymentPayload and a
    # PaymentRequirements, not a raw header str + dict.
    from x402.schemas import PaymentPayload, PaymentRequirements

    v_payload, v_reqs = captured["verify_args"]
    s_payload, s_reqs = captured["settle_args"]
    assert isinstance(v_payload, PaymentPayload)
    assert isinstance(v_reqs, PaymentRequirements)
    assert isinstance(s_payload, PaymentPayload)
    assert isinstance(s_reqs, PaymentRequirements)
    assert v_reqs.network == network
    # Amount must be encoded in on-chain integer units (USDC 6 decimals).
    assert v_reqs.amount == "50000"   # 0.05 USDC = 50_000 (6 decimals)


@pytest.mark.asyncio
async def test_check_payment_rejects_unknown_network():
    """An X-PAYMENT header referencing a chain that isn't enabled returns 402,
    never an unhandled exception. Defends against silently routing payments
    to chains we don't actually support.
    """
    from fastapi import Request

    from hyrule_cloud.middleware.x402 import PaymentGate

    gate = PaymentGate(PaymentConfig())
    gate.server._initialized = True

    # eip155:10 (Optimism) is not in _DEFAULT_ENABLED_KEYS.
    header = _build_payment_header(network="eip155:10", payer="0xABC", amount_int=10)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/vm/create",
        "headers": [(b"x-payment", header.encode())],
        "query_string": b"",
        "url": b"http://localhost/v1/vm/create",
    }

    async def receive():  # pragma: no cover
        return {"type": "http.disconnect"}

    request = Request(scope, receive)
    result = await gate.check_payment(
        request, amount=Decimal("0.05"), description="test"
    )

    from fastapi import Response

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert b"Unsupported network" in result.body


@pytest.mark.asyncio
async def test_402_body_emits_svm_shape_when_enabled(monkeypatch):
    """Block H: when PAYMENT_ENABLE_SVM=true, the 402 `accepts` list includes
    a Solana entry with `family="svm"` and no EVM-only fields (chain_id,
    eip712_domain). EVM entries keep their existing shape."""
    monkeypatch.setenv("PAYMENT_ENABLE_SVM", "true")

    from fastapi import Request

    from hyrule_cloud.middleware.x402 import PaymentGate

    gate = PaymentGate(PaymentConfig())
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/vm/create",
        "headers": [],
        "query_string": b"",
        "url": b"http://localhost/v1/vm/create",
    }

    async def receive():  # pragma: no cover
        return {"type": "http.disconnect"}

    request = Request(scope, receive)
    resp = await gate.check_payment(request, amount=Decimal("0.05"), description="test")
    assert resp.status_code == 402

    import base64
    import json
    header = resp.headers.get("X-PAYMENT-REQUIRED")
    decoded = json.loads(base64.b64decode(header))
    accepts = decoded["accepts"]

    svm_entry = next(
        (a for a in accepts if a["network"] == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
        None,
    )
    assert svm_entry is not None, f"SVM entry missing from accepts: {accepts}"
    assert svm_entry["family"] == "svm"
    assert svm_entry["token_address"] == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    assert svm_entry["token_decimals"] == 6
    # Solana doesn't use EIP-712 — the facilitator builds the SPL tx for the
    # wallet to sign directly.
    assert "eip712_domain" not in svm_entry
    assert "chain_id" not in svm_entry

    # EVM entries remain untouched
    base_entry = next(a for a in accepts if a["network"] == "eip155:8453")
    assert base_entry["family"] == "evm"
    assert base_entry["chain_id"] == 8453
    assert base_entry["eip712_domain"]["version"] == "2"


@pytest.mark.asyncio
async def test_check_payment_rejects_malformed_header():
    """A garbage X-PAYMENT header returns 402, not 500."""
    from fastapi import Request, Response

    from hyrule_cloud.middleware.x402 import PaymentGate

    gate = PaymentGate(PaymentConfig())
    gate.server._initialized = True

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/vm/create",
        "headers": [(b"x-payment", b"not-base64-json")],
        "query_string": b"",
        "url": b"http://localhost/v1/vm/create",
    }

    async def receive():  # pragma: no cover
        return {"type": "http.disconnect"}

    request = Request(scope, receive)
    result = await gate.check_payment(
        request, amount=Decimal("0.05"), description="test"
    )

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert b"Malformed" in result.body
