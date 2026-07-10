"""Trust-layer receipts (M1): dual-signed payment receipts at the gate.

Invariants pinned here:
- every settled payment can mint a receipt verifiable OFFLINE from the JWKS
  and the published EVM signer alone;
- no receipt exists for 402 / verify-failed / settle-failed outcomes;
- native rails never disclose payment details, not even when a caller
  passes them;
- a broken or disabled trust layer never changes payment behavior.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from x402.http import (
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
)

from hyrule_cloud.app import app, attach_payment_response_headers
from hyrule_cloud.config import TrustConfig
from hyrule_cloud.db import Base, FulfillmentReceiptRow, PaymentEventRow
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.trust import TrustServices
from hyrule_cloud.trust.identity import build_jwks
from hyrule_cloud.trust.models import ReceiptKind
from hyrule_cloud.trust.receipts import (
    LEGACY_RECEIPT_HEADER,
    RECEIPT_HEADER,
    ReceiptService,
    canonical_receipt_bytes,
    enforce_trust_key_guard,
    load_signing_keys,
    recover_receipt_signer,
    verify_receipt_jws,
)
from tests.test_api import (
    MockConfig,
    MockGate,
    MockNetworkProvider,
    MockOrchestrator,
)
from tests.test_payment_gate_x402 import (
    PAYER,
    _FakeServer,
    _gate,
    _payment_header,
    _request,
)

EVM_TEST_KEY = "0x" + "ab" * 32


def _fresh_es256_pem() -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


ES256_TEST_PEM = _fresh_es256_pem()


def _trust_config(**overrides) -> TrustConfig:
    values = dict(
        receipts_enabled=True,
        receipt_signing_key_pem=ES256_TEST_PEM,
        receipt_signing_key_path="",
        receipt_key_id="",
        receipt_retired_jwks_json="",
        receipt_evm_signing_key=EVM_TEST_KEY,
        receipt_evm_signing_key_path="",
        deployment_sha="deadbeefcafe",
        erc8004_registry_caip10="",
        erc8004_agent_id=None,
    )
    values.update(overrides)
    return TrustConfig(**values)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def trust_config() -> TrustConfig:
    return _trust_config()


@pytest.fixture
def receipts(session_factory, trust_config) -> ReceiptService:
    keys = load_signing_keys(trust_config)
    return ReceiptService(
        trust_config,
        session_factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=keys,
    )


async def _receipt_rows(factory) -> list[FulfillmentReceiptRow]:
    async with factory() as session:
        return list((await session.execute(select(FulfillmentReceiptRow))).scalars())


# --- Signing / verification core ---


@pytest.mark.asyncio
async def test_mint_and_offline_verify_roundtrip(receipts, session_factory, trust_config) -> None:
    started = datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC)
    receipt_id = await receipts.mint(
        kind=ReceiptKind.FULFILLMENT,
        outcome="provisioned",
        resource_path="/v1/vm/create",
        method="POST",
        rail="x402-exact-evm",
        network="eip155:8453",
        asset="USDC",
        amount_usd=Decimal("0.05"),
        payer=PAYER,
        tx_hash="0xSETTLED",
        quote_id="q_test",
        vm_id="vm_test",
        provision_started_at=started,
        provisioned_at=started + timedelta(seconds=12),
    )
    assert receipt_id is not None and receipt_id.startswith("hyr_rcpt_")

    row = await receipts.get(receipt_id)
    assert row is not None
    assert row.kind == "fulfillment"
    assert row.service_group == "vm"
    assert row.payer_wallet == PAYER
    assert row.tx_hash == "0xSETTLED"
    assert row.vm_id == "vm_test"

    # Offline JWS verification from the served JWKS alone.
    jwks = build_jwks(receipts.keys, trust_config)
    payload = verify_receipt_jws(row.jws, jwks["keys"][0])
    assert payload == row.payload
    assert payload["profile"] == "x402-compute-fulfillment-receipt/0.1"
    assert payload["payment"]["amount_usd"] == "0.05"
    assert payload["timing"]["provision_seconds"] == "12.000"
    assert payload["service"]["deployment_sha"] == "deadbeefcafe"

    # Offline EIP-712 verification: recovered signer matches the published one.
    assert receipts.keys is not None
    recovered = recover_receipt_signer(row.payload, row.evm_signature)
    assert recovered == receipts.keys.evm_signer == row.evm_signer

    # Tampering with the payload breaks the EIP-712 binding.
    tampered = json.loads(json.dumps(row.payload))
    tampered["payment"]["amount_usd"] = "999.00"
    assert recover_receipt_signer(tampered, row.evm_signature) != row.evm_signer

    # Tampering with the JWS fails outright.
    with pytest.raises(Exception):
        verify_receipt_jws(row.jws[:-6] + "AAAAAA", jwks["keys"][0])


@pytest.mark.asyncio
async def test_payload_shape_is_the_documented_profile(receipts) -> None:
    receipt_id = await receipts.mint(
        kind=ReceiptKind.PAYMENT,
        outcome="settled",
        resource_path="/v1/dns/lookup",
        method="POST",
        rail="x402-exact-evm",
        amount_usd=Decimal("0.001"),
        payer=PAYER,
        tx_hash="0xABC",
    )
    assert receipt_id is not None
    row = await receipts.get(receipt_id)
    assert row is not None
    assert set(row.payload) == {
        "profile",
        "receipt_id",
        "kind",
        "issuer",
        "resource",
        "payment",
        "correlation",
        "outcome",
        "timing",
        "service",
        "agent",
        "evidence",
    }
    assert row.payload["resource"]["service_group"] == "network_intel"
    assert row.payload["kind"] == "payment"


def test_canonicalization_rejects_floats() -> None:
    with pytest.raises(ValueError, match="float"):
        canonical_receipt_bytes({"amount": 0.05})


@pytest.mark.asyncio
async def test_native_rail_discloses_no_payment_details(receipts) -> None:
    """Privacy invariant: even when a caller passes address/txid for a native
    rail, neither may appear in the payload or the row — in any form."""
    receipt_id = await receipts.mint(
        kind=ReceiptKind.PAYMENT,
        outcome="settled",
        resource_path="/v1/vm/create",
        method="POST",
        rail="native-btc",
        amount_usd=Decimal("0.10"),
        payer="bc1qexampledepositaddress",
        tx_hash="f00dfeed" * 8,
        intent_id="intent-123",
    )
    assert receipt_id is not None
    row = await receipts.get(receipt_id)
    assert row is not None
    assert row.payload["payment"]["payer"] is None
    assert row.payload["payment"]["tx_ref"] is None
    assert row.payer_wallet is None
    assert row.tx_hash is None
    blob = json.dumps(row.payload)
    assert "bc1qexampledepositaddress" not in blob
    assert "f00dfeed" not in blob
    # Correlation stays possible via the unguessable intent id.
    assert row.payload["correlation"]["intent_id"] == "intent-123"


def test_key_guard_refuses_enabled_but_broken_keys() -> None:
    broken = SimpleNamespace(trust=_trust_config(receipt_signing_key_pem="", receipt_signing_key_path=""))
    with pytest.raises(RuntimeError, match="receipt signing is broken"):
        enforce_trust_key_guard(broken)

    disabled = SimpleNamespace(trust=_trust_config(receipts_enabled=False, receipt_signing_key_pem=""))
    enforce_trust_key_guard(disabled)  # must not raise

    healthy = SimpleNamespace(trust=_trust_config())
    enforce_trust_key_guard(healthy)  # must not raise


def test_jwks_serves_active_then_retired_keys(trust_config) -> None:
    keys = load_signing_keys(trust_config)
    retired = {"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB", "kid": "hyr-rcpt-old"}
    config = _trust_config(receipt_retired_jwks_json=json.dumps([retired]))
    jwks = build_jwks(keys, config)
    assert [k["kid"] for k in jwks["keys"]] == [keys.kid, "hyr-rcpt-old"]


# --- Gate integration (real PaymentGate + _FakeServer harness) ---


@pytest.mark.asyncio
async def test_settled_payment_mints_receipt_with_ledger_link(
    receipts, session_factory
) -> None:
    server = _FakeServer()
    gate = _gate(server)
    gate.ledger = PaymentLedger(session_factory)
    gate.receipts = receipts
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == PAYER  # Response|str contract unchanged
    headers = req.state.payment_response_headers
    assert headers[PAYMENT_RESPONSE_HEADER]
    receipt_id = headers[RECEIPT_HEADER]
    assert headers[LEGACY_RECEIPT_HEADER] == receipt_id

    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    row = rows[0]
    assert row.receipt_id == receipt_id
    assert row.kind == "payment"
    assert row.outcome == "settled"
    assert row.rail == "x402-exact-evm"
    assert row.payer_wallet == PAYER
    assert row.tx_hash == "0xSETTLED"
    assert row.payload["resource"]["description"] == "VM creation"

    # Soft link to the ledger event that recorded the same settlement.
    async with session_factory() as session:
        events = list((await session.execute(select(PaymentEventRow))).scalars())
    settled_events = [e for e in events if e.event_type == "settled"]
    assert len(settled_events) == 1
    assert row.payment_event_id == settled_events[0].event_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_kwargs",
    [dict(valid=False), dict(settle_success=False)],
    ids=["verify_failed", "settle_failed"],
)
async def test_failed_payment_mints_no_receipt(receipts, session_factory, server_kwargs) -> None:
    server = _FakeServer(**server_kwargs)
    gate = _gate(server)
    gate.receipts = receipts
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert await _receipt_rows(session_factory) == []


@pytest.mark.asyncio
async def test_402_challenge_mints_no_receipt(receipts, session_factory) -> None:
    gate = _gate(_FakeServer())
    gate.receipts = receipts

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert RECEIPT_HEADER not in result.headers
    assert await _receipt_rows(session_factory) == []


@pytest.mark.asyncio
async def test_dev_bypass_mints_dev_rail_receipt(receipts, session_factory) -> None:
    from hyrule_cloud.config import PaymentConfig
    from hyrule_cloud.middleware.x402 import PaymentGate

    gate = PaymentGate(
        PaymentConfig(
            receiver_address="0xFf4555af30A1066A889324a3Fe88c76796159f15",
            facilitator_url="https://facilitator.payai.network",
            dev_bypass_secret="sekrit",
        ),
        receipts=receipts,
    )
    req = _request({"X-DEV-BYPASS": "sekrit"})

    result = await gate.check_payment(req, Decimal("0.01"), "dns lookup")

    assert result == "0xDEV_TEST_WALLET"
    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    assert rows[0].rail == "dev-bypass"
    assert rows[0].tx_hash is None
    assert req.state.payment_response_headers[RECEIPT_HEADER] == rows[0].receipt_id


@pytest.mark.asyncio
async def test_two_phase_settle_verified_mints_receipt(receipts, session_factory) -> None:
    server = _FakeServer()
    gate = _gate(server)
    gate.receipts = receipts
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    verified = await gate.verify_only(req, Decimal("0.01"), "proxy request")
    assert not isinstance(verified, Response)
    # Nothing minted before delivery+settlement.
    assert await _receipt_rows(session_factory) == []

    assert await gate.settle_verified(req, verified) is True
    rows = await _receipt_rows(session_factory)
    assert len(rows) == 1
    assert rows[0].payload["resource"]["description"] == "proxy request"
    headers = req.state.payment_response_headers
    assert headers[RECEIPT_HEADER] == rows[0].receipt_id
    assert headers[PAYMENT_RESPONSE_HEADER]


@pytest.mark.asyncio
async def test_receipt_persist_failure_never_breaks_payment(trust_config) -> None:
    class BrokenFactory:
        def __call__(self):
            raise RuntimeError("receipts db down")

    broken = ReceiptService(
        trust_config,
        BrokenFactory(),  # type: ignore[arg-type]
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=load_signing_keys(trust_config),
    )
    server = _FakeServer()
    gate = _gate(server)
    gate.receipts = broken
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == PAYER
    assert RECEIPT_HEADER not in req.state.payment_response_headers
    assert req.state.payment_response_headers[PAYMENT_RESPONSE_HEADER]


@pytest.mark.asyncio
async def test_disabled_receipts_change_nothing(session_factory) -> None:
    disabled = ReceiptService(
        _trust_config(receipts_enabled=False),
        session_factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=None,
    )
    assert disabled.enabled is False
    assert (
        await disabled.mint(
            kind=ReceiptKind.PAYMENT,
            outcome="settled",
            resource_path="/v1/dns/lookup",
            method="POST",
            rail="x402-exact-evm",
        )
        is None
    )

    server = _FakeServer()
    gate = _gate(server)
    gate.receipts = disabled
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})
    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")
    assert result == PAYER
    assert RECEIPT_HEADER not in req.state.payment_response_headers
    assert await _receipt_rows(session_factory) == []


# --- Response-header exposure middleware ---


@pytest.mark.asyncio
async def test_receipt_header_exposed_only_when_present() -> None:
    async def with_receipt(request):
        request.state.payment_response_headers = {
            PAYMENT_RESPONSE_HEADER: "settled",
            RECEIPT_HEADER: "hyr_rcpt_x",
            LEGACY_RECEIPT_HEADER: "hyr_rcpt_x",
        }
        return Response("ok")

    async def without_receipt(request):
        request.state.payment_response_headers = {PAYMENT_RESPONSE_HEADER: "settled"}
        return Response("ok")

    req = _request()
    result = await attach_payment_response_headers(req, with_receipt)
    assert result.headers[RECEIPT_HEADER] == "hyr_rcpt_x"
    assert RECEIPT_HEADER in result.headers["Access-Control-Expose-Headers"]

    req2 = _request()
    result2 = await attach_payment_response_headers(req2, without_receipt)
    assert RECEIPT_HEADER not in result2.headers
    # Trust-disabled deployments must not even mention the header in CORS.
    assert "HYRULE-RECEIPT" not in result2.headers["Access-Control-Expose-Headers"]


# --- Public retrieval endpoints ---


@pytest.fixture
def trust_app_state(receipts):
    from hyrule_cloud.state import AppState

    og_state = getattr(app.state, "_typed_state", None)
    app_state = AppState(
        config=MockConfig(),
        orchestrator=MockOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider(),
        trust=TrustServices(receipts=receipts),
    )
    app.state._typed_state = app_state
    yield app_state
    if og_state:
        app.state._typed_state = og_state


@pytest.mark.asyncio
async def test_receipt_endpoint_serves_verifiable_receipt(trust_app_state, receipts) -> None:
    receipt_id = await receipts.mint(
        kind=ReceiptKind.PAYMENT,
        outcome="settled",
        resource_path="/v1/dns/lookup",
        method="POST",
        rail="x402-exact-evm",
        amount_usd=Decimal("0.001"),
        payer=PAYER,
        tx_hash="0xABC",
    )
    assert receipt_id is not None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(f"/v1/receipts/{receipt_id}")
        assert res.status_code == 200
        body = res.json()
        assert body["receipt_id"] == receipt_id
        assert body["jwks_url"].endswith("/.well-known/jwks.json")

        jwks_res = await client.get("/.well-known/jwks.json")
        assert jwks_res.status_code == 200
        keys = jwks_res.json()["keys"]
        assert keys, "JWKS must serve the active key"

        # End-to-end offline verification using only the two responses.
        payload = verify_receipt_jws(body["jws"], keys[0])
        assert payload == body["payload"]
        assert recover_receipt_signer(body["payload"], body["evm_signature"]) == body["evm_signer"]

        missing = await client.get("/v1/receipts/hyr_rcpt_doesnotexist000000")
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_receipt_endpoint_404s_when_trust_absent() -> None:
    from hyrule_cloud.state import AppState

    og_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=MockConfig(),
        orchestrator=MockOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider(),
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/v1/receipts/hyr_rcpt_whatever0000000000")
            assert res.status_code == 404
            jwks_res = await client.get("/.well-known/jwks.json")
            assert jwks_res.status_code == 200
            assert jwks_res.json() == {"keys": []}
    finally:
        if og_state:
            app.state._typed_state = og_state
