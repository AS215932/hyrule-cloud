"""Caller-agent binding (M7): RFC 9421 HTTP signatures → did:web.

Observe-only invariants: a verifiable signature yields a verified
AgentPrincipal recorded in ledger extras and receipts; anything broken —
bad signature, unresolvable DID, RFC1918 DID host, resolver outage —
yields an unverified/absent principal and NEVER affects the request.
"""

from __future__ import annotations

import base64
import time
from decimal import Decimal

import pytest
import pytest_asyncio
import respx
from cryptography.hazmat.primitives.asymmetric import ed25519
from httpx import ASGITransport, AsyncClient, ConnectError
from httpx import Response as HttpxResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from x402.http import PAYMENT_SIGNATURE_HEADER

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, PaymentEventRow
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.state import AppState
from hyrule_cloud.trust import TrustServices
from hyrule_cloud.trust.models import AgentPrincipal
from hyrule_cloud.trust.principal import (
    AgentPrincipalResolver,
    did_web_document_url,
)
from hyrule_cloud.trust.receipts import ReceiptService, load_signing_keys
from tests.test_api import (
    _TEST_TOKEN,
    MockConfig,
    MockGate,
    MockNetworkProvider,
)
from tests.test_payment_gate_x402 import (
    PAYER,
    _FakeServer,
    _gate,
    _payment_header,
    _request,
)
from tests.test_trust_fulfillment import _ExtendOrchestrator
from tests.test_trust_receipts import _trust_config

DID = "did:web:agent.example"
KEYID = f"{DID}#key1"
DID_DOC_URL = "https://agent.example/.well-known/did.json"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def _did_document(private_key: ed25519.Ed25519PrivateKey) -> dict:
    public = private_key.public_key().public_bytes_raw()
    return {
        "id": DID,
        "verificationMethod": [
            {
                "id": KEYID,
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public)},
            }
        ],
    }


def _sign_headers(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    method: str,
    target_uri: str,
    created: int | None = None,
    keyid: str = KEYID,
) -> dict[str, str]:
    created = created or int(time.time())
    inner = f'("@method" "@target-uri");created={created};keyid="{keyid}";alg="ed25519"'
    base = (
        f'"@method": {method.upper()}\n'
        f'"@target-uri": {target_uri}\n'
        f'"@signature-params": {inner}'
    )
    signature = private_key.sign(base.encode())
    return {
        "Signature-Input": f"sig1={inner}",
        "Signature": f"sig1=:{base64.b64encode(signature).decode()}:",
    }


def _resolver(monkeypatch=None) -> AgentPrincipalResolver:
    resolver = AgentPrincipalResolver(
        _trust_config(receipts_enabled=False, principal_mode="observe"),
        public_base_url="",
    )
    if monkeypatch is not None:
        # The SSRF pre-flight resolves real DNS; tests pin a public answer.
        monkeypatch.setattr(
            "hyrule_cloud.trust.principal.resolve_public_addresses",
            lambda host: ["203.0.113.5"],
        )
    return resolver


def test_did_web_document_urls() -> None:
    assert did_web_document_url(DID) == DID_DOC_URL
    assert (
        did_web_document_url("did:web:example.com:agents:alpha")
        == "https://example.com/agents/alpha/did.json"
    )
    assert did_web_document_url("did:web:example.com%3A8443") is None  # ports rejected
    assert did_web_document_url("did:key:z6Mk...") is None


@pytest.mark.asyncio
@respx.mock
async def test_valid_signature_yields_verified_principal(ed25519_key, monkeypatch) -> None:
    respx.get(DID_DOC_URL).mock(return_value=HttpxResponse(200, json=_did_document(ed25519_key)))
    resolver = _resolver(monkeypatch)
    req = _request(
        _sign_headers(ed25519_key, method="POST", target_uri="http://testserver/v1/vm/create")
    )

    principal = await resolver.resolve_principal(req)

    assert principal is not None
    assert principal.verified is True
    assert principal.did == DID
    assert principal.key_id == KEYID

    # Document cache: a second resolution must not refetch.
    assert respx.calls.call_count == 1
    again = await resolver.resolve_principal(req)
    assert again is not None and again.verified is True
    assert respx.calls.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_bad_signature_yields_unverified_principal(ed25519_key, monkeypatch) -> None:
    respx.get(DID_DOC_URL).mock(return_value=HttpxResponse(200, json=_did_document(ed25519_key)))
    resolver = _resolver(monkeypatch)
    headers = _sign_headers(
        ed25519_key, method="POST", target_uri="http://testserver/v1/vm/create"
    )
    other_key = ed25519.Ed25519PrivateKey.generate()
    forged = _sign_headers(
        other_key, method="POST", target_uri="http://testserver/v1/vm/create"
    )
    headers["Signature"] = forged["Signature"]

    principal = await resolver.resolve_principal(_request(headers))

    assert principal is not None
    assert principal.verified is False
    assert principal.did == DID


@pytest.mark.asyncio
async def test_private_did_host_is_refused(ed25519_key) -> None:
    """did:web:127.0.0.1 must be blocked by the SSRF guard (no patching)."""
    resolver = _resolver()  # real resolve_public_addresses
    headers = _sign_headers(
        ed25519_key,
        method="POST",
        target_uri="http://testserver/v1/vm/create",
        keyid="did:web:127.0.0.1#key1",
    )
    principal = await resolver.resolve_principal(_request(headers))
    assert principal is not None and principal.verified is False


@pytest.mark.asyncio
@respx.mock
async def test_resolver_outage_never_blocks_requests(
    ed25519_key, monkeypatch, session_factory
) -> None:
    """DID host down: the request must proceed and settle normally."""
    respx.get(DID_DOC_URL).mock(side_effect=ConnectError("down"))
    monkeypatch.setattr(
        "hyrule_cloud.trust.principal.resolve_public_addresses",
        lambda host: ["203.0.113.5"],
    )
    resolver = AgentPrincipalResolver(
        _trust_config(receipts_enabled=False, principal_mode="observe"),
        public_base_url="",
    )
    receipts = ReceiptService(
        _trust_config(receipts_enabled=False),
        session_factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=None,
    )
    state = AppState(
        config=MockConfig(),
        orchestrator=_ExtendOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider(),
        trust=TrustServices(receipts=receipts, principal=resolver),
    )
    og_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.post(
                "/v1/vm/vm_test123/extend",
                json={"days": 3},
                headers={
                    "X-Mock-Wallet": PAYER,
                    "Authorization": f"Bearer {_TEST_TOKEN}",
                    **_sign_headers(
                        ed25519_key, method="POST", target_uri="http://t/v1/vm/vm_test123/extend"
                    ),
                },
            )
    finally:
        if og_state is not None:
            app.state._typed_state = og_state
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_principal_lands_in_ledger_extra_and_receipt(session_factory) -> None:
    """A recorded principal must flow into the settled ledger event's extra
    and into the minted receipt's agent field."""
    trust_config = _trust_config()
    receipts = ReceiptService(
        trust_config,
        session_factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=load_signing_keys(trust_config),
    )
    server = _FakeServer()
    gate = _gate(server)
    gate.ledger = PaymentLedger(session_factory)
    gate.receipts = receipts
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})
    req.state.agent_principal = AgentPrincipal(did=DID, key_id=KEYID, verified=True)

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")
    assert result == PAYER

    async with session_factory() as session:
        settled = [
            e
            for e in (await session.execute(select(PaymentEventRow))).scalars()
            if e.event_type == "settled"
        ]
    assert settled[0].extra["agent"] == {"did": DID, "key_id": KEYID, "verified": True}

    from hyrule_cloud.db import FulfillmentReceiptRow

    async with session_factory() as session:
        receipt = (
            (await session.execute(select(FulfillmentReceiptRow))).scalars().one()
        )
    assert receipt.agent_did == DID
    assert receipt.payload["agent"] == {"did": DID, "key_id": KEYID, "verified": True}
