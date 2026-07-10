"""Trust-layer identity surfaces (M3): ERC-8004 agent registration + manifest.

The hard invariant guarded here: with all TRUST_* flags off, the announced
surface — especially /.well-known/x402.json — is byte-identical to a
deployment that has never heard of the trust layer (protects the pending
launch announcement, hyrule-cloud#53).
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base
from hyrule_cloud.state import AppState
from hyrule_cloud.trust import TrustServices
from hyrule_cloud.trust.identity import (
    REGISTRATION_TYPE,
    build_agent_registration,
)
from hyrule_cloud.trust.receipts import ReceiptService, load_signing_keys
from tests.test_api import (
    MockConfig,
    MockGate,
    MockNetworkProvider,
    MockOrchestrator,
)
from tests.test_trust_receipts import _trust_config

REGISTRY_CAIP10 = "eip155:84532:0x8004A818BFB912233c491871b3d84c89A494BD9e"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _service(factory, trust_config) -> ReceiptService:
    return ReceiptService(
        trust_config,
        factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=load_signing_keys(trust_config) if trust_config.receipts_enabled else None,
    )


class _SwapState:
    """Context helper: install an AppState, restore the previous on exit."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.previous = getattr(app.state, "_typed_state", None)

    def __enter__(self) -> AppState:
        app.state._typed_state = self.state
        return self.state

    def __exit__(self, *exc: object) -> None:
        if self.previous is not None:
            app.state._typed_state = self.previous


def _app_state(config, trust: TrustServices | None) -> AppState:
    return AppState(
        config=config,
        orchestrator=MockOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider(),
        trust=trust,
    )


# --- Registration document ---


def test_registration_document_matches_pinned_spec(session_factory) -> None:
    config = _trust_config(agent_card_enabled=True)
    doc = build_agent_registration(
        config,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0",
        keys=load_signing_keys(config),
    )
    # Required fields per the pinned draft (2026-07-10).
    assert doc["type"] == REGISTRATION_TYPE
    assert doc["name"] == "Hyrule Cloud Provisioning Agent"
    assert doc["description"]
    assert doc["image"].startswith("https://cloud.hyrule.host/")
    service_names = {s["name"] for s in doc["services"]}
    assert {"web", "OpenAPI", "x402", "receipts", "jwks"} <= service_names
    assert doc["x402Support"] is True
    assert doc["active"] is True
    # No on-chain registration configured yet → no registrations entry, and
    # no supportedTrust until a trust model is actually implemented (M9).
    assert "registrations" not in doc
    assert "supportedTrust" not in doc
    # Receipts are live → verification pointers included.
    assert doc["receipts"]["receiptSigners"]


def test_registration_document_includes_onchain_registration() -> None:
    config = _trust_config(
        agent_card_enabled=True,
        erc8004_registry_caip10=REGISTRY_CAIP10,
        erc8004_agent_id=42,
    )
    doc = build_agent_registration(
        config,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0",
        keys=None,
    )
    assert doc["registrations"] == [
        {"agentId": 42, "agentRegistry": REGISTRY_CAIP10}
    ]


@pytest.mark.asyncio
async def test_registration_endpoint_is_flag_gated(session_factory) -> None:
    disabled = _service(session_factory, _trust_config(agent_card_enabled=False))
    with _SwapState(_app_state(MockConfig(), TrustServices(receipts=disabled))):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.get("/.well-known/agent-registration.json")
            assert res.status_code == 404

    enabled = _service(
        session_factory,
        _trust_config(
            agent_card_enabled=True,
            erc8004_registry_caip10=REGISTRY_CAIP10,
            erc8004_agent_id=7,
        ),
    )
    with _SwapState(_app_state(MockConfig(), TrustServices(receipts=enabled))):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.get("/.well-known/agent-registration.json")
            assert res.status_code == 200
            doc = res.json()
            assert doc["type"] == REGISTRATION_TYPE
            assert doc["registrations"][0]["agentId"] == 7


# --- Manifest guard ---


@pytest.mark.asyncio
async def test_manifest_byte_identical_when_trust_flags_off(session_factory) -> None:
    """A trust-layer-aware deployment with all flags off must serve the exact
    manifest a pre-trust deployment served."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        # Pre-trust world: config has no `trust` attribute, no trust services.
        with _SwapState(_app_state(MockConfig(), None)):
            before = (await client.get("/.well-known/x402.json")).content
        # Trust-aware world, every flag off.
        config = MockConfig()
        config.trust = _trust_config(receipts_enabled=False, agent_card_enabled=False)
        disabled = _service(session_factory, config.trust)
        with _SwapState(_app_state(config, TrustServices(receipts=disabled))):
            after = (await client.get("/.well-known/x402.json")).content

    assert before == after
    assert b'"identity"' not in after
    assert b'"receipts"' not in after


@pytest.mark.asyncio
async def test_manifest_gains_trust_blocks_when_enabled(session_factory) -> None:
    config = MockConfig()
    config.public_base_url = "https://cloud.hyrule.host"
    config.trust = _trust_config(
        agent_card_enabled=True,
        erc8004_registry_caip10=REGISTRY_CAIP10,
        erc8004_agent_id=42,
    )
    service = _service(session_factory, config.trust)
    with _SwapState(_app_state(config, TrustServices(receipts=service))):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            manifest = (await client.get("/.well-known/x402.json")).json()

    receipts_block = manifest["receipts"]
    assert receipts_block["profile"] == "x402-compute-fulfillment-receipt/0.1"
    assert receipts_block["header"] == "HYRULE-RECEIPT"
    assert receipts_block["jwks"] == "https://cloud.hyrule.host/.well-known/jwks.json"
    assert service.keys is not None
    assert receipts_block["receiptSigners"] == [service.keys.evm_signer]
    identity = manifest["identity"]
    assert identity["agentRegistration"].endswith("/.well-known/agent-registration.json")
    assert identity["registrations"] == [{"agentId": 42, "agentRegistry": REGISTRY_CAIP10}]
