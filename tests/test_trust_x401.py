"""x401 shadow + step-up scaffolding (M5/M6).

Pinned invariants:
- mode=off is a complete no-op (zero DB writes, no route effect);
- shadow changes NOTHING about HTTP behavior — responses are identical to
  mode=off; it only logs what enforcement WOULD require;
- enforce is proof-first-then-pay: a step-up order carrying a payment
  header but no valid proof gets 401 + PROOF-REQUEST and the payment gate
  is NEVER invoked (no verify, no settle);
- proof tokens are TTL-bounded, reusable within TTL, and bound to the
  exact quote/amount/route/method they were issued for.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, X401ProofLogRow
from hyrule_cloud.state import AppState
from hyrule_cloud.trust import TrustServices
from hyrule_cloud.trust.receipts import ReceiptService
from hyrule_cloud.trust.x401 import (
    PROOF_REQUEST_HEADER,
    PROOF_RESPONSE_HEADER,
    PROOF_RESULT_HEADER,
    PolicyTier,
    X401PolicyEngine,
    X401Service,
    b64url_decode_json,
    extract_verification_token,
)
from tests.test_api import (
    _TEST_TOKEN,
    MockConfig,
    MockGate,
    MockNetworkProvider,
    MockOrchestrator,
)
from tests.test_trust_fulfillment import _ExtendOrchestrator
from tests.test_trust_receipts import _trust_config

PAYER = "0xFBD95291e4b9C901E084a8856eA184d3F7A232ed"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _x401(factory, **config_overrides) -> X401Service:
    config = _trust_config(receipts_enabled=False, **config_overrides)
    return X401Service(config, factory, public_base_url="https://cloud.hyrule.host")


def _disabled_receipts(factory) -> ReceiptService:
    return ReceiptService(
        _trust_config(receipts_enabled=False),
        factory,
        public_base_url="https://cloud.hyrule.host",
        api_version="0.1.0-test",
        keys=None,
    )


async def _log_rows(factory) -> list[X401ProofLogRow]:
    async with factory() as session:
        return list((await session.execute(select(X401ProofLogRow))).scalars())


class _SwapState:
    def __init__(self, state: AppState) -> None:
        self.state = state
        self.previous = getattr(app.state, "_typed_state", None)

    def __enter__(self) -> AppState:
        app.state._typed_state = self.state
        return self.state

    def __exit__(self, *exc: object) -> None:
        if self.previous is not None:
            app.state._typed_state = self.previous


class _Breakdown:
    def model_dump(self) -> dict:
        return {"total": "priced"}


class _CreateOrchestrator(MockOrchestrator):
    """Enough of the create path for the pre-payment x401 checks."""

    def compute_price(self, order):
        return Decimal("0.05") * order.duration_days, _Breakdown()


class _CreateAndExtendOrchestrator(_CreateOrchestrator, _ExtendOrchestrator):
    """Create pricing + extend/get_vm, for tests that drive both routes."""


def _app_state(x401: X401Service | None, factory, orchestrator=None) -> AppState:
    trust = None
    if x401 is not None:
        trust = TrustServices(receipts=_disabled_receipts(factory), x401=x401)
    return AppState(
        config=MockConfig(),
        orchestrator=orchestrator or _CreateOrchestrator(),
        payment_gate=MockGate(),
        network_provider=MockNetworkProvider(),
        trust=trust,
    )


def _order(duration_days: int = 180) -> dict:
    return {
        "duration_days": duration_days,
        "size": "xs",
        "os": "debian-13",
        "ssh_pubkey": "ssh-ed25519 AAAA...",
        "domain_mode": "auto",
        "open_ports": [80, 443],
    }


# --- Policy engine ---


def test_policy_engine_tiers() -> None:
    engine = X401PolicyEngine(_trust_config(receipts_enabled=False))

    never = engine.evaluate(
        route="/v1/dns/lookup", method="POST", amount=Decimal("0.001"), duration_days=None
    )
    assert never.tier == PolicyTier.NEVER

    small = engine.evaluate(
        route="/v1/vm/create", method="POST", amount=Decimal("0.05"), duration_days=1
    )
    assert small.tier == PolicyTier.NEVER

    long_running = engine.evaluate(
        route="/v1/vm/create", method="POST", amount=Decimal("9.00"), duration_days=180
    )
    assert long_running.tier == PolicyTier.STEP_UP
    assert long_running.reasons["duration_days"] == "180"

    expensive = engine.evaluate(
        route="/v1/vm/create", method="POST", amount=Decimal("40"), duration_days=30
    )
    assert expensive.tier == PolicyTier.STEP_UP
    assert expensive.reasons["amount_usd"] == "40"

    extend = engine.evaluate(
        route="/v1/vm/vm_abc/extend", method="POST", amount=Decimal("30"), duration_days=10
    )
    assert extend.tier == PolicyTier.STEP_UP


# --- Shadow mode ---


@pytest.mark.asyncio
async def test_mode_off_is_a_complete_noop(session_factory) -> None:
    service = _x401(session_factory, x401_mode="off")
    assert service.enabled is False
    assert service.advisory_extension() is None
    decision = await service.observe(
        route="/v1/vm/create", method="POST", amount=Decimal("40"), duration_days=180
    )
    assert decision.requires_proof  # policy still evaluates...
    assert await _log_rows(session_factory) == []  # ...but nothing is written


@pytest.mark.asyncio
async def test_shadow_logs_reasons_without_blocking(session_factory) -> None:
    service = _x401(session_factory, x401_mode="shadow")
    would = await service.observe(
        route="/v1/vm/create", method="POST", amount=Decimal("36"), duration_days=180
    )
    assert would.requires_proof
    would_not = await service.observe(
        route="/v1/vm/create", method="POST", amount=Decimal("0.05"), duration_days=1
    )
    assert not would_not.requires_proof

    rows = await _log_rows(session_factory)
    assert [r.decision for r in rows] == ["would_require", "would_not_require"]
    assert rows[0].mode == "shadow"
    assert rows[0].policy_tier == "step_up"
    assert rows[0].reasons["duration_days"] == "180"
    assert rows[0].reasons["amount_usd"] == "36"


@pytest.mark.asyncio
async def test_shadow_responses_identical_to_off(session_factory) -> None:
    """Route behavior must be byte-identical between off and shadow — for
    the unpaid 402 round-trip AND a successful paid call."""

    def _normalize(res):
        headers = {k.lower(): v for k, v in res.headers.items() if k.lower() != "date"}
        return res.status_code, headers, res.content

    results = {}
    for label, x401 in (
        ("off", None),
        ("shadow", _x401(session_factory, x401_mode="shadow")),
    ):
        with _SwapState(
            _app_state(x401, session_factory, orchestrator=_CreateAndExtendOrchestrator())
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://t"
            ) as client:
                unpaid = await client.post("/v1/vm/create", json=_order(180))
                paid = await client.post(
                    "/v1/vm/vm_test123/extend",
                    json={"days": 3},
                    headers={
                        "X-Mock-Wallet": PAYER,
                        "Authorization": f"Bearer {_TEST_TOKEN}",
                    },
                )
        results[label] = (_normalize(unpaid), _normalize(paid))

    assert results["off"] == results["shadow"]
    # ...and shadow DID observe both requests.
    rows = await _log_rows(session_factory)
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_advisory_extension_rides_the_real_gate_402(session_factory) -> None:
    from tests.test_payment_gate_x402 import _FakeServer, _gate, _request

    service = _x401(session_factory, x401_mode="shadow")
    server = _FakeServer()
    gate = _gate(server)
    gate.advertised_extensions = service.advisory_extension() or {}

    result = await gate.check_payment(_request(), Decimal("9.00"), "VM creation")
    assert result.status_code == 402
    assert server.last_extensions is not None
    assert server.last_extensions["x401"]["version"] == "0.2.0"
    assert server.last_extensions["x401"]["mode"] == "advisory"
    # Bazaar discovery still present alongside the advisory block.
    assert "bazaar" in server.last_extensions


@pytest.mark.asyncio
async def test_broken_x401_store_never_breaks_the_route(session_factory) -> None:
    class BrokenFactory:
        def __call__(self):
            raise RuntimeError("x401 store down")

    service = X401Service(
        _trust_config(receipts_enabled=False, x401_mode="shadow"),
        BrokenFactory(),  # type: ignore[arg-type]
        public_base_url="https://cloud.hyrule.host",
    )
    with _SwapState(_app_state(service, session_factory, orchestrator=_ExtendOrchestrator())):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.post(
                "/v1/vm/vm_test123/extend",
                json={"days": 3},
                headers={"X-Mock-Wallet": PAYER, "Authorization": f"Bearer {_TEST_TOKEN}"},
            )
    assert res.status_code == 200


# --- Enforce mode (ships OFF; exercised here explicitly) ---


@pytest.mark.asyncio
async def test_enforce_returns_401_before_the_gate(session_factory) -> None:
    """Proof-first-then-pay: a step-up order with a payment header but no
    proof gets 401 + PROOF-REQUEST and the gate is NEVER called."""
    service = _x401(session_factory, x401_mode="enforce")
    state = _app_state(service, session_factory)
    with _SwapState(state):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.post(
                "/v1/vm/create",
                json=_order(180),
                headers={"X-Mock-Wallet": PAYER},  # payment credential present
            )

    assert res.status_code == 401
    assert state.payment_gate.checked == 0  # never verified, never settled
    assert PROOF_REQUEST_HEADER in res.headers
    payload = b64url_decode_json(res.headers[PROOF_REQUEST_HEADER])
    assert payload is not None
    assert payload["scheme"] == "x401" and payload["version"] == "0.2.0"
    assert payload["credential_requirements"]["digital"]["requests"]
    assert payload["hyrule"]["route"] == "/v1/vm/create"
    assert res.json()["error"] == "identity_proof_required"

    rows = await _log_rows(session_factory)
    assert [r.decision for r in rows] == ["would_require", "proof_missing"]


@pytest.mark.asyncio
async def test_enforce_small_orders_pass_untouched(session_factory) -> None:
    service = _x401(session_factory, x401_mode="enforce")
    with _SwapState(_app_state(service, session_factory)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.post("/v1/vm/create", json=_order(duration_days=7))
    # Below every threshold: straight to the (mock) 402 challenge.
    assert res.status_code == 402


@pytest.mark.asyncio
async def test_proof_flow_end_to_end(session_factory) -> None:
    """PROOF-REQUEST → /v1/x401/proof → retry with PROOF-RESPONSE → the
    x401 layer is satisfied and the request reaches the payment gate."""
    service = _x401(
        session_factory, x401_mode="enforce", x401_accept_structural=True
    )
    state = _app_state(service, session_factory)
    with _SwapState(state):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            proof = await client.post(
                "/v1/x401/proof",
                json={
                    "route": "/v1/vm/create",
                    "method": "POST",
                    "quote_id": None,
                    "amount_usd": "9.00",
                    "result_artifact": {"credential_result": {"vp_token": "..."}},
                },
            )
            assert proof.status_code == 200
            body = proof.json()
            assert body["result"] == "satisfied"
            assert PROOF_RESULT_HEADER in proof.headers
            header_value = body["proof_response_header"]
            assert extract_verification_token(header_value) == body["verification_token"]

            retry = await client.post(
                "/v1/vm/create",
                json=_order(180),  # 0.05 * 180 = 9.00, matches the binding
                headers={PROOF_RESPONSE_HEADER: header_value},
            )
    # Proof accepted → past x401 → the mock gate issues its 402 challenge.
    assert retry.status_code == 402
    assert state.payment_gate.checked == 1
    rows = await _log_rows(session_factory)
    assert rows[-1].decision == "proof_valid"


@pytest.mark.asyncio
async def test_proof_bound_to_exact_amount(session_factory) -> None:
    service = _x401(
        session_factory, x401_mode="enforce", x401_accept_structural=True
    )
    with _SwapState(_app_state(service, session_factory)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            proof = await client.post(
                "/v1/x401/proof",
                json={
                    "route": "/v1/vm/create",
                    "method": "POST",
                    "amount_usd": "9.00",
                    "result_artifact": {"credential_result": {}},
                },
            )
            header_value = proof.json()["proof_response_header"]
            # Different order (duration 200 → $10.00) — binding must fail.
            retry = await client.post(
                "/v1/vm/create",
                json=_order(200),
                headers={PROOF_RESPONSE_HEADER: header_value},
            )
    assert retry.status_code == 401
    rows = await _log_rows(session_factory)
    assert rows[-1].decision == "proof_invalid"


@pytest.mark.asyncio
async def test_proof_token_ttl_and_reuse(session_factory) -> None:
    service = _x401(session_factory, x401_mode="enforce")
    token = await service.issue_proof_token(
        bound_quote_hash="h" * 64, route="/v1/vm/create", method="POST"
    )
    check = dict(bound_quote_hash="h" * 64, route="/v1/vm/create", method="POST")
    # Reusable within TTL (must survive the 402→sign→retry round-trip).
    assert await service.check_proof_token(token, **check) is True
    assert await service.check_proof_token(token, **check) is True
    # Wrong binding fails.
    assert (
        await service.check_proof_token(token, bound_quote_hash="x" * 64,
                                        route="/v1/vm/create", method="POST")
        is False
    )
    # Expired fails.
    expired_service = _x401(
        session_factory, x401_mode="enforce", x401_proof_token_ttl_seconds=0
    )
    expired = await expired_service.issue_proof_token(
        bound_quote_hash="h" * 64, route="/v1/vm/create", method="POST"
    )
    assert await expired_service.check_proof_token(expired, **check) is False


@pytest.mark.asyncio
async def test_proof_endpoint_honest_without_verifier(session_factory) -> None:
    """Without TRUST_X401_ACCEPT_STRUCTURAL (the test-only switch), the
    endpoint must refuse rather than pretend to verify."""
    service = _x401(session_factory, x401_mode="enforce")
    with _SwapState(_app_state(service, session_factory)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.post(
                "/v1/x401/proof",
                json={"result_artifact": {"credential_result": {}}},
            )
    assert res.status_code == 503
    assert PROOF_RESULT_HEADER in res.headers
    assert res.json()["error"] == "verification_unavailable_or_failed"


@pytest.mark.asyncio
async def test_proof_endpoint_404_when_off(session_factory) -> None:
    with _SwapState(_app_state(None, session_factory)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            res = await client.post(
                "/v1/x401/proof", json={"result_artifact": {"credential_result": {}}}
            )
    assert res.status_code == 404
