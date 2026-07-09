"""Block E: native crypto intent engine.

Covers:
  - LENIENT off-amount policy (overpay → SETTLED; underpay → REFUND_MANUAL;
    late-paid → re-quote then SETTLED if within slippage)
  - client_order_id idempotency (no second deposit address on replay)
  - Atomic exactly-once provisioning trigger
  - One-shot anon-token reveal on first PROVISIONED GET, NULL'd on second
  - Esplora fallback path (mempool.space fails → blockstream.info)
  - QR URI builder shapes (bitcoin:... / monero:...)
  - Rate provider primary+fallback contract
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, CryptoIntentRow, VMRow
from hyrule_cloud.models import (
    CryptoIntentStatus,
    VMSize,
    VMStatus,
)
from hyrule_cloud.providers.native_crypto import (
    AddressScanResult,
    NativeCryptoProvider,
)
from hyrule_cloud.services.intents import (
    LATE_PAID_SLIPPAGE,
    IntentExistsError,
    create_intent,
    poll_one_intent,
)


def _now() -> datetime:
    return datetime.now(UTC)


# --- Fixtures ---


class _StubRateProvider:
    """Returns a stable rate; callers can mutate `usd_per` mid-test."""

    def __init__(self, usd_per: Decimal | None = None) -> None:
        self.usd_per: dict[str, Decimal] = {
            "BTC": usd_per or Decimal("65000.00"),
            "XMR": usd_per or Decimal("160.00"),
        }

    async def get_usd_per(self, asset: str) -> Decimal:
        return self.usd_per[asset.upper()]

    async def start(self) -> None: ...
    async def close(self) -> None: ...


class _StubNativeProvider:
    """Lets tests precisely control derive/create + scan results."""

    def __init__(self) -> None:
        self.next_btc_addr_per_index: dict[int, str] = {}
        self.next_xmr_addr_per_index: list[tuple[str, int]] = []
        self.scan_results: dict[str, AddressScanResult] = {}

    def derive_btc_address(self, bip32_index: int) -> str:
        return self.next_btc_addr_per_index.get(bip32_index, f"bc1qbtc{bip32_index:04d}")

    async def create_xmr_subaddress(self, label: str | None = None) -> tuple[str, int]:
        if self.next_xmr_addr_per_index:
            return self.next_xmr_addr_per_index.pop(0)
        return ("4Ahyr_subaddress_default", 1)

    async def scan_btc_address(self, address: str) -> AddressScanResult:
        return self.scan_results.get(
            address, AddressScanResult(address=address, received_total=Decimal("0"), confirmations=0)
        )

    async def scan_xmr_subaddress(self, subaddr_index: int) -> AddressScanResult:
        return self.scan_results.get(
            f"xmr:{subaddr_index}",
            AddressScanResult(address="", received_total=Decimal("0"), confirmations=0),
        )


class _StubOrchestrator:
    """Owns the session factory and provides the create_vm contract intent service expects."""

    def __init__(self, session_factory: async_sessionmaker) -> None:
        self.db = session_factory
        self.created_vms: list[tuple[str, str | None]] = []
        self.provisioning_started: list[str] = []
        self.native_refunds: list[str] = []

    def compute_price(self, request):
        # 0.05/day * 1 day = 0.05 for xs
        return Decimal("0.05") * request.duration_days, None

    def start_provisioning(self, vm_id: str) -> None:
        self.provisioning_started.append(vm_id)

    async def record_native_intent_refund(self, intent_id, *, reason, vm_id=None):
        self.native_refunds.append(intent_id)
        async with self.db() as db:
            intent = await db.get(CryptoIntentRow, intent_id)
            if intent is not None:
                intent.status = CryptoIntentStatus.REFUND_MANUAL
                await db.commit()
        return True

    async def create_vm(
        self,
        request,
        owner_wallet: str,
        owner_account_id: str | None = None,
        start_provisioning: bool = True,
    ):
        from hyrule_cloud.middleware.anon_token import hash_anon_token
        from hyrule_cloud.models import (
            generate_anon_management_token,
            generate_vm_id,
        )
        vm_id = generate_vm_id()
        anon_token = generate_anon_management_token()
        anon_hash = hash_anon_token(anon_token)
        async with self.db() as session:
            row = VMRow(
                vm_id=vm_id,
                owner_wallet=owner_wallet,
                owner_account_id=owner_account_id,
                anon_management_token_hash=anon_hash,
                status=VMStatus.PROVISIONING,
                size=VMSize.XS,
                os=request.os,
                ssh_pubkey=request.ssh_pubkey,
                open_ports=[22, 80, 443],
                expires_at=_now() + timedelta(days=request.duration_days),
                cost_total=Decimal("0.05"),
            )
            session.add(row)
            await session.commit()
            # Skip refresh() — SQLite with concurrent sessions sometimes raises
            # InvalidRequestError on refresh after commit. For the stub we just
            # need a row in DB; the orchestrator's return path doesn't depend
            # on server-defaults beyond what we already populated above.
        self.created_vms.append((vm_id, owner_account_id))
        return row, anon_token


def _vm_create_request():
    from hyrule_cloud.models import DomainMode, VMCreateRequest, VMSize
    return VMCreateRequest(
        duration_days=1,
        size=VMSize.XS,
        os="debian-13",
        ssh_pubkey="ssh-ed25519 AAAA...",
        domain_mode=DomainMode.AUTO,
        domain=None,
        open_ports=[80, 443],
        setup_script=None,
    )


@pytest_asyncio.fixture
async def intent_state(tmp_path):
    """In-process SQLite + stub providers wired into AppState.

    File-backed rather than :memory:: the aiosqlite :memory: dialect shares a
    single connection (StaticPool), so the concurrent-poll tests randomly hit
    "cannot commit transaction - SQL statements in progress". A file DB gives
    each session its own connection, like the production Postgres pool.
    """
    from hyrule_cloud.state import AppState

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/intents.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    orch = _StubOrchestrator(factory)
    rates = _StubRateProvider()
    provider = _StubNativeProvider()

    state = AppState(
        config=type("Cfg", (), {
            "payment": type("Pay", (), {"price_vm_xs": Decimal("0.05"), "dev_bypass_secret": ""})(),
            "deploy_domain": "deploy.hyrule.host",
            "blocked_ports": [25],
        })(),
        orchestrator=orch,
        payment_gate=AsyncMock(),
        network_provider=None,
        native_crypto=provider,
        rate_provider=rates,
        native_payment_assets=["BTC", "XMR"],
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev
        await engine.dispose()


# --- create_intent: idempotency + address allocation ---


@pytest.mark.asyncio
async def test_create_intent_btc_allocates_bip32_index_and_address(intent_state):
    intent_state.native_crypto.next_btc_addr_per_index = {1: "bc1qfirst", 2: "bc1qsecond"}
    row1 = await create_intent(
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        asset="BTC",
        order_payload=_vm_create_request(),
        amount_usd=Decimal("0.05"),
        client_order_id=None,
        owner_account_id=None,
    )
    assert row1.asset == "BTC"
    assert row1.bip32_index == 1
    assert row1.address == "bc1qfirst"
    assert row1.status == CryptoIntentStatus.CREATED
    # Amount: 0.05 / 65000 = ~7.69e-7 BTC
    assert row1.amount_crypto > 0
    assert row1.amount_crypto < Decimal("0.00001")
    assert row1.rate_snapshot == Decimal("65000.00")

    row2 = await create_intent(
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        asset="BTC",
        order_payload=_vm_create_request(),
        amount_usd=Decimal("0.05"),
        client_order_id=None,
        owner_account_id=None,
    )
    assert row2.bip32_index == 2  # second intent gets the next index
    assert row2.address == "bc1qsecond"


@pytest.mark.asyncio
async def test_create_intent_idempotency_returns_existing(intent_state):
    intent_state.native_crypto.next_btc_addr_per_index = {1: "bc1qonly"}
    first = await create_intent(
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        asset="BTC",
        order_payload=_vm_create_request(),
        amount_usd=Decimal("0.05"),
        client_order_id="order-abc",
        owner_account_id=None,
    )
    with pytest.raises(IntentExistsError) as excinfo:
        await create_intent(
            session_factory=intent_state.orchestrator.db,
            provider=intent_state.native_crypto,
            rates=intent_state.rate_provider,
            asset="BTC",
            order_payload=_vm_create_request(),
            amount_usd=Decimal("0.05"),
            client_order_id="order-abc",
            owner_account_id=None,
        )
    assert excinfo.value.existing.intent_id == first.intent_id


@pytest.mark.asyncio
async def test_create_intent_xmr_allocates_subaddress(intent_state):
    intent_state.native_crypto.next_xmr_addr_per_index = [("4AhyrSubaddr", 7)]
    row = await create_intent(
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        asset="XMR",
        order_payload=_vm_create_request(),
        amount_usd=Decimal("0.05"),
        client_order_id=None,
        owner_account_id=None,
    )
    assert row.asset == "XMR"
    assert row.address == "4AhyrSubaddr"
    assert row.xmr_subaddr_index == 7
    assert row.bip32_index is None


# --- poll_one_intent: LENIENT policy table ---


async def _seed_intent(
    state, asset: str = "BTC", amount_crypto: Decimal | None = None, amount_usd: Decimal | None = None,
    rate_valid_until: datetime | None = None,
):
    intent_state_provider = state.native_crypto
    if asset == "BTC":
        intent_state_provider.next_btc_addr_per_index = {1: "bc1qtest"}
    else:
        intent_state_provider.next_xmr_addr_per_index = [("4Atest", 1)]
    row = await create_intent(
        session_factory=state.orchestrator.db,
        provider=intent_state_provider,
        rates=state.rate_provider,
        asset=asset,
        order_payload=_vm_create_request(),
        amount_usd=amount_usd or Decimal("0.05"),
        client_order_id=None,
        owner_account_id=None,
    )
    if rate_valid_until is not None:
        async with state.orchestrator.db() as db:
            r = await db.get(CryptoIntentRow, row.intent_id)
            r.rate_valid_until = rate_valid_until
            await db.commit()
            await db.refresh(r)
            row = r
    return row


@pytest.mark.asyncio
async def test_poll_overpay_settles_and_provisions(intent_state):
    """LENIENT: receiving MORE than quote still settles and provisions."""
    row = await _seed_intent(intent_state, asset="BTC")
    overpay = row.amount_crypto * Decimal("1.20")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=overpay, confirmations=2
    )

    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.PROVISIONED
    # Compare at DB precision (Numeric(24,12)) — raw multiplication carries
    # extra trailing digits that the DB truncates on persistence.
    assert updated.amount_received_crypto.quantize(Decimal("0.000000000001")) == overpay.quantize(
        Decimal("0.000000000001")
    )
    assert updated.vm_id is not None
    assert updated.anon_token_cleartext is not None


@pytest.mark.asyncio
async def test_xmr_intent_provisions_with_bounded_owner_wallet(intent_state):
    """XMR subaddresses (~95 chars) must not be written to VMRow.owner_wallet
    (String(64)) — in Postgres the insert would fail before the intent links its
    vm_id and before any refund could be recorded. owner_wallet carries the
    bounded intent_id; the real deposit address stays on the intent."""
    long_xmr = "8" + "B" * 94  # 95 chars, exceeds owner_wallet String(64)
    intent_state.native_crypto.next_xmr_addr_per_index = [(long_xmr, 3)]
    row = await create_intent(
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        asset="XMR",
        order_payload=_vm_create_request(),
        amount_usd=Decimal("0.05"),
        client_order_id=None,
        owner_account_id=None,
    )
    assert row.address == long_xmr
    # XMR scans are keyed by subaddress index, not the address string.
    intent_state.native_crypto.scan_results[f"xmr:{row.xmr_subaddr_index}"] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto * Decimal("1.20"), confirmations=10
    )

    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.PROVISIONED
    async with intent_state.orchestrator.db() as db:
        vm = await db.get(VMRow, updated.vm_id)
    assert vm.owner_wallet == row.intent_id  # bounded reference, not the 95-char address
    assert len(vm.owner_wallet) <= 64


@pytest.mark.asyncio
async def test_poll_underpay_flips_to_refund_manual(intent_state):
    """LENIENT: paying less than quote requires operator action."""
    row = await _seed_intent(intent_state, asset="BTC")
    underpay = row.amount_crypto * Decimal("0.90")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=underpay, confirmations=2
    )

    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.REFUND_MANUAL
    assert updated.vm_id is None
    assert intent_state.orchestrator.created_vms == []


@pytest.mark.asyncio
async def test_poll_no_payment_yet_stays_waiting(intent_state):
    row = await _seed_intent(intent_state, asset="BTC")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=Decimal("0"), confirmations=0
    )
    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.WAITING_PAYMENT


@pytest.mark.asyncio
async def test_poll_seen_but_unconfirmed_stays_waiting(intent_state):
    """Money on-chain but below the min-confirmations threshold → keep waiting."""
    row = await _seed_intent(intent_state, asset="BTC")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto, confirmations=0
    )
    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.WAITING_PAYMENT
    assert updated.amount_received_crypto == row.amount_crypto


@pytest.mark.asyncio
async def test_poll_late_paid_within_slippage_re_quotes_and_settles(intent_state):
    """LENIENT: paid after rate snapshot expired → re-quote; within 1% → SETTLED."""
    expired = _now() - timedelta(minutes=1)
    row = await _seed_intent(intent_state, asset="BTC", amount_usd=Decimal("1.00"), rate_valid_until=expired)
    # Rate moved by < 1% so the same crypto amount still matches a fresh quote
    intent_state.rate_provider.usd_per["BTC"] = Decimal("65500.00")
    # Customer sent the amount that matches the NEW rate (1.00 / 65500)
    fresh_amount = (Decimal("1.00") / Decimal("65500.00")).quantize(Decimal("0.000000000001"))
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=fresh_amount, confirmations=2
    )

    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.PROVISIONED
    assert updated.vm_id is not None


@pytest.mark.asyncio
async def test_poll_late_paid_outside_slippage_refund_manual(intent_state):
    expired = _now() - timedelta(minutes=1)
    row = await _seed_intent(intent_state, asset="BTC", amount_usd=Decimal("1.00"), rate_valid_until=expired)
    # Rate moved by 10% — customer sent the OLD amount but USD value drifted
    intent_state.rate_provider.usd_per["BTC"] = Decimal("72000.00")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto, confirmations=2
    )

    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.REFUND_MANUAL
    assert updated.vm_id is None


@pytest.mark.asyncio
async def test_poll_terminal_states_are_noop(intent_state):
    """PROVISIONED / REFUND_MANUAL / FAILED / EXPIRED never re-run."""
    row = await _seed_intent(intent_state)
    async with intent_state.orchestrator.db() as db:
        r = await db.get(CryptoIntentRow, row.intent_id)
        r.status = CryptoIntentStatus.PROVISIONED
        await db.commit()

    # Even with a scan that would normally trigger settlement, terminal state holds
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto * Decimal("10"), confirmations=10
    )
    updated = await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    assert updated.status == CryptoIntentStatus.PROVISIONED
    assert intent_state.orchestrator.created_vms == []


# --- Atomic provisioning trigger: exactly-once ---


@pytest.mark.asyncio
async def test_provisioning_fires_exactly_once_even_with_concurrent_polls(intent_state):
    row = await _seed_intent(intent_state, asset="BTC")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto, confirmations=2
    )
    # Two concurrent polls; only one should provision
    import asyncio as _aio
    r1, r2 = await _aio.gather(
        poll_one_intent(
            intent_id=row.intent_id,
            session_factory=intent_state.orchestrator.db,
            provider=intent_state.native_crypto,
            rates=intent_state.rate_provider,
            orch=intent_state.orchestrator,
        ),
        poll_one_intent(
            intent_id=row.intent_id,
            session_factory=intent_state.orchestrator.db,
            provider=intent_state.native_crypto,
            rates=intent_state.rate_provider,
            orch=intent_state.orchestrator,
        ),
    )
    # The critical invariant: exactly ONE VM is created, regardless of how
    # the two concurrent pollers interleave.
    assert len(intent_state.orchestrator.created_vms) == 1
    # The winner drives the intent SETTLED → PROVISIONING → PROVISIONED and is
    # guaranteed to return PROVISIONED. The loser lost the atomic UPDATE...
    # RETURNING race, so _trigger_provisioning was a no-op for it; the status it
    # returns is whatever its post-trigger re-fetch (intents.py) happened to
    # observe of the winner's in-flight transition — SETTLED (winner not yet at
    # PROVISIONING), PROVISIONING (winner mid-create_vm), or PROVISIONED (winner
    # done). All three are benign: the invariants that matter (exactly one VM,
    # winner reached PROVISIONED) already hold above. Pinning the loser to a
    # single state made this test flaky under CI scheduling.
    terminal_states = {r1.status, r2.status}
    assert CryptoIntentStatus.PROVISIONED in terminal_states
    assert terminal_states.issubset(
        {
            CryptoIntentStatus.PROVISIONED,
            CryptoIntentStatus.PROVISIONING,
            CryptoIntentStatus.SETTLED,
        }
    )


# --- HTTP endpoints: route shape + one-shot reveal ---


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        yield c


@pytest.mark.asyncio
async def test_intent_create_endpoint_returns_qr_uri(intent_state, client):
    intent_state.native_crypto.next_btc_addr_per_index = {1: "bc1qroute"}
    res = await client.post(
        "/v1/intent/create",
        json={
            "asset": "BTC",
            "order_payload": {
                "duration_days": 1,
                "size": "xs",
                "os": "debian-13",
                "ssh_pubkey": "ssh-ed25519 AAAA",
            },
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["asset"] == "BTC"
    assert body["address"] == "bc1qroute"
    assert body["status"] == "CREATED"
    assert body["qr_code_uri"].startswith("bitcoin:bc1qroute?amount=")
    # rate is stored as Numeric(20,8) so str(Decimal) carries 8 fractional digits
    assert Decimal(body["rate_snapshot"]) == Decimal("65000.00")


@pytest.mark.asyncio
async def test_intent_create_replay_returns_same_intent_id(intent_state, client):
    intent_state.native_crypto.next_btc_addr_per_index = {1: "bc1qreplay"}
    payload = {
        "asset": "BTC",
        "client_order_id": "client-xyz",
        "order_payload": {
            "duration_days": 1,
            "size": "xs",
            "os": "debian-13",
            "ssh_pubkey": "ssh-ed25519 AAAA",
        },
    }
    first = await client.post("/v1/intent/create", json=payload)
    second = await client.post("/v1/intent/create", json=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["intent_id"] == second.json()["intent_id"]


@pytest.mark.asyncio
async def test_intent_get_first_read_reveals_token_then_nulls(intent_state, client):
    """First GET after PROVISIONED includes management_token; second GET does not."""
    row = await _seed_intent(intent_state, asset="BTC")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto, confirmations=2
    )
    await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )
    first = await client.get(f"/v1/intent/{row.intent_id}")
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["status"] == "PROVISIONED"
    assert first_body["management_token"] is not None
    assert first_body["management_url"].startswith("http://localhost/v1/vm/")
    assert first_body["vm_id"] is not None

    second = await client.get(f"/v1/intent/{row.intent_id}")
    second_body = second.json()
    assert second_body["status"] == "PROVISIONED"
    assert second_body["management_token"] is None
    assert second_body["vm_id"] is not None


# --- Esplora fallback (NativeCryptoProvider unit) ---


@pytest.mark.asyncio
async def test_esplora_falls_back_to_blockstream_on_mempool_failure(monkeypatch):
    """When mempool.space returns non-200, blockstream.info is queried."""
    from hyrule_cloud.providers import native_crypto as nc

    class _FakeResp:
        def __init__(self, status: int, body=None, text: str = ""):
            self.status_code = status
            self._body = body
            self.text = text

        def json(self):
            return self._body

    calls: list[str] = []

    class _FakeClient:
        async def get(self, url):
            calls.append(url)
            if url.startswith(nc._ESPLORA_PRIMARY):
                return _FakeResp(503)
            if url.endswith("/address/bc1qtest"):
                return _FakeResp(
                    200,
                    {"chain_stats": {"funded_txo_sum": 100000}, "mempool_stats": {"funded_txo_sum": 0}},
                )
            if url.endswith("/address/bc1qtest/txs"):
                return _FakeResp(
                    200,
                    [{"txid": "abc", "status": {"confirmed": True, "block_height": 100}}],
                )
            if url.endswith("/blocks/tip/height"):
                return _FakeResp(200, text="101")
            return _FakeResp(404)

    # Patch the http client into a NativeCryptoProvider instance
    from hyrule_cloud.config import PaymentConfig
    p = NativeCryptoProvider(PaymentConfig())
    p._http = _FakeClient()  # type: ignore[assignment]
    result = await p.scan_btc_address("bc1qtest")
    assert result.received_total == Decimal("0.001")  # 100000 sats
    # Verify primary was tried first AND failed (so we hit secondary at least once)
    assert any(c.startswith(nc._ESPLORA_PRIMARY) for c in calls)
    assert any(c.startswith(nc._ESPLORA_FALLBACK) for c in calls)


# --- QR URI builder ---


def test_build_uri_btc():
    uri = NativeCryptoProvider.build_uri("BTC", "bc1qabc", Decimal("0.00001234"))
    assert uri == "bitcoin:bc1qabc?amount=0.00001234"


def test_build_uri_xmr():
    uri = NativeCryptoProvider.build_uri("XMR", "4Atest", Decimal("0.001234567890"))
    assert uri == "monero:4Atest?tx_amount=0.001234567890"


def test_build_uri_rejects_unknown_asset():
    with pytest.raises(ValueError):
        NativeCryptoProvider.build_uri("DOGE", "addr", Decimal("1"))  # type: ignore[arg-type]


# --- Slippage constant sanity ---


def test_late_paid_slippage_is_one_percent():
    """The plan locked LENIENT slippage at ±1%. Guard the constant."""
    assert LATE_PAID_SLIPPAGE == Decimal("0.01")


@pytest.mark.asyncio
async def test_get_intent_by_client_order_id_returns_existing(intent_state):
    """Replay lookup used by POST /v1/intent/create BEFORE validation/caps:
    a retry must get the original deposit address even if capacity filled up
    in between."""
    from hyrule_cloud.services.intents import get_intent_by_client_order_id

    row = await create_intent(
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        asset="BTC",
        order_payload=_vm_create_request(),
        amount_usd=Decimal("0.05"),
        client_order_id="replay-key-1",
        owner_account_id=None,
    )

    found = await get_intent_by_client_order_id(intent_state.orchestrator.db, "replay-key-1")
    assert found is not None
    assert found.intent_id == row.intent_id
    assert found.address == row.address

    missing = await get_intent_by_client_order_id(intent_state.orchestrator.db, "nope")
    assert missing is None


@pytest.mark.asyncio
async def test_native_intent_records_refund_when_create_vm_fails(intent_state, monkeypatch):
    """If create_vm raises AFTER the native funds settle (capacity exhausted, DB
    insert failure, unsupported old order), the intent service records the native
    refund — the settled customer must not be left with only a FAILED intent."""
    row = await _seed_intent(intent_state, asset="BTC")
    intent_state.native_crypto.scan_results[row.address] = AddressScanResult(
        address=row.address, received_total=row.amount_crypto * Decimal("1.20"), confirmations=2
    )

    async def _boom(*args, **kwargs):
        raise RuntimeError("capacity exhausted between settlement and create")

    monkeypatch.setattr(intent_state.orchestrator, "create_vm", _boom)

    await poll_one_intent(
        intent_id=row.intent_id,
        session_factory=intent_state.orchestrator.db,
        provider=intent_state.native_crypto,
        rates=intent_state.rate_provider,
        orch=intent_state.orchestrator,
    )

    # The refund path ran (not just a silent FAILED).
    assert intent_state.orchestrator.native_refunds == [row.intent_id]
    async with intent_state.orchestrator.db() as db:
        intent = await db.get(CryptoIntentRow, row.intent_id)
        assert intent.status == CryptoIntentStatus.REFUND_MANUAL
