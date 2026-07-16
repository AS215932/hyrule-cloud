"""Block B: live runtime metrics endpoint + per-process p50 middleware.

Covers the contract:
  - /v1/stats/runtime returns the documented shape with `api_p50_source`
    labelling the latency number as per-worker (not fleet-wide)
  - Live/build counts come from real DB rows
  - avg_provision_seconds is computed over rows that have provisioned_at set
  - The TTL cache short-circuits repeated calls (call count stays at 1)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.middleware.metrics import MetricsRecorder
from hyrule_cloud.models import VMSize, VMStatus, generate_vm_id


def _now() -> datetime:
    return datetime.now(UTC)


class _MockPaymentConfig:
    price_vm_xs = Decimal("0.05")
    price_vm_sm = Decimal("0.10")
    price_vm_md = Decimal("0.20")
    price_vm_lg = Decimal("0.40")
    price_domain_markup = Decimal("1.00")
    price_proxy_direct = Decimal("0.01")
    price_proxy_tor = Decimal("0.05")
    price_proxy_i2p = Decimal("0.05")
    price_proxy_yggdrasil = Decimal("0.03")
    dev_bypass_secret = ""


class _MockXCPNG:
    templates = {"debian-13": "uuid-debian-13"}


class _MockConfig:
    payment = _MockPaymentConfig()
    xcpng = _MockXCPNG()
    deploy_domain = "deploy.hyrule.host"
    blocked_ports = [25]


class _StubOrchestrator:
    def __init__(self, session_factory):
        self.db = session_factory


@pytest_asyncio.fixture
async def metrics_state():
    """In-process SQLite + fresh state. Also resets the in-process runtime
    cache so cache-hit/miss tests stay deterministic between runs."""
    from hyrule_cloud.api.routes import _RUNTIME_CACHE
    from hyrule_cloud.state import AppState

    _RUNTIME_CACHE.clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    orch = _StubOrchestrator(factory)
    state = AppState(
        config=_MockConfig(),
        orchestrator=orch,
        payment_gate=None,
        network_provider=None,
    )

    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    # The middleware was installed at module-load time, but we want a fresh
    # recorder so prior tests don't bleed samples into this one.
    app.state.metrics = MetricsRecorder(window=1000)
    try:
        yield state, factory
    finally:
        _RUNTIME_CACHE.clear()
        if prev is not None:
            app.state._typed_state = prev
        await engine.dispose()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        yield c


def _make_vm(
    status: VMStatus,
    created_at: datetime | None = None,
    provisioned_at: datetime | None = None,
    provision_started_at: datetime | None = None,
) -> VMRow:
    return VMRow(
        vm_id=generate_vm_id(),
        owner_wallet="0xtest",
        status=status,
        size=VMSize.XS,
        os="debian-13",
        ssh_pubkey="ssh-ed25519 AAAA",
        open_ports=[22],
        expires_at=_now() + timedelta(days=7),
        cost_total=Decimal("0.35"),
        created_at=created_at or _now(),
        provision_started_at=provision_started_at,
        provisioned_at=provisioned_at,
    )


# --- middleware ---


def test_metrics_recorder_p50_smoke():
    r = MetricsRecorder(window=100)
    for v in (10, 20, 30, 40, 50):
        r.record(v)
    assert r.percentile(0.5) == 30
    assert r.sample_count() == 5


def test_metrics_recorder_empty_returns_none():
    r = MetricsRecorder()
    assert r.percentile() is None
    assert r.sample_count() == 0


def test_metrics_recorder_bounded_window():
    r = MetricsRecorder(window=3)
    for v in (1.0, 2.0, 3.0, 4.0):
        r.record(v)
    # Only the last 3 are retained
    assert r.sample_count() == 3
    assert r.percentile(0.5) == 3


@pytest.mark.asyncio
async def test_middleware_records_request_latency(metrics_state, client):
    """A request through the app should leave a sample in the recorder."""
    # /v1/pricing is cheap, on the router, and skips the payment-networks
    # dependency our minimal mock config doesn't satisfy.
    res = await client.get("/v1/pricing")
    assert res.status_code == 200
    assert app.state.metrics.sample_count() >= 1


@pytest.mark.asyncio
async def test_middleware_skips_runtime_endpoint_itself(metrics_state, client):
    """The runtime endpoint must NOT record its own latency, else it would
    skew the very number it publishes."""
    await client.get("/v1/stats/runtime")
    # Sample count is whatever the request stamped from other middleware/
    # downstream, but it must NOT include the runtime endpoint hit.
    # Re-call and check the count doesn't go up by 1 per call.
    before = app.state.metrics.sample_count()
    for _ in range(3):
        await client.get("/v1/stats/runtime")
    after = app.state.metrics.sample_count()
    assert after == before


# --- /v1/stats/runtime ---


@pytest.mark.asyncio
async def test_runtime_endpoint_shape(metrics_state, client):
    res = await client.get("/v1/stats/runtime")
    assert res.status_code == 200
    body = res.json()
    assert set(body.keys()) >= {
        "api_p50_ms",
        "api_p50_source",
        "build_queue",
        "live_vms",
        "avg_provision_seconds",
        "updated_at",
    }
    assert body["api_p50_source"] == "api-process-local-rolling-window"


@pytest.mark.asyncio
async def test_runtime_counts_live_and_build_queue(metrics_state, client):
    _state, factory = metrics_state
    async with factory() as session:
        # 2 PROVISIONING, 3 READY, 1 DESTROYED (excluded from live)
        for _ in range(2):
            session.add(_make_vm(VMStatus.PROVISIONING))
        for _ in range(3):
            session.add(_make_vm(VMStatus.READY))
        session.add(_make_vm(VMStatus.DESTROYED))
        session.add(_make_vm(VMStatus.FAILED))
        await session.commit()

    res = await client.get("/v1/stats/runtime")
    body = res.json()
    assert body["build_queue"] == 2
    assert body["live_vms"] == 5  # 2 provisioning + 3 ready


@pytest.mark.asyncio
async def test_runtime_avg_provision_seconds(metrics_state, client):
    """Issue #51: the metric is the median of (provisioned_at -
    provision_started_at) — the actual provisioning window."""
    _state, factory = metrics_state
    now = _now()
    async with factory() as session:
        session.add(_make_vm(
            VMStatus.READY,
            provision_started_at=now - timedelta(seconds=60),
            provisioned_at=now,
        ))
        session.add(_make_vm(
            VMStatus.READY,
            provision_started_at=now - timedelta(seconds=120),
            provisioned_at=now,
        ))
        # READY but no provisioned_at — must be excluded
        session.add(_make_vm(VMStatus.READY, created_at=now - timedelta(hours=1)))
        await session.commit()

    res = await client.get("/v1/stats/runtime")
    body = res.json()
    # median(60, 120) = 90
    assert body["avg_provision_seconds"] == 90


@pytest.mark.asyncio
async def test_runtime_avg_ignores_payment_wait_time(metrics_state, client):
    """Issue #51 regression: a crypto-intent VM whose row sat for hours in
    WAITING_PAYMENT must contribute only its real provision window. The old
    (provisioned_at - created_at) formula reported 4720.3s in prod."""
    _state, factory = metrics_state
    now = _now()
    async with factory() as session:
        session.add(_make_vm(
            VMStatus.READY,
            created_at=now - timedelta(hours=2),  # row born at intent time
            provision_started_at=now - timedelta(seconds=45),  # deposit confirmed
            provisioned_at=now,
        ))
        await session.commit()

    res = await client.get("/v1/stats/runtime")
    body = res.json()
    assert body["avg_provision_seconds"] == 45


@pytest.mark.asyncio
async def test_runtime_avg_is_median_not_mean(metrics_state, client):
    """A single anomalous row (stuck build that eventually recovered) must
    not swing the advertised number — median, not mean."""
    _state, factory = metrics_state
    now = _now()
    async with factory() as session:
        for secs in (10, 20, 5000):
            session.add(_make_vm(
                VMStatus.READY,
                provision_started_at=now - timedelta(seconds=secs),
                provisioned_at=now,
            ))
        await session.commit()

    res = await client.get("/v1/stats/runtime")
    body = res.json()
    # mean would be 1676.7; the median holds at 20.
    assert body["avg_provision_seconds"] == 20


@pytest.mark.asyncio
async def test_provision_vm_stamps_provision_started_at(metrics_state):
    """Issue #51 end-to-end: _provision_vm (simulation path, the test
    default) stamps provision_started_at when the background task begins,
    independent of how old the row is."""
    from hyrule_cloud.config import HyruleConfig
    from hyrule_cloud.orchestrator import Orchestrator

    _state, factory = metrics_state
    orch = Orchestrator(HyruleConfig(), factory)

    async with factory() as session:
        row = _make_vm(VMStatus.PROVISIONING, created_at=_now() - timedelta(hours=2))
        row.vm_id = "vm_stamp"
        row.ipv6_prefix_index = 7
        row.ipv6_prefix = "2a0c:b641:b51:7::/64"
        session.add(row)
        await session.commit()

    await orch._provision_vm("vm_stamp")

    async with factory() as session:
        row = await session.get(VMRow, "vm_stamp")
        assert row.provision_started_at is not None
        assert row.provisioned_at is not None
        assert row.provisioned_at >= row.provision_started_at
        # The provision window is seconds, not the 2h the row existed.
        window = (row.provisioned_at - row.provision_started_at).total_seconds()
        assert window < 60


@pytest.mark.asyncio
async def test_runtime_avg_excludes_legacy_rows_without_start_stamp(metrics_state, client):
    """Pre-014 rows have provisioned_at but no provision_started_at — they
    must not contribute (their created_at-based window is the polluted one)."""
    _state, factory = metrics_state
    now = _now()
    async with factory() as session:
        # Legacy row: provisioned long after creation, no start stamp.
        session.add(_make_vm(
            VMStatus.READY,
            created_at=now - timedelta(hours=2),
            provisioned_at=now - timedelta(hours=1),
        ))
        await session.commit()

    res = await client.get("/v1/stats/runtime")
    body = res.json()
    assert body["avg_provision_seconds"] is None


@pytest.mark.asyncio
async def test_runtime_avg_provision_seconds_null_when_no_samples(metrics_state, client):
    res = await client.get("/v1/stats/runtime")
    body = res.json()
    assert body["avg_provision_seconds"] is None


@pytest.mark.asyncio
async def test_runtime_p50_reflects_recorder_samples(metrics_state, client):
    """Seed the recorder, ensure the published p50 matches the recorder readout."""
    for v in (10, 20, 30, 40, 50):
        app.state.metrics.record(v)
    res = await client.get("/v1/stats/runtime")
    body = res.json()
    assert body["api_p50_ms"] == 30
    assert body["api_p50_sample_count"] == 5


@pytest.mark.asyncio
async def test_runtime_ttl_cache_short_circuits(metrics_state, client):
    """Two back-to-back calls should hit the cache the second time. We can't
    easily inspect cache state, but we can verify shape stays stable and the
    `updated_at` matches between calls within the TTL window."""
    res1 = await client.get("/v1/stats/runtime")
    res2 = await client.get("/v1/stats/runtime")
    assert res1.json()["updated_at"] == res2.json()["updated_at"]


@pytest.mark.asyncio
async def test_runtime_graceful_degrades_on_db_failure(metrics_state, client):
    """Per Sourcery cloud#6 review: a DB outage must NOT 500 /v1/stats/runtime.
    The handler swallows the exception, logs, and returns 200 with the
    p50/sample count from the in-process recorder and zeroed counts. Locks
    in the graceful-degradation contract so a future refactor can't silently
    drop the try/except."""
    from hyrule_cloud.api.routes import _RUNTIME_CACHE

    _RUNTIME_CACHE.clear()  # don't serve a stale happy-path payload

    state, _factory = metrics_state
    orch = state.orchestrator

    class _BadCM:
        async def __aenter__(self) -> None:
            raise RuntimeError("simulated DB outage")

        async def __aexit__(self, *_exc: object) -> None:
            return None

    original_db = orch.db
    orch.db = lambda: _BadCM()
    try:
        res = await client.get("/v1/stats/runtime")
    finally:
        orch.db = original_db
        _RUNTIME_CACHE.clear()

    assert res.status_code == 200
    body = res.json()
    assert body["live_vms"] == 0
    assert body["build_queue"] == 0
    assert body["avg_provision_seconds"] is None
    # p50 source label still set so the frontend doesn't render a lying number.
    assert body["api_p50_source"] == "api-process-local-rolling-window"
