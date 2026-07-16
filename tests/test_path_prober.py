"""Phase 4a: real prober-backed /v1/path/* measurements.

Covers the prober client (error mapping, health cache), the diagnostics
conversion (prober outcome -> findings + source health, 100%-loss-is-a-
measurement), and the route's deliver-then-settle contract (never settle when
the prober fails to deliver).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.middleware.x402 import VerifiedPayment
from hyrule_cloud.models import (
    DiagnosticStatus,
    DiagnosticVantage,
    PathProbeKind,
    PathProbeRequest,
    PathReportRequest,
)
from hyrule_cloud.providers.prober_client import (
    ProbeOutcome,
    ProbeRejectedError,
    ProberProvider,
    ProbeUnavailableError,
    VantageOutcome,
    prober_configured,
)
from hyrule_cloud.services.path import diagnostics as pd


def _provider_with_transport(handler) -> ProberProvider:
    provider = ProberProvider(prober_url="http://prober.test", token="secret", health_ttl_seconds=30)
    provider._client = httpx.AsyncClient(
        base_url="http://prober.test",
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer secret"},
    )
    return provider


# --- prober client -----------------------------------------------------------


def test_prober_configured_prefers_singleton_then_env(monkeypatch):
    monkeypatch.delenv("HYRULE_PROBER_TOKEN", raising=False)
    assert prober_configured() is False
    monkeypatch.setenv("HYRULE_PROBER_TOKEN", "x")
    assert prober_configured() is True


def test_unconfigured_provider_is_not_configured():
    assert ProberProvider(token="").configured() is False
    assert ProberProvider(token="set").configured() is True


@pytest.mark.asyncio
async def test_probe_maps_status_to_exceptions():
    async def call(status: int):
        provider = _provider_with_transport(
            lambda req: httpx.Response(status, json={"detail": "bad target"})
        )
        try:
            await provider.probe(
                target="example.com", kind="ping", family="any", count=2, vantages=["as215932"]
            )
        finally:
            await provider.close()

    with pytest.raises(ProbeRejectedError):
        await call(400)
    for status in (429, 500, 502, 503):
        with pytest.raises(ProbeUnavailableError):
            await call(status)


@pytest.mark.asyncio
async def test_probe_unreachable_raises_unavailable():
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    provider = _provider_with_transport(handler)
    try:
        with pytest.raises(ProbeUnavailableError):
            await provider.probe(
                target="example.com", kind="ping", family="any", count=2, vantages=["as215932"]
            )
    finally:
        await provider.close()


@pytest.mark.asyncio
async def test_probe_unconfigured_never_calls_prober():
    provider = ProberProvider(token="")  # not configured
    with pytest.raises(ProbeUnavailableError):
        await provider.probe(
            target="example.com", kind="ping", family="any", count=2, vantages=["as215932"]
        )


@pytest.mark.asyncio
async def test_health_cache_parses_and_caches():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            200,
            json={
                "status": "degraded",
                "vantages": {
                    "as215932": {"ok": True},
                    "extmon": {"ok": False},
                },
            },
        )

    provider = _provider_with_transport(handler)
    try:
        first = await provider.healthy_vantage_names()
        second = await provider.healthy_vantage_names()
    finally:
        await provider.close()
    assert first == {"as215932"}
    assert second == {"as215932"}
    assert calls["n"] == 1  # TTL-cached: only one health call


@pytest.mark.asyncio
async def test_health_failure_yields_no_healthy_vantages():
    provider = _provider_with_transport(lambda req: httpx.Response(503))
    try:
        assert await provider.healthy_vantage_names() == set()
    finally:
        await provider.close()


# --- diagnostics conversion --------------------------------------------------


class _FakeProber:
    def __init__(self, *, healthy=("as215932",), outcomes=None, configured=True):
        self._healthy = set(healthy)
        self._outcomes = outcomes or {}
        self._configured = configured
        self.probe_calls: list[dict] = []

    def configured(self) -> bool:
        return self._configured

    async def healthy_vantage_names(self) -> set[str]:
        return set(self._healthy)

    async def probe(self, **kwargs) -> ProbeOutcome:
        self.probe_calls.append(kwargs)
        results = self._outcomes.get(kwargs["kind"], [])
        return ProbeOutcome(
            target=kwargs["target"],
            kind=kwargs["kind"],
            family=kwargs["family"],
            resolved_addresses=["2001:db8::1"],
            probed_address="2001:db8::1",
            results=results,
        )


def _ping_result(vantage: str, loss: float) -> VantageOutcome:
    return VantageOutcome(
        vantage=vantage,
        ok=True,
        ping={
            "packets_transmitted": 4,
            "packets_received": 4 - int(loss / 25),
            "loss_pct": loss,
            "rtt_ms": {"min": 1.0, "avg": 2.0, "max": 3.0} if loss < 100 else None,
        },
    )


def _trace_result(vantage: str, reached: bool) -> VantageOutcome:
    hops = [{"hop": 1, "raw": "2001:db8::a"}, {"hop": 2, "raw": "2001:db8::1" if reached else "*"}]
    return VantageOutcome(
        vantage=vantage,
        ok=True,
        traceroute={"hops": hops, "hop_count": len(hops), "last_hop_responded": reached},
    )


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    # The service resolves the target for its own SSRF guard; stub it so unit
    # tests never depend on live DNS. The prober itself is faked.
    monkeypatch.setattr(
        pd, "assert_safe_active_probe_target", lambda host, family=0: ["2001:db8::1"]
    )


@pytest.mark.asyncio
async def test_path_probe_converts_reachable_ping():
    prober = _FakeProber(outcomes={"ping": [_ping_result("as215932", 0.0)]})
    body = PathProbeRequest(target="example.com", probe=PathProbeKind.PING)
    resp = await pd.path_probe(body, prober)
    assert resp.status == DiagnosticStatus.OK
    assert any(f.code == "ping_reachable_as215932" for f in resp.findings)
    assert resp.sources["as215932"].status.value == "ok"
    assert prober.probe_calls[0]["kind"] == "ping"


@pytest.mark.asyncio
async def test_path_probe_100pct_loss_is_a_measurement():
    prober = _FakeProber(outcomes={"ping": [_ping_result("as215932", 100.0)]})
    body = PathProbeRequest(target="example.com", probe=PathProbeKind.PING)
    resp = await pd.path_probe(body, prober)
    # 100% loss is a real, chargeable measurement, not an error.
    assert resp.status == DiagnosticStatus.WARNING
    assert any(f.code == "ping_no_response_as215932" for f in resp.findings)
    assert resp.sources["as215932"].status.value == "ok"


@pytest.mark.asyncio
async def test_path_probe_no_healthy_vantage_raises_unavailable():
    prober = _FakeProber(healthy=(), outcomes={"ping": []})
    body = PathProbeRequest(target="example.com", probe=PathProbeKind.PING)
    with pytest.raises(ProbeUnavailableError):
        await pd.path_probe(body, prober)


@pytest.mark.asyncio
async def test_path_probe_all_vantages_error_raises_unavailable():
    # Prober answered but produced no parsed measurement (e.g. SSH failed).
    dead = VantageOutcome(vantage="as215932", ok=False, error="ssh failed")
    prober = _FakeProber(outcomes={"ping": [dead]})
    body = PathProbeRequest(target="example.com", probe=PathProbeKind.PING)
    with pytest.raises(ProbeUnavailableError):
        await pd.path_probe(body, prober)


@pytest.mark.asyncio
async def test_path_probe_none_provider_raises_unavailable():
    body = PathProbeRequest(target="example.com", probe=PathProbeKind.PING)
    with pytest.raises(ProbeUnavailableError):
        await pd.path_probe(body, None)


@pytest.mark.asyncio
async def test_path_report_classifies_from_ping_and_trace():
    prober = _FakeProber(
        outcomes={
            "ping": [_ping_result("as215932", 0.0)],
            "traceroute": [_trace_result("as215932", reached=True)],
        }
    )
    body = PathReportRequest(target="example.com", vantages=[DiagnosticVantage.AS215932])
    resp = await pd.path_report(body, prober)
    assert resp.raw["classification"] == "reachable"
    assert any(f.code == "path_classification" for f in resp.findings)
    # Control-plane checks point at the dedicated endpoints, not a placeholder.
    assert any(f.code.startswith("control_plane_available_") for f in resp.findings)
    kinds = [c["kind"] for c in prober.probe_calls]
    assert kinds == ["ping", "traceroute"]


@pytest.mark.asyncio
async def test_path_report_degraded_classification():
    prober = _FakeProber(
        outcomes={
            "ping": [_ping_result("as215932", 40.0)],
            "traceroute": [_trace_result("as215932", reached=False)],
        }
    )
    body = PathReportRequest(target="example.com", vantages=[DiagnosticVantage.AS215932])
    resp = await pd.path_report(body, prober)
    assert resp.raw["classification"] == "degraded"
    assert resp.status == DiagnosticStatus.WARNING


# --- route deliver-then-settle ----------------------------------------------


class _FakeGate:
    def __init__(self, *, verify_ok=True, settle_ok=True):
        self.verify_ok = verify_ok
        self.settle_ok = settle_ok
        self.verify_calls = 0
        self.settle_calls = 0

    async def verify_only(self, request, amount, description=""):
        self.verify_calls += 1
        if not self.verify_ok:
            from fastapi.responses import JSONResponse

            return JSONResponse(status_code=402, content={"payment_required": True})
        return VerifiedPayment(payer="0xtest", amount=Decimal(str(amount)))

    async def settle_verified(self, request, verified) -> bool:
        self.settle_calls += 1
        return self.settle_ok


def _wire_state(gate, prober):
    return SimpleNamespace(config=HyruleConfig(), payment_gate=gate, prober_provider=prober)


async def _post(json_body):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/v1/path/ping", json=json_body)


@pytest.mark.asyncio
async def test_ping_route_delivers_then_settles(monkeypatch):
    monkeypatch.setenv("HYRULE_PROBER_TOKEN", "x")  # enables the gate
    gate = _FakeGate()
    prober = _FakeProber(outcomes={"ping": [_ping_result("as215932", 0.0)]})
    old = getattr(app.state, "_typed_state", None)
    app.state._typed_state = _wire_state(gate, prober)
    try:
        res = await _post({"target": "example.com"})
    finally:
        if old is not None:
            app.state._typed_state = old
        else:
            delattr(app.state, "_typed_state")
    assert res.status_code == 200, res.text
    assert gate.verify_calls == 1
    assert gate.settle_calls == 1  # settled exactly once, after delivery
    assert any(f["code"] == "ping_reachable_as215932" for f in res.json()["findings"])


@pytest.mark.asyncio
async def test_ping_route_does_not_settle_when_prober_down(monkeypatch):
    monkeypatch.setenv("HYRULE_PROBER_TOKEN", "x")
    gate = _FakeGate()
    prober = _FakeProber(healthy=(), outcomes={"ping": []})  # no healthy vantage
    old = getattr(app.state, "_typed_state", None)
    app.state._typed_state = _wire_state(gate, prober)
    try:
        res = await _post({"target": "example.com"})
    finally:
        if old is not None:
            app.state._typed_state = old
        else:
            delattr(app.state, "_typed_state")
    assert res.status_code == 502  # undelivered
    assert gate.verify_calls == 1
    assert gate.settle_calls == 0  # never charged


@pytest.mark.asyncio
async def test_ping_route_501_before_charge_when_no_prober(monkeypatch):
    monkeypatch.delenv("HYRULE_PROBER_TOKEN", raising=False)
    gate = _FakeGate()
    prober = _FakeProber()
    old = getattr(app.state, "_typed_state", None)
    app.state._typed_state = _wire_state(gate, prober)
    try:
        res = await _post({"target": "example.com"})
    finally:
        if old is not None:
            app.state._typed_state = old
        else:
            delattr(app.state, "_typed_state")
    assert res.status_code == 501
    assert res.json()["error"] == "not_implemented"
    assert gate.verify_calls == 0  # gated before any payment step
