"""Block H: /v1/stats/network — live fleet metrics from Prometheus on `mon`.

Covers the contract:
  - Reachable Prometheus → returns live numbers with _source="prometheus-..."
  - Unreachable Prometheus → returns the static fallback shape with
    _source="fallback", never 500
  - Empty prometheus_url → static fallback (used in CI / local dev)
  - 30s TTL cache short-circuits repeated calls
"""

from __future__ import annotations

from decimal import Decimal
from typing import ClassVar

import pytest
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient, Response

from hyrule_cloud.app import app


class _MockPaymentConfig:
    price_vm_xs = Decimal("0.05")
    price_vm_sm = Decimal("0.10")
    price_vm_md = Decimal("0.20")
    price_vm_lg = Decimal("0.40")
    price_vpn = Decimal("0.02")
    price_domain_markup = Decimal("1.00")
    price_proxy_direct = Decimal("0.01")
    price_proxy_tor = Decimal("0.05")
    price_proxy_i2p = Decimal("0.05")
    price_proxy_yggdrasil = Decimal("0.03")
    dev_bypass_secret = ""


class _MockXCPNG:
    templates: ClassVar[dict[str, str]] = {"debian-13": "uuid-debian-13"}


class _MockConfig:
    payment = _MockPaymentConfig()
    xcpng = _MockXCPNG()
    deploy_domain = "deploy.hyrule.host"
    blocked_ports: ClassVar[list[int]] = [25]
    prometheus_url = "http://prom.test:9090"


class _StubOrchestrator:
    db = None


@pytest_asyncio.fixture
async def network_state():
    """Wire the test config + reset the in-process TTL cache so cache-hit/miss
    tests stay deterministic across runs."""
    from hyrule_cloud.api.routes import _NETWORK_CACHE
    from hyrule_cloud.state import AppState

    _NETWORK_CACHE["value"] = None
    _NETWORK_CACHE["expires_at"] = 0.0

    state = AppState(
        config=_MockConfig(),
        orchestrator=_StubOrchestrator(),
        payment_gate=None,
        network_provider=None,
    )

    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        _NETWORK_CACHE["value"] = None
        _NETWORK_CACHE["expires_at"] = 0.0
        if prev is not None:
            app.state._typed_state = prev


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        yield c


def _prom_vector(value: float) -> dict:
    """Shape a Prometheus instant-query response with a single scalar sample."""
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {}, "value": [1716000000, str(value)]}],
        },
    }


def _prom_empty() -> dict:
    return {"status": "success", "data": {"resultType": "vector", "result": []}}


@pytest.mark.asyncio
@respx.mock
async def test_network_endpoint_returns_live_when_prometheus_responds(network_state, client):
    """Block H happy path: all three queries succeed → numbers + live _source."""
    route = respx.get("http://prom.test:9090/api/v1/query")
    route.side_effect = [
        Response(200, json=_prom_vector(4)),      # bgp_peer_state == 1 → 4
        Response(200, json=_prom_vector(7)),      # ipv6 prefixes → 7
        Response(200, json=_prom_vector(1284)),   # nat64 sessions → 1284
    ]
    res = await client.get("/v1/stats/network")
    assert res.status_code == 200
    body = res.json()
    assert body["bgp_peers_established"] == 4
    assert body["ipv6_prefixes_announced"] == 7
    assert body["nat64_sessions_active"] == 1284
    assert body["_source"].startswith("prometheus-")
    assert body["transit_providers"] == ["AS34872", "AS210233"]


@pytest.mark.asyncio
@respx.mock
async def test_network_endpoint_falls_through_on_prometheus_5xx(network_state, client):
    """Block H fail-soft: Prometheus down → static fallback, never 500."""
    respx.get("http://prom.test:9090/api/v1/query").mock(
        return_value=Response(503, text="upstream connection refused")
    )
    res = await client.get("/v1/stats/network")
    assert res.status_code == 200, "must never propagate a 5xx to the homepage"
    body = res.json()
    assert body["_source"] == "fallback"
    # Static fallback values still present
    assert body["ipv6_prefixes_announced"] == 3
    assert body["transit_providers"] == ["AS34872", "AS210233"]


@pytest.mark.asyncio
@respx.mock
async def test_network_endpoint_falls_through_on_network_error(network_state, client):
    """Connect-refused (unreachable host) is treated the same as a 5xx."""
    import httpx
    respx.get("http://prom.test:9090/api/v1/query").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    res = await client.get("/v1/stats/network")
    assert res.status_code == 200
    body = res.json()
    assert body["_source"] == "fallback"


@pytest.mark.asyncio
@respx.mock
async def test_network_endpoint_partial_live_per_metric(network_state, client):
    """If only some Prometheus queries return data, only those fields go live;
    the rest keep the static fallback value. _source flips to live because at
    least one metric was sourced from Prometheus."""
    route = respx.get("http://prom.test:9090/api/v1/query")
    # bgp_peer_state == 1 succeeds; both prefixes + nat64 return empty vectors
    route.side_effect = [
        Response(200, json=_prom_vector(5)),
        Response(200, json=_prom_empty()),     # 1st fallback bgp variant
        Response(200, json=_prom_empty()),     # prefixes empty
        Response(200, json=_prom_empty()),     # nat64 empty
    ]
    res = await client.get("/v1/stats/network")
    body = res.json()
    assert body["bgp_peers_established"] == 5
    assert body["ipv6_prefixes_announced"] == 3   # static fallback
    assert body["nat64_sessions_active"] is None  # static fallback (None)
    assert body["_source"].startswith("prometheus-")


@pytest.mark.asyncio
async def test_network_endpoint_static_fallback_with_empty_prometheus_url(network_state, client):
    """An empty prometheus_url disables the Prometheus path entirely — used in
    CI and local dev where there's no mon VM to scrape."""
    app.state._typed_state.config.prometheus_url = ""
    res = await client.get("/v1/stats/network")
    assert res.status_code == 200
    body = res.json()
    assert body["_source"] == "fallback"
    assert body["transit_providers"] == ["AS34872", "AS210233"]


@pytest.mark.asyncio
@respx.mock
async def test_network_endpoint_ttl_cache_short_circuits(network_state, client):
    """Two back-to-back calls within the 30s TTL share the same updated_at,
    proving the second call hit the in-process cache rather than re-querying."""
    respx.get("http://prom.test:9090/api/v1/query").mock(
        return_value=Response(200, json=_prom_vector(1))
    )
    res1 = await client.get("/v1/stats/network")
    res2 = await client.get("/v1/stats/network")
    assert res1.json()["updated_at"] == res2.json()["updated_at"]
