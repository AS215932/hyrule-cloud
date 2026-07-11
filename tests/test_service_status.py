"""Public /v1/status contract and monitoring-data disclosure boundary."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import pytest_asyncio
import respx
from httpx import ASGITransport, AsyncClient, Response

from hyrule_cloud.app import app
from hyrule_cloud.state import AppState


def _prometheus(alerts: list[dict]) -> dict:
    return {"status": "success", "data": {"alerts": alerts}}


def _alert(
    *,
    name: str = "HyrulePublicApiUnavailable",
    state: str = "outage",
    components: str = "api_checkout,intelligence",
    firing: str = "firing",
    public: str = "true",
) -> dict:
    return {
        "labels": {
            "alertname": name,
            "instance": "[2a0c:b641:b50:2::20]:8402",
            "public_status": public,
            "public_state": state,
            "public_components": components,
        },
        "annotations": {
            "summary": "internal summary naming api-01.servify.network",
            "description": "internal runbook and secret topology details",
            "public_title": "Cloud API unavailable",
            "public_message": "Purchasing and API-backed services are currently unavailable.",
        },
        "state": firing,
        "activeAt": "2026-07-11T12:00:00Z",
        "value": "1e+00",
    }


@pytest_asyncio.fixture
async def status_state():
    from hyrule_cloud.api.status import _STATUS_CACHE

    _STATUS_CACHE.update(value=None, expires_at=0.0, successful_at=0.0)
    previous = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=SimpleNamespace(prometheus_url="http://prom.test:9090"),
        orchestrator=None,
        payment_gate=None,
        network_provider=None,
    )
    try:
        yield
    finally:
        _STATUS_CACHE.update(value=None, expires_at=0.0, successful_at=0.0)
        if previous is None:
            delattr(app.state, "_typed_state")
        else:
            app.state._typed_state = previous


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as value:
        yield value


@pytest.mark.asyncio
@respx.mock
async def test_no_public_alerts_is_operational(status_state, client):
    respx.get("http://prom.test:9090/api/v1/alerts").mock(
        return_value=Response(200, json=_prometheus([]))
    )

    response = await client.get("/v1/status")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "operational"
    assert body["stale"] is False
    assert [component["id"] for component in body["components"]] == [
        "api_checkout",
        "compute",
        "intelligence",
        "domains_dns",
        "network_proxy",
    ]
    assert {component["status"] for component in body["components"]} == {"operational"}
    assert body["incidents"] == []


@pytest.mark.asyncio
@respx.mock
async def test_only_explicit_firing_public_alerts_cross_boundary(status_state, client):
    alerts = [
        _alert(),
        _alert(name="Pending", firing="pending"),
        _alert(name="Internal", public="false"),
        _alert(name="BadState", state="critical"),
        _alert(name="UnknownComponent", components="private_database"),
    ]
    respx.get("http://prom.test:9090/api/v1/alerts").mock(
        return_value=Response(200, json=_prometheus(alerts))
    )

    response = await client.get("/v1/status")

    body = response.json()
    assert body["status"] == "outage"
    assert len(body["incidents"]) == 1
    incident = body["incidents"][0]
    assert incident["id"].startswith("inc_")
    assert incident["component_ids"] == ["api_checkout", "intelligence"]
    assert incident["title"] == "Cloud API unavailable"
    serialized = response.text
    assert "2a0c:b641" not in serialized
    assert "servify.network" not in serialized
    assert "runbook" not in serialized
    statuses = {component["id"]: component["status"] for component in body["components"]}
    assert statuses["api_checkout"] == "outage"
    assert statuses["intelligence"] == "outage"
    assert statuses["compute"] == "operational"


@pytest.mark.asyncio
@respx.mock
async def test_highest_incident_state_wins_per_component(status_state, client):
    alerts = [
        _alert(name="Routing", state="degraded", components="compute,network_proxy"),
        _alert(name="Proxy", state="outage", components="network_proxy"),
    ]
    respx.get("http://prom.test:9090/api/v1/alerts").mock(
        return_value=Response(200, json=_prometheus(alerts))
    )

    body = (await client.get("/v1/status")).json()

    components = {component["id"]: component for component in body["components"]}
    assert body["status"] == "outage"
    assert components["compute"]["status"] == "degraded"
    assert components["network_proxy"]["status"] == "outage"


@pytest.mark.asyncio
@respx.mock
async def test_recent_success_is_returned_stale_on_prometheus_failure(status_state, client):
    from hyrule_cloud.api.status import _STATUS_CACHE

    route = respx.get("http://prom.test:9090/api/v1/alerts")
    route.side_effect = [
        Response(200, json=_prometheus([_alert(state="degraded")])),
        Response(503, text="unavailable"),
    ]
    first = await client.get("/v1/status")
    _STATUS_CACHE["expires_at"] = 0.0

    second = await client.get("/v1/status")

    assert second.status_code == 200
    assert second.json()["status"] == "degraded"
    assert second.json()["stale"] is True
    assert second.json()["checked_at"] == first.json()["checked_at"]


@pytest.mark.asyncio
@respx.mock
async def test_old_or_missing_snapshot_becomes_unknown(status_state, client):
    from hyrule_cloud.api.status import _STATUS_CACHE

    respx.get("http://prom.test:9090/api/v1/alerts").mock(
        return_value=Response(503, text="unavailable")
    )
    _STATUS_CACHE["successful_at"] = 1.0

    body = (await client.get("/v1/status")).json()

    assert body["status"] == "unknown"
    assert body["stale"] is True
    assert {component["status"] for component in body["components"]} == {"unknown"}


@pytest.mark.asyncio
@respx.mock
async def test_prometheus_failure_is_cached_briefly(status_state, client):
    route = respx.get("http://prom.test:9090/api/v1/alerts").mock(
        return_value=Response(503, text="unavailable")
    )

    first = await client.get("/v1/status")
    second = await client.get("/v1/status")

    assert first.json()["status"] == "unknown"
    assert second.json()["status"] == "unknown"
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_status_cache_avoids_repeated_prometheus_requests(status_state, client):
    route = respx.get("http://prom.test:9090/api/v1/alerts").mock(
        return_value=Response(200, json=_prometheus([]))
    )

    await client.get("/v1/status")
    await client.get("/v1/status")

    assert route.call_count == 1
