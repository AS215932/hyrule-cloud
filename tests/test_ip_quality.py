from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from x402.http import PAYMENT_SIGNATURE_HEADER

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, IPQualityConfig, PaymentConfig
from hyrule_cloud.models import (
    IPQualityConnection,
    IPQualityConsistency,
    IPQualityLocation,
    IPQualityNetwork,
    IPQualityRegistration,
    IPQualityRegistrationHistory,
    IPQualityRequest,
    IPQualityResponse,
    IPQualityRisk,
    IPQualityRouting,
    IPQualityRoutingHistory,
    IPQualityUsageSignals,
    IPQualityVerdict,
    IPQualityVerdictLevel,
)
from hyrule_cloud.providers.ip_quality import (
    IPQSEvidence,
    IPQualityProvider,
    IPQualityProviderError,
    MaxMindEvidence,
)
from hyrule_cloud.services.discovery import build_curated_openapi, build_x402_manifest
from hyrule_cloud.services.intel import ip_quality as quality_service
from hyrule_cloud.services.intel.ip import _parse_cymru_as_name, _parse_cymru_txt
from hyrule_cloud.services.intel.ip_quality import (
    classify_quality_verdict,
    quality_gate_status,
)
from tests.test_payment_gate_x402 import _FakeServer, _gate, _payment_header


def _quality_config(**updates: Any) -> HyruleConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "maxmind_account_id": "123456",
        "maxmind_license_key": "maxmind-secret",
        "maxmind_resale_approved": True,
        "maxmind_unit_cost_usd": Decimal("0.004"),
        "ipqs_api_key": "ipqs-secret",
        "ipqs_resale_approved": True,
        "ipqs_unit_cost_usd": Decimal("0.004"),
    }
    values.update(updates)
    return HyruleConfig(
        ip_quality=IPQualityConfig(**values),
        payment=PaymentConfig(price_ip_quality=Decimal("0.02")),
    )


def _report() -> IPQualityResponse:
    return IPQualityResponse(
        address="8.8.8.8",
        location=IPQualityLocation(country_code="US"),
        registration=IPQualityRegistration(country_code="US"),
        network=IPQualityNetwork(asn=15169),
        connection=IPQualityConnection(),
        risk=IPQualityRisk(fraud_score=5),
        usage=IPQualityUsageSignals(),
        routing=IPQualityRouting(),
        routing_history=IPQualityRoutingHistory(status="available", days_requested=90),
        registration_history=IPQualityRegistrationHistory(
            status="unsupported", days_requested=90
        ),
        consistency=IPQualityConsistency(),
        verdict=IPQualityVerdict(level=IPQualityVerdictLevel.LOW_RISK),
    )


def test_quality_gate_requires_every_contract_and_margin_guard() -> None:
    assert quality_gate_status(_quality_config()).enabled is True
    assert quality_gate_status(_quality_config(enabled=False)).reason == "operator_disabled"
    assert (
        quality_gate_status(_quality_config(maxmind_license_key="")).reason
        == "maxmind_credentials_missing"
    )
    assert (
        quality_gate_status(_quality_config(ipqs_resale_approved=False)).reason
        == "ipqs_resale_not_approved"
    )
    assert quality_gate_status(
        _quality_config(ipqs_unit_cost_usd=Decimal("0.0041"))
    ).reason == "provider_cost_exceeds_margin_guard"


def test_quality_request_rejects_non_public_addresses_and_invalid_timezones() -> None:
    with pytest.raises(ValueError, match="globally routable"):
        IPQualityRequest(address="192.168.1.1")
    with pytest.raises(ValueError, match="IANA timezone"):
        IPQualityRequest(
            address="8.8.8.8",
            client_context={"timezone": "UTC+2"},
        )


@pytest.mark.asyncio
async def test_provider_uses_header_auth_fixed_options_and_normalizes_payloads() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "geoip.maxmind.com":
            return httpx.Response(
                200,
                json={
                    "country": {"iso_code": "US", "names": {"en": "United States"}},
                    "registered_country": {
                        "iso_code": "US",
                        "names": {"en": "United States"},
                    },
                    "city": {"names": {"en": "Mountain View"}},
                    "location": {"time_zone": "America/Los_Angeles"},
                    "traits": {
                        "autonomous_system_number": 15169,
                        "autonomous_system_organization": "Google LLC",
                        "isp": "Google LLC",
                        "network": "8.8.8.0/24",
                        "user_count": 12,
                        "static_ip_score": 80.5,
                    },
                    "anonymizer": {
                        "is_anonymous": False,
                        "is_anonymous_vpn": False,
                        "is_hosting_provider": True,
                        "is_tor_exit_node": False,
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "success": True,
                "fraud_score": 7,
                "country_code": "US",
                "ASN": 15169,
                "ISP": "Google LLC",
                "organization": "Google LLC",
                "connection_type": "Data Center",
                "proxy": False,
                "vpn": False,
                "tor": False,
                "recent_abuse": False,
                "bot_status": False,
                "shared_connection": True,
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = IPQualityProvider(_quality_config().ip_quality, client=client)
    try:
        maxmind, ipqs = await provider.fetch(
            IPQualityRequest(
                address="8.8.8.8",
                client_context={
                    "user_agent": "Example Browser",
                    "accept_language": "en-US",
                    "timezone": "America/Los_Angeles",
                },
            )
        )
    finally:
        await client.aclose()

    assert maxmind.network.asn == 15169
    assert maxmind.connection.hosting_provider is True
    assert maxmind.usage.estimated_users_24h == 12
    assert ipqs.risk.fraud_score == 7
    assert ipqs.usage.shared_connection is True
    assert len(seen) == 2
    maxmind_request = next(request for request in seen if request.url.host == "geoip.maxmind.com")
    ipqs_request = next(request for request in seen if request.url.host == "www.ipqualityscore.com")
    assert maxmind_request.headers["authorization"].startswith("Basic ")
    assert "maxmind-secret" not in str(maxmind_request.url)
    assert ipqs_request.headers["ipqs-key"] == "ipqs-secret"
    assert "ipqs-secret" not in str(ipqs_request.url)
    assert ipqs_request.url.params["strictness"] == "0"
    assert ipqs_request.url.params["allow_public_access_points"] == "true"
    assert ipqs_request.url.params["lighter_penalties"] == "true"
    assert ipqs_request.url.params["user_agent"] == "Example Browser"
    assert ipqs_request.url.params["user_language"] == "en-US"


@pytest.mark.asyncio
async def test_provider_does_not_retry_when_required_source_fails() -> None:
    calls = {"maxmind": 0, "ipqs": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "geoip.maxmind.com":
            calls["maxmind"] += 1
            return httpx.Response(200, json={"traits": {"autonomous_system_number": 15169}})
        calls["ipqs"] += 1
        return httpx.Response(503, json={"success": False})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = IPQualityProvider(_quality_config().ip_quality, client=client)
    try:
        with pytest.raises(IPQualityProviderError) as exc_info:
            await provider.fetch(IPQualityRequest(address="8.8.8.8"))
    finally:
        await client.aclose()

    assert exc_info.value.providers == ("ipqualityscore",)
    assert calls == {"maxmind": 1, "ipqs": 1}


@pytest.mark.parametrize(
    ("risk", "connection", "expected_level"),
    [
        (IPQualityRisk(fraud_score=90), IPQualityConnection(), "high_risk"),
        (IPQualityRisk(fraud_score=80), IPQualityConnection(), "review"),
        (IPQualityRisk(fraud_score=10), IPQualityConnection(vpn=True), "review"),
        (IPQualityRisk(fraud_score=10), IPQualityConnection(), "low_risk"),
    ],
)
def test_verdict_thresholds(
    risk: IPQualityRisk,
    connection: IPQualityConnection,
    expected_level: str,
) -> None:
    verdict = classify_quality_verdict(
        risk=risk,
        connection=connection,
        network=IPQualityNetwork(),
        consistency=IPQualityConsistency(),
        routing=IPQualityRouting(),
        routing_history=IPQualityRoutingHistory(status="available", days_requested=90),
        providers_successful=True,
    )
    assert verdict.level == expected_level


def test_cymru_metadata_does_not_pretend_an_as_number_is_an_isp() -> None:
    network = _parse_cymru_txt("15169 | 8.8.8.0/24 | US | arin | 2000-03-30")
    assert network.asn == 15169
    assert network.country_code == "US"
    assert network.asn_name is None
    assert network.isp is None
    assert _parse_cymru_as_name(
        "15169 | US | arin | 2000-03-30 | GOOGLE, US"
    ) == "GOOGLE, US"


def test_routing_history_is_bounded_and_detects_origin_changes() -> None:
    history = quality_service._routing_history_from_data(
        {
            "by_origin": [
                {
                    "origin": 64500,
                    "prefixes": [
                        {
                            "timelines": [
                                {
                                    "starttime": "2026-07-01T00:00:00Z",
                                    "endtime": "2026-07-15T00:00:00Z",
                                    "visibility": 0.9,
                                }
                            ]
                        }
                    ],
                },
                {
                    "origin": 64501,
                    "prefixes": [
                        {
                            "timelines": [
                                {
                                    "starttime": "2026-07-15T00:00:00Z",
                                    "endtime": "2026-07-16T00:00:00Z",
                                    "visibility": -1,
                                }
                            ]
                        }
                    ],
                },
            ]
        },
        90,
    )
    assert history.origin_changed is True
    assert {event.origin_asn for event in history.events} == {64500, 64501}
    assert history.events[0].visibility is None


@pytest.mark.asyncio
async def test_ripe_registration_history_follows_suggestion_and_compares_countries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, str | int]] = []

    async def fake_get(
        _client: httpx.AsyncClient,
        _endpoint: str,
        params: dict[str, str | int],
    ) -> dict[str, Any]:
        calls.append(params)
        resource = params["resource"]
        if resource == "8.8.8.0/24":
            return {
                "versions": [],
                "suggestions": [{"type": "inetnum", "key": "8.8.8.0 - 8.8.8.255"}],
            }
        if "version" not in params:
            return {
                "versions": [
                    {
                        "version": 2,
                        "from_time": "2026-07-01T00:00:00",
                        "to_time": "2026-07-16T00:00:00",
                    },
                    {
                        "version": 1,
                        "from_time": "2026-06-01T00:00:00",
                        "to_time": "2026-07-01T00:00:00",
                    },
                ]
            }
        country = "US" if params["version"] == 2 else "NL"
        return {
            "objects": [
                {
                    "attributes": [
                        {"attribute": "country", "value": country},
                        {"attribute": "netname", "value": "EXAMPLE-NET"},
                    ]
                }
            ]
        }

    monkeypatch.setattr(quality_service, "_ripestat_get", fake_get)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(500))) as client:
        history, health = await quality_service._registration_history(
            client,
            "8.8.8.0/24",
            "ripe",
            90,
        )
    assert history.status == "available"
    assert history.country_changed is True
    assert {version.country_code for version in history.versions} == {"US", "NL"}
    assert health.status == "ok"
    assert calls[1]["resource"] == "inetnum:8.8.8.0 - 8.8.8.255"


@pytest.mark.asyncio
async def test_open_source_failures_are_partial_after_both_premium_sources_deliver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("public source unavailable")

    async def no_ripestat(*_args: Any, **_kwargs: Any) -> None:
        return None

    class Provider:
        async def fetch(
            self, _request: IPQualityRequest
        ) -> tuple[MaxMindEvidence, IPQSEvidence]:
            return (
                MaxMindEvidence(
                    location=IPQualityLocation(country_code="US"),
                    registration=IPQualityRegistration(country_code="US"),
                    network=IPQualityNetwork(asn=15169),
                    connection=IPQualityConnection(),
                    usage=IPQualityUsageSignals(),
                ),
                IPQSEvidence(
                    location=IPQualityLocation(country_code="US"),
                    network=IPQualityNetwork(asn=15169),
                    connection=IPQualityConnection(),
                    risk=IPQualityRisk(fraud_score=5),
                    usage=IPQualityUsageSignals(),
                ),
            )

    monkeypatch.setattr(quality_service, "lookup_ip", fail)
    monkeypatch.setattr(quality_service, "lookup_bgp", fail)
    monkeypatch.setattr(quality_service, "_ripestat_get", no_ripestat)
    report = await quality_service.build_quality_report(
        IPQualityRequest(address="8.8.8.8"),
        Provider(),
    )
    assert report.partial is True
    assert report.verdict.level == "low_risk"
    assert report.sources["maxmind_insights"].status == "ok"
    assert report.sources["ipqualityscore"].status == "ok"
    assert report.sources["team_cymru"].status == "degraded"
    assert report.sources["ripestat_current_routing"].status == "degraded"


@pytest.mark.asyncio
async def test_disabled_quality_is_501_and_absent_from_public_catalogs() -> None:
    config = HyruleConfig()
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=config, payment_gate=None)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/ip/quality", json={"address": "8.8.8.8"})
            quote = await client.post(
                "/v1/ip/quality/quote", json={"address": "8.8.8.8"}
            )
            capabilities = (await client.get("/v1/ip/capabilities")).json()
            pricing = (await client.get("/v1/ip/pricing")).json()
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 501
    assert quote.status_code == 501
    assert pricing["quality_report_usd"] is None
    assert "/v1/ip/quality" not in {
        endpoint["path"] for endpoint in capabilities["paid_endpoints"]
    }
    assert "/v1/ip/quality" not in {
        resource["path"] for resource in build_x402_manifest(config)["resources"]
    }
    assert "/v1/ip/quality" not in build_curated_openapi(app, config)["paths"]


def test_enabled_quality_is_present_in_config_scoped_discovery() -> None:
    config = _quality_config()
    manifest_paths = {
        resource["path"] for resource in build_x402_manifest(config)["resources"]
    }
    openapi = build_curated_openapi(app, config)

    assert "/v1/ip/quality" in manifest_paths
    assert "/v1/ip/quality" in openapi["paths"]
    operation = openapi["paths"]["/v1/ip/quality"]["post"]
    assert operation["x-payment-info"]["price"]["amount"] == "0.02"


class _PaymentGate:
    def __init__(self, *, settle: bool = True) -> None:
        self.settle = settle
        self.verify_calls = 0
        self.settle_calls = 0

    async def verify_only(self, *_args: Any, **_kwargs: Any) -> object:
        self.verify_calls += 1
        return object()

    async def settle_verified(self, *_args: Any, **_kwargs: Any) -> bool:
        self.settle_calls += 1
        return self.settle


@pytest.mark.asyncio
async def test_provider_failure_returns_503_without_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*_args: Any, **_kwargs: Any) -> IPQualityResponse:
        raise IPQualityProviderError(("ipqualityscore",))

    monkeypatch.setattr("hyrule_cloud.api.ip.build_quality_report", fail)
    config = _quality_config()
    gate = _PaymentGate()
    provider = SimpleNamespace(close=lambda: None)
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=config,
        payment_gate=gate,
        ip_quality_provider=provider,
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/ip/quality", json={"address": "8.8.8.8"})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 503
    assert gate.verify_calls == 1
    assert gate.settle_calls == 0


@pytest.mark.asyncio
async def test_real_payment_gate_verifies_but_does_not_settle_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*_args: Any, **_kwargs: Any) -> IPQualityResponse:
        raise IPQualityProviderError(("maxmind_insights",))

    monkeypatch.setattr("hyrule_cloud.api.ip.build_quality_report", fail)
    server = _FakeServer()
    gate = _gate(server, public_base_url="https://cloud.hyrule.host")
    # This test targets deferred verification/settlement, not facilitator
    # initialization. Avoid the SDK's synchronous initialization thread.
    gate._initialized = True
    config = _quality_config()
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=config,
        payment_gate=gate,
        ip_quality_provider=object(),
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/v1/ip/quality",
                json={"address": "8.8.8.8"},
                headers={PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])},
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 503
    assert server.verify_payment_calls == 1
    assert server.settle_payment_calls == 0


@pytest.mark.asyncio
async def test_successful_report_settles_once_and_records_fixed_price(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def succeed(*_args: Any, **_kwargs: Any) -> IPQualityResponse:
        return _report()

    monkeypatch.setattr("hyrule_cloud.api.ip.build_quality_report", succeed)
    config = _quality_config()
    gate = _PaymentGate()
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=config,
        payment_gate=gate,
        ip_quality_provider=object(),
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/ip/quality", json={"address": "8.8.8.8"})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 200
    assert response.json()["charged_amount_usd"] == "0.02"
    assert gate.verify_calls == 1
    assert gate.settle_calls == 1


@pytest.mark.asyncio
async def test_free_nat_context_is_bounded_and_single_line() -> None:
    long_agent = "Browser/1.0 " + "x" * 800
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            "/v1/nat/ip",
            headers={"User-Agent": long_agent, "Accept-Language": "en-US, nl;q=0.9"},
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body["client_context"]["user_agent"]) == 512
    assert body["client_context"]["accept_language"] == "en-US, nl;q=0.9"
