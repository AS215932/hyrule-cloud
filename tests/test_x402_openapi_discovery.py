from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from x402.http import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    decode_payment_required_header,
)

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.services.discovery import (
    DISCOVERY,
    PAID_OPERATIONS,
    build_curated_openapi,
    build_x402_manifest,
    enabled_paid_operations,
)
from tests.test_payment_gate_x402 import _FakeServer, _gate, _request


def _enable_all_catalog_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning",
        lambda: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.path.diagnostics.path_active_probe_enabled",
        lambda _vantages=None: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.threat.lookup.threat_intel_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.voip.diagnostics.number_intel_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.bgp.stream.bgpstream_worker_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.bgp.snapshots.router_snapshot_download_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.api.bgp.router_snapshot_download_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.tunnel.readiness.tunnel_service_ready",
        lambda: True,
    )


def _schema_operations(schema: dict) -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, path_item in schema["paths"].items()
        for method in path_item
        if method.lower() in {"get", "post", "put", "delete", "patch", "head"}
    }


def test_every_catalog_operation_has_complete_x402_openapi_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_all_catalog_gates(monkeypatch)
    config = HyruleConfig()
    schema = build_curated_openapi(app, config)

    assert _schema_operations(schema) == {operation.key for operation in PAID_OPERATIONS}
    assert "/v1/domain/register" not in schema["paths"]

    for operation in PAID_OPERATIONS:
        documented = schema["paths"][operation.path][operation.method.lower()]
        assert documented["security"] == [], operation.key
        assert documented["x-payment-info"]["protocols"] == [{"x402": {}}]
        price = documented["x-payment-info"]["price"]
        assert price["currency"] == "USD"
        if operation.price.mode == "fixed":
            assert price == {
                "mode": "fixed",
                "currency": "USD",
                "amount": str(operation.price.minimum(config.payment)),
            }
        else:
            assert price["mode"] == "dynamic"
            assert price["min"] == str(operation.price.minimum(config.payment))
            maximum = operation.price.maximum(config.payment)
            assert price.get("max") == (str(maximum) if maximum is not None else None)

        challenge = documented["responses"]["402"]
        assert "Payment-Required" in challenge["headers"]
        assert challenge["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/X402PaymentRequired"
        }
        if operation.key == ("POST", "/v1/vm/create"):
            assert "202" in documented["responses"]

        if operation.method == "POST":
            request = documented["requestBody"]["content"]["application/json"]
            assert request["schema"], operation.key
            assert request["example"] == operation.input_example
        else:
            path_parameters = [
                parameter
                for parameter in documented["parameters"]
                if parameter["in"] == "path"
            ]
            assert path_parameters
            assert all(parameter["required"] is True for parameter in path_parameters)

        success_content = [
            response.get("content", {})
            for status, response in documented["responses"].items()
            if str(status).startswith("2")
        ]
        assert any(
            media.get("schema")
            for content in success_content
            for media in content.values()
        ), operation.key
        assert all(
            media.get("example") == operation.output_example
            for content in success_content
            for media in content.values()
        ), operation.key


def test_post_examples_are_executable_and_marketplace_renderable() -> None:
    """Agentic Market builds its parameter table from ``info.input.body``.

    It currently turns object-valued examples into ``object / null``, so the
    curated example surface must stay scalar/array-only and agree with the
    advertised schema. Rich nested options remain available in JSON Schema.
    """

    for operation in PAID_OPERATIONS:
        if operation.method != "POST":
            continue
        assert operation.request_model is not None
        assert operation.input_schema is not None
        assert operation.input_example is not None
        operation.request_model.model_validate(operation.input_example)

        properties = operation.input_schema["properties"]
        assert set(operation.input_example) <= set(properties), operation.key
        assert set(operation.input_schema.get("required", [])) <= set(operation.input_example), (
            operation.key
        )
        assert not any(isinstance(value, dict) for value in operation.input_example.values()), (
            operation.key
        )

        bazaar_body = operation.declaration["bazaar"]["info"]["input"]["body"]
        assert bazaar_body == operation.input_example


@pytest.mark.parametrize(
    ("path", "subject_type", "subject_value"),
    [
        ("/v1/bgp/lookup", "prefix", "2a0c:b641:b50::/44"),
        ("/v1/bgp/jobs", "prefix", "2a0c:b641:b50::/44"),
        ("/v1/rdap/lookup", "domain", "example.com"),
        ("/v1/whois/lookup", "domain", "example.com"),
        ("/v1/threat/lookup", "domain", "example.com"),
    ],
)
def test_flat_subject_discovery_form_preserves_nested_api_contract(
    path: str,
    subject_type: str,
    subject_value: str,
) -> None:
    operation = next(item for item in PAID_OPERATIONS if item.path == path)
    assert operation.request_model is not None
    assert operation.input_schema is not None
    parsed = operation.request_model.model_validate(operation.input_example)

    assert parsed.subject.type == subject_type
    assert parsed.subject.value == subject_value
    assert "subject" not in operation.input_schema["properties"]
    assert operation.input_schema["required"][:2] == [
        "subject_type",
        "subject_value",
    ]


def test_vm_discovery_minimum_is_a_purchasable_one_day_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_all_catalog_gates(monkeypatch)
    # Ignore a developer's local .env: discovery must expose the shipped
    # catalog floor, and add-on unit prices are not independently purchasable.
    config = HyruleConfig(payment=PaymentConfig(_env_file=None))
    schema = build_curated_openapi(app, config)

    price = schema["paths"]["/v1/vm/create"]["post"]["x-payment-info"]["price"]

    assert price == {"mode": "dynamic", "currency": "USD", "min": "0.20"}


def test_manifest_openapi_and_bazaar_share_the_same_enabled_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_all_catalog_gates(monkeypatch)
    config = HyruleConfig()
    manifest = build_x402_manifest(config)
    schema = build_curated_openapi(app, config)

    catalog_keys = {operation.key for operation in enabled_paid_operations()}
    manifest_keys = {
        (resource["method"], resource["path"])
        for resource in manifest["resources"]
    }
    assert catalog_keys == manifest_keys == _schema_operations(schema) == set(DISCOVERY)
    assert all(resource["discoverable"] is True for resource in manifest["resources"])
    assert ("POST", "/v1/domain/register") not in catalog_keys


@pytest.mark.asyncio
async def test_unpaid_catalog_probes_reach_valid_402_before_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_all_catalog_gates(monkeypatch)
    server = _FakeServer()
    gate = _gate(server, public_base_url="https://cloud.hyrule.host")
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            for operation in enabled_paid_operations():
                path = re.sub(r"\{[^}]+\}", "probe-value", operation.path)
                kwargs = {}
                if operation.method == "POST":
                    # Deliberately malformed: the payment gate must run before
                    # FastAPI attempts JSON or Pydantic validation.
                    kwargs = {
                        "content": b"{",
                        "headers": {"Content-Type": "application/json"},
                    }
                response = await client.request(operation.method, path, **kwargs)
                assert response.status_code == 402, operation.key
                assert PAYMENT_REQUIRED_HEADER in response.headers, operation.key

                body = response.json()
                decoded = decode_payment_required_header(
                    response.headers[PAYMENT_REQUIRED_HEADER]
                ).model_dump(by_alias=True, exclude_none=True)
                for canonical_field in (
                    "x402Version",
                    "accepts",
                    "resource",
                    "extensions",
                ):
                    assert body[canonical_field] == decoded[canonical_field], operation.key
                assert body["extensions"]["bazaar"]["info"]["input"]["method"] == operation.method

                # Bazaar quality scoring weighs metadata completeness: every
                # catalog 402 must carry full resource metadata on the wire.
                resource = decoded["resource"]
                assert resource["serviceName"] == "Hyrule Cloud", operation.key
                assert resource["mimeType"] == "application/json", operation.key
                assert resource["description"].startswith(
                    "Hyrule Cloud is pay-per-use infrastructure for AI agents on AS215932"
                ), operation.key
                assert operation.description in resource["description"], operation.key
                for capability in ("IPv6-native compute", "Tor", "BGP", "VoIP"):
                    assert capability in resource["description"], operation.key
                assert resource["iconUrl"] == "https://cloud.hyrule.host/icon-192.png", (
                    operation.key
                )
                tags = resource["tags"]
                assert 1 <= len(tags) <= 5, operation.key
                assert all(len(tag) <= 32 and tag.isascii() for tag in tags), operation.key
                assert len(resource["serviceName"]) <= 32
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")


@pytest.mark.asyncio
async def test_valid_dynamic_input_reaches_handler_for_exact_first_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # /v1/bgp/jobs is worker-gated; enable both the catalog gate and the
    # route-level guard binding so the dynamic-price path stays covered.
    monkeypatch.setattr(
        "hyrule_cloud.services.bgp.stream.bgpstream_worker_enabled", lambda: True
    )
    monkeypatch.setattr("hyrule_cloud.api.bgp.bgpstream_worker_enabled", lambda: True)
    config = HyruleConfig()
    gate = _gate(_FakeServer(), public_base_url="https://cloud.hyrule.host")
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=config, payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/v1/bgp/jobs",
                json={
                    "subject": {
                        "type": "prefix",
                        "value": "2a0c:b641:b50::/44",
                    },
                    "record_type": "ribs",
                },
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 402
    assert response.json()["amount"] == str(config.payment.price_bgpstream_rib)


@pytest.mark.asyncio
async def test_gated_bgp_jobs_post_returns_501_without_payment_challenge() -> None:
    """With no BGPStream worker deployed (default), a valid /v1/bgp/jobs body
    must be refused with 501 and never see a payment challenge, even with the
    payment gate fully wired."""
    gate = _gate(_FakeServer(), public_base_url="https://cloud.hyrule.host")
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/v1/bgp/jobs",
                json={
                    "subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"},
                    "record_type": "updates",
                },
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 501
    assert response.json()["error"] == "not_implemented"
    assert PAYMENT_REQUIRED_HEADER not in response.headers


@pytest.mark.asyncio
async def test_gated_router_snapshot_download_returns_501_without_payment_challenge() -> None:
    """Metadata-only snapshots on noc cannot be downloaded from api.

    The route must refuse before charging and remain outside the default
    catalog until artifact transfer/shared storage is explicitly enabled.
    """
    gate = _gate(_FakeServer(), public_base_url="https://cloud.hyrule.host")
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/v1/bgp/snapshots/router/bgps_probe/download",
            )
            manifest = await client.get("/.well-known/x402.json")
            capabilities = await client.get("/v1/bgp/capabilities")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 501
    assert response.json()["error"] == "not_implemented"
    assert PAYMENT_REQUIRED_HEADER not in response.headers
    manifest_paths = {resource["path"] for resource in manifest.json()["resources"]}
    assert "/v1/bgp/snapshots/router/{snapshot_id}/download" not in manifest_paths
    paid_paths = {endpoint["path"] for endpoint in capabilities.json()["paid_endpoints"]}
    assert "/v1/bgp/snapshots/router/{snapshot_id}/download" not in paid_paths


@pytest.mark.asyncio
async def test_router_snapshot_download_readvertises_when_artifacts_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HYRULE_BGP_ROUTER_SNAPSHOT_DOWNLOAD_ENABLED", "1")
    gate = _gate(_FakeServer(), public_base_url="https://cloud.hyrule.host")
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get(
                "/v1/bgp/snapshots/router/bgps_probe/download",
            )
            manifest = await client.get("/.well-known/x402.json")
            capabilities = await client.get("/v1/bgp/capabilities")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 402
    assert PAYMENT_REQUIRED_HEADER in response.headers
    manifest_paths = {resource["path"] for resource in manifest.json()["resources"]}
    assert "/v1/bgp/snapshots/router/{snapshot_id}/download" in manifest_paths
    paid_paths = {endpoint["path"] for endpoint in capabilities.json()["paid_endpoints"]}
    assert "/v1/bgp/snapshots/router/{snapshot_id}/download" in paid_paths


@pytest.mark.asyncio
async def test_trailing_slash_probe_still_reaches_prevalidation_challenge() -> None:
    gate = _gate(_FakeServer())
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/v1/ip/lookup/",
                content=b"{",
                headers={"Content-Type": "application/json"},
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 402
    assert PAYMENT_REQUIRED_HEADER in response.headers


@pytest.mark.asyncio
async def test_payment_credentials_bypass_prevalidation_gate() -> None:
    gate = _gate(_FakeServer())
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), payment_gate=gate)

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/v1/ip/lookup",
                content=b"{",
                headers={
                    "Content-Type": "application/json",
                    PAYMENT_SIGNATURE_HEADER: "present-but-malformed",
                },
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    # FastAPI owns malformed paid requests; the preflight gate only challenges
    # callers that have not supplied payment credentials.
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_payment_required_json_body_preserves_bazaar_extension() -> None:
    gate = _gate(_FakeServer())
    response = await gate.challenge_payment(
        _request(path="/v1/ip/lookup"),
        HyruleConfig().payment.price_ip_lookup,
        "IP lookup",
        route_path="/v1/ip/lookup",
    )

    body = json.loads(response.body)
    assert body["extensions"]["bazaar"]["info"]["input"]["method"] == "POST"
    assert body["extensions"]["bazaar"]["schema"]
