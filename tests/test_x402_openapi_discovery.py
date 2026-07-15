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
from hyrule_cloud.config import HyruleConfig
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
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")


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
