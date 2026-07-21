from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from x402 import PaymentCreationContext

import hyrule_cloud_mcp.buyer as buyer_module
from hyrule_cloud_mcp.buyer import Buyer, _decode_body, _followup_path, _read_limited
from hyrule_cloud_mcp.catalog import CatalogError, CatalogResource, build_request, parse_manifest
from hyrule_cloud_mcp.config import Settings
from hyrule_cloud_mcp.payments import (
    PaymentGuard,
    SpendLedger,
    SpendLimitError,
    build_x402_client,
)


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "base_url": "https://cloud.hyrule.host",
        "private_key": None,
        "max_payment_atomic": 100_000,
        "daily_budget_atomic": 200_000,
        "ledger_path": tmp_path / "spend.sqlite3",
        "capabilities": frozenset(),
        "capabilities_explicit": False,
        "allow_infrastructure": False,
        "preferred_network": "eip155:8453",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _resource(capability_id: str = "hyrule.dns.lookup") -> CatalogResource:
    return CatalogResource(
        capability_id=capability_id,
        method="POST",
        path="/v1/dns/lookup",
        description="Resolve public DNS records with source evidence.",
        intents=("look up DNS records",),
        capabilities=("DNS lookup",),
        price={"mode": "fixed", "amount": "0.01", "currency": "USD"},
    )


def _payment_context(
    url: str,
    amount: str,
    *,
    network: str = "eip155:8453",
    asset: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
) -> PaymentCreationContext:
    payment_required = SimpleNamespace(
        x402_version=2,
        resource=SimpleNamespace(url=url),
    )
    requirements = SimpleNamespace(
        get_amount=lambda: amount,
        network=network,
        asset=asset,
    )
    return PaymentCreationContext(payment_required, requirements)  # type: ignore[arg-type]


def test_parse_manifest_requires_v2_and_unique_stable_ids() -> None:
    manifest = {
        "x402Version": 2,
        "resources": [
            {
                "id": "hyrule.dns.lookup",
                "method": "POST",
                "path": "/v1/dns/lookup",
                "intents": ["look up DNS"],
                "capabilities": ["DNS"],
                "price": {
                    "mode": "fixed",
                    "amount": "0.01",
                    "currency": "USD",
                },
                "inputSchema": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {"name": {"type": "string"}},
                },
                "inputExample": {"name": "example.com"},
            }
        ],
    }
    parsed = parse_manifest(manifest)[0]
    assert parsed.capability_id == "hyrule.dns.lookup"
    assert parsed.input_schema["required"] == ["name"]
    assert parsed.input_example == {"name": "example.com"}
    manifest["resources"] = [manifest["resources"][0], manifest["resources"][0]]
    with pytest.raises(CatalogError, match="duplicate"):
        parse_manifest(manifest)


def test_catalog_rejects_capability_id_path_mismatch() -> None:
    with pytest.raises(CatalogError, match="does not match"):
        CatalogResource.from_json(
            {
                "id": "hyrule.dns.lookup",
                "method": "POST",
                "path": "/v1/network/request",
            }
        )


def test_build_request_escapes_path_parameters_and_separates_query() -> None:
    resource = CatalogResource(
        capability_id="hyrule.bgp.snapshot.download",
        method="GET",
        path="/v1/bgp/snapshots/router/{snapshot_id}/download",
        description="download",
        intents=(),
        capabilities=(),
        price={},
    )
    path, kwargs = build_request(resource, {"snapshot_id": "a/b", "format": "json"})
    assert path == "/v1/bgp/snapshots/router/a%2Fb/download"
    assert kwargs == {"params": {"format": "json"}}


def test_spend_ledger_reserves_atomically_against_daily_cap(tmp_path: Path) -> None:
    ledger = SpendLedger(tmp_path / "ledger.sqlite3")
    now = datetime(2026, 7, 18, 12, tzinfo=UTC)
    first = ledger.reserve(
        amount_atomic=75_000,
        daily_budget_atomic=100_000,
        resource_url="https://cloud.hyrule.host/v1/dns/lookup",
        now=now,
    )
    assert first.total_atomic == 75_000
    with pytest.raises(SpendLimitError, match="daily"):
        ledger.reserve(
            amount_atomic=30_000,
            daily_budget_atomic=100_000,
            resource_url="https://cloud.hyrule.host/v1/dns/lookup",
            now=now,
        )


def test_payment_guard_rejects_origin_path_and_amount_before_signing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    guard = PaymentGuard(
        settings,
        "/v1/dns/lookup",
        SpendLedger(settings.ledger_path),
        minimum_amount_atomic=10_000,
        maximum_amount_atomic=10_000,
    )

    assert guard(_payment_context("https://attacker.test/v1/dns/lookup", "10000")) is not None
    assert guard(_payment_context("https://cloud.hyrule.host/v1/vm/create", "10000")) is not None
    assert guard(_payment_context("https://cloud.hyrule.host/v1/dns/lookup", "9999")) is not None
    assert guard(_payment_context("https://cloud.hyrule.host/v1/dns/lookup", "10001")) is not None
    assert guard(_payment_context("https://cloud.hyrule.host/v1/dns/lookup", "100001")) is not None
    assert (
        guard(
            _payment_context(
                "https://cloud.hyrule.host/v1/dns/lookup",
                "10000",
                asset="0x0000000000000000000000000000000000000001",
            )
        )
        is not None
    )
    assert (
        guard(
            _payment_context(
                "https://cloud.hyrule.host/v1/dns/lookup",
                "10000",
                network="eip155:137",
                asset="0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
            )
        )
        is not None
    )
    assert guard(_payment_context("https://cloud.hyrule.host/v1/dns/lookup", "10000")) is None


def test_dynamic_manifest_price_bounds_are_enforced_before_signing(tmp_path: Path) -> None:
    resource = CatalogResource(
        capability_id="hyrule.dns.lookup",
        method="POST",
        path="/v1/dns/lookup",
        description="lookup",
        intents=(),
        capabilities=(),
        price={"mode": "dynamic", "min": "0.001", "max": "0.005", "currency": "USD"},
    )
    minimum, maximum = resource.payment_bounds_atomic()
    assert (minimum, maximum) == (1_000, 5_000)

    settings = _settings(tmp_path)
    guard = PaymentGuard(
        settings,
        resource.path,
        SpendLedger(settings.ledger_path),
        minimum_amount_atomic=minimum,
        maximum_amount_atomic=maximum,
    )
    url = "https://cloud.hyrule.host/v1/dns/lookup"
    assert guard(_payment_context(url, "999")) is not None
    assert guard(_payment_context(url, "1000")) is None
    assert guard(_payment_context(url, "5001")) is not None


def test_infrastructure_requires_two_explicit_operator_opt_ins(tmp_path: Path) -> None:
    denied = _settings(
        tmp_path,
        capabilities=frozenset({"hyrule.vm.create"}),
        capabilities_explicit=True,
    )
    assert denied.allows("hyrule.vm.create") is False
    allowed = _settings(
        tmp_path,
        capabilities=frozenset({"hyrule.vm.create"}),
        capabilities_explicit=True,
        allow_infrastructure=True,
    )
    assert allowed.allows("hyrule.vm.create") is True
    assert allowed.allows_resource("hyrule.vm.create", "/v1/vm/create") is True
    assert allowed.allows_resource("hyrule.dns.lookup", "/v1/network/request") is False


def test_official_x402_client_builds_with_runtime_wallet_only(tmp_path: Path) -> None:
    settings = _settings(tmp_path, private_key="0x" + "1" * 64)
    client = build_x402_client(
        settings,
        allowed_path="/v1/dns/lookup",
        ledger=SpendLedger(settings.ledger_path),
        minimum_amount_atomic=10_000,
        maximum_amount_atomic=10_000,
    )

    assert client is not None


@pytest.mark.asyncio
async def test_discovery_reports_policy_without_requiring_a_wallet(tmp_path: Path) -> None:
    async def catalog_loader(_base_url: str) -> list[CatalogResource]:
        return [_resource(), _resource("hyrule.vm.create")]

    buyer = Buyer(_settings(tmp_path), catalog_loader=catalog_loader)
    result = await buyer.discover("hyrule")
    policy = {item["id"]: item["automaticPaymentAllowed"] for item in result}
    assert policy == {"hyrule.dns.lookup": True, "hyrule.vm.create": False}
    dns = next(item for item in result if item["id"] == "hyrule.dns.lookup")
    assert dns["inputSchema"] == {}
    assert dns["inputExample"] == {}


@pytest.mark.asyncio
async def test_snapshot_discovery_exposes_unpaid_listing_and_preflights_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot_resource = CatalogResource(
        capability_id="hyrule.bgp.snapshots.router.snapshot_id.download",
        method="GET",
        path="/v1/bgp/snapshots/router/{snapshot_id}/download",
        description="Download a live router snapshot.",
        intents=("download BGP snapshot",),
        capabilities=("BGP snapshot",),
        price={"amount": "0.10"},
    )

    async def catalog_loader(_base_url: str) -> list[CatalogResource]:
        return [snapshot_resource]

    buyer = Buyer(_settings(tmp_path, max_response_bytes=512), catalog_loader=catalog_loader)

    async def listing(_path: str, arguments=None) -> dict:
        return {
            "result": {
                "snapshots": [
                    {
                        "snapshot_id": "small",
                        "size_bytes": 128,
                        "download_available": True,
                    },
                    {
                        "snapshot_id": "large",
                        "size_bytes": 1024,
                        "download_available": True,
                    },
                    {
                        "snapshot_id": "stale",
                        "size_bytes": 128,
                        "download_available": False,
                    },
                    {"snapshot_id": "unconfirmed", "size_bytes": 128},
                ]
            }
        }

    monkeypatch.setattr(buyer, "follow", listing)

    discovered = await buyer.discover("snapshot")
    assert discovered[0]["prerequisite"]["followUpUrl"] == "/v1/bgp/snapshots/router"
    with pytest.raises(ValueError, match="MAX_RESPONSE_BYTES"):
        await buyer.call(snapshot_resource.capability_id, {"snapshot_id": "large"})
    with pytest.raises(ValueError, match="live unpaid discovery"):
        await buyer.call(snapshot_resource.capability_id, {"snapshot_id": "fabricated"})
    for snapshot_id in ("stale", "unconfirmed"):
        with pytest.raises(ValueError, match="not currently available"):
            await buyer.call(snapshot_resource.capability_id, {"snapshot_id": snapshot_id})


def test_snapshot_listing_is_an_allowed_non_paying_followup() -> None:
    assert (
        _followup_path("https://cloud.hyrule.host", "/v1/bgp/snapshots/router")
        == "/v1/bgp/snapshots/router"
    )


def test_response_limit_is_operator_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HYRULE_MCP_MAX_RESPONSE_BYTES", "33554432")
    assert Settings.from_env().max_response_bytes == 33_554_432


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.yielded = 0

    async def __aiter__(self):
        for chunk in (b"1234", b"5678", b"unreachable"):
            self.yielded += 1
            yield chunk


@pytest.mark.asyncio
async def test_response_limit_stops_streaming_immediately() -> None:
    stream = _ChunkStream()
    response = httpx.Response(200, stream=stream)
    with pytest.raises(ValueError, match="response limit"):
        await _read_limited(response, 5)
    await response.aclose()
    assert stream.yielded == 2


def test_binary_response_is_losslessly_base64_encoded() -> None:
    body = b"\x1f\x8b\x08\x00\xff"
    response = httpx.Response(200, headers={"content-type": "application/gzip"})

    assert _decode_body(response, body) == {
        "encoding": "base64",
        "mediaType": "application/gzip",
        "bytes": len(body),
        "data": "H4sIAP8=",
    }


@pytest.mark.asyncio
async def test_followup_is_same_origin_narrow_and_non_paying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_async_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/bgp/jobs/bgpj_123"
        assert request.url.params["token"] == "returned-secret"
        return httpx.Response(200, json={"status": "completed"})

    def client_factory(**kwargs: object) -> httpx.AsyncClient:
        return real_async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(buyer_module.httpx, "AsyncClient", client_factory)
    buyer = Buyer(_settings(tmp_path))

    result = await buyer.follow("/v1/bgp/jobs/bgpj_123", {"token": "returned-secret"})

    assert result["result"] == {"status": "completed"}
    with pytest.raises(ValueError, match="configured Hyrule origin"):
        await buyer.follow("https://attacker.test/v1/bgp/jobs/bgpj_123")
    with pytest.raises(ValueError, match="not an allowed"):
        await buyer.follow("/v1/pricing")


def test_registry_metadata_matches_package_verification_marker() -> None:
    root = Path(__file__).parents[1]
    server = json.loads((root / "server.json").read_text())
    readme = (root / "README.md").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    assert server["$schema"].endswith("/2025-12-11/server.schema.json")
    assert f"mcp-name: {server['name']}" in readme
    assert server["packages"][0]["identifier"] == "hyrule-cloud-mcp"
    assert 'name = "hyrule-cloud-mcp"' in pyproject
