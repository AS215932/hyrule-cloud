from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from x402 import PaymentCreationContext

from hyrule_cloud_mcp.buyer import Buyer
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
            }
        ],
    }
    assert parse_manifest(manifest)[0].capability_id == "hyrule.dns.lookup"
    manifest["resources"] = [manifest["resources"][0], manifest["resources"][0]]
    with pytest.raises(CatalogError, match="duplicate"):
        parse_manifest(manifest)


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
    guard = PaymentGuard(settings, "/v1/dns/lookup", SpendLedger(settings.ledger_path))

    def context(url: str, amount: str) -> PaymentCreationContext:
        payment_required = SimpleNamespace(
            x402_version=2,
            resource=SimpleNamespace(url=url),
        )
        requirements = SimpleNamespace(get_amount=lambda: amount)
        return PaymentCreationContext(payment_required, requirements)  # type: ignore[arg-type]

    assert guard(context("https://attacker.test/v1/dns/lookup", "1000")) is not None
    assert guard(context("https://cloud.hyrule.host/v1/vm/create", "1000")) is not None
    assert guard(context("https://cloud.hyrule.host/v1/dns/lookup", "100001")) is not None
    assert guard(context("https://cloud.hyrule.host/v1/dns/lookup", "1000")) is None


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


def test_official_x402_client_builds_with_runtime_wallet_only(tmp_path: Path) -> None:
    settings = _settings(tmp_path, private_key="0x" + "1" * 64)
    client = build_x402_client(
        settings,
        allowed_path="/v1/dns/lookup",
        ledger=SpendLedger(settings.ledger_path),
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


def test_registry_metadata_matches_package_verification_marker() -> None:
    root = Path(__file__).parents[1]
    server = json.loads((root / "server.json").read_text())
    readme = (root / "README.md").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    assert server["$schema"].endswith("/2025-12-11/server.schema.json")
    assert f"mcp-name: {server['name']}" in readme
    assert server["packages"][0]["identifier"] == "hyrule-cloud-mcp"
    assert 'name = "hyrule-cloud-mcp"' in pyproject
