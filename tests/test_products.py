"""Issue #14: GET /v1/products/vms — machine-readable VM catalog."""

from __future__ import annotations

from decimal import Decimal

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.state import AppState


class _Pay:
    price_vm_xs = Decimal("0.05")
    price_vm_sm = Decimal("0.10")
    price_vm_md = Decimal("0.20")
    price_vm_lg = Decimal("0.40")


class _Cfg:
    payment = _Pay()


@pytest_asyncio.fixture
async def products_state():
    state = AppState(
        config=_Cfg(),
        orchestrator=None,
        payment_gate=None,
        network_provider=None,
    )
    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        yield state
    finally:
        if prev is not None:
            app.state._typed_state = prev


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        yield c


@pytest.mark.asyncio
async def test_products_lists_all_sizes_with_specs_and_prices(products_state, client):
    res = await client.get("/v1/products/vms")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["currency"] == "USD"
    assert body["billing"] == "prepaid-daily"

    by_size = {p["size"]: p for p in body["products"]}
    assert set(by_size) == {"xs", "sm", "md", "lg"}
    # Specs come from VM_SPECS; prices from the configured per-size values.
    assert by_size["xs"]["vcpu"] == 1
    assert by_size["xs"]["ram_mb"] == 512
    assert by_size["xs"]["disk_gb"] == 10
    assert by_size["xs"]["price_usd_day"] == "0.05"
    assert by_size["xs"]["name"] == "Starter"
    assert by_size["lg"]["name"] == "Performance"
    assert by_size["lg"]["price_usd_day"] == "0.40"
    assert body["os_templates_url"].endswith("/v1/os/list")
