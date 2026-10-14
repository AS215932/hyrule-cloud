from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from hyrule_cloud.api import tunnel


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["admin-bypass", "dev-bypass", None])
async def test_failed_extension_only_owes_refund_when_payment_collected(monkeypatch, mode):
    record = AsyncMock()
    monkeypatch.setattr(tunnel, "_record_extend_refund", record)
    request = SimpleNamespace(state=SimpleNamespace(payment_mode=mode))
    error = await tunnel._extend_failed_after_payment(
        request, object(), "fixture-tunnel", Decimal("1.00"), "fixture-payer", 502,
    )
    assert error.status_code == 502
    if mode is None:
        record.assert_awaited_once()
        assert "refund is owed" in error.detail
    else:
        record.assert_not_awaited()
        assert "no payment was collected" in error.detail
        assert "refund" not in error.detail
