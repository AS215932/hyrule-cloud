"""MCP deletion reports the actual API lifecycle outcome."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tests.test_mcp_payment_tools import _patch_client_factory


@pytest.mark.asyncio
@pytest.mark.parametrize(('result', 'expected'), [
    ({'status': 'retained'}, 'VM fixture is stopped and retained for recovery.'),
    ({'status': 'ok'}, 'VM fixture destroyed.'),
    ({'status': 'pending'}, 'VM fixture deletion completion was not confirmed.'),
    ({}, 'VM fixture deletion completion was not confirmed.'),
])
async def test_destroy_reports_api_outcome(monkeypatch, result, expected):
    from hyrule_cloud.mcp_server import destroy_vm

    client = SimpleNamespace(destroy_vm=AsyncMock(return_value=result))
    _patch_client_factory(monkeypatch, client)
    assert await destroy_vm('fixture', management_token='fixture-token') == expected
    client.destroy_vm.assert_awaited_once_with('fixture', management_token='fixture-token')
