"""Ambiguous provider deletion succeeds only after confirmed UUID absence."""

from unittest.mock import AsyncMock, call

import pytest

from hyrule_cloud.providers.xcpng import XCPNGProvider, XOError


@pytest.mark.asyncio
async def test_delete_reply_lost_and_vm_absent_is_recoverable():
    provider = object.__new__(XCPNGProvider)
    provider._xo_call = AsyncMock(side_effect=[XOError("vm.delete", {"message": "missing"}), {}])
    await provider.destroy_vm("test-guest")
    assert provider._xo_call.await_args_list == [
        call("vm.delete", id="test-guest"),
        call("xo.getAllObjects", filter={"id": "test-guest"}),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory", [{"test-guest": {"type": "VM"}}, None, []])
async def test_delete_error_does_not_succeed_without_confirmed_absence(inventory):
    provider = object.__new__(XCPNGProvider)
    error = XOError("vm.delete", {"message": "denied"})
    provider._xo_call = AsyncMock(side_effect=[error, inventory])
    with pytest.raises(XOError) as caught:
        await provider.destroy_vm("test-guest")
    assert caught.value is error


@pytest.mark.asyncio
async def test_delete_inventory_failure_stays_failed():
    provider = object.__new__(XCPNGProvider)
    provider._xo_call = AsyncMock(side_effect=[RuntimeError("delete unavailable"), RuntimeError("inventory unavailable")])
    with pytest.raises(RuntimeError, match="inventory unavailable"):
        await provider.destroy_vm("test-guest")
