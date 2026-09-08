from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Request

from hyrule_cloud.api.routes import extend_vm
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import AccountRow, VMRow
from hyrule_cloud.middleware.anon_token import VMManagementIdentity
from hyrule_cloud.models import VMExtendRequest
from tests.test_vm_expiry_renewal import _stored_vm


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['extend', 'reboot', 'delete'])
@pytest.mark.parametrize('change', ['unchanged', 'account', 'wallet', 'token'])
async def test_management_action_rechecks_authorized_resource_identity(action, change):
    orch, engine = await _stored_vm()
    orch.xcpng.reboot_vm = AsyncMock()
    gate = SimpleNamespace(check_payment=AsyncMock(return_value='test-owner'))
    try:
        authorized = await orch.get_vm('vm_lifecycle')
        identity = VMManagementIdentity.capture(authorized)
        if change != 'unchanged':
            async with orch.db.begin() as session:
                row = await session.get(VMRow, 'vm_lifecycle')
                if change == 'account':
                    session.add(AccountRow(account_id='H1234567890', password_hash='fixture'))
                    await session.flush()
                    row.owner_account_id = 'H1234567890'
                elif change == 'wallet':
                    row.owner_wallet = 'new-owner'
                else:
                    row.anon_management_token_hash = 'new-token-hash'
        if action == 'extend':
            request = Request({'type': 'http', 'method': 'POST', 'path': '/fixture', 'headers': []})
            if change == 'unchanged':
                result = await extend_vm('vm_lifecycle', VMExtendRequest(days=3), request,
                                         authorized, orch, HyruleConfig(), gate)
                assert result['vm_id'] == 'vm_lifecycle'
                gate.check_payment.assert_awaited_once()
            else:
                with pytest.raises(HTTPException) as exc:
                    await extend_vm('vm_lifecycle', VMExtendRequest(days=3), request,
                                    authorized, orch, HyruleConfig(), gate)
                assert exc.value.status_code == 404
                gate.check_payment.assert_not_awaited()
        else:
            operation = orch.reboot_vm if action == 'reboot' else orch.destroy_vm
            assert await operation('vm_lifecycle', management_identity=identity) == (change == 'unchanged')
        if change != 'unchanged':
            orch.xcpng.reboot_vm.assert_not_awaited()
            orch.xcpng.destroy_vm.assert_not_awaited()
            async with orch.db() as session:
                assert (await session.get(VMRow, 'vm_lifecycle')).deletion_started_at is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['delete', 'reboot'])
async def test_customer_action_rechecks_disabled_owner_when_token_was_already_absent(action):
    from datetime import UTC, datetime

    orch, engine = await _stored_vm()
    orch.xcpng.reboot_vm = AsyncMock()
    operation = orch.destroy_vm if action == 'delete' else orch.reboot_vm
    provider_operation = orch.xcpng.destroy_vm if action == 'delete' else orch.xcpng.reboot_vm
    try:
        async with orch.db.begin() as session:
            session.add(AccountRow(account_id='H1234567890', password_hash='fixture'))
            await session.flush()
            vm = await session.get(VMRow, 'vm_lifecycle')
            vm.owner_account_id = 'H1234567890'
            vm.anon_management_token_hash = None
        identity = VMManagementIdentity.capture(await orch.get_vm('vm_lifecycle'))
        async with orch.db.begin() as session:
            owner = await session.get(AccountRow, 'H1234567890')
            owner.disabled_at = datetime.now(UTC)
        assert identity.matches(await orch.get_vm('vm_lifecycle'))
        assert not await operation('vm_lifecycle', management_identity=identity)
        provider_operation.assert_not_awaited()
        async with orch.db() as session:
            assert (await session.get(VMRow, 'vm_lifecycle')).deletion_started_at is None
        # Trusted lifecycle cleanup does not borrow a revoked customer request.
        assert await operation('vm_lifecycle')
        provider_operation.assert_awaited_once()
    finally:
        await engine.dispose()
