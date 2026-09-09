from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Request

from hyrule_cloud.api import routes
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
@pytest.mark.parametrize("power", ["Halted", "Unknown", "error"])
async def test_expired_extension_reconciles_provider_power_before_payment(power):
    orch, engine = await _stored_vm()
    gate = SimpleNamespace(check_payment=AsyncMock(return_value="test-owner"))
    authorized = await orch.get_vm("vm_lifecycle")
    request = Request(
        {"type": "http", "method": "POST", "path": "/fixture", "headers": []}
    )
    if power == "error":
        orch.xcpng.get_vm_power_state.side_effect = RuntimeError("provider unavailable")
    else:
        orch.xcpng.get_vm_power_state.return_value = power
    try:
        if power == "Halted":
            result = await extend_vm(
                "vm_lifecycle",
                VMExtendRequest(days=3),
                request,
                authorized,
                orch,
                HyruleConfig(),
                gate,
            )
            assert result["status"] == "running"
            gate.check_payment.assert_awaited_once()
            orch.xcpng.start_vm.assert_awaited_once_with("test-guest")
        else:
            with pytest.raises(HTTPException) as refused:
                await extend_vm(
                    "vm_lifecycle",
                    VMExtendRequest(days=3),
                    request,
                    authorized,
                    orch,
                    HyruleConfig(),
                    gate,
                )
            assert refused.value.status_code == 503
            gate.check_payment.assert_not_awaited()
            orch.xcpng.start_vm.assert_not_awaited()
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


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['delete', 'reboot'])
@pytest.mark.parametrize('revocation', ['disable', 'demote'])
async def test_public_admin_action_rechecks_privilege_under_lifecycle_lock(action, revocation):
    from datetime import UTC, datetime

    orch, engine = await _stored_vm()
    orch.xcpng.reboot_vm = AsyncMock()
    try:
        async with orch.db.begin() as session:
            owner = AccountRow(account_id='HOWNER00000', password_hash='fixture')
            actor = AccountRow(account_id='HACTOR00000', password_hash='fixture', is_admin=True)
            session.add_all([owner, actor])
            await session.flush()
            vm = await session.get(VMRow, 'vm_lifecycle')
            vm.owner_account_id = owner.account_id
        authorized = await orch.get_vm('vm_lifecycle')
        async with orch.db.begin() as session:
            current = await session.get(AccountRow, actor.account_id)
            if revocation == 'disable':
                current.disabled_at = datetime.now(UTC)
            else:
                current.is_admin = False

        request = Request({
            'type': 'http', 'method': 'POST', 'path': '/fixture',
            'query_string': b'', 'headers': [],
        })
        with pytest.raises(HTTPException) as refused:
            if action == 'reboot':
                await routes.reboot_vm('vm_lifecycle', request, authorized, orch, actor)
            else:
                await routes.destroy_vm('vm_lifecycle', request, authorized, orch, actor)
        assert refused.value.status_code == 403
        orch.xcpng.reboot_vm.assert_not_awaited()
        orch.xcpng.destroy_vm.assert_not_awaited()
        async with orch.db() as session:
            assert (await session.get(VMRow, 'vm_lifecycle')).deletion_started_at is None
    finally:
        await engine.dispose()
