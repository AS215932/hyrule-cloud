"""Waived VM acceptance rechecks the selected actor inside its transaction."""
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import AccountRow, VMRow
from hyrule_cloud.middleware.x402 import AdminBypassContext, admin_waiver_dispatch_guard
from hyrule_cloud.models import VMCreateRequest, VMSize
from tests.test_vm_expiry_renewal import _stored_vm


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['activate', 'create'])
@pytest.mark.parametrize('revoked', [False, True])
async def test_selected_vm_waiver_actor_is_fenced_at_acceptance(action, revoked, monkeypatch):
    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: False)
    orch, engine = await _stored_vm()
    orch.config = HyruleConfig()
    orch._spawn_provisioning = AsyncMock()
    actor_id = 'HADMIN00001'
    request = Request({'type': 'http', 'method': 'POST', 'path': '/v1/vm/create', 'headers': []})
    request.state.payment_mode = 'admin-bypass'
    request.state.admin_bypass_context = AdminBypassContext(actor_id, 'real_cost')
    async with orch.db.begin() as session:
        session.add(AccountRow(account_id=actor_id, password_hash='fixture', is_admin=True))
        await session.flush()
        row = await session.get(VMRow, 'vm_lifecycle')
        row.owner_account_id = actor_id
    guard = admin_waiver_dispatch_guard(request)
    if revoked:
        async with orch.db.begin() as session:
            (await session.get(AccountRow, actor_id)).is_admin = False
    try:
        async def accept():
            if action == 'activate':
                return await orch.activate_vm_reservation('vm_lifecycle', owner_wallet='waived-owner',
                    owner_account_id=actor_id, start_provisioning=False, admin_waived=True,
                    dispatch_guard=guard)
            return await orch.create_vm(VMCreateRequest(duration_days=1, size=VMSize.XS,
                ssh_pubkey='ssh-ed25519 fixture'), owner_wallet='waived-owner', owner_account_id=actor_id,
                vm_id='vm_waived_create', start_provisioning=False, admin_waived=True, dispatch_guard=guard)

        if revoked:
            with pytest.raises(HTTPException) as denied:
                await accept()
            assert denied.value.status_code == 403
        else:
            assert await accept() is not None
        orch._spawn_provisioning.assert_not_awaited()
        async with orch.db() as session:
            original = await session.get(VMRow, 'vm_lifecycle')
            assert original.owner_wallet == ('waived-owner' if action == 'activate' and not revoked else 'test-owner')
            created = await session.scalar(select(VMRow).where(VMRow.vm_id == 'vm_waived_create'))
            assert (created is not None) == (action == 'create' and not revoked)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('revoked', [False, True])
async def test_vm_extension_waiver_fences_actor_before_owner_lock(monkeypatch, revoked):
    monkeypatch.setattr('hyrule_cloud.api.routes._require_vm_service_open', lambda gate: None)
    from datetime import UTC, datetime, timedelta

    from hyrule_cloud.api.routes import extend_vm
    from hyrule_cloud.models import VMExtendRequest
    from tests.test_admin_control_plane import _admin_credentials, _admin_gate, _browser_request

    orch, engine = await _stored_vm()
    orch.config = HyruleConfig()
    try:
        credentials = await _admin_credentials(orch.db, elevated=True)
        gate = _admin_gate(orch.db)
        request = _browser_request(credentials, path='/v1/vm/vm_lifecycle/extend')
        async with orch.db.begin() as session:
            row = await session.get(VMRow, 'vm_lifecycle')
            row.owner_account_id = 'HAAAAAAAAAA'
            row.expires_at = datetime.now(UTC) + timedelta(days=1)
        authorized = await orch.get_vm('vm_lifecycle')
        original_expiry = authorized.expires_at
        select_guard = gate.prospective_admin_dispatch_guard

        async def revoke_after_selection(req):
            guard = await select_guard(req)
            if revoked:
                async with orch.db.begin() as session:
                    (await session.get(AccountRow, 'HAAAAAAAAAA')).is_admin = False
            return guard

        monkeypatch.setattr(gate, 'prospective_admin_dispatch_guard', revoke_after_selection)
        if revoked:
            with pytest.raises(HTTPException) as denied:
                await extend_vm('vm_lifecycle', VMExtendRequest(days=2), request,
                                authorized, orch, orch.config, gate)
            assert denied.value.status_code == 403
        else:
            assert await extend_vm('vm_lifecycle', VMExtendRequest(days=2), request,
                                   authorized, orch, orch.config, gate)
        updated = await orch.get_vm('vm_lifecycle')
        assert (updated.expires_at > original_expiry) == (not revoked)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['GET', 'POST'])
@pytest.mark.parametrize('revoked', [False, True])
async def test_external_waiver_fences_actor_before_proxy_dispatch(monkeypatch, method, revoked):
    from hyrule_cloud.api.routes import proxy_network_request
    from hyrule_cloud.models import NetworkRequest
    from tests.test_admin_control_plane import _admin_credentials, _admin_gate, _browser_request
    from tests.test_api import MockNetworkProvider

    orch, engine = await _stored_vm()
    try:
        credentials = await _admin_credentials(orch.db, elevated=True)
        gate = _admin_gate(orch.db)
        request = _browser_request(credentials, path='/v1/network/request')
        provider = MockNetworkProvider()
        select_guard = gate.prospective_admin_dispatch_guard

        async def revoke_after_selection(req):
            guard = await select_guard(req)
            if revoked:
                async with orch.db.begin() as session:
                    (await session.get(AccountRow, 'HAAAAAAAAAA')).is_admin = False
            return guard

        monkeypatch.setattr(gate, 'prospective_admin_dispatch_guard', revoke_after_selection)
        body = NetworkRequest(url='https://example.com', method=method)
        if revoked:
            with pytest.raises(HTTPException) as denied:
                await proxy_network_request(body, request, HyruleConfig(), gate, provider)
            assert denied.value.status_code == 403
        else:
            result = await proxy_network_request(body, request, HyruleConfig(), gate, provider)
            assert result.status_code == 200
        assert len(provider.requests) == int(not revoked)
    finally:
        await engine.dispose()
