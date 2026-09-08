from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from hyrule_cloud.api.routes import destroy_vm as destroy_vm_route
from hyrule_cloud.db import VMRetentionRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.providers.xcpng import VMProtectionManifest
from tests.test_vm_expiry_renewal import _stored_vm


@pytest.mark.asyncio
@pytest.mark.parametrize('initial_expiry_delete', [False, True])
async def test_sweep_does_not_convert_existing_delete_claim_to_retention(initial_expiry_delete):
    orch, engine = await _stored_vm(VMStatus.SUSPENDED)
    orch.config.vm_expiry_retention_enabled = not initial_expiry_delete
    orch.config.vm_retention_days = 30
    orch.xcpng.capture_vm_protection = AsyncMock()
    orch.xcpng.protect_retained_vm = AsyncMock()
    orch.xcpng.destroy_vm.side_effect = [ConnectionError('interrupted delete'), None]
    try:
        kwargs = {'expired_before': datetime.now(UTC) - timedelta(days=2)} if initial_expiry_delete else {}
        with pytest.raises(ConnectionError, match='interrupted delete'):
            await orch.destroy_vm('vm_lifecycle', **kwargs)
        async with orch.db() as session:
            assert (await session.get(VMRow, 'vm_lifecycle')).deletion_started_at is not None
            assert await session.get(VMRetentionRow, 'vm_lifecycle') is None
        # Includes a legacy expiry claim made before the retention rollout.
        orch.config.vm_expiry_retention_enabled = True
        await orch.check_expiries()
        async with orch.db() as session:
            assert (await session.get(VMRow, 'vm_lifecycle')).status == VMStatus.DESTROYED
            assert await session.get(VMRetentionRow, 'vm_lifecycle') is None
        assert orch.xcpng.destroy_vm.await_count == 2
        orch.xcpng.capture_vm_protection.assert_not_awaited()
        orch.xcpng.protect_retained_vm.assert_not_awaited()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('interrupted', [False, True])
async def test_expiry_commits_retention_before_delete_and_preserves_it_on_retry(interrupted):
    orch, engine = await _stored_vm(VMStatus.SUSPENDED)
    orch.config.vm_expiry_retention_enabled = True
    orch.config.vm_retention_days = 30
    manifest = VMProtectionManifest('test-guest', ('disk',), (), True, "restart", ())
    orch.xcpng.capture_vm_protection = AsyncMock(return_value=manifest)
    observations = []

    async def preserve_delete(received):
        assert received == manifest
        # Separate session observes committed evidence before the provider action.
        async with orch.db() as session:
            row = await session.get(VMRow, 'vm_lifecycle')
            saved = await session.get(VMRetentionRow, 'vm_lifecycle')
            assert row.deletion_started_at is not None
            assert saved.manifest['disk_ids'][0] == 'disk'
            assert saved.owner_wallet == 'test-owner'
            assert saved.state in {'prepared', 'retained'}
        observations.append(True)
        if interrupted and len(observations) == 1:
            raise ConnectionError('provider verification unavailable')

    orch.xcpng.protect_retained_vm = AsyncMock(side_effect=preserve_delete)
    try:
        async with orch.db.begin() as session:
            row = await session.get(VMRow, 'vm_lifecycle')
            row.ipv6_prefix_index = 7
            row.ipv6_prefix = '2a0c:b641:b51:7::/64'
        if interrupted:
            with pytest.raises(ConnectionError):
                await orch.destroy_vm('vm_lifecycle', expired_before=datetime.now(UTC) - timedelta(days=2))
            async with orch.db() as session:
                assert (await session.get(VMRow, 'vm_lifecycle')).status == VMStatus.SUSPENDED
                assert (await session.get(VMRetentionRow, 'vm_lifecycle')).state == 'prepared'
            orch.config.vm_expiry_retention_enabled = False
            # A customer retry without the expiry parameter must still retain disks.
            assert await orch.destroy_vm('vm_lifecycle')
        else:
            assert await orch.destroy_vm('vm_lifecycle', expired_before=datetime.now(UTC) - timedelta(days=2))
        async with orch.db() as session:
            assert (await session.get(VMRow, 'vm_lifecycle')).status == VMStatus.SUSPENDED
            assert (await session.get(VMRow, 'vm_lifecycle')).ipv6_prefix_index == 7
            saved = await session.get(VMRetentionRow, 'vm_lifecycle')
            assert saved.state == 'retained'
            assert saved.retained_at is not None
        response = await destroy_vm_route('vm_lifecycle', await orch.get_vm('vm_lifecycle'), orch)
        assert response.status == 'retained'
        assert 'stopped and retained' in response.message
        orch.xcpng.capture_vm_protection.assert_awaited_once_with('test-guest')
        orch.xcpng.destroy_vm.assert_not_awaited()
        async with orch.db.begin() as session:
            saved = await session.get(VMRetentionRow, 'vm_lifecycle')
            saved.state = 'restoring'
        orch.xcpng.protect_retained_vm.reset_mock()
        assert not await orch.destroy_vm('vm_lifecycle')
        orch.xcpng.protect_retained_vm.assert_not_awaited()
    finally:
        await engine.dispose()
