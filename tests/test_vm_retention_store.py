from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import Base, VMRetentionRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.providers.xcpng import VMProtectionManifest
from hyrule_cloud.services.vm_retention import prepare_retention, stored_manifest


@pytest.mark.asyncio
@pytest.mark.parametrize('rollback', [False, True])
async def test_retention_is_transactional_and_survives_resource_deletion(rollback):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    deadline = datetime.now(UTC) + timedelta(days=30)
    manifest = VMProtectionManifest('guest', ('disk',), (), True, "restart", ())
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sessions.begin() as session:
            session.add(VMRow(vm_id='vm_retained', xcpng_uuid='guest', owner_wallet='original-owner',
                              status=VMStatus.SUSPENDED, os='debian-13', ssh_pubkey='fixture-key'))
        async with sessions() as session:
            await prepare_retention(session, 'vm_retained', manifest, deadline)
            if rollback:
                await session.rollback()
            else:
                await session.commit()
        async with sessions() as session:
            saved = await session.get(VMRetentionRow, 'vm_retained')
            assert (saved is None) == rollback
        if rollback:
            return
        async with sessions.begin() as session:
            vm = await session.get(VMRow, 'vm_retained')
            vm.owner_wallet = 'changed-owner'
        async with sessions.begin() as session:
            retry = await prepare_retention(session, 'vm_retained', manifest, deadline + timedelta(days=7))
            assert retry.owner_wallet == 'original-owner'
            assert retry.retain_until.replace(tzinfo=UTC) == deadline
            changed = VMProtectionManifest('guest', ('different',), (), True, 'restart', ())
            with pytest.raises(ValueError, match='cannot be replaced'):
                await prepare_retention(session, 'vm_retained', changed, deadline)
        async with sessions.begin() as session:
            await session.delete(await session.get(VMRow, 'vm_retained'))
        async with sessions() as session:
            saved = await session.get(VMRetentionRow, 'vm_retained')
            assert saved.source_vm_uuid == 'guest'
            assert saved.state == 'prepared'
            assert saved.manifest['disk_ids'][0] == 'disk'
            assert saved.restore_config['os'] == 'debian-13'
            assert stored_manifest(saved) == manifest
            assert saved.manifest['mode'] == 'whole_vm'
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_restore_authorization_preserves_changed_expiry():
    from uuid import uuid4

    from hyrule_cloud.services.vm_retention import authorize_restore, prepare_restore
    from tests.test_vm_expiry_renewal import _stored_vm

    orch, engine = await _stored_vm(VMStatus.SUSPENDED)
    now = datetime.now(UTC)
    try:
        async with orch.db.begin() as session:
            vm = await session.get(VMRow, 'vm_lifecycle')
            vm.deletion_started_at = now
            retained = await prepare_retention(session, vm.vm_id,
                VMProtectionManifest(vm.xcpng_uuid, ('disk',), (), False, '', ()), now + timedelta(days=30))
            retained.state = 'retained'
            operation = await prepare_restore(session, vm, operation_id=str(uuid4()), actor_account_id='fixture-admin', days=7, reason='fixture restore')
            await session.commit()
        async with orch.db.begin() as session:
            vm = await session.get(VMRow, 'vm_lifecycle')
            vm.expires_at = now + timedelta(days=60)
        async with orch.db.begin() as session:
            from hyrule_cloud.db import VMRestoreRow
            vm = await session.get(VMRow, 'vm_lifecycle')
            operation = await session.get(VMRestoreRow, operation.operation_id)
            with pytest.raises(ValueError, match='Recovery identity'):
                await authorize_restore(session, vm, operation)
            assert vm.expires_at.replace(tzinfo=UTC) == now + timedelta(days=60)
            assert operation.state == 'pending'
    finally:
        await engine.dispose()
