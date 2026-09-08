from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import Base, VMRetentionRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.providers.xcpng import RetainedDisk, VMRetentionManifest
from hyrule_cloud.services.vm_retention import prepare_retention


@pytest.mark.asyncio
@pytest.mark.parametrize('rollback', [False, True])
async def test_retention_is_transactional_and_survives_resource_deletion(rollback):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    deadline = datetime.now(UTC) + timedelta(days=30)
    manifest = VMRetentionManifest('guest', (RetainedDisk('disk', 'sr', 4096, '0', True, False),))
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
            changed = VMRetentionManifest('guest', (RetainedDisk('different', 'sr', 4096, '0', True, False),))
            with pytest.raises(ValueError, match='cannot be replaced'):
                await prepare_retention(session, 'vm_retained', changed, deadline)
        async with sessions.begin() as session:
            await session.delete(await session.get(VMRow, 'vm_retained'))
        async with sessions() as session:
            saved = await session.get(VMRetentionRow, 'vm_retained')
            assert saved.source_vm_uuid == 'guest'
            assert saved.state == 'prepared'
            assert saved.manifest['disks'][0]['vdi_uuid'] == 'disk'
            assert saved.restore_config['os'] == 'debian-13'
    finally:
        await engine.dispose()
