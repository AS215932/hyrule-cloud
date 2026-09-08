"""Opt-in migration and retention-evidence preservation proof."""
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import VMRetentionRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.providers.xcpng import RetainedDisk, VMRetentionManifest
from hyrule_cloud.services.vm_retention import prepare_retention


@pytest.mark.asyncio
async def test_retention_migration_refuses_to_erase_recovery_evidence():
    url = os.getenv('HCP_RETENTION_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local retention_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'retention_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    engine = create_async_engine(url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    def migrate(direction, revision):
        return subprocess.run(
            [sys.executable, '-m', 'alembic', direction, revision],
            cwd=Path(__file__).resolve().parents[1],
            env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True, text=True, timeout=120,
        )

    try:
        async with engine.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0
        for direction, target in [('upgrade', 'head'), ('downgrade', '020'), ('upgrade', 'head')]:
            result = migrate(direction, target)
            assert result.returncode == 0, result.stderr
        uuid = '00000000-0000-0000-0000-000000000001'
        disk = '00000000-0000-0000-0000-000000000002'
        manifest = VMRetentionManifest(uuid, (RetainedDisk(disk, 'fixture-sr', 4096, '0', True, False),))
        deadline = datetime.now(UTC) + timedelta(days=30)
        async with sessions.begin() as session:
            session.add(VMRow(vm_id='vm_retention_fixture', xcpng_uuid=uuid, owner_wallet='fixture-owner',
                              status=VMStatus.SUSPENDED, os='debian-13'))
        async with sessions.begin() as session:
            await prepare_retention(session, 'vm_retention_fixture', manifest, deadline)
        result = migrate('downgrade', '020')
        assert result.returncode != 0
        assert 'Preserve and reconcile VM retention records before downgrade' in result.stderr
        async with sessions.begin() as session:
            assert await session.scalar(text('SELECT version_num FROM alembic_version')) == '024'
            saved = await session.get(VMRetentionRow, 'vm_retention_fixture')
            assert saved.retain_until == deadline
            assert saved.manifest['disks'][0]['vdi_uuid'] == disk
            await session.delete(await session.get(VMRow, 'vm_retention_fixture'))
        # Reconnect and prove recovery evidence remains without a live VM row.
        await engine.dispose()
        async with sessions() as session:
            saved = await session.get(VMRetentionRow, 'vm_retention_fixture')
            assert saved.owner_wallet == 'fixture-owner'
            assert saved.source_vm_uuid == uuid
            assert saved.restore_config['os'] == 'debian-13'
            assert await session.get(VMRow, 'vm_retention_fixture') is None
    finally:
        await engine.dispose()
