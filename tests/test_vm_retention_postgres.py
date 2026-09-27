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

from hyrule_cloud.db import VMRestoreRow, VMRetentionRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.providers.xcpng import VMProtectionManifest
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
        manifest = VMProtectionManifest(uuid, (disk,), (), True, "restart", ())
        deadline = datetime.now(UTC) + timedelta(days=30)
        async with sessions.begin() as session:
            session.add(VMRow(vm_id='vm_retention_fixture', xcpng_uuid=uuid, owner_wallet='fixture-owner',
                              status=VMStatus.SUSPENDED, os='debian-13'))
        async with sessions.begin() as session:
            retained = await prepare_retention(session, 'vm_retention_fixture', manifest, deadline)
            retained.last_verified_at = deadline - timedelta(days=30)
            retained.verification_attempted_at = retained.last_verified_at + timedelta(minutes=1)
            retained.verification_error = 'provider_verification_failed'
            retained.next_verification_at = deadline - timedelta(days=29)
        result = migrate('downgrade', '020')
        assert result.returncode != 0
        assert 'Preserve and reconcile VM retention records before downgrade' in result.stderr
        async with sessions.begin() as session:
            assert await session.scalar(text('SELECT version_num FROM alembic_version')) == '025'
            saved = await session.get(VMRetentionRow, 'vm_retention_fixture')
            assert saved.retain_until == deadline
            assert saved.manifest['disk_ids'][0] == disk
            await session.delete(await session.get(VMRow, 'vm_retention_fixture'))
        # Reconnect and prove recovery evidence remains without a live VM row.
        await engine.dispose()
        async with sessions() as session:
            saved = await session.get(VMRetentionRow, 'vm_retention_fixture')
            assert saved.owner_wallet == 'fixture-owner'
            assert saved.source_vm_uuid == uuid
            assert saved.restore_config['os'] == 'debian-13'
            assert saved.last_verified_at == deadline - timedelta(days=30)
            assert saved.verification_attempted_at == deadline - timedelta(days=30) + timedelta(minutes=1)
            assert saved.verification_error == 'provider_verification_failed'
            assert saved.next_verification_at == deadline - timedelta(days=29)
            assert await session.get(VMRow, 'vm_retention_fixture') is None
        # Completed recovery evidence must independently prevent schema removal,
        # including when neither the VM nor active retention row remains.
        operation_id = '00000000-0000-0000-0000-000000000003'
        async with sessions.begin() as session:
            saved = await session.get(VMRetentionRow, 'vm_retention_fixture')
            session.add(VMRestoreRow(
                operation_id=operation_id, vm_id=saved.vm_id, actor_account_id='HAAAAAAAAAA',
                days=7, reason='Fixture recovery history', state='completed',
                retention_snapshot={'manifest': saved.manifest, 'owner_wallet': saved.owner_wallet},
                new_expiry=deadline, completed_at=datetime.now(UTC),
            ))
            await session.delete(saved)
        result = migrate('downgrade', '020')
        assert result.returncode != 0
        assert 'Preserve and reconcile VM retention records before downgrade' in result.stderr
        await engine.dispose()
        async with sessions() as session:
            assert await session.scalar(text('SELECT version_num FROM alembic_version')) == '025'
            assert await session.get(VMRetentionRow, 'vm_retention_fixture') is None
            history = await session.get(VMRestoreRow, operation_id)
            assert history.retention_snapshot['manifest']['disk_ids'] == [disk]
            assert history.state == 'completed'
    finally:
        await engine.dispose()
