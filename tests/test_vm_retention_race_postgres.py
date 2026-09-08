"""Opt-in proof of actual PostgreSQL recovery/expiry lifecycle serialization."""
import asyncio
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api.admin import RetainedRestoreRequest, restore_retained_vm
from hyrule_cloud.api.auth import _account_deletion_snapshot
from hyrule_cloud.db import AccountRow, AdminAuditRow, VMRestoreRow, VMRetentionRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.xcpng import VMProtectionManifest
from hyrule_cloud.services.vm_retention import prepare_retention


@pytest.mark.asyncio
async def test_recovery_serializes_with_expiry_and_account_disable():
    url = os.getenv('HCP_RETENTION_RACE_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local retention_race_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'retention_race_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    engines = [create_async_engine(url, connect_args={'server_settings': {'application_name': name}})
               for name in ('retention-api-fixture', 'retention-worker-fixture', 'retention-observer-fixture')]
    sessions = async_sessionmaker(engines[2], expire_on_commit=False)
    tasks, releases = [], []
    actor = AccountRow(account_id='HADMIN00001', password_hash='fixture', is_admin=True)
    request = Request({'type': 'http', 'method': 'POST', 'path': '/fixture', 'headers': []})

    def orchestrator(engine):
        obj = object.__new__(Orchestrator)
        obj.db = async_sessionmaker(engine, expire_on_commit=False)
        obj.config = SimpleNamespace(vm_expiry_retention_enabled=False)
        obj.xcpng = SimpleNamespace(protect_retained_vm=AsyncMock(), restore_retained_vm=AsyncMock(),
                                    destroy_vm=AsyncMock(side_effect=AssertionError('unexpected destruction')))
        return obj

    async def blocked(application):
        # Observe an actual lock waiter, rather than infer blocking from a sleep.
        async with asyncio.timeout(5):
            while True:
                async with engines[2].connect() as conn:
                    waiting = await conn.scalar(text(
                        'SELECT EXISTS(SELECT 1 FROM pg_stat_activity '
                        'WHERE application_name=:app AND cardinality(pg_blocking_pids(pid)) > 0)'
                    ), {'app': application})
                if waiting:
                    return
                await asyncio.sleep(0.02)

    try:
        async with engines[2].connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0
        migrated = subprocess.run(
            [sys.executable, '-m', 'alembic', 'upgrade', 'head'],
            cwd=Path(__file__).resolve().parents[1], env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True, text=True, timeout=120,
        )
        assert migrated.returncode == 0, migrated.stderr
        async with sessions.begin() as session:
            session.add(actor)
        for index, ordering in enumerate(('restore_first', 'protect_first', 'stale_protect', 'disable_first')):
            vm_id = f'vm_{ordering}'
            guest = str(uuid4())
            manifest = VMProtectionManifest(guest, (str(uuid4()),), (), True, 'restart', ())
            now = datetime.now(UTC)
            async with sessions.begin() as session:
                session.add(VMRow(vm_id=vm_id, owner_wallet='fixture', owner_account_id=actor.account_id,
                                  status=VMStatus.SUSPENDED, xcpng_uuid=guest,
                                  expires_at=now - timedelta(days=3), deletion_started_at=now,
                                  suspension_reason='expired', ipv6_prefix_index=40 + index))
            async with sessions.begin() as session:
                retained = await prepare_retention(session, vm_id, manifest, now + timedelta(days=30))
                retained.state = 'retained'
                retained.retained_at = now
            api, worker = orchestrator(engines[0]), orchestrator(engines[1])
            body = RetainedRestoreRequest(operation_id=uuid4(), days=7, reason='PostgreSQL recovery fixture')
            entered, release = asyncio.Event(), asyncio.Event()
            releases.append(release)

            async def recover():
                return await restore_retained_vm(vm_id, body, request, actor, SimpleNamespace(orchestrator=api))

            async def sweep():
                return await worker.destroy_vm(vm_id, expired_before=now - timedelta(days=2))

            async def held_provider(received):
                assert received == manifest
                entered.set()
                await release.wait()

            if ordering == 'disable_first':
                async with sessions.begin() as session:
                    owner = await session.scalar(select(AccountRow).where(
                        AccountRow.account_id == actor.account_id).with_for_update())
                    owner.disabled_at = now
                    await session.flush()
                    recovery = asyncio.create_task(recover())
                    tasks.append(recovery)
                    await blocked('retention-api-fixture')
                with pytest.raises(HTTPException) as exc:
                    await asyncio.wait_for(recovery, 5)
                assert exc.value.status_code == 409
                api.xcpng.restore_retained_vm.assert_not_awaited()
                async with sessions.begin() as session:
                    owner = await session.get(AccountRow, actor.account_id)
                    owner.disabled_at = None
                assert (await recover())['state'] == 'completed'
            elif ordering == 'stale_protect':
                real_locked_vm = worker.locked_vm
                calls = 0

                @asynccontextmanager
                async def delayed_second_lock(resource):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        entered.set()
                        await release.wait()
                    async with real_locked_vm(resource) as pair:
                        yield pair

                worker.locked_vm = delayed_second_lock
                expiry = asyncio.create_task(sweep())
                tasks.append(expiry)
                await asyncio.wait_for(entered.wait(), 5)
                assert (await recover())['state'] == 'completed'
                release.set()
                assert await asyncio.wait_for(expiry, 5) is False
                worker.xcpng.protect_retained_vm.assert_not_awaited()
            else:
                if ordering == 'restore_first':
                    api.xcpng.restore_retained_vm.side_effect = held_provider
                    first = asyncio.create_task(recover())
                    tasks.append(first)
                    await asyncio.wait_for(entered.wait(), 5)
                    second = asyncio.create_task(sweep())
                    tasks.append(second)
                    await blocked('retention-worker-fixture')
                else:
                    worker.xcpng.protect_retained_vm.side_effect = held_provider
                    first = asyncio.create_task(sweep())
                    tasks.append(first)
                    await asyncio.wait_for(entered.wait(), 5)
                    second = asyncio.create_task(recover())
                    tasks.append(second)
                    await blocked('retention-api-fixture')
                release.set()
                outcomes = await asyncio.wait_for(asyncio.gather(first, second), 5)
                restored = outcomes[0] if ordering == 'restore_first' else outcomes[1]
                assert restored['state'] == 'completed'
                assert outcomes[1 if ordering == 'restore_first' else 0] is (ordering == 'protect_first')
                assert worker.xcpng.protect_retained_vm.await_count == int(ordering == 'protect_first')
            async with sessions() as session:
                vm = await session.get(VMRow, vm_id)
                assert vm.status == VMStatus.SUSPENDED and vm.deletion_started_at is None
                assert vm.ipv6_prefix_index == 40 + index and vm.expires_at > now + timedelta(days=6)
                assert await session.get(VMRetentionRow, vm_id) is None
                operation = await session.get(VMRestoreRow, str(body.operation_id))
                assert operation.state == 'completed' and operation.retention_snapshot['manifest']['vm_uuid'] == guest
                audits = list(await session.scalars(select(AdminAuditRow).where(AdminAuditRow.target_id == vm_id)))
                assert sorted(audit.action for audit in audits) == ['vm.restore_completed', 'vm.restore_requested']
            worker.xcpng.destroy_vm.assert_not_awaited()
            api.xcpng.restore_retained_vm.assert_awaited_once_with(manifest)
        # Account deletion and initial retention use the same account-first fence.
        for index, retention_first in enumerate((True, False)):
            owner_id, vm_id = f'HDELETE000{index}', f'vm_delete_race_{index}'
            guest = str(uuid4())
            manifest = VMProtectionManifest(guest, (str(uuid4()),), (), False, '', ())
            async with sessions.begin() as session:
                session.add(AccountRow(account_id=owner_id, password_hash='fixture'))
                session.add(VMRow(vm_id=vm_id, owner_account_id=owner_id, owner_wallet='fixture',
                                  status=VMStatus.SUSPENDED, xcpng_uuid=guest,
                                  expires_at=datetime.now(UTC) - timedelta(days=3)))
            api, worker = orchestrator(engines[0]), orchestrator(engines[1])

            async def deletion_snapshot():
                async with api.db() as session:
                    return await _account_deletion_snapshot(session, owner_id)

            async def claim_retention():
                async with worker.locked_vm(vm_id) as (session, vm):
                    await prepare_retention(session, vm_id, manifest, datetime.now(UTC) + timedelta(days=30))
                    vm.deletion_started_at = datetime.now(UTC)
                    await session.commit()

            if retention_first:
                async with worker.locked_vm(vm_id) as (session, vm):
                    await prepare_retention(session, vm_id, manifest, datetime.now(UTC) + timedelta(days=30))
                    vm.deletion_started_at = datetime.now(UTC)
                    task = asyncio.create_task(deletion_snapshot())
                    tasks.append(task)
                    await blocked('retention-api-fixture')
                    await session.commit()
                with pytest.raises(HTTPException) as refused:
                    await asyncio.wait_for(task, 5)
                assert refused.value.status_code == 409
                async with sessions() as session:
                    assert (await session.get(VMRow, vm_id)).owner_account_id == owner_id
                    assert (await session.get(VMRetentionRow, vm_id)).owner_account_id == owner_id
            else:
                async with api.db() as session:
                    account, vms = await _account_deletion_snapshot(session, owner_id)
                    task = asyncio.create_task(claim_retention())
                    tasks.append(task)
                    await blocked('retention-worker-fixture')
                    vms[0].owner_account_id = None
                    await session.delete(account)
                    await session.commit()
                with pytest.raises(RuntimeError, match='ownership changed'):
                    await asyncio.wait_for(task, 5)
                async with sessions() as session:
                    assert await session.get(AccountRow, owner_id) is None
                    assert (await session.get(VMRow, vm_id)).owner_account_id is None
                    assert await session.get(VMRetentionRow, vm_id) is None
    finally:
        for release in releases:
            release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
