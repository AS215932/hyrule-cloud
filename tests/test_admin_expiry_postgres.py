"""Opt-in operator recovery/deletion race proof on a freshly migrated database."""
import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api.admin import ExpiryExtensionRequest, extend_vm_expiry
from hyrule_cloud.db import AccountRow, AdminAuditRow, PaymentEventRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_admin_extension_serializes_with_deletion_and_rolls_back_audit_failure():
    url = os.getenv('HCP_ADMIN_EXPIRY_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local admin_expiry_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'admin_expiry_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    engines = [create_async_engine(url) for _ in range(3)]
    entered, release, deleting, finish_delete = [asyncio.Event() for _ in range(4)]
    blocker = []
    tasks = []

    class HeldAuditSession(AsyncSession):
        async def commit(self):
            audit = next((row for row in self.new if isinstance(row, AdminAuditRow)), None)
            if audit is not None:
                await self.flush()
                if audit.target_id == 'vm_audit_rollback':
                    raise RuntimeError('fixture failure after audit and expiry flush')
                blocker.append(await self.scalar(text('SELECT pg_backend_pid()')))
                entered.set()
                await release.wait()
            await super().commit()

    def orchestrator(engine, session_class=AsyncSession):
        obj = object.__new__(Orchestrator)
        obj.db = async_sessionmaker(engine, class_=session_class, expire_on_commit=False)
        obj.xcpng = SimpleNamespace(destroy_vm=AsyncMock(), start_vm=AsyncMock())
        return obj

    api, worker = orchestrator(engines[0], HeldAuditSession), orchestrator(engines[1])
    request = Request({'type': 'http', 'method': 'POST', 'path': '/fixture', 'headers': []})
    actor = AccountRow(account_id='HADMIN00001', password_hash='fixture', is_admin=True)
    body = ExpiryExtensionRequest(days=7, reason='Recovery window fixture')
    old_expiry = datetime.now(UTC) - timedelta(days=3)

    async def extend(vm_id):
        return await extend_vm_expiry(vm_id, body, request, actor, SimpleNamespace(orchestrator=api))

    try:
        async with engines[2].connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0
        result = subprocess.run(
            [sys.executable, '-m', 'alembic', 'upgrade', 'head'],
            cwd=Path(__file__).resolve().parents[1], env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
        async with worker.db.begin() as session:
            session.add(actor)
            for vm_id in ('vm_extend_first', 'vm_delete_first', 'vm_audit_rollback'):
                session.add(VMRow(vm_id=vm_id, owner_wallet='fixture', status=VMStatus.SUSPENDED,
                                  xcpng_uuid=vm_id, expires_at=old_expiry, suspension_reason='expired'))
        extension = asyncio.create_task(extend('vm_extend_first'))
        tasks.append(extension)
        await asyncio.wait_for(entered.wait(), 5)
        sweep = asyncio.create_task(worker.destroy_vm('vm_extend_first', expired_before=datetime.now(UTC) - timedelta(days=2)))
        tasks.append(sweep)
        async with asyncio.timeout(5):
            while True:
                async with engines[2].connect() as conn:
                    blocked = await conn.scalar(text(
                        'SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))'
                    ), {'pid': blocker[0]})
                if blocked:
                    break
                await asyncio.sleep(0.02)
        release.set()
        assert (await asyncio.wait_for(extension, 5))['power_changed'] is False
        assert await asyncio.wait_for(sweep, 5) is False
        worker.xcpng.destroy_vm.assert_not_awaited()

        async def held_delete(_uuid):
            deleting.set()
            await finish_delete.wait()

        worker.xcpng.destroy_vm.side_effect = held_delete
        destroy = asyncio.create_task(worker.destroy_vm('vm_delete_first', expired_before=datetime.now(UTC) - timedelta(days=2)))
        tasks.append(destroy)
        await asyncio.wait_for(deleting.wait(), 5)
        with pytest.raises(HTTPException) as rejected:
            await extend('vm_delete_first')
        assert rejected.value.status_code == 409
        finish_delete.set()
        assert await asyncio.wait_for(destroy, 5)
        with pytest.raises(RuntimeError, match='fixture failure'):
            await extend('vm_audit_rollback')
        async with worker.db() as session:
            audits = list(await session.scalars(select(AdminAuditRow)))
            assert len(audits) == 1 and audits[0].target_id == 'vm_extend_first'
            first = await session.get(VMRow, 'vm_extend_first')
            assert first.expires_at > datetime.now(UTC) + timedelta(days=6)
            assert first.deletion_started_at is None and first.status == VMStatus.SUSPENDED
            assert (await session.get(VMRow, 'vm_delete_first')).expires_at == old_expiry
            assert (await session.get(VMRow, 'vm_audit_rollback')).expires_at == old_expiry
        api.xcpng.start_vm.assert_not_awaited()

        # Exercise actual PostgreSQL commits, including acknowledgment failure
        # after the database applied the transaction. Reconciliation uses a new
        # session after the original connection has returned to the pool.
        for committed in (False, True):
            vm_id = f"vm_commit_{committed}"
            expiry = datetime.now(UTC) + timedelta(days=1)
            async with worker.db.begin() as session:
                session.add(VMRow(vm_id=vm_id, owner_wallet="fixture",
                                  status=VMStatus.RUNNING, expires_at=expiry))
            async with worker.locked_vm(vm_id) as (session, _row):
                commit = session.commit

                async def lost_ack():
                    if committed:
                        await commit()
                    else:
                        await session.flush()
                    raise ConnectionError("fixture lost commit acknowledgment")

                session.commit = lost_ack
                result = await worker.extend_vm(vm_id, 3, session=session,
                                                payment_tx=f"fixture-{committed}")
            async with async_sessionmaker(engines[2])() as check:
                stored = await check.get(VMRow, vm_id)
                receipts = list(await check.scalars(select(PaymentEventRow).where(
                    PaymentEventRow.tx_hash == f"fixture-{committed}")))
                assert stored.expires_at == expiry + timedelta(days=3 if committed else 0)
                assert (result is not None) == committed
                assert len(receipts) == int(committed)
                if receipts:
                    assert receipts[0].event_type == "extend_applied"
                    assert receipts[0].amount_usd == 0
        async with engines[2].connect() as conn:
            before = (await conn.execute(text("SELECT vm_id, expires_at FROM vms ORDER BY vm_id"))).all()
        for target in ("020", "head"):
            direction = "downgrade" if target == "020" else "upgrade"
            migration = subprocess.run(
                [sys.executable, "-m", "alembic", direction, target],
                cwd=Path(__file__).resolve().parents[1],
                env=dict(os.environ, HYRULE_DATABASE_URL=url),
                capture_output=True, text=True, timeout=120,
            )
            assert migration.returncode == 0, migration.stderr
            async with engines[2].connect() as conn:
                assert (await conn.execute(text("SELECT vm_id, expires_at FROM vms ORDER BY vm_id"))).all() == before
                assert await conn.scalar(text("SELECT count(*) FROM payment_events WHERE event_type='extend_applied'")) == 1
        # Admin downgrade explicitly drops audit history; this fixture does not
        # imply that a production downgrade preserves it.
        async with engines[2].connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM admin_audit")) == 0
            assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "023"
    finally:
        release.set()
        finish_delete.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
