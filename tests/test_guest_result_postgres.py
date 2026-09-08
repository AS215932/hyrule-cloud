"""Opt-in proof of migration safety and actual PostgreSQL receipt locking."""
import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import VMGuestResultRow, VMRow
from hyrule_cloud.models import VMStatus
from hyrule_cloud.services.guest_result import (
    GuestResult,
    GuestResultRejectedError,
    accept_guest_result,
    prepare_guest_result,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_postgres_concurrent_receipts_and_downgrade_guard():
    url = os.environ.get('HCP_GUEST_RESULT_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh disposable guest_result_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'guest_result_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    env = dict(os.environ, HYRULE_DATABASE_URL=url)

    def migrate(direction, revision, *, check=True):
        return subprocess.run([sys.executable, '-m', 'alembic', direction, revision],
                              cwd=ROOT, env=env, capture_output=True, text=True,
                              timeout=120, check=check)

    engines = [create_async_engine(url, pool_size=1, max_overflow=0) for _ in range(3)]
    first_factory, second_factory, observer_factory = [async_sessionmaker(e, expire_on_commit=False) for e in engines]
    contender = None
    try:
        async with observer_factory() as session:
            count = await session.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"))
            assert count == 0, 'requires an empty database; never replaces existing tables'
        migrate('upgrade', 'head')
        async with first_factory.begin() as session:
            session.add(VMRow(vm_id='vm_pg_guest', owner_wallet='test', vcpu=1, memory_mb=1024, disk_gb=10))
        async with first_factory.begin() as session:
            generation, token = await prepare_guest_result(session, 'vm_pg_guest', datetime.now(UTC) + timedelta(minutes=10))
        started = asyncio.Event()
        contender_pid = None

        async def conflicting_report():
            nonlocal contender_pid
            async with second_factory.begin() as session:
                contender_pid = await session.scalar(text('SELECT pg_backend_pid()'))
                started.set()
                try:
                    await accept_guest_result(session, 'vm_pg_guest', generation, token,
                                              GuestResult(outcome='succeeded', stage='cloud_init', exit_code=0))
                except GuestResultRejectedError as exc:
                    return exc.status_code
                return 204

        async with first_factory() as owner:
            owner_pid = await owner.scalar(text('SELECT pg_backend_pid()'))
            await accept_guest_result(owner, 'vm_pg_guest', generation, token,
                                      GuestResult(outcome='failed', stage='setup_script', exit_code=7))
            contender = asyncio.create_task(conflicting_report())
            await asyncio.wait_for(started.wait(), 5)
            blocked = False
            for _ in range(100):
                async with observer_factory() as observer:
                    blockers = await observer.scalar(text('SELECT pg_blocking_pids(:pid)'), {'pid': contender_pid})
                if owner_pid in blockers:
                    blocked = True
                    break
                await asyncio.sleep(0.01)
            assert blocked, 'must prove actual row lock contention, not merely task timing'
            assert not contender.done()
            await owner.commit()
        assert await asyncio.wait_for(contender, 5) == 409
        async with observer_factory() as session:
            receipt = await session.get(VMGuestResultRow, 'vm_pg_guest')
            assert (receipt.outcome, receipt.stage, receipt.exit_code) == ('failed', 'setup_script', 7)
        # Parent is still provisioning until the orchestrator consumes the report.
        rejected = migrate('downgrade', '020', check=False)
        assert rejected.returncode != 0
        assert 'Refusing to remove guest receipts while provisioning is active' in rejected.stderr
        async with observer_factory() as session:
            assert await session.scalar(text('SELECT version_num FROM alembic_version')) == '022'
            assert await session.get(VMGuestResultRow, 'vm_pg_guest') is not None
        async with first_factory.begin() as session:
            vm = await session.get(VMRow, 'vm_pg_guest')
            vm.status = VMStatus.FAILED
        migrate('downgrade', '020')
        migrate('upgrade', 'head')
        async with observer_factory() as session:
            assert (await session.get(VMRow, 'vm_pg_guest')).status == VMStatus.FAILED
    finally:
        if contender is not None and not contender.done():
            contender.cancel()
            await asyncio.gather(contender, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
