"""Opt-in PostgreSQL proof using a disposable, explicitly supplied database."""

import asyncio
import os
import runpy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api import routes
from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.models import VMExtendRequest, VMStatus
from hyrule_cloud.orchestrator import Orchestrator

TEST_URL = os.getenv("HCP_LIFECYCLE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="requires disposable PostgreSQL database")


def _orchestrator(engine):
    orch = object.__new__(Orchestrator)
    orch.db = async_sessionmaker(engine, expire_on_commit=False)
    orch.config = SimpleNamespace(vm_grace_period_hours=48)
    orch.xcpng = SimpleNamespace(
        suspend_vm=AsyncMock(), destroy_vm=AsyncMock(),
        get_vm_power_state=AsyncMock(return_value="Halted"), start_vm=AsyncMock(),
    )
    return orch


async def _wait_until_blocked(observer, blocker_pid):
    async with asyncio.timeout(5):
        while True:
            async with observer.connect() as connection:
                waiting = await connection.scalar(text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE :pid = ANY(pg_blocking_pids(pid)))"
                ), {"pid": blocker_pid})
            if waiting:
                return
            await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_renewal_and_expiry_serialize_across_postgres_connections(monkeypatch):
    # This URL is an explicit opt-in test target; never read application config.
    assert TEST_URL is not None and "cloud_lifecycle_test" in TEST_URL
    api_engine = create_async_engine(TEST_URL, pool_size=3)
    worker_engine = create_async_engine(TEST_URL, pool_size=3)
    observer = create_async_engine(TEST_URL, pool_size=1)
    api = _orchestrator(api_engine)
    worker = _orchestrator(worker_engine)
    tasks = []
    release = asyncio.Event()
    try:
        async with api_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with api.db() as session:
            session.add(VMRow(
                vm_id="vm_pg_lifecycle", owner_wallet="test-owner", status=VMStatus.RUNNING,
                xcpng_uuid="test-guest", ssh_pubkey="ssh-ed25519 test",
                expires_at=datetime.now(UTC) - timedelta(days=3),
            ))
            await session.commit()

        # An expiry worker must wait while the API owns the decision/payment
        # boundary, then read the newly committed deadline rather than act.
        async with api.locked_vm("vm_pg_lifecycle") as (session, _):
            pid = await session.scalar(text("SELECT pg_backend_pid()"))
            sweep = asyncio.create_task(worker.check_expiries())
            tasks.append(sweep)
            await _wait_until_blocked(observer, pid)
            await api.extend_vm("vm_pg_lifecycle", 5, session=session)
        await asyncio.wait_for(sweep, 5)
        worker.xcpng.destroy_vm.assert_not_awaited()
        worker.xcpng.suspend_vm.assert_not_awaited()

        # The reverse order is also safe: renewal waits for an in-flight
        # suspend, then resumes the guest and cannot be overwritten by it.
        async with api.db() as session:
            row = await session.get(VMRow, "vm_pg_lifecycle")
            row.expires_at = datetime.now(UTC) - timedelta(hours=1)
            await session.commit()
        entered = asyncio.Event()

        async def suspended(_uuid):
            entered.set()
            await release.wait()

        worker.xcpng.suspend_vm.side_effect = suspended
        sweep = asyncio.create_task(worker.check_expiries())
        tasks.append(sweep)
        await asyncio.wait_for(entered.wait(), 5)
        extension = asyncio.create_task(api.extend_vm("vm_pg_lifecycle", 5))
        tasks.append(extension)
        async with observer.connect() as connection:
            worker_pid = await connection.scalar(text(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() "
                "AND state='idle in transaction' AND query LIKE '%vms.vm_id%' LIMIT 1"
            ))
        assert worker_pid is not None
        await _wait_until_blocked(observer, worker_pid)
        release.set()
        await asyncio.wait_for(asyncio.gather(sweep, extension), 5)
        api.xcpng.start_vm.assert_awaited_once()
        async with api.db() as session:
            row = await session.get(VMRow, "vm_pg_lifecycle")
            assert row.status == VMStatus.RUNNING
            assert row.expires_at > datetime.now(UTC)

        # Provider failure leaves a durable claim visible to a fresh API
        # instance, and the actual route refuses it before calling payment.
        worker.xcpng.destroy_vm.side_effect = RuntimeError("provider unavailable")
        with pytest.raises(RuntimeError, match="provider unavailable"):
            await worker.destroy_vm("vm_pg_lifecycle")
        restarted = _orchestrator(observer)
        gate = SimpleNamespace(check_payment=AsyncMock())
        monkeypatch.setattr(routes, "_require_vm_service_open", lambda _gate: None)
        authorized = await restarted.get_vm("vm_pg_lifecycle")
        assert authorized is not None
        with pytest.raises(HTTPException) as rejected:
            await routes.extend_vm(
                "vm_pg_lifecycle", VMExtendRequest(days=5),
                Request({"type": "http", "method": "POST", "path": "/"}),
                row=authorized, orch=restarted, cfg=None, gate=gate,
            )
        assert rejected.value.status_code == 409
        gate.check_payment.assert_not_awaited()
        migration = runpy.run_path(str(Path(__file__).parents[1] / "alembic/versions/021_vm_deletion_claim.py"))

        def run_migration(connection, operation):
            with Operations.context(MigrationContext.configure(connection)):
                migration[operation]()

        async with api_engine.begin() as connection:
            with pytest.raises(RuntimeError, match="pending VM deletion claims"):
                await connection.run_sync(run_migration, "downgrade")
            await connection.execute(text("UPDATE vms SET status='destroyed' WHERE vm_id='vm_pg_lifecycle'"))
            with pytest.raises(RuntimeError, match="pending VM deletion claims"):
                await connection.run_sync(run_migration, "downgrade")
            await connection.execute(text(
                "UPDATE vms SET metadata=jsonb_build_object('provider_deleted_uuid', xcpng_uuid), "
                "ipv6_prefix_index=7, ipv6_prefix='2a0c:b641:b51:7::/64' "
                "WHERE vm_id='vm_pg_lifecycle'"
            ))
            with pytest.raises(RuntimeError, match="pending VM deletion claims"):
                await connection.run_sync(run_migration, "downgrade")
            await connection.execute(text(
                "UPDATE vms SET ipv6_prefix_index=NULL, ipv6_prefix=NULL "
                "WHERE vm_id='vm_pg_lifecycle'"
            ))
            await connection.run_sync(run_migration, "downgrade")
            await connection.run_sync(run_migration, "upgrade")
            assert await connection.scalar(text("SELECT count(*) FROM vms WHERE vm_id='vm_pg_lifecycle' AND deletion_started_at IS NULL")) == 1
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await api_engine.dispose()
        await worker_engine.dispose()
        await observer.dispose()
