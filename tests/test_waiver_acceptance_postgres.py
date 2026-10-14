"""Opt-in PostgreSQL proof that revocation serializes with privileged dispatch."""
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

from hyrule_cloud.api.admin import ReasonRequest, RoleRequest, set_account_role, vm_action
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import AccountRow, AdminAuditRow, AdminBypassUsageRow, VMRow
from hyrule_cloud.middleware.x402 import (
    AdminBypassContext,
    PaymentGate,
    admin_waiver_dispatch_guard,
    external_admin_waiver_guard,
)
from hyrule_cloud.models import VMCreateRequest, VMSize
from hyrule_cloud.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_waiver_acceptance_serializes_with_revocation(monkeypatch):
    monkeypatch.setattr("hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: False)
    url = os.getenv('HCP_WAIVER_ACCEPTANCE_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local waiver_acceptance_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'waiver_acceptance_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    names = ('admin-action-fixture', 'admin-revoke-fixture', 'admin-observer-fixture')
    engines = [create_async_engine(url, connect_args={'server_settings': {'application_name': name}})
               for name in names]
    sessions = async_sessionmaker(engines[2], expire_on_commit=False)
    tasks, releases = [], []
    request = Request({'type': 'http', 'method': 'POST', 'path': '/fixture', 'headers': []})

    async def blocked(name):
        async with asyncio.timeout(5):
            while True:
                async with engines[2].connect() as conn:
                    waiting = await conn.scalar(text(
                        'SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=:name '
                        'AND cardinality(pg_blocking_pids(pid)) > 0)'
                    ), {'name': name})
                if waiting:
                    return
                await asyncio.sleep(0.02)

    try:
        async with engines[2].connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0
        result = subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'],
                                cwd=Path(__file__).resolve().parents[1],
                                env=dict(os.environ, HYRULE_DATABASE_URL=url),
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        for index, (mode, dispatch_first) in enumerate(
                (mode, first) for mode in ('admin', 'activate', 'create', 'external') for first in (True, False)):
            actor = AccountRow(account_id=f'HACTOR0000{index}', password_hash='fixture', is_admin=True)
            revoker = AccountRow(account_id=f'HREVOKE000{index}', password_hash='fixture', is_admin=True)
            vm_id = f'vm_admin_race_{index}'
            async with sessions.begin() as session:
                session.add_all([actor, revoker])
                session.add(VMRow(vm_id=vm_id, owner_wallet='fixture', owner_account_id=actor.account_id,
                                  status='suspended', xcpng_uuid=f'guest-{index}',
                                  expires_at=datetime.now(UTC) + timedelta(days=1)))
            entered, release = asyncio.Event(), asyncio.Event()
            releases.append(release)

            class HeldRevocationSession(AsyncSession):
                async def commit(self):
                    if not dispatch_first and any(isinstance(row, AdminAuditRow)
                                                  and row.action == 'account.demote' for row in self.new):
                        await self.flush()
                        entered.set()
                        await release.wait()
                    await super().commit()

            async def start_guest(_uuid):
                if dispatch_first:
                    entered.set()
                    await release.wait()

            provider = SimpleNamespace(start_vm=AsyncMock(side_effect=start_guest))
            action_state = SimpleNamespace(
                session_factory=async_sessionmaker(engines[0], expire_on_commit=False),
                orchestrator=SimpleNamespace(xcpng=provider),
            )
            revoke_state = SimpleNamespace(session_factory=async_sessionmaker(
                engines[1], class_=HeldRevocationSession, expire_on_commit=False))

            class HeldAcceptanceSession(AsyncSession):
                async def commit(self):
                    if dispatch_first:
                        await self.flush()
                        entered.set()
                        await release.wait()
                    await super().commit()

            orch = object.__new__(Orchestrator)
            orch.config = HyruleConfig()
            orch.db = async_sessionmaker(engines[0], class_=HeldAcceptanceSession, expire_on_commit=False)
            request.state.payment_mode = 'admin-bypass'
            request.state.admin_bypass_context = AdminBypassContext(actor.account_id, 'real_cost')
            guard = admin_waiver_dispatch_guard(request)
            gate = object.__new__(PaymentGate)
            gate.session_factory = async_sessionmaker(engines[0], expire_on_commit=False)
            gate.prospective_admin_dispatch_guard = AsyncMock(return_value=guard)

            async def start():
                if mode == 'admin':
                    return await vm_action(vm_id, 'start', ReasonRequest(reason='fixture start'),
                                           request, actor, action_state)
                if mode == 'activate':
                    return await orch.activate_vm_reservation(vm_id, owner_wallet='waived-owner',
                        owner_account_id=actor.account_id, start_provisioning=False,
                        admin_waived=True, dispatch_guard=guard)
                if mode == 'create':
                    return await orch.create_vm(VMCreateRequest(duration_days=1, size=VMSize.XS,
                        ssh_pubkey='ssh-ed25519 fixture'), owner_wallet='waived-owner',
                        owner_account_id=actor.account_id, vm_id=vm_id + '_created',
                        start_provisioning=False, admin_waived=True, dispatch_guard=guard)
                async with external_admin_waiver_guard(request, gate):
                    # Quota/audit FK writes use an independent session while
                    # the external guard holds its non-key account lock.
                    async with sessions.begin() as quota:
                        await quota.execute(text("SET LOCAL lock_timeout = '1s'"))
                        quota.add(AdminBypassUsageRow(actor_account_id=actor.account_id,
                            operation_class='real_cost', window_started_at=datetime.now(UTC), count=1))
                        await quota.flush()
                    await provider.start_vm(vm_id)
                return True

            async def demote():
                return await set_account_role(actor.account_id, RoleRequest(is_admin=False, reason='fixture revocation'),
                                              request, revoker, revoke_state)

            first = asyncio.create_task(start() if dispatch_first else demote())
            tasks.append(first)
            await asyncio.wait_for(entered.wait(), 5)
            second = asyncio.create_task(demote() if dispatch_first else start())
            tasks.append(second)
            await blocked(names[1] if dispatch_first else names[0])
            release.set()
            assert (await asyncio.wait_for(first, 5)) is not None
            if dispatch_first:
                assert (await asyncio.wait_for(second, 5))['is_admin'] is False
            else:
                with pytest.raises(HTTPException) as refused:
                    await asyncio.wait_for(second, 5)
                assert refused.value.status_code == 403
            assert provider.start_vm.await_count == int(dispatch_first and mode in ('admin', 'external'))
            async with sessions() as session:
                assert not (await session.get(AccountRow, actor.account_id)).is_admin
                assert (await session.get(VMRow, vm_id)).status == ('running' if dispatch_first and mode == 'admin' else 'suspended')
                assert (await session.get(VMRow, vm_id)).owner_wallet == ('waived-owner' if dispatch_first and mode == 'activate' else 'fixture')
                assert (await session.get(VMRow, vm_id + '_created') is not None) == (dispatch_first and mode == 'create')
                audits = list(await session.scalars(select(AdminAuditRow).where(AdminAuditRow.target_id == vm_id)))
                assert len(audits) == int(dispatch_first and mode == 'admin')
    finally:
        for release in releases:
            release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
