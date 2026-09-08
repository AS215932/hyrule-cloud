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
from hyrule_cloud.db import AccountRow, AdminAuditRow, VMRow


@pytest.mark.asyncio
async def test_admin_revocation_serializes_with_provider_dispatch():
    url = os.getenv('HCP_ADMIN_REVOCATION_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local admin_revocation_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'admin_revocation_test'
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
        for index, dispatch_first in enumerate((True, False)):
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

            async def start():
                return await vm_action(vm_id, 'start', ReasonRequest(reason='fixture start'),
                                       request, actor, action_state)

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
            assert provider.start_vm.await_count == int(dispatch_first)
            async with sessions() as session:
                assert not (await session.get(AccountRow, actor.account_id)).is_admin
                assert (await session.get(VMRow, vm_id)).status == ('running' if dispatch_first else 'suspended')
                audits = list(await session.scalars(select(AdminAuditRow).where(AdminAuditRow.target_id == vm_id)))
                assert len(audits) == int(dispatch_first)
    finally:
        for release in releases:
            release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
