"""Account deletion cannot orphan a concurrently transferred domain/VM bundle."""
import asyncio
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api.admin import OwnershipTransferRequest, transfer_domain
from hyrule_cloud.api.auth import delete_me
from hyrule_cloud.db import AccountRow, AdminAuditRow, DomainRow, VMRow
from hyrule_cloud.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_account_delete_and_domain_transfer_are_serialized():
    url = os.getenv('HCP_ACCOUNT_DELETE_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local account_delete_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'account_delete_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    engines = [create_async_engine(url) for _ in range(3)]
    sessions = async_sessionmaker(engines[2], expire_on_commit=False)
    tasks, releases = [], []
    request = Request({'type': 'http', 'method': 'DELETE', 'path': '/v1/me',
                       'query_string': b'vm_policy=destroy', 'headers': []})
    try:
        async with engines[2].connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0
        result = subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'],
            cwd=Path(__file__).resolve().parents[1], env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        for index, (delete_first, cancel_delete) in enumerate(((True, False), (False, False), (True, True))):
            actor = AccountRow(account_id=f'HADMIN0000{index}', password_hash='fixture', is_admin=True)
            source = AccountRow(account_id=f'HSOURCE000{index}', password_hash='fixture')
            target = AccountRow(account_id=f'HTARGET000{index}', password_hash='fixture')
            source_vm, target_vm = f'vm_source_{index}', f'vm_target_{index}'
            fqdn = f'transfer{index}.dev'
            async with sessions.begin() as session:
                session.add_all([actor, source, target])
                await session.flush()
                session.add_all([
                    VMRow(vm_id=source_vm, owner_wallet='source', owner_account_id=source.account_id,
                          status='running', xcpng_uuid=f'source-guest-{index}', anon_management_token_hash='source-token'),
                    VMRow(vm_id=target_vm, owner_wallet='target', owner_account_id=target.account_id,
                          status='running', xcpng_uuid=f'target-guest-{index}'),
                ])
                await session.flush()
                session.add(DomainRow(name=f'transfer{index}', extension='dev', fqdn=fqdn,
                    owner_wallet='source', owner_account_id=source.account_id, status='active',
                    nameserver_mode='managed', dnssec_mode='managed', dnssec_status='active',
                    vm_id=source_vm, anon_management_token_hash='domain-token'))
            entered, release = asyncio.Event(), asyncio.Event()
            releases.append(release)

            class HeldTransferSession(AsyncSession):
                async def commit(self):
                    if not delete_first and any(isinstance(row, AdminAuditRow) and row.action == 'domain.transfer'
                                                for row in self.new):
                        await self.flush()
                        entered.set()
                        await release.wait()
                    await super().commit()

            async def delete_guest(_uuid):
                if delete_first:
                    # delete_me has already released its initial account/VM
                    # snapshot, but its outer lifecycle guard must remain held.
                    entered.set()
                    await release.wait()

            orch = object.__new__(Orchestrator)
            orch.db = async_sessionmaker(engines[0], expire_on_commit=False)
            orch.xcpng = SimpleNamespace(destroy_vm=AsyncMock(side_effect=delete_guest))
            deleting_state = SimpleNamespace(session_factory=orch.db, orchestrator=orch)
            transfer_state = SimpleNamespace(session_factory=async_sessionmaker(
                engines[1], class_=HeldTransferSession, expire_on_commit=False), orchestrator=orch)

            async def deleting():
                return await delete_me(request, Response(), target, deleting_state, None)

            async def transferring():
                return await transfer_domain(fqdn, OwnershipTransferRequest(
                    target_account_id=target.account_id, reason='fixture transfer'), request, actor, transfer_state)

            first = asyncio.create_task(deleting() if delete_first else transferring())
            tasks.append(first)
            await asyncio.wait_for(entered.wait(), 5)
            with pytest.raises(HTTPException) as refused:
                await asyncio.wait_for(transferring() if delete_first else deleting(), 5)
            assert refused.value.status_code == 409
            assert 'in progress' in refused.value.detail
            if cancel_delete:
                first.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await first
                # Cancellation releases the transaction-scoped guard. The
                # account survives, so a later transfer can safely retain it.
                await asyncio.wait_for(transferring(), 5)
            else:
                release.set()
                await asyncio.wait_for(first, 5)
            async with sessions() as session:
                surviving_target = await session.get(AccountRow, target.account_id)
                assert (surviving_target is None) == (delete_first and not cancel_delete)
                domain = await session.scalar(select(DomainRow).where(DomainRow.fqdn == fqdn))
                vm = await session.get(VMRow, source_vm)
                expected_owner = source.account_id if delete_first and not cancel_delete else target.account_id
                assert domain.owner_account_id == vm.owner_account_id == expected_owner
                assert domain.anon_management_token_hash == ('domain-token' if delete_first and not cancel_delete else None)
                assert vm.anon_management_token_hash == ('source-token' if delete_first and not cancel_delete else None)
                assert await session.get(AccountRow, expected_owner) is not None
            if not delete_first or cancel_delete:
                # The transfer is durable; a later deletion retry must see its
                # domain and refuse assisted-deletion resources before cleanup.
                with pytest.raises(HTTPException) as assisted:
                    await deleting()
                assert 'assisted deletion' in assisted.value.detail
    finally:
        for release in releases:
            release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
