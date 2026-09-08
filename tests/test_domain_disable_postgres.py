"""Opt-in real PostgreSQL proof of the customer domain account-disable fence."""
import asyncio
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api.admin import ReasonRequest, disable_account
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import AccountRow, DomainOperationRow, DomainRow
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import (
    DNSChange,
    DNSChangeAction,
    DNSChangesetRequest,
    DNSRRSet,
    DNSSECMode,
    DNSSECUpdateRequest,
    ManagedRecordType,
    NameserverMode,
    NameserverUpdateRequest,
)
from hyrule_cloud.domains.service import DomainService
from hyrule_cloud.middleware.anon_token import hash_anon_token


@pytest.mark.asyncio
async def test_domain_mutations_serialize_with_account_disable():
    url = os.getenv('HCP_DOMAIN_DISABLE_TEST_DATABASE_URL')
    if not url:
        pytest.skip('requires fresh local domain_disable_test PostgreSQL')
    parsed = make_url(url)
    assert parsed.drivername == 'postgresql+asyncpg' and parsed.database == 'domain_disable_test'
    assert parsed.host in (None, 'localhost', '127.0.0.1', '::1')
    names = ('domain-mutation-fixture', 'domain-disable-fixture', 'domain-observer-fixture')
    engines = [create_async_engine(url, connect_args={'server_settings': {'application_name': name}})
               for name in names]
    sessions = async_sessionmaker(engines[2], expire_on_commit=False)
    request = Request({'type': 'http', 'method': 'POST', 'path': '/fixture', 'headers': []})
    tasks, releases = [], []

    async def blocked(name):
        async with asyncio.timeout(5):
            while True:
                async with engines[2].connect() as conn:
                    waiting = await conn.scalar(text(
                        'SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=:name '
                        'AND cardinality(pg_blocking_pids(pid)) > 0)'), {'name': name})
                if waiting:
                    return
                await asyncio.sleep(0.02)

    try:
        async with engines[2].connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")) == 0
        result = subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'],
            cwd=Path(__file__).resolve().parents[1], env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        actor = AccountRow(account_id='HADMIN00001', password_hash='fixture', is_admin=True)
        async with sessions.begin() as session:
            session.add(actor)
        for index, (action, mutation_first) in enumerate(
                (action, first) for action in ('changeset', 'nameservers', 'dnssec', 'claim') for first in (True, False)):
            owner_id, fqdn = f'HOWNER0000{index}', f'fixture{index}.dev'
            async with sessions.begin() as session:
                session.add(AccountRow(account_id=owner_id, password_hash='fixture'))
                await session.flush()
                session.add(DomainRow(name=f'fixture{index}', extension='dev', fqdn=fqdn,
                    owner_wallet='fixture', owner_account_id=None if action == 'claim' else owner_id, status='active',
                    anon_management_token_hash=hash_anon_token('fixture-token') if action == 'claim' else None,
                    nameserver_mode='managed', nameservers=['ns1.servify.network', 'ns2.servify.network'],
                    dnssec_mode='managed', dnssec_status='active'))
            entered, release = asyncio.Event(), asyncio.Event()
            releases.append(release)

            class HeldCommitSession(AsyncSession):
                async def commit(self):
                    await self.flush()
                    entered.set()
                    await release.wait()
                    await super().commit()

            service = object.__new__(DomainService)
            service.db = async_sessionmaker(engines[0], expire_on_commit=False,
                class_=HeldCommitSession if mutation_first else AsyncSession)
            service.domain_config = HyruleConfig().domain
            service.dns = SimpleNamespace(apply_zone=AsyncMock())
            state = SimpleNamespace(session_factory=async_sessionmaker(engines[1], expire_on_commit=False,
                class_=AsyncSession if mutation_first else HeldCommitSession))

            async def mutate():
                if action == 'claim':
                    return await service.claim_legacy_domain(owner_id, fqdn, 'fixture-token')
                if action == 'changeset':
                    return await service.apply_changeset(owner_id, fqdn, 1,
                        DNSChangesetRequest(changes=[DNSChange(action=DNSChangeAction.UPSERT,
                            rrset=DNSRRSet(name='www', type=ManagedRecordType.A, ttl=300, values=['192.0.2.1']))]),
                        idempotency_key='fixture')
                if action == 'nameservers':
                    return await service.enqueue_nameserver_update(owner_id, fqdn,
                        NameserverUpdateRequest(mode=NameserverMode.MANAGED), 'fixture')
                return await service.enqueue_dnssec_update(owner_id, fqdn,
                    DNSSECUpdateRequest(mode=DNSSECMode.MANAGED), 'fixture')

            async def disable():
                return await disable_account(owner_id, ReasonRequest(reason='fixture disable'), request, actor, state)

            first = asyncio.create_task(mutate() if mutation_first else disable())
            tasks.append(first)
            await asyncio.wait_for(entered.wait(), 5)
            second = asyncio.create_task(disable() if mutation_first else mutate())
            tasks.append(second)
            await blocked(names[1] if mutation_first else names[0])
            release.set()
            await asyncio.wait_for(first, 5)
            if mutation_first:
                await asyncio.wait_for(second, 5)
            else:
                with pytest.raises(DomainProblem) as denied:
                    await asyncio.wait_for(second, 5)
                assert denied.value.code == 'account_disabled'
            assert service.dns.apply_zone.await_count == int(mutation_first and action == 'changeset')
            async with sessions() as session:
                assert (await session.get(AccountRow, owner_id)).disabled_at is not None
                domain = await session.scalar(select(DomainRow).where(DomainRow.fqdn == fqdn))
                assert domain.zone_revision == 1 + int(mutation_first and action == 'changeset')
                if action == 'claim':
                    assert domain.owner_account_id == (owner_id if mutation_first else None)
                    assert domain.anon_management_token_hash == (None if mutation_first else hash_anon_token('fixture-token'))
                operations = list(await session.scalars(select(DomainOperationRow).where(DomainOperationRow.fqdn == fqdn)))
                assert len(operations) == int(mutation_first and action in ('nameservers', 'dnssec'))
    finally:
        for release in releases:
            release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
