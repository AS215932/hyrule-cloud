"""Opt-in real PostgreSQL proof of the customer domain account-disable fence."""
import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api.admin import ReasonRequest, disable_account
from hyrule_cloud.api.auth import ClaimByTokenRequest, claim_vm
from hyrule_cloud.api.routes import _vm_payment_account_guard
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    DomainOperationRow,
    DomainOrderRow,
    DomainQuoteRow,
    DomainRow,
    VMRow,
)
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
from hyrule_cloud.orchestrator import AccountDisabledError
from hyrule_cloud.services.intents import native_intent_account_guard


@pytest.mark.asyncio
async def test_domain_payment_guard_holds_account_fence_through_settlement():
    url = os.getenv("HCP_DOMAIN_DISABLE_TEST_DATABASE_URL")
    if not url:
        pytest.skip("requires fresh local domain_disable_test PostgreSQL")
    parsed = make_url(url)
    assert parsed.drivername == "postgresql+asyncpg" and parsed.database == "domain_disable_test"
    assert parsed.host in (None, "localhost", "127.0.0.1", "::1")
    names = ("domain-payment-fixture", "domain-disable-fixture", "domain-observer-fixture")
    engines = [
        create_async_engine(
            url, connect_args={"server_settings": {"application_name": name}}
        )
        for name in names
    ]
    sessions = async_sessionmaker(engines[2], expire_on_commit=False)
    entered, release = asyncio.Event(), asyncio.Event()
    vm_entered, vm_release = asyncio.Event(), asyncio.Event()
    native_entered, native_release = asyncio.Event(), asyncio.Event()
    tasks: list[asyncio.Task] = []
    request = Request({"type": "http", "method": "POST", "path": "/fixture", "headers": []})
    actor = AccountRow(account_id="HADMIN00001", password_hash="fixture", is_admin=True)
    owner_id = "HOWNERPAY01"
    vm_owner_id = "HOWNERPAY02"
    disabled_owner_id = "HOWNERPAY03"
    native_owner_id = "HOWNERPAY04"
    disabled_native_owner_id = "HOWNERPAY05"

    async def wait_until_disable_is_blocked() -> None:
        async with asyncio.timeout(5):
            while True:
                async with engines[2].connect() as connection:
                    waiting = await connection.scalar(
                        text(
                            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                            "WHERE application_name='domain-disable-fixture' "
                            "AND cardinality(pg_blocking_pids(pid)) > 0)"
                        )
                    )
                if waiting:
                    return
                await asyncio.sleep(0.02)

    try:
        async with engines[2].connect() as connection:
            assert (
                await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema='public'"
                    )
                )
                == 0
            )
        migrated = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=Path(__file__).resolve().parents[1],
            env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert migrated.returncode == 0, migrated.stderr
        async with sessions.begin() as session:
            session.add_all(
                [
                    actor,
                    AccountRow(account_id=owner_id, password_hash="fixture"),
                    AccountRow(account_id=vm_owner_id, password_hash="fixture"),
                    AccountRow(account_id=disabled_owner_id, password_hash="fixture"),
                    AccountRow(account_id=native_owner_id, password_hash="fixture"),
                    AccountRow(account_id=disabled_native_owner_id, password_hash="fixture"),
                ]
            )
            await session.flush()
            session.add(
                DomainQuoteRow(
                    quote_id="quote-payment-fence",
                    fqdn="payment-fence.dev",
                    action="register",
                    owner_account_id=owner_id,
                    status="reserved",
                    provider_cost=Decimal("10"),
                    provider_currency="USD",
                    fx_rate=Decimal("1"),
                    provider_cost_usd=Decimal("10"),
                    hyrule_fee_usd=Decimal("3"),
                    tax_usd=Decimal("0"),
                    total_usd=Decimal("13"),
                    available=True,
                    premium=False,
                    terms_version="fixture",
                    expires_at=datetime.now(UTC) + timedelta(minutes=10),
                )
            )
            await session.flush()
            session.add(
                DomainOrderRow(
                    order_id="order-payment-fence",
                    quote_id="quote-payment-fence",
                    fqdn="payment-fence.dev",
                    action="register",
                    owner_account_id=owner_id,
                    idempotency_key="payment-fence",
                    status="awaiting_payment",
                    amount_usd=Decimal("13"),
                    domain_amount_usd=Decimal("13"),
                    vm_amount_usd=Decimal("0"),
                    payment_method="usdc",
                    terms_version="fixture",
                    terms_accepted_at=datetime.now(UTC),
                )
            )
        service = object.__new__(DomainService)
        service.db = async_sessionmaker(engines[0], expire_on_commit=False)

        async def settle() -> None:
            async with service.x402_payment_guard(
                "order-payment-fence", owner_id
            ):
                entered.set()
                await release.wait()

        settlement = asyncio.create_task(settle())
        tasks.append(settlement)
        await asyncio.wait_for(entered.wait(), 5)
        disable = asyncio.create_task(
            disable_account(
                owner_id,
                ReasonRequest(reason="fixture disable"),
                request,
                actor,
                SimpleNamespace(
                    session_factory=async_sessionmaker(engines[1], expire_on_commit=False)
                ),
            )
        )
        tasks.append(disable)
        await wait_until_disable_is_blocked()
        assert not disable.done()
        release.set()
        await asyncio.wait_for(settlement, 5)
        await asyncio.wait_for(disable, 5)
        async with sessions() as session:
            assert (await session.get(AccountRow, owner_id)).disabled_at is not None

        # The authenticated VM create path uses the same lifecycle fence and
        # holds it through its external check_payment call.
        vm_orchestrator = SimpleNamespace(
            db=async_sessionmaker(engines[0], expire_on_commit=False)
        )

        async def settle_vm() -> None:
            async with _vm_payment_account_guard(vm_orchestrator, vm_owner_id):
                vm_entered.set()
                await vm_release.wait()

        vm_settlement = asyncio.create_task(settle_vm())
        tasks.append(vm_settlement)
        await asyncio.wait_for(vm_entered.wait(), 5)
        vm_disable = asyncio.create_task(
            disable_account(
                vm_owner_id,
                ReasonRequest(reason="fixture disable"),
                request,
                actor,
                SimpleNamespace(
                    session_factory=async_sessionmaker(
                        engines[1], expire_on_commit=False
                    )
                ),
            )
        )
        tasks.append(vm_disable)
        await wait_until_disable_is_blocked()
        assert not vm_disable.done()
        vm_release.set()
        await asyncio.wait_for(vm_settlement, 5)
        await asyncio.wait_for(vm_disable, 5)

        # If disable commits first, the guarded body (the payment call in the
        # route) is never entered.
        await disable_account(
            disabled_owner_id,
            ReasonRequest(reason="fixture disable first"),
            request,
            actor,
            SimpleNamespace(
                session_factory=async_sessionmaker(
                    engines[1], expire_on_commit=False
                )
            ),
        )
        payment_called = False
        with pytest.raises(HTTPException) as refused:
            async with _vm_payment_account_guard(
                vm_orchestrator, disabled_owner_id
            ):
                payment_called = True
        assert refused.value.status_code == 403
        assert payment_called is False

        # Native BTC/XMR address allocation and intent persistence hold the
        # same cross-process account lifecycle fence.
        native_factory = async_sessionmaker(engines[0], expire_on_commit=False)

        async def issue_native_address() -> None:
            async with native_intent_account_guard(native_factory, native_owner_id):
                # Route/domain callers deliberately retain this outer fence;
                # the service-level guard must reuse it without self-blocking.
                async with native_intent_account_guard(native_factory, native_owner_id):
                    native_entered.set()
                    await native_release.wait()

        native_issuance = asyncio.create_task(issue_native_address())
        tasks.append(native_issuance)
        await asyncio.wait_for(native_entered.wait(), 5)
        native_disable = asyncio.create_task(
            disable_account(
                native_owner_id,
                ReasonRequest(reason="fixture disable"),
                request,
                actor,
                SimpleNamespace(
                    session_factory=async_sessionmaker(
                        engines[1], expire_on_commit=False
                    )
                ),
            )
        )
        tasks.append(native_disable)
        await wait_until_disable_is_blocked()
        assert not native_disable.done()
        native_release.set()
        await asyncio.wait_for(native_issuance, 5)
        await asyncio.wait_for(native_disable, 5)

        await disable_account(
            disabled_native_owner_id,
            ReasonRequest(reason="fixture disable first"),
            request,
            actor,
            SimpleNamespace(
                session_factory=async_sessionmaker(
                    engines[1], expire_on_commit=False
                )
            ),
        )
        address_allocated = False
        with pytest.raises(AccountDisabledError):
            async with native_intent_account_guard(
                native_factory, disabled_native_owner_id
            ):
                address_allocated = True
        assert address_allocated is False
    finally:
        release.set()
        vm_release.set()
        native_release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()


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
                (action, first) for action in ('changeset', 'nameservers', 'dnssec', 'claim', 'vm_claim') for first in (True, False)):
            owner_id, fqdn = f'HOWNER0000{index}', f'fixture{index}.dev'
            owner = AccountRow(account_id=owner_id, password_hash='fixture')
            vm_id = f'vm_claim_{index}'
            async with sessions.begin() as session:
                session.add(owner)
                await session.flush()
                session.add(DomainRow(name=f'fixture{index}', extension='dev', fqdn=fqdn,
                    owner_wallet='fixture', owner_account_id=None if action == 'claim' else owner_id, status='active',
                    anon_management_token_hash=hash_anon_token('fixture-token') if action == 'claim' else None,
                    nameserver_mode='managed', nameservers=['ns1.servify.network', 'ns2.servify.network'],
                    dnssec_mode='managed', dnssec_status='active'))
                if action == 'vm_claim':
                    session.add(VMRow(
                        vm_id=vm_id, owner_wallet='fixture', status='running',
                        anon_management_token_hash=hash_anon_token('fixture-token'),
                    ))
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
                if action == 'vm_claim':
                    claim_state = SimpleNamespace(
                        orchestrator=SimpleNamespace(db=service.db)
                    )
                    return await claim_vm(
                        vm_id,
                        ClaimByTokenRequest(
                            proof='management_token', token='fixture-token'
                        ),
                        request,
                        owner,
                        claim_state,
                    )
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
            elif action == 'vm_claim':
                with pytest.raises(HTTPException) as denied:
                    await asyncio.wait_for(second, 5)
                assert denied.value.status_code == 403
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
                if action == 'vm_claim':
                    vm = await session.get(VMRow, vm_id)
                    assert vm.owner_account_id == (owner_id if mutation_first else None)
                    assert vm.anon_management_token_hash == (
                        None if mutation_first else hash_anon_token('fixture-token')
                    )
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
