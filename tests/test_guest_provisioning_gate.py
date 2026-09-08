import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
import yaml
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.api.routes import get_orch, router
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, VMEventRow, VMRow
from hyrule_cloud.models import DNSResolutionStatus, VMStatus
from hyrule_cloud.orchestrator import Orchestrator


@pytest.mark.asyncio
@pytest.mark.parametrize('crash_state', ['no_clone', 'running', 'halted', 'multiple', 'reported_missing', 'legacy'])
async def test_receipt_backed_pre_uuid_attempts_are_reconciled(tmp_path, monkeypatch, crash_state):
    import json

    from hyrule_cloud.db import VMGuestResultRow
    from hyrule_cloud.services.guest_result import (
        GuestResult,
        accept_guest_result,
        prepare_guest_result,
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'pre-uuid.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    config = HyruleConfig()
    config.xcpng.templates = {'debian-13': 'test-template'}
    orch = Orchestrator(config, factory)
    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: True)
    orch.dns.create_aaaa = AsyncMock()
    orch.dns.verify_aaaa = AsyncMock(return_value=True)
    orch._wait_for_ipv6 = AsyncMock(return_value='2a0c:b641:b51:5::2')
    orch._probe_ssh = AsyncMock(return_value=True)
    orch._probe_customer_dns_resolution = AsyncMock(return_value=DNSResolutionStatus.PASSED)
    orch._record_vm_refund = AsyncMock()
    orch.xcpng.destroy_vm = AsyncMock(side_effect=AssertionError('must preserve ambiguous guest data'))
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(vm_id='vm_pre_uuid', owner_wallet='test',
                              hostname='test.deploy.hyrule.host', ipv6_prefix='2a0c:b641:b51:5::/64',
                              ipv6_prefix_index=5, expires_at=datetime.now(UTC) + timedelta(days=1)))
        async with factory.begin() as session:
            generation, token = await prepare_guest_result(session, 'vm_pre_uuid', datetime.now(UTC) + timedelta(minutes=5))
        if crash_state in ('running', 'reported_missing'):
            async with factory.begin() as session:
                await accept_guest_result(session, 'vm_pre_uuid', generation, token,
                                          GuestResult(outcome='succeeded', stage='cloud_init', exit_code=0))

        async def find(label):
            if crash_state == 'legacy' and label == 'hyrule-vm_pre_uuid':
                return ['legacy-guest']
            if label != f'hyrule-vm_pre_uuid-{generation}':
                return []
            return {'running': ['existing'], 'halted': ['existing'], 'multiple': ['first', 'second']}.get(crash_state, [])

        async def create(**kwargs):
            cloud = yaml.safe_load(kwargs['cloud_init_config'])
            report = json.loads(next(entry['content'] for entry in cloud['write_files'] if entry['path'].endswith('/config.json')))
            new_generation = report['url'].rsplit('/', 1)[1]
            assert kwargs['name_label'] == f'hyrule-vm_pre_uuid-{new_generation}'
            assert new_generation != generation
            async with factory.begin() as session:
                await accept_guest_result(session, 'vm_pre_uuid', new_generation, report['token'],
                                          GuestResult(outcome='succeeded', stage='cloud_init', exit_code=0))
            return 'new-guest'

        orch.xcpng.find_vm_ids_by_name_label = AsyncMock(side_effect=find)
        orch.xcpng.get_vm_power_state = AsyncMock(return_value='Halted' if crash_state == 'halted' else 'Running')
        orch.xcpng.create_vm = AsyncMock(side_effect=create)
        assert await orch.recover_tracked_provisioning() == 1  # No UUID is persisted.
        await asyncio.wait_for(asyncio.gather(*list(orch._tasks)), 10)
        async with factory() as session:
            vm = await session.get(VMRow, 'vm_pre_uuid')
            receipt = await session.get(VMGuestResultRow, 'vm_pre_uuid')
            if crash_state in ('running', 'no_clone'):
                assert vm.status == VMStatus.READY
                assert vm.xcpng_uuid == ('existing' if crash_state == 'running' else 'new-guest')
                orch._record_vm_refund.assert_not_awaited()
                events = list(await session.scalars(
                    select(VMEventRow.event).where(VMEventRow.vm_id == vm.vm_id).order_by(VMEventRow.event_id)
                ))
                assert events.count('vm_created') == 1
                assert events.index('vm_created') < events.index('network_ready')
            else:
                assert vm.status == VMStatus.FAILED
                assert vm.xcpng_uuid is None
                assert 'interrupted' in vm.error
                orch._record_vm_refund.assert_awaited_once()
            if crash_state != 'no_clone':
                assert receipt.generation == generation
                orch.xcpng.create_vm.assert_not_awaited()
        orch.xcpng.destroy_vm.assert_not_awaited()
        if crash_state not in ('running', 'no_clone'):
            orch.dns.delete_aaaa = AsyncMock()
            # Customer rollback, repeated deletion and deferred DNS cleanup
            # must all preserve quarantine while retained guests lack a UUID.
            for _ in range(2):
                assert await orch.destroy_vm('vm_pre_uuid')
                await orch.release_destroyed_prefix('vm_pre_uuid')
                async with factory() as session:
                    vm = await session.get(VMRow, 'vm_pre_uuid')
                    assert vm.status == VMStatus.DESTROYED
                    assert vm.ipv6_prefix_index == 5
                    assert vm.ipv6_prefix == '2a0c:b641:b51:5::/64'
            orch.xcpng.destroy_vm.assert_not_awaited()
    finally:
        await orch.shutdown()
        await engine.dispose()


@pytest.mark.asyncio
async def test_waiter_cancellation_joins_inflight_database_poll(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'cancel.db'}")
    orch = Orchestrator(HyruleConfig(), async_sessionmaker(engine, expire_on_commit=False))
    entered, release, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def poll(*args):
        entered.set()
        try:
            await release.wait()
            return None
        finally:
            closed.set()

    orch._poll_guest_result = poll
    waiter = asyncio.create_task(orch._wait_for_guest_result('vm_cancel', 'a' * 32))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        waiter.cancel()
        await asyncio.sleep(0)
        assert not waiter.done()
        assert not closed.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(waiter, 2)
        assert closed.is_set()
    finally:
        release.set()
        await asyncio.gather(waiter, return_exceptions=True)
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['succeeded', 'failed', 'timeout'])
async def test_worker_recovers_tracked_guest_after_api_stops(tmp_path, monkeypatch, outcome):
    from hyrule_cloud.db import VMGuestResultRow
    from hyrule_cloud.services.guest_result import (
        GuestResult,
        accept_guest_result,
        prepare_guest_result,
    )

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'restart.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    config = HyruleConfig()
    config.xcpng.templates = {'debian-13': 'test-template'}
    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: True)

    def fresh_orchestrator():
        orch = Orchestrator(config, factory)
        orch.xcpng.create_vm = AsyncMock(side_effect=AssertionError('must retain existing guest'))
        orch.xcpng.destroy_vm = AsyncMock(side_effect=AssertionError('must retain guest data'))
        orch.dns.create_aaaa = AsyncMock()
        orch.dns.verify_aaaa = AsyncMock(return_value=True)
        orch._wait_for_ipv6 = AsyncMock(return_value='2a0c:b641:b51:5::2')
        orch._probe_ssh = AsyncMock(return_value=True)
        orch._probe_customer_dns_resolution = AsyncMock(return_value=DNSResolutionStatus.PASSED)
        orch._record_vm_refund = AsyncMock()
        return orch

    original, recovered = fresh_orchestrator(), fresh_orchestrator()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(vm_id='vm_restart', owner_wallet='test',
                              hostname='test.deploy.hyrule.host', ipv6_prefix='2a0c:b641:b51:5::/64',
                              ipv6_prefix_index=5, expires_at=datetime.now(UTC) + timedelta(days=1)))
        async with factory.begin() as session:
            generation, token = await prepare_guest_result(session, 'vm_restart', datetime.now(UTC) + timedelta(minutes=5))
            vm = await session.get(VMRow, 'vm_restart')
            vm.xcpng_uuid = 'retained-guest'
        waiting = asyncio.Event()
        real_wait = original._wait_for_guest_result

        async def observed_wait(*args):
            waiting.set()
            return await real_wait(*args)

        original._wait_for_guest_result = observed_wait
        original.start_provisioning('vm_restart')
        await asyncio.wait_for(waiting.wait(), 10)
        # A second process-equivalent orchestrator cannot duplicate an active attempt.
        await asyncio.wait_for(recovered._provision_vm('vm_restart'), 2)
        recovered._wait_for_ipv6.assert_not_awaited()
        await original.shutdown()
        # Match API/worker lifespan shutdown: close the old process's pool too.
        # A cancelled aiosqlite cursor must not survive into the restarted fixture.
        await engine.dispose()
        async with factory.begin() as session:
            if outcome == 'timeout':
                receipt = await session.get(VMGuestResultRow, 'vm_restart')
                receipt.deadline = datetime.now(UTC) - timedelta(seconds=1)
            else:
                await accept_guest_result(session, 'vm_restart', generation, token, GuestResult(
                    outcome=outcome, stage='cloud_init' if outcome == 'succeeded' else 'setup_script',
                    exit_code=0 if outcome == 'succeeded' else 7,
                ))
        assert await recovered.recover_tracked_provisioning() == 1
        await asyncio.wait_for(asyncio.gather(*list(recovered._tasks)), 10)
        async with factory() as session:
            vm = await session.get(VMRow, 'vm_restart')
            receipt = await session.get(VMGuestResultRow, 'vm_restart')
            assert vm.status == (VMStatus.READY if outcome == 'succeeded' else VMStatus.FAILED)
            assert vm.xcpng_uuid == 'retained-guest'
            assert receipt.generation == generation
        recovered.xcpng.create_vm.assert_not_awaited()
        recovered.xcpng.destroy_vm.assert_not_awaited()
        assert recovered._record_vm_refund.await_count == (0 if outcome == 'succeeded' else 1)
        assert await recovered.recover_tracked_provisioning() == 0
    finally:
        await original.shutdown()
        await recovered.shutdown()
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('exit_code', [0, 7])
async def test_guest_completion_controls_public_status_and_launch_proof(tmp_path, monkeypatch, exit_code):
    import json
    from urllib.parse import urlsplit

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'provision.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    config = HyruleConfig()
    config.xcpng.templates = {'debian-13': 'test-template'}
    orch = Orchestrator(config, factory)
    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: True)
    orch.xcpng.find_vm_ids_by_name_label = AsyncMock(return_value=[])
    orch.xcpng.destroy_vm = AsyncMock()
    orch.dns.create_aaaa = AsyncMock()
    orch.dns.verify_aaaa = AsyncMock(return_value=True)
    orch._wait_for_ipv6 = AsyncMock(return_value='2a0c:b641:b51:5::2')
    orch._probe_ssh = AsyncMock(return_value=True)
    orch._probe_customer_dns_resolution = AsyncMock(return_value=DNSResolutionStatus.PASSED)
    orch._record_vm_refund = AsyncMock()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_orch] = lambda: orch
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(
                vm_id='vm_guest', owner_wallet='test', hostname='test.deploy.hyrule.host',
                ipv6_prefix='2a0c:b641:b51:5::/64', ipv6_prefix_index=5,
                setup_script=f'#!/bin/sh\nexit {exit_code}\n',
                expires_at=datetime.now(UTC) + timedelta(days=1),
            ))
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
            async def create(**kwargs):
                cloud = yaml.safe_load(kwargs['cloud_init_config'])
                entry = next(item for item in cloud['write_files'] if item['path'].endswith('/config.json'))
                report = json.loads(entry['content'])
                before = await client.get('/v1/vm/vm_guest/status')
                assert before.json()['status'] == 'provisioning'
                outcome = {'outcome': 'failed', 'stage': 'setup_script', 'exit_code': exit_code} if exit_code else {
                    'outcome': 'succeeded', 'stage': 'cloud_init', 'exit_code': 0,
                }
                response = await client.post(urlsplit(report['url']).path, json=outcome,
                                             headers={'Authorization': 'Bearer ' + report['token']})
                assert response.status_code == 204
                return 'test-guest-uuid'

            orch.xcpng.create_vm = AsyncMock(side_effect=create)
            await orch._provision_vm('vm_guest')
            response = await client.get('/v1/vm/vm_guest/status')
            body = response.json()
            assert body['status'] == ('failed' if exit_code else 'ready')
            assert body['launch_proof_status'] == ('failed' if exit_code else 'provisioned')
            if exit_code:
                assert 'setup script failed' in body['customer_message']
                orch._record_vm_refund.assert_awaited_once()
            else:
                orch._record_vm_refund.assert_not_awaited()
            orch.xcpng.destroy_vm.assert_not_awaited()
            async with factory() as session:
                vm = await session.get(VMRow, 'vm_guest')
                assert vm.xcpng_uuid == 'test-guest-uuid'
                assert vm.status == (VMStatus.FAILED if exit_code else VMStatus.READY)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['missing', 'expired', 'superseded', 'completed_retry'])
async def test_guest_waiter_never_infers_success_from_missing_or_stale_report(tmp_path, case):
    from hyrule_cloud.db import VMGuestResultRow
    from hyrule_cloud.orchestrator import GuestGenerationChangedError
    from hyrule_cloud.services.guest_result import (
        GuestResult,
        accept_guest_result,
        prepare_guest_result,
    )
    from hyrule_cloud.services.vm_events import FAILURE_GUEST_REPORT, ProvisioningFailedError

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'waiter.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    orch = Orchestrator(HyruleConfig(), factory)
    generation = 'a' * 32
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(vm_id='vm_wait', owner_wallet='test'))
        if case != 'missing':
            async with factory.begin() as session:
                generation, token = await prepare_guest_result(session, 'vm_wait', datetime.now(UTC) + timedelta(minutes=1))
            if case == 'completed_retry':
                async with factory.begin() as session:
                    await accept_guest_result(session, 'vm_wait', generation, token,
                                              GuestResult(outcome='succeeded', stage='cloud_init', exit_code=0))
            async with factory.begin() as session:
                row = await session.get(VMGuestResultRow, 'vm_wait')
                if case in ('expired', 'completed_retry'):
                    row.deadline = datetime.now(UTC) - timedelta(seconds=1)
                elif case == 'superseded':
                    row.generation = 'b' * 32
        if case == 'completed_retry':
            assert await orch._wait_for_guest_result('vm_wait', generation) == generation
        elif case == 'superseded':
            with pytest.raises(GuestGenerationChangedError):
                await orch._wait_for_guest_result('vm_wait', generation)
        else:
            with pytest.raises(ProvisioningFailedError, match=FAILURE_GUEST_REPORT):
                await orch._wait_for_guest_result('vm_wait', generation)
        async with factory() as session:
            assert (await session.get(VMRow, 'vm_wait')).status == VMStatus.PROVISIONING
    finally:
        await engine.dispose()
