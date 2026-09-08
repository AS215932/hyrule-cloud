import asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock

import pytest
import yaml
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.api.routes import get_orch, router
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, CryptoIntentRow, VMEventRow, VMGuestResultRow, VMRow
from hyrule_cloud.models import CryptoIntentStatus, DNSResolutionStatus, VMCreateRequest, VMStatus
from hyrule_cloud.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_guest_recovery_waits_for_native_intent_handoff(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'native-handoff.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    orch = Orchestrator(HyruleConfig(), factory)
    orch._spawn_provisioning = AsyncMock()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(
                vm_id='vm_native_handoff', owner_wallet='fixture',
                status=VMStatus.PROVISIONING,
            ))
            session.add(VMGuestResultRow(
                vm_id='vm_native_handoff', generation='a' * 32,
                token_hash='b' * 64,
                deadline=datetime.now(UTC) + timedelta(minutes=5),
            ))
            session.add(CryptoIntentRow(
                intent_id='native-handoff', asset='BTC', amount_crypto=Decimal('0.1'),
                address='fixture', status=CryptoIntentStatus.PROVISIONING,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                resource_type='vm', vm_id='vm_native_handoff',
            ))
        assert await orch.recover_tracked_provisioning() == 0
        orch._spawn_provisioning.assert_not_awaited()
        async with factory.begin() as session:
            intent = await session.get(CryptoIntentRow, 'native-handoff')
            intent.status = CryptoIntentStatus.PROVISIONED
        assert await orch.recover_tracked_provisioning() == 1
        orch._spawn_provisioning.assert_awaited_once_with('vm_native_handoff')
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_paid_dispatch_survives_restart_while_waiting_for_provisioning_slots(tmp_path, monkeypatch):
    from hyrule_cloud.db import VMGuestResultRow

    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'queued.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    config = HyruleConfig()
    config.xcpng.templates = {"debian-13": "fixture-template"}
    original, recovered = [Orchestrator(config, factory) for _ in range(2)]
    entered = []
    four_active = asyncio.Event()
    release = asyncio.Event()

    async def held_attempt(vm_id):
        entered.append(vm_id)
        if len(entered) == 4:
            four_active.set()
        await release.wait()

    original._provision_vm_owned = held_attempt
    resumed = []

    async def recovered_attempt(vm_id):
        # This fixture verifies durable dispatch, not provider completion.
        resumed.append(vm_id)

    recovered._provision_vm_owned = recovered_attempt
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        request = VMCreateRequest(ssh_pubkey='ssh-ed25519 fixture', duration_days=7)
        for i in range(8):
            vm, _ = await original.create_vm(request, owner_wallet='paid-fixture',
                                             vm_id=f'vm_queued_{i}', start_provisioning=False)
            async with factory() as session:
                assert await session.get(VMGuestResultRow, vm.vm_id) is not None
            # Models dispatch after the caller has linked its paid quote/intent.
            await original.start_provisioning(vm.vm_id)
        accepted, _ = await original.create_vm(
            request, owner_wallet='paid-fixture', vm_id='vm_accepted_no_task',
            start_provisioning=False,
        )
        async with factory() as session:
            assert await session.get(VMGuestResultRow, accepted.vm_id) is not None
        unpaid, _ = await original.reserve_vm(request, vm_id='vm_unpaid')
        await original.start_provisioning(unpaid.vm_id)
        await asyncio.wait_for(four_active.wait(), 5)
        assert len(entered) == 4
        assert len(original._tasks) == 8
        async with factory() as session:
            assert len(list(await session.scalars(select(VMGuestResultRow.vm_id)))) == 9
            assert await session.get(VMGuestResultRow, unpaid.vm_id) is None
        await original.shutdown()
        await engine.dispose()
        assert await recovered.recover_tracked_provisioning() == 4
        assert await recovered.recover_tracked_provisioning() == 4
        assert await recovered.recover_tracked_provisioning() == 1
        await asyncio.wait_for(asyncio.gather(*list(recovered._tasks)), 5)
        async with factory() as session:
            rows = list(await session.scalars(select(VMRow).where(VMRow.vm_id.like('vm_queued_%'))))
            assert len(rows) == 8 and all(row.status == VMStatus.PROVISIONING for row in rows)
            assert sorted(resumed) == sorted([*(row.vm_id for row in rows), accepted.vm_id])
            assert (await session.get(VMRow, unpaid.vm_id)).status == VMStatus.PROVISIONING
    finally:
        await original.shutdown()
        await recovered.shutdown()
        await engine.dispose()


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
        await original.start_provisioning('vm_restart')
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


@pytest.mark.asyncio
@pytest.mark.parametrize('existing_attempt', [False, True])
async def test_simulation_does_not_create_or_erase_real_guest_receipts(tmp_path, monkeypatch, existing_attempt):
    from hyrule_cloud.db import VMGuestResultRow
    from hyrule_cloud.services.guest_result import prepare_guest_result

    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: False)
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'simulation.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    orch = Orchestrator(HyruleConfig(), factory)
    orch.dns.delete_aaaa = AsyncMock()
    orch.xcpng.create_vm = AsyncMock(side_effect=AssertionError('simulation must not create guests'))
    orch.xcpng.destroy_vm = AsyncMock(side_effect=AssertionError('unknown guest must be preserved'))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        vm, _ = await orch.create_vm(
            VMCreateRequest(ssh_pubkey='ssh-ed25519 fixture', duration_days=7),
            owner_wallet='fixture', start_provisioning=False,
        )
        if existing_attempt:
            async with factory() as session:
                await prepare_guest_result(session, vm.vm_id, datetime.now(UTC) + timedelta(minutes=5))
                await session.commit()
        await orch.start_provisioning(vm.vm_id)
        await asyncio.wait_for(asyncio.gather(*list(orch._tasks)), 5)
        async with factory() as session:
            row = await session.get(VMRow, vm.vm_id)
            assert row.status == (VMStatus.PROVISIONING if existing_attempt else VMStatus.READY)
            assert (await session.get(VMGuestResultRow, vm.vm_id) is not None) == existing_attempt
        assert await orch.destroy_vm(vm.vm_id)
        await orch.release_destroyed_prefix(vm.vm_id)
        async with factory() as session:
            row = await session.get(VMRow, vm.vm_id)
            assert row.status == VMStatus.DESTROYED
            assert (row.ipv6_prefix_index is not None) == existing_attempt
            assert (await session.get(VMGuestResultRow, vm.vm_id) is not None) == existing_attempt
        orch.xcpng.create_vm.assert_not_awaited()
        orch.xcpng.destroy_vm.assert_not_awaited()
    finally:
        await orch.shutdown()
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize('stop_fails', [False, True])
@pytest.mark.parametrize('restriction', ['disabled', 'deleted'])
async def test_disable_during_clone_stops_before_initialization_and_retries(tmp_path, monkeypatch, stop_fails, restriction):
    from hyrule_cloud.db import AccountRow, VMGuestResultRow
    from hyrule_cloud.services.guest_result import prepare_guest_result

    monkeypatch.setattr('hyrule_cloud.services.launch_proof.use_real_provisioning', lambda: True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'late-disabled.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    config = HyruleConfig()
    config.xcpng.templates = {'debian-13': 'fixture-template'}
    orch = Orchestrator(config, factory)
    orch.xcpng.find_vm_ids_by_name_label = AsyncMock(return_value=[])
    orch.xcpng.suspend_vm = AsyncMock(side_effect=RuntimeError('temporarily unavailable') if stop_fails else None)
    orch._wait_for_ipv6 = AsyncMock(side_effect=AssertionError('disabled guest reached network wait'))
    orch._wait_for_guest_result = AsyncMock(side_effect=AssertionError('disabled guest reached guest wait'))
    orch._record_vm_refund = AsyncMock()
    orch.xcpng.destroy_vm = AsyncMock(side_effect=RuntimeError('temporarily unavailable') if stop_fails else None)
    owner = 'HOWNER00001'
    vm_id = 'vm_late_disabled'
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(AccountRow(account_id=owner))
        async with factory.begin() as session:
            session.add(VMRow(vm_id=vm_id, owner_wallet='fixture', owner_account_id=owner,
                              ipv6_prefix='2a0c:b641:b51:5::/64', ipv6_prefix_index=5,
                              expires_at=datetime.now(UTC) + timedelta(days=1)))
        async with factory.begin() as session:
            await prepare_guest_result(session, vm_id, datetime.now(UTC) + timedelta(minutes=5))

        async def finish_clone_after_disable(**kwargs):
            # Model the durable result of account-disable finishing while XO
            # creates a UUID-less guest. Its old worker job will not run again.
            if restriction == 'deleted':
                assert await orch.destroy_vm(vm_id)
            else:
                async with factory.begin() as session:
                    account = await session.get(AccountRow, owner)
                    account.disabled_at = datetime.now(UTC)
                    row = await session.get(VMRow, vm_id)
                    row.suspension_reason = 'account_disabled'
            return 'late-provider-guest'

        orch.xcpng.create_vm = AsyncMock(side_effect=finish_clone_after_disable)
        await orch._provision_vm_owned(vm_id)
        action = orch.xcpng.destroy_vm if restriction == 'deleted' else orch.xcpng.suspend_vm
        action.assert_awaited_once_with('late-provider-guest')
        orch._wait_for_ipv6.assert_not_awaited()
        orch._wait_for_guest_result.assert_not_awaited()
        orch._record_vm_refund.assert_not_awaited()
        async with factory() as session:
            row = await session.get(VMRow, vm_id)
            assert row.status == (VMStatus.DESTROYED if restriction == 'deleted' else VMStatus.PROVISIONING)
            assert row.xcpng_uuid == 'late-provider-guest'
            assert await session.get(VMGuestResultRow, vm_id) is not None
        # Restarted dispatch keeps the known UUID and retries a failed stop.
        action.side_effect = None
        if restriction == 'deleted':
            await orch.check_expiries()
            assert action.await_count == (2 if stop_fails else 1)
            async with factory() as session:
                row = await session.get(VMRow, vm_id)
                assert row.metadata_['provider_deleted_uuid'] == 'late-provider-guest'
                assert row.ipv6_prefix_index is None
        else:
            await orch._provision_vm_owned(vm_id)
            assert action.await_count == 2
        orch.xcpng.create_vm.assert_awaited_once()
        orch._wait_for_ipv6.assert_not_awaited()
    finally:
        await orch.shutdown()
        await engine.dispose()
