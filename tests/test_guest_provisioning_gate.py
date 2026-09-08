from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
import yaml
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.api.routes import get_orch, router
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.models import DNSResolutionStatus, VMStatus
from hyrule_cloud.orchestrator import Orchestrator


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
