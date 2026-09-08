from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from hyrule_cloud.api.metrics import _render
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import VMRetentionRow, VMRow
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.xcpng import VMProtectionManifest
from hyrule_cloud.services.vm_retention import prepare_retention
from tests.test_vm_expiry_renewal import _stored_vm


@pytest.mark.asyncio
async def test_verification_persists_failures_bounds_work_and_recovers_after_restart():
    orch, engine = await _stored_vm()
    orch.config = HyruleConfig(vm_retention_verify_batch_size=1)
    orch.xcpng.verify_retained_vm = AsyncMock(side_effect=[RuntimeError('private backend detail'), None, None])
    now = datetime.now(UTC)
    try:
        for key, state in [('a', 'retained'), ('b', 'retained'), ('c', 'prepared'), ('d', 'restoring')]:
            async with orch.db.begin() as session:
                session.add(VMRow(vm_id=f'vm_verify_{key}', owner_wallet='fixture', status='suspended',
                                  xcpng_uuid=f'guest-{key}', deletion_started_at=now))
            async with orch.db.begin() as session:
                retained = await prepare_retention(session, f'vm_verify_{key}',
                                                   VMProtectionManifest(f'guest-{key}', (f'disk-{key}',), (), False, '', ()),
                                                   now + timedelta(days=30))
                retained.state = state
                retained.created_at = now - timedelta(days=1)
        before = await _render(orch.db)
        assert 'hyrule_retention_verification_overdue 2\n' in before
        assert await orch.verify_retained_vms() == 1
        async with orch.db() as session:
            failed = await session.get(VMRetentionRow, 'vm_verify_a')
            assert failed.verification_error == 'provider_verification_failed'
            assert failed.last_verified_at is None and failed.verification_attempted_at is not None
            assert failed.next_verification_at.replace(tzinfo=UTC) > now
        partial = await _render(orch.db)
        assert 'hyrule_retention_verification_failures 1\n' in partial
        assert 'hyrule_retention_verification_overdue 1\n' in partial
        assert 'private backend detail' not in partial
        assert await orch.verify_retained_vms() == 1  # Failure backoff lets the next VM progress.
        assert await orch.verify_retained_vms() == 0
        assert orch.xcpng.verify_retained_vm.await_count == 2
        # A fresh orchestrator sees the persisted retry schedule and failure.
        restarted = object.__new__(Orchestrator)
        restarted.db, restarted.config, restarted.xcpng = orch.db, orch.config, orch.xcpng
        async with orch.db.begin() as session:
            failed = await session.get(VMRetentionRow, 'vm_verify_a')
            failed.next_verification_at = now - timedelta(seconds=1)
        assert await restarted.verify_retained_vms() == 1
        async with orch.db() as session:
            repaired = await session.get(VMRetentionRow, 'vm_verify_a')
            assert repaired.last_verified_at is not None and repaired.verification_error is None
            assert repaired.state == 'retained'
        after = await _render(orch.db)
        assert 'hyrule_retention_verification_failures 0\n' in after
        assert 'hyrule_retention_verification_overdue 0\n' in after
        orch.xcpng.destroy_vm.assert_not_awaited()
        orch.xcpng.start_vm.assert_not_awaited()
    finally:
        await engine.dispose()
