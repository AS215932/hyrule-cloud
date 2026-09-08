from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.models import VMExpiryState, VMStatus
from hyrule_cloud.services.vm_expiry import build_vm_expiry
from tests.test_api import _TEST_TOKEN, override_state  # noqa: F401

EXPIRY = datetime(2026, 9, 8, tzinfo=UTC)


@pytest.mark.asyncio
async def test_destroyed_vm_overrides_persisted_readiness_message(override_state):
    row = await override_state.orchestrator.get_vm('vm_test123')
    row.status = VMStatus.DESTROYED
    row.metadata_ = {'launch_proof': {'customer_message': 'Your VM is ready.'}}
    override_state.orchestrator.get_vm = AsyncMock(return_value=row)
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        response = await client.get('/v1/vm/vm_test123/status')
        assert response.status_code == 200
        body = response.json()
        assert body['status'] == body['expiry']['state'] == 'destroyed'
        assert body['customer_message'] == 'The VM is destroyed.'
        assert body['expiry']['grace_ends_at'] is None
        assert row.metadata_['launch_proof']['customer_message'] == 'Your VM is ready.'


@pytest.mark.parametrize(('seconds', 'state', 'eligible'), [
    (-1, VMExpiryState.ACTIVE, False),
    (0, VMExpiryState.ACTIVE, False),
    (1, VMExpiryState.EXPIRED, False),
    (7 * 3600, VMExpiryState.EXPIRED, False),
    (7 * 3600 + 1, VMExpiryState.DELETION_ELIGIBLE, True),
])
def test_matches_worker_strict_expiry_and_configured_grace_boundaries(seconds, state, eligible):
    result = build_vm_expiry(VMStatus.READY, EXPIRY, 7, now=EXPIRY + timedelta(seconds=seconds))
    assert result.state == state
    assert result.deletion_eligible is eligible
    assert result.grace_ends_at == EXPIRY + timedelta(hours=7)


@pytest.mark.parametrize('expiry', [EXPIRY.replace(tzinfo=None), EXPIRY.astimezone(timezone(timedelta(hours=2)))])
def test_normalizes_legacy_naive_and_offset_datetimes(expiry):
    result = build_vm_expiry(VMStatus.SUSPENDED, expiry, 48, now=EXPIRY + timedelta(hours=1))
    assert result.state == VMExpiryState.EXPIRED
    assert result.grace_ends_at == EXPIRY + timedelta(hours=48)


@pytest.mark.parametrize(('status', 'expiry', 'claim', 'state'), [
    (VMStatus.FAILED, EXPIRY, None, VMExpiryState.NOT_APPLICABLE),
    (VMStatus.DESTROYED, EXPIRY, EXPIRY, VMExpiryState.DESTROYED),
    (VMStatus.READY, None, None, VMExpiryState.NOT_SET),
    (VMStatus.FAILED, EXPIRY, EXPIRY, VMExpiryState.DELETING),
    (VMStatus.SUSPENDED, EXPIRY + timedelta(days=30), None, VMExpiryState.ACTIVE),
])
def test_no_invented_suspension_reason_or_deletion_deadline(status, expiry, claim, state):
    result = build_vm_expiry(status, expiry, 48, now=EXPIRY + timedelta(days=3), deletion_started_at=claim)
    assert result.state == state
    assert result.deletion_eligible is (state == VMExpiryState.DELETING)
    if state != VMExpiryState.ACTIVE:
        assert result.grace_ends_at is None


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [VMStatus.READY, VMStatus.SUSPENDED])
async def test_public_and_owner_views_share_expiry_without_claiming_ready(override_state, status):
    row = await override_state.orchestrator.get_vm('vm_test123')
    row.status = status
    row.expires_at = datetime.now(UTC) - timedelta(hours=1)
    row.metadata_ = {'launch_proof': {'customer_message': 'Your VM is ready.'}}
    override_state.orchestrator.get_vm = AsyncMock(return_value=row)
    override_state.config.vm_grace_period_hours = 7
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        public = await client.get('/v1/vm/vm_test123/status')
        owner = await client.get('/v1/vm/vm_test123', headers={'Authorization': 'Bearer ' + _TEST_TOKEN})
        assert public.status_code == owner.status_code == 200
        for body in (public.json(), owner.json()):
            assert body['status'] == status.value
            assert body['expiry']['state'] == 'expired'
            assert datetime.fromisoformat(body['expiry']['grace_ends_at']) == row.expires_at + timedelta(hours=7)
            assert body['expiry']['deletion_eligible'] is False
        assert 'has expired' in public.json()['customer_message']
        assert 'ssh' not in public.json() and 'error' not in public.json()
        assert (await client.get('/v1/vm/vm_test123')).status_code == 404
        # Reading status neither mutates the VM nor overwrites persisted proof.
        assert row.status == status
        assert row.metadata_['launch_proof']['customer_message'] == 'Your VM is ready.'
        row.expires_at = datetime.now(UTC) + timedelta(days=1)
        renewed = await client.get('/v1/vm/vm_test123/status')
        assert renewed.json()['expiry']['state'] == 'active'
        if status == VMStatus.SUSPENDED:
            assert 'suspended' in renewed.json()['customer_message']
            assert 'ready' not in renewed.json()['customer_message']
        assert override_state.payment_gate.checked == 0
