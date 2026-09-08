from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from hyrule_cloud.providers.xcpng import XCPNGProvider, XOError


def fixture_provider():
    objects = {
        'vm': {'type': 'VM', 'VBDs': ['vbd'], 'snapshots': []},
        'vbd': {'type': 'VBD', 'VM': 'vm', 'VDI': 'disk', 'is_cd_drive': False,
                'position': '0', 'bootable': True, 'read_only': False},
        'disk': {'type': 'VDI', '$SR': 'sr', 'size': 4096, 'missing': False},
    }
    provider = object.__new__(XCPNGProvider)

    async def inventory(**filters):
        if 'id' in filters:
            key = filters['id']
            return {key: deepcopy(objects[key])} if key in objects else {}
        return {key: deepcopy(row) for key, row in objects.items()
                if all(row.get(field) == value for field, value in filters.items())}

    async def delete(method, **kwargs):
        assert method == 'vm.delete'
        assert kwargs == {'id': 'vm', 'deleteDisks': False}
        objects.pop('vm', None)
        objects.pop('vbd', None)

    provider._xo_objects = AsyncMock(side_effect=inventory)
    provider._xo_call = AsyncMock(side_effect=delete)
    return provider, objects


@pytest.mark.asyncio
async def test_preserved_disks_verified_on_delete_and_retry():
    provider, objects = fixture_provider()
    manifest = await provider.capture_retention_manifest('vm')
    assert manifest.disks[0].vdi_uuid == 'disk'
    assert manifest.disks[0].position == '0'
    assert manifest.disks[0].bootable
    await provider.delete_vm_retaining_disks(manifest)
    await provider.delete_vm_retaining_disks(manifest)
    provider._xo_call.assert_awaited_once_with('vm.delete', id='vm', deleteDisks=False)
    assert objects['disk']['size'] == 4096


@pytest.mark.asyncio
@pytest.mark.parametrize('damage', ['missing_vbd', 'missing_disk', 'unknown_missing', 'duplicate', 'size_change', 'snapshots', 'unknown_snapshots'])
async def test_invalid_or_changed_manifest_prevents_delete(damage):
    provider, objects = fixture_provider()
    manifest = await provider.capture_retention_manifest('vm')
    if damage == 'missing_vbd':
        objects.pop('vbd')
    elif damage == 'missing_disk':
        objects.pop('disk')
    elif damage == 'unknown_missing':
        objects['disk'].pop('missing')
    elif damage == 'duplicate':
        objects['vm']['VBDs'].append('second')
        objects['second'] = dict(objects['vbd'], position='1')
    elif damage == 'snapshots':
        objects['vm']['snapshots'] = ['existing-recovery-point']
    elif damage == 'unknown_snapshots':
        objects['vm'].pop('snapshots')
    else:
        objects['disk']['size'] = 8192
    with pytest.raises(XOError):
        await provider.delete_vm_retaining_disks(manifest)
    provider._xo_call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['lost_ack', 'vm_still_present', 'disk_missing', 'inventory_unavailable'])
async def test_delete_response_requires_complete_retention_proof(outcome):
    provider, objects = fixture_provider()
    manifest = await provider.capture_retention_manifest('vm')

    async def deletion(*args, **kwargs):
        if outcome != 'vm_still_present':
            objects.pop('vm')
        if outcome == 'disk_missing':
            objects.pop('disk')
        if outcome == 'inventory_unavailable':
            provider._xo_objects.side_effect = ConnectionError('inventory unavailable')
        raise ConnectionError('delete reply unavailable')

    provider._xo_call.side_effect = deletion
    if outcome == 'lost_ack':
        await provider.delete_vm_retaining_disks(manifest)
    else:
        with pytest.raises((XOError, ConnectionError)):
            await provider.delete_vm_retaining_disks(manifest)


@pytest.mark.asyncio
async def test_wrong_exact_object_response_is_not_absence():
    provider, _ = fixture_provider()
    manifest = await provider.capture_retention_manifest('vm')
    provider._xo_objects.side_effect = None
    provider._xo_objects.return_value = {'different-vm': {'type': 'VM'}}
    with pytest.raises(XOError):
        await provider.delete_vm_retaining_disks(manifest)
    provider._xo_call.assert_not_awaited()
