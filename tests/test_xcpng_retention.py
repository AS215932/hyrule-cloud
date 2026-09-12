from copy import deepcopy
from unittest.mock import AsyncMock

import pytest

from hyrule_cloud.providers.xcpng import XCPNGProvider, XOError


def fixture_provider():
    objects = {
        'vm': {'type': 'VM', '$VBDs': ['vbd'], 'snapshots': [],
               'power_state': 'Halted', 'auto_poweron': False, 'high_availability': '', 'blockedOperations': {},
               'CPUs': {'number': 2, 'max': 2},
               'memory': {'dynamic': [1024, 2048], 'static': [0, 4096]},
               'boot': {'firmware': 'bios', 'order': 'c'}, 'bios_strings': {},
               'secureBoot': False, 'virtualizationMode': 'hvm', 'needsVtpm': False,
               'VTPMs': [], 'VGPUs': [], 'nicType': 'e1000'},
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

    provider._xo_objects = AsyncMock(side_effect=inventory)
    provider._xo_call = AsyncMock(side_effect=AssertionError("unexpected provider mutation"))
    return provider, objects


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['protected', 'running', 'autostart', 'missing'])
async def test_whole_vm_retention_protects_guest_without_deleting_data(outcome):
    provider, objects = fixture_provider()
    vm = objects['vm']
    vm.update(power_state='Running', auto_poweron=True, high_availability='restart',
              blockedOperations={'destroy': 'operator-existing-block'})
    snapshots = ['existing-snapshot']
    vm['snapshots'] = snapshots
    objects['existing-snapshot'] = {'type': 'VM-snapshot'}
    manifest = await provider.capture_vm_protection('vm')

    async def mutate(method, **kwargs):
        assert method in ('vm.set', 'vm.stop')
        if method == 'vm.set':
            vm['auto_poweron'] = kwargs['auto_poweron']
            vm['high_availability'] = kwargs['high_availability']
            vm['blockedOperations'] = kwargs['blockedOperations']
        else:
            vm['power_state'] = 'Halted'
            if outcome == 'running':
                vm['power_state'] = 'Running'
            elif outcome == 'autostart':
                vm['auto_poweron'] = True
            elif outcome == 'missing':
                objects.pop('vm')

    provider._xo_call.side_effect = mutate
    if outcome == 'protected':
        await provider.protect_retained_vm(manifest)
        assert vm['blockedOperations']['destroy'] == 'operator-existing-block'
        assert vm['snapshots'] == snapshots
        assert 'disk' in objects and 'vbd' in objects
    else:
        with pytest.raises(XOError):
            await provider.protect_retained_vm(manifest)
    assert all(call.args[0] != 'vm.delete' for call in provider._xo_call.await_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['restored', 'lost_reply', 'ignored_patch', 'disk_missing', 'running'])
async def test_restore_retained_vm_preserves_operator_blocks_and_reconciles_retry(outcome):
    provider, objects = fixture_provider()
    vm = objects['vm']
    vm.update(power_state='Halted', auto_poweron=True, high_availability='restart',
              blockedOperations={'destroy': 'original-operator-block', 'resume': ''})
    manifest = await provider.capture_vm_protection('vm')
    vm.update(auto_poweron=False, high_availability='', blockedOperations={
        'start': 'hyrule:retained', 'resume': 'hyrule:retained',
        'destroy': 'new-operator-block', 'migrate': 'maintenance'})

    async def mutate(method, **kwargs):
        assert method == 'vm.set'  # Recovery must never start or destroy a guest.
        vm['auto_poweron'] = kwargs['auto_poweron']
        vm['high_availability'] = kwargs['high_availability']
        assert kwargs['blockedOperations'] == {'start': None, 'resume': ''}
        if outcome != 'ignored_patch':
            for key, value in kwargs['blockedOperations'].items():
                if value is None:
                    vm['blockedOperations'].pop(key, None)
                else:
                    vm['blockedOperations'][key] = value
        if outcome == 'lost_reply':
            raise ConnectionError('reply lost after applying settings')
        if outcome == 'disk_missing':
            objects.pop('disk')
        if outcome == 'running':
            vm['power_state'] = 'Running'

    provider._xo_call.side_effect = mutate
    if outcome == 'restored':
        await provider.restore_retained_vm(manifest)
    else:
        with pytest.raises((XOError, ConnectionError)):
            await provider.restore_retained_vm(manifest)
    if outcome in ('restored', 'lost_reply'):
        await provider.restore_retained_vm(manifest)
        assert provider._xo_call.await_count == 1
        assert vm['power_state'] == 'Halted'
        assert vm['blockedOperations'] == {
            'resume': '', 'destroy': 'new-operator-block', 'migrate': 'maintenance'}
        assert 'disk' in objects


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['running', 'storage'])
async def test_restore_rejects_changed_guest_before_mutation(change):
    provider, objects = fixture_provider()
    vm = objects['vm']
    vm.update(power_state='Halted', auto_poweron=False, high_availability='',
              blockedOperations={'start': 'hyrule:retained'})
    manifest = await provider.capture_vm_protection('vm')
    if change == 'running':
        vm['power_state'] = 'Running'
    else:
        objects['another-disk'] = objects.pop('disk')
        objects['vbd']['VDI'] = 'another-disk'
    with pytest.raises(XOError):
        await provider.restore_retained_vm(manifest)
    provider._xo_call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('damage', ['wrong_id', 'missing_vm', 'vbd_coverage', 'missing_disk',
                                  'missing_snapshot', 'invalid_flags'])
async def test_incomplete_whole_vm_inventory_prevents_provider_mutation(damage):
    provider, objects = fixture_provider()
    manifest = await provider.capture_vm_protection('vm')
    if damage == 'wrong_id':
        provider._xo_objects.side_effect = None
        provider._xo_objects.return_value = {'different-vm': {'type': 'VM'}}
    elif damage == 'missing_vm':
        objects.pop('vm')
    elif damage == 'vbd_coverage':
        objects['vm']['$VBDs'] = []
    elif damage == 'missing_disk':
        objects.pop('disk')
    elif damage == 'missing_snapshot':
        objects['vm']['snapshots'] = ['unavailable']
    else:
        objects['vm']['auto_poweron'] = 'false'
    with pytest.raises(XOError):
        await provider.protect_retained_vm(manifest)
    with pytest.raises(XOError):
        await provider.restore_retained_vm(manifest)
    provider._xo_call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('drift', ['none', 'running', 'autostart', 'ha', 'unblocked', 'disk_missing'])
async def test_periodic_verification_detects_drift_without_mutation(drift):
    provider, objects = fixture_provider()
    manifest = await provider.capture_vm_protection('vm')
    vm = objects['vm']
    vm['blockedOperations'] = {'start': 'retained', 'resume': 'retained', 'destroy': 'operator'}
    if drift == 'running':
        vm['power_state'] = 'Running'
    elif drift == 'autostart':
        vm['auto_poweron'] = True
    elif drift == 'ha':
        vm['high_availability'] = 'restart'
    elif drift == 'unblocked':
        vm['blockedOperations'].pop('start')
    elif drift == 'disk_missing':
        objects['disk']['missing'] = True
    if drift == 'none':
        await provider.verify_retained_vm(manifest)
    else:
        with pytest.raises(XOError):
            await provider.verify_retained_vm(manifest)
    provider._xo_call.assert_not_awaited()
