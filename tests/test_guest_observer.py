import json
import subprocess

import pytest
import yaml

from hyrule_cloud.providers import guest_observer
from hyrule_cloud.providers.cloudinit import render_cloud_init


@pytest.mark.parametrize(('code', 'status', 'setup_required', 'setup_exit', 'expected'), [
    (0, {'status': 'done', 'extended_status': 'done', 'errors': [], 'recoverable_errors': {}}, True, 0, 'succeeded'),
    (2, {'status': 'done', 'extended_status': 'degraded done'}, False, None, 'failed'),
    (1, {'status': 'error', 'errors': ['private error']}, False, None, 'failed'),
    (0, {'status': 'done', 'errors': ['private error']}, False, None, 'failed'),
    (0, {'status': 'done'}, True, None, 'failed'),
    (0, {'status': 'running'}, False, None, None),
    (0, {'status': 'done'}, True, 7, 'failed'),
    (0, {'status': 'disabled'}, False, None, 'failed'),
])
def test_only_clean_cloud_init_can_succeed(code, status, setup_required, setup_exit, expected):
    result = guest_observer.classify(code, json.dumps(status).encode(), setup_required, setup_exit)
    assert (result['outcome'] if result else None) == expected
    assert 'private error' not in json.dumps(result)


def test_malformed_status_is_failure():
    assert guest_observer.classify(0, b'invalid status', False, None)['outcome'] == 'failed'


def test_report_render_records_setup_failure_without_blocking_cloud_final(tmp_path):
    config = yaml.safe_load(render_cloud_init(
        hostname='test-guest', ssh_pubkey='ssh-ed25519 test', open_ports=[22],
        setup_script='#!/bin/sh\nexit 7\n',
        guest_report={'url': 'https://cloud.example.test/result', 'token': 'test-only', 'deadline': 1},
    ))
    files = {entry['path']: entry for entry in config['write_files']}
    unit = files['/etc/systemd/system/hyrule-guest-result.service']['content']
    assert 'After=cloud-final.service network-online.target' in unit
    assert 'Requires=cloud-final' not in unit
    assert 'systemctl enable --now --no-block hyrule-guest-result.service' in config['runcmd']
    assert files['/var/lib/hyrule-guest-result/config.json']['permissions'] == '0600'
    setup = tmp_path / 'setup.sh'
    setup.write_text(files['/root/setup.sh']['content'])
    setup.chmod(0o700)
    command = config['runcmd'][-1].replace('/root/setup.sh', str(setup)).replace(
        '/var/log/hyrule-setup.log', str(tmp_path / 'setup.log'),
    ).replace('/var/lib/hyrule-guest-result', str(tmp_path))
    result = subprocess.run(['/bin/sh', '-c', command], check=False)
    assert result.returncode == 7
    assert int((tmp_path / 'setup-exit').read_text()) == 7


@pytest.mark.parametrize('guest_wall_time', [0, 99999999999])
def test_retry_uses_persisted_result_and_removes_token_after_ack(tmp_path, monkeypatch, guest_wall_time):
    monkeypatch.setattr(guest_observer, 'STATE', tmp_path)
    monkeypatch.setattr(guest_observer.time, 'time', lambda: guest_wall_time)
    (tmp_path / 'config.json').write_text(json.dumps({
        'url': 'https://cloud.example.test/result', 'token': 'test-only',
        'deadline': 9999999999, 'setup_required': True,
    }))
    original = {'outcome': 'failed', 'stage': 'setup_script', 'exit_code': 7}
    guest_observer.save_receipt(tmp_path / 'result.json', original)
    sent = []

    class Reply:
        status = 204
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    class Sender:
        def open(self, request, timeout):
            assert timeout == 10
            sent.append(json.loads(request.data))
            return Reply()

    monkeypatch.setattr(guest_observer, 'build_opener', lambda *args: Sender())
    monkeypatch.setattr(guest_observer, 'read_cloud_status', lambda: pytest.fail('must not reclassify saved result'))
    assert guest_observer.main() == 0
    assert sent == [original]
    assert not (tmp_path / 'config.json').exists()
    assert guest_observer.main() == 0  # Restart after ack never sends again.
    assert sent == [original]


def test_network_failure_retries_are_bounded_by_monotonic_time(tmp_path, monkeypatch):
    monkeypatch.setattr(guest_observer, 'STATE', tmp_path)
    (tmp_path / 'config.json').write_text(json.dumps({
        'url': 'https://cloud.example.test/result', 'token': 'test-only',
        'deadline': 1, 'retry_seconds': 60, 'setup_required': False,
    }))
    guest_observer.save_receipt(tmp_path / 'result.json', {
        'outcome': 'succeeded', 'stage': 'cloud_init', 'exit_code': 0,
    })
    clock = [100.0]
    calls = []

    class Sender:
        def open(self, request, timeout):
            calls.append(clock[0])
            raise OSError('test network unavailable')

    monkeypatch.setattr(guest_observer, 'build_opener', lambda *args: Sender())
    monkeypatch.setattr(guest_observer.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(guest_observer.time, 'time', lambda: pytest.fail('guest wall clock is not authoritative'))
    monkeypatch.setattr(guest_observer.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    assert guest_observer.main() == 0
    assert len(calls) == 12
    assert clock[0] == 160
    assert (tmp_path / 'config.json').exists()
    assert not (tmp_path / 'delivered').exists()


@pytest.mark.parametrize('recovers', [True, False])
def test_observer_local_errors_retry_without_persisting_false_failure(tmp_path, monkeypatch, recovers):
    monkeypatch.setattr(guest_observer, 'STATE', tmp_path)
    (tmp_path / 'config.json').write_text(json.dumps({
        'url': 'https://cloud.example.test/result', 'token': 'test-only',
        'retry_seconds': 60, 'setup_required': False,
    }))
    clock = [0.0]
    reads = []
    sent = []

    def read():
        reads.append(clock[0])
        assert not (tmp_path / 'result.json').exists()
        if not recovers or len(reads) <= 4:
            errors = [TimeoutError(), OSError(), subprocess.TimeoutExpired('cloud-init', 30), ValueError()]
            raise errors[(len(reads) - 1) % len(errors)]
        return 0, json.dumps({'status': 'done', 'extended_status': 'done'}).encode()

    class Reply:
        status = 204
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    class Sender:
        def open(self, request, timeout):
            sent.append(json.loads(request.data))
            return Reply()

    monkeypatch.setattr(guest_observer, 'read_cloud_status', read)
    monkeypatch.setattr(guest_observer, 'build_opener', lambda *args: Sender())
    monkeypatch.setattr(guest_observer.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(guest_observer.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    assert guest_observer.main() == 0
    if recovers:
        assert len(reads) == 5
        assert sent == [{'outcome': 'succeeded', 'stage': 'cloud_init', 'exit_code': 0}]
        assert (tmp_path / 'delivered').exists()
    else:
        assert len(reads) == 12 and clock[0] == 60
        assert not sent
        assert not (tmp_path / 'result.json').exists()
        assert (tmp_path / 'config.json').exists()


@pytest.mark.parametrize('length', [32, 70000])
def test_status_command_output_is_bounded(monkeypatch, length):
    import sys

    spawn = subprocess.Popen
    monkeypatch.setattr(guest_observer.subprocess, 'Popen', lambda *args, **kwargs: spawn(
        [sys.executable, '-c', f'import sys; sys.stdout.write("x" * {length})'], **kwargs,
    ))
    if length > 65536:
        with pytest.raises(ValueError, match='too large'):
            guest_observer.read_cloud_status()
    else:
        code, output = guest_observer.read_cloud_status()
        assert code == 0 and output == b'x' * length
