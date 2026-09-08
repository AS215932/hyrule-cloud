"""Standalone guest helper: stdlib only; installed without the cloud application."""
from __future__ import annotations

import json
import os
import select
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

STATE = Path('/var/lib/hyrule-guest-result')


def classify(returncode: int, output: bytes, setup_required: bool, setup_exit: int | None) -> dict[str, str | int] | None:
    """Only explicit clean completion is success; never send raw status output."""
    if setup_exit is not None and setup_exit != 0:
        return {'outcome': 'failed', 'stage': 'setup_script', 'exit_code': min(255, max(1, setup_exit))}
    try:
        if len(output) > 65536:
            raise ValueError('status too large')
        status = json.loads(output)
        if not isinstance(status, dict):
            raise ValueError('invalid status')
    except (ValueError, UnicodeError):
        return {'outcome': 'failed', 'stage': 'cloud_init', 'exit_code': 1}
    if status.get('status') == 'running':
        return None
    clean = (
        returncode == 0 and status.get('status') == 'done'
        and status.get('extended_status') == 'done'
        and not status.get('errors') and not status.get('recoverable_errors')
    )
    if not clean:
        return {'outcome': 'failed', 'stage': 'cloud_init', 'exit_code': min(255, max(1, returncode))}
    if setup_required and setup_exit != 0:
        return {'outcome': 'failed', 'stage': 'setup_script', 'exit_code': 1}
    return {'outcome': 'succeeded', 'stage': 'cloud_init', 'exit_code': 0}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def save_receipt(path: Path, payload: dict[str, str | int | bool]) -> None:
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        json.dump(payload, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_cloud_status() -> tuple[int, bytes]:
    """Bound both the command duration and captured status JSON."""
    process = subprocess.Popen(
        ['cloud-init', 'status', '--format=json'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    limit = time.monotonic() + 30
    output = bytearray()
    try:
        assert process.stdout is not None
        while True:
            remaining = limit - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise TimeoutError('cloud-init status timeout')
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            if len(output) + len(chunk) > 65536:
                raise ValueError('cloud-init status too large')
            output.extend(chunk)
        return process.wait(timeout=max(0.01, limit - time.monotonic())), bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


def main() -> int:
    if (STATE / 'delivered').exists():
        return 0
    config = json.loads((STATE / 'config.json').read_text())
    url = config['url']
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return 1
    opener = build_opener(ProxyHandler({}), NoRedirect())
    receipt = STATE / 'result.json'
    # The controller enforces the absolute receipt deadline. Guest RTC/NTP can
    # be wrong at boot, so only use a bounded monotonic window for local retries.
    retry_until = time.monotonic() + min(3600, max(60, int(config.get('retry_seconds', 900))))
    while time.monotonic() < retry_until:
        if receipt.exists():
            payload = json.loads(receipt.read_text())
        else:
            try:
                returncode, output = read_cloud_status()
                setup_path = STATE / 'setup-exit'
                setup_exit = int(setup_path.read_text()) if setup_path.exists() else None
                payload = classify(returncode, output, config['setup_required'], setup_exit)
            except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
                payload = {'outcome': 'failed', 'stage': 'cloud_init', 'exit_code': 1}
            if payload is None:
                time.sleep(5)
                continue
            save_receipt(receipt, payload)
        request = Request(url, data=json.dumps(payload).encode(), method='POST', headers={
            'Authorization': 'Bearer ' + config['token'], 'Content-Type': 'application/json',
        })
        try:
            with opener.open(request, timeout=10) as response:
                if response.status == 204:
                    save_receipt(STATE / 'delivered', {'delivered': True})
                    (STATE / 'config.json').unlink(missing_ok=True)
                    return 0
        except HTTPError as exc:
            if exc.code in (400, 404, 409, 410, 413, 415):
                return 0  # Invalid or stale identity cannot be repaired by retrying.
        except (URLError, TimeoutError, OSError):
            pass
        time.sleep(5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
