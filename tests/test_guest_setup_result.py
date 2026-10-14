from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from hyrule_cloud.providers.cloudinit import render_cloud_init


@pytest.mark.parametrize("os_name", ["debian-13", "openbsd-7.7"])
@pytest.mark.parametrize("exit_code", [0, 7])
def test_setup_exit_status_reaches_cloud_init(tmp_path: Path, os_name: str, exit_code: int) -> None:
    script = f"#!/bin/sh\nprintf 'setup stage executed\\n'\nexit {exit_code}\n"
    config = yaml.safe_load(render_cloud_init(
        os_name=os_name, hostname="test-guest", ssh_pubkey="ssh-ed25519 test",
        open_ports=[22], setup_script=script,
    ))
    setup = next(entry for entry in config["write_files"] if entry["path"] == "/root/setup.sh")
    assert setup["content"] == script
    assert setup["permissions"] == "0700"
    assert setup["owner"] == ("root:wheel" if os_name.startswith("openbsd") else "root:root")
    local_script = tmp_path / "setup.sh"
    local_script.write_text(setup["content"])
    local_script.chmod(0o700)
    local_log = tmp_path / "setup.log"
    command = config["runcmd"][-1].replace("/root/setup.sh", str(local_script)).replace(
        "/var/log/hyrule-setup.log", str(local_log),
    )
    result = subprocess.run(["/bin/sh", "-c", command], check=False)
    assert result.returncode == exit_code
    assert local_log.read_text() == "setup stage executed\n"
