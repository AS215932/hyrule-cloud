import asyncio
import json
from typing import Any, cast

import pytest

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.models import VMOrderResources, VMSize
from hyrule_cloud.providers.cloudinit import render_cloud_init
from hyrule_cloud.providers.xcpng import XCPNGProvider


class _ConcurrentWebSocket:
    def __init__(self) -> None:
        self.pending_ids: list[int] = []
        self.active_receivers = 0
        self.max_active_receivers = 0

    async def send(self, raw: str) -> None:
        self.pending_ids.append(int(json.loads(raw)["id"]))

    async def recv(self) -> str:
        self.active_receivers += 1
        self.max_active_receivers = max(
            self.max_active_receivers,
            self.active_receivers,
        )
        try:
            await asyncio.sleep(0)
            request_id = self.pending_ids.pop(0)
            return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": request_id})
        finally:
            self.active_receivers -= 1

    async def close(self) -> None: ...


class CreateProvider(XCPNGProvider):
    def __init__(self) -> None:
        super().__init__(XCPNGConfig())
        self.events: list[str] = []
        self.vm_create_params: dict | None = None
        self.resize_specs: dict | None = None

    async def _xo_call(self, method: str, **params):
        self.events.append(method)
        if method == "vm.create":
            self.vm_create_params = params
            return "vm-new"
        return None

    async def _resize_vm(self, vm_uuid: str, specs: dict):
        self.events.append("resize")
        self.resize_specs = specs
        return "vdi-root", specs["disk_gb"] * 1024 * 1024 * 1024

    async def _prepare_openbsd_root_disk(
        self,
        *,
        vm_uuid: str,
        root_vdi_uuid: str,
        disk_bytes: int,
    ):
        self.events.append("openbsd-prep")


class BuilderProvider(XCPNGProvider):
    def __init__(self) -> None:
        super().__init__(
            XCPNGConfig(
                openbsd_builder_vm_uuid="builder-vm",
                openbsd_builder_ssh_host="builder.example",
                openbsd_builder_ssh_user="svag",
                openbsd_builder_disk_device="sd1",
            )
        )
        self.calls: list[tuple[str, dict]] = []
        self.power = {"builder-vm": "Halted"}
        self.vbds = {
            "vbd-prep": {
                "VM": "builder-vm",
                "VDI": "target-vdi",
                "type": "Disk",
            }
        }

    async def _xo_call(self, method: str, **params):
        self.calls.append((method, params))
        if method == "vm.attachDisk":
            return None
        if method == "vm.start":
            self.power[params["id"]] = "Running"
            return None
        if method == "vm.stop":
            self.power[params["id"]] = "Halted"
            return None
        return None

    async def _xo_objects(self, **filter_):
        if filter_.get("type") == "VBD":
            return {
                uuid: record
                for uuid, record in self.vbds.items()
                if record.get("VM") == filter_.get("VM")
            }
        return {}

    async def _xo_get_object(self, uuid: str):
        if uuid in self.power:
            return {"id": uuid, "power_state": self.power[uuid]}
        return None

    async def _wait_for_openbsd_builder_ssh(self) -> None:
        self.calls.append(("wait_builder_ssh", {}))

    async def _run_ssh(
        self,
        remote_command: list[str],
        *,
        stdin: bytes | None = None,
        timeout: int = 300,
    ):
        self.calls.append(
            (
                "ssh",
                {
                    "remote_command": remote_command,
                    "has_stdin": stdin is not None,
                    "timeout": timeout,
                },
            )
        )
        return "", ""


@pytest.mark.asyncio
async def test_openbsd_create_runs_prep_before_start():
    provider = CreateProvider()

    vm_uuid = await provider.create_vm(
        template_uuid="template",
        name_label="test-openbsd",
        os_name="openbsd-7.8",
        size=VMSize.XS,
        cloud_init_config="#cloud-config\n{}",
    )

    assert vm_uuid == "vm-new"
    assert provider.events == ["vm.create", "resize", "openbsd-prep", "vm.start"]


@pytest.mark.asyncio
async def test_debian_create_skips_openbsd_prep():
    provider = CreateProvider()

    await provider.create_vm(
        template_uuid="template",
        name_label="test-debian",
        os_name="debian-13",
        size=VMSize.XS,
        cloud_init_config="#cloud-config\n{}",
    )

    assert provider.events == ["vm.create", "resize", "vm.start"]
    assert "networkConfig" not in provider.vm_create_params


@pytest.mark.asyncio
async def test_exact_name_lookup_supports_crash_recovery(monkeypatch):
    provider = XCPNGProvider(XCPNGConfig())

    async def objects(**filters):
        assert filters == {"type": "VM"}
        return {
            "vm-b": {"name_label": "hyrule-vm_target"},
            "vm-other": {"name_label": "hyrule-vm_other"},
            "vm-a": {"name_label": "hyrule-vm_target"},
        }

    monkeypatch.setattr(provider, "_xo_objects", objects)

    assert await provider.find_vm_ids_by_name_label("hyrule-vm_target") == [
        "vm-a",
        "vm-b",
    ]


@pytest.mark.asyncio
async def test_xo_calls_serialize_websocket_request_response_exchanges():
    provider = XCPNGProvider(XCPNGConfig())
    websocket = _ConcurrentWebSocket()
    provider._xo_ws = cast(Any, websocket)

    first, second = await asyncio.gather(
        provider._xo_call("test.first"),
        provider._xo_call("test.second"),
    )

    assert first != second
    assert websocket.max_active_receivers == 1


@pytest.mark.asyncio
async def test_debian_create_passes_network_config_to_xo():
    provider = CreateProvider()

    await provider.create_vm(
        template_uuid="template",
        name_label="test-debian",
        os_name="debian-13",
        size=VMSize.XS,
        cloud_init_config="#cloud-config\n{}",
        network_config="version: 2\n",
    )

    assert provider.vm_create_params["networkConfig"] == "version: 2\n"


@pytest.mark.asyncio
async def test_create_uses_exact_order_resources_instead_of_profile_defaults():
    provider = CreateProvider()

    await provider.create_vm(
        template_uuid="template",
        name_label="test-custom",
        os_name="debian-13",
        size=VMSize.MD,
        resources=VMOrderResources(vcpu=3, ram_mb=6144, disk_gb=30),
        cloud_init_config="#cloud-config\n{}",
    )

    assert provider.resize_specs == {"vcpu": 3, "memory_mb": 6144, "disk_gb": 30}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cpu_fields",
    [
        pytest.param({"cores": 16}, id="cores"),
        pytest.param({"cpu_count": "16"}, id="xo-cpu-count"),
    ],
)
async def test_capacity_reads_host_running_vm_and_default_sr_state(
    monkeypatch, cpu_fields: dict[str, int | str]
):
    provider = XCPNGProvider(XCPNGConfig(default_sr_uuid="sr-default"))

    async def objects(**filters):
        if filters == {"type": "host"}:
            return {
                "host-1": {
                    "CPUs": cpu_fields,
                    "memory": {"size": 64 * 1024**3, "usage": 50 * 1024**3},
                }
            }
        if filters == {"type": "VM"}:
            return {
                "running": {"power_state": "Running", "CPUs": {"number": 22}},
                "halted": {"power_state": "Halted", "CPUs": {"number": 4}},
                "template": {
                    "power_state": "Running",
                    "CPUs": {"number": 8},
                    "is_a_template": True,
                },
            }
        if filters == {"type": "SR"}:
            return {
                "sr-default": {
                    "physical_size": 400 * 1024**3,
                    "physical_usage": 200 * 1024**3,
                }
            }
        raise AssertionError(filters)

    monkeypatch.setattr(provider, "_xo_objects", objects)
    capacity = await provider.capacity()

    assert capacity.physical_vcpu == 16
    assert capacity.allocated_vcpu == 22
    assert capacity.free_memory_bytes == 14 * 1024**3
    assert capacity.free_storage_bytes == 200 * 1024**3


@pytest.mark.asyncio
async def test_openbsd_builder_attaches_runs_and_detaches_target_vdi():
    provider = BuilderProvider()

    await provider._prepare_openbsd_root_disk(
        vm_uuid="target-vm",
        root_vdi_uuid="target-vdi",
        disk_bytes=10 * 1024 * 1024 * 1024,
    )

    assert provider.calls == [
        (
            "vm.attachDisk",
            {
                "vm": "builder-vm",
                "vdi": "target-vdi",
                "position": "1",
                "mode": "RW",
                "bootable": False,
            },
        ),
        ("vm.start", {"id": "builder-vm"}),
        ("wait_builder_ssh", {}),
        (
            "ssh",
            {
                "remote_command": ["doas", "sh", "-s", "--", "sd1"],
                "has_stdin": True,
                "timeout": 300,
            },
        ),
        ("vm.stop", {"id": "builder-vm", "force": True}),
        ("vbd.disconnect", {"id": "vbd-prep"}),
        ("vbd.delete", {"id": "vbd-prep"}),
    ]


def test_openbsd_cloud_init_uses_pf_not_ufw():
    user_data = render_cloud_init(
        os_name="openbsd-7.8",
        hostname="vm-test",
        ssh_pubkey="ssh-ed25519 AAAA test",
        open_ports=[80, 443],
    )

    assert user_data.startswith("#cloud-config\n")
    assert "pfctl -f /etc/pf.conf" in user_data
    assert "apt-get" not in user_data
    assert "ufw" not in user_data
