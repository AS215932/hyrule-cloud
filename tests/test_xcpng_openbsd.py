import pytest

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.models import VMSize
from hyrule_cloud.providers.cloudinit import render_cloud_init
from hyrule_cloud.providers.xcpng import XCPNGProvider


class CreateProvider(XCPNGProvider):
    def __init__(self) -> None:
        super().__init__(XCPNGConfig())
        self.events: list[str] = []

    async def _xo_call(self, method: str, **params):
        self.events.append(method)
        if method == "vm.create":
            return "vm-new"
        return None

    async def _resize_vm(self, vm_uuid: str, specs: dict):
        self.events.append("resize")
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

    async def _run_openbsd_builder_prep(self, disk_device: str) -> None:
        self.calls.append(("run_prep", {"disk_device": disk_device}))


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
        ("run_prep", {"disk_device": "sd1"}),
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
