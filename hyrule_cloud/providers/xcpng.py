"""
XCP-NG provider via Xen Orchestra.

All XCP-NG operations go through XO's JSON-RPC WebSocket API. XO has
mgmt-side access to XAPI (dom0 10.0.0.1) and proxies the calls internally,
keeping dom0 underlay-only.

XO API: https://docs.xen-orchestra.com/
"""

from __future__ import annotations

import asyncio
import json
import ssl
from itertools import count
from pathlib import Path
from typing import Any

import structlog
import websockets

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.models import VM_SPECS, VMSize
from hyrule_cloud.providers.base import Provider, ProviderError

log = structlog.get_logger()

_xo_req_id = count(1)


class XOError(ProviderError):
    """Raised when XO JSON-RPC returns an error."""

    def __init__(self, method: str, error: dict) -> None:
        self.method = method
        self.error = error
        super().__init__("XCPNG", method, str(error))


class XCPNGProvider(Provider):
    """XO JSON-RPC client for XCP-NG VM lifecycle."""

    def __init__(self, config: XCPNGConfig) -> None:
        self.config = config

        self._xo_ws: websockets.WebSocketClientProtocol | None = None
        if config.xo_url.startswith("wss://"):
            self._xo_ssl: ssl.SSLContext | None = ssl.create_default_context()
            if not config.xo_verify_ssl:
                self._xo_ssl.check_hostname = False
                self._xo_ssl.verify_mode = ssl.CERT_NONE
        else:
            self._xo_ssl = None

        self._openbsd_builder_lock = asyncio.Lock()

    # --- XO JSON-RPC ---

    async def _xo_connect(self) -> None:
        self._xo_ws = await websockets.connect(
            self.config.xo_url, ssl=self._xo_ssl, max_size=50 * 1024 * 1024,
        )
        result = await self._xo_call(
            "session.signInWithToken", token=self.config.xo_token
        )
        log.info("xo_login_success", user=result.get("email"))

    async def _xo_call(self, method: str, **params: Any) -> Any:
        if not self._xo_ws:
            await self._xo_connect()

        req_id = next(_xo_req_id)
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": req_id,
        })
        await self._xo_ws.send(msg)

        # XO sends notifications (method="all") interleaved with responses
        while True:
            raw = await asyncio.wait_for(self._xo_ws.recv(), timeout=300)
            resp = json.loads(raw)
            if resp.get("id") == req_id:
                if "error" in resp:
                    raise XOError(method, resp["error"])
                return resp.get("result")

    async def _xo_objects(self, **filter_: Any) -> dict[str, dict]:
        """Query XO's object cache. Returns {uuid: record}."""
        return await self._xo_call("xo.getAllObjects", filter=filter_)

    async def health_check(self) -> bool:
        """Check if connection to XO is alive."""
        try:
            if not self._xo_ws:
                await self._xo_connect()
            # A simple call to verify it's reachable and working
            await self._xo_call("system.getInfo")
            return True
        except Exception:
            return False

    async def _xo_get_object(self, uuid: str) -> dict | None:
        objs = await self._xo_objects(id=uuid)
        return next(iter(objs.values()), None)

    async def login(self) -> None:
        await self._xo_connect()

    async def logout(self) -> None:
        if self._xo_ws:
            await self._xo_ws.close()
            self._xo_ws = None

    # --- VM Lifecycle ---

    async def create_vm(
        self,
        *,
        template_uuid: str,
        name_label: str,
        os_name: str = "debian-13",
        size: VMSize,
        cloud_init_config: str,
    ) -> str:
        """
        Create a VM via XO's JSON-RPC API.

        XO handles: clone, cloud-init config drive, disk, network, boot.
        We handle: CPU/memory/disk sizing after creation.

        Returns the new VM's UUID.
        """
        specs = VM_SPECS[size]
        log.info("vm_create_start", template=template_uuid, name=name_label, size=size.value)

        vm_uuid = await self._xo_call(
            "vm.create",
            template=template_uuid,
            name_label=name_label,
            cloudConfig=cloud_init_config,
            VIFs=[{"network": self.config.default_network_uuid}],
            bootAfterCreate=False,
            clone=True,
        )
        log.info("vm_cloned", uuid=vm_uuid)

        try:
            root_vdi_uuid, disk_bytes = await self._resize_vm(vm_uuid, specs)
            if self._is_openbsd_template(os_name):
                await self._prepare_openbsd_root_disk(
                    vm_uuid=vm_uuid,
                    root_vdi_uuid=root_vdi_uuid,
                    disk_bytes=disk_bytes,
                )
            await self._xo_call("vm.start", id=vm_uuid)
            log.info("vm_created", uuid=vm_uuid, size=size.value, name=name_label)
            return vm_uuid

        except Exception:
            log.error("vm_create_failed", uuid=vm_uuid, exc_info=True)
            try:
                await self._xo_call("vm.delete", id=vm_uuid)
            except Exception:
                log.error("vm_cleanup_failed", uuid=vm_uuid, exc_info=True)
            raise

    async def _resize_vm(self, vm_uuid: str, specs: dict) -> tuple[str, int]:
        """Set CPU, memory, and disk to match a size tier via XO.

        Returns the root VDI UUID and requested disk size in bytes. OpenBSD uses
        that VDI in an offline builder pass before the VM is first started.
        """
        vcpu = specs["vcpu"]
        memory_bytes = specs["memory_mb"] * 1024 * 1024

        # vm.set with CPUs sets both VCPUs_max and VCPUs_at_startup on a
        # halted VM; coresPerSocket must divide CPUs evenly.
        await self._xo_call(
            "vm.set",
            id=vm_uuid,
            CPUs=vcpu,
            coresPerSocket=vcpu,
            memory=memory_bytes,
        )

        # Resize the clone's root disk (not the CloudConfigDrive).
        vbds = await self._xo_objects(type="VBD", VM=vm_uuid, is_cd_drive=False)
        disk_bytes = specs["disk_gb"] * 1024 * 1024 * 1024
        for vbd in vbds.values():
            vdi_uuid = vbd.get("VDI")
            if not vdi_uuid:
                continue
            vdi = await self._xo_get_object(vdi_uuid)
            if not vdi or vdi.get("name_label") == "XO CloudConfigDrive":
                continue
            if int(vdi.get("size", 0)) < disk_bytes:
                await self._xo_call("vdi.set", id=vdi_uuid, size=disk_bytes)
            return vdi_uuid, disk_bytes

        raise XOError("_resize_vm", {"message": f"No root VDI found for VM {vm_uuid}"})

    @staticmethod
    def _is_openbsd_template(os_name: str) -> bool:
        return os_name.lower().startswith("openbsd")

    async def _prepare_openbsd_root_disk(
        self,
        *,
        vm_uuid: str,
        root_vdi_uuid: str,
        disk_bytes: int,
    ) -> None:
        """Grow an OpenBSD root filesystem offline before first boot.

        OpenBSD growfs cannot safely grow a mounted root filesystem. Instead, we
        attach the target VM's halted root VDI to a dedicated OpenBSD builder VM,
        boot the builder, run native OpenBSD fdisk/disklabel/growfs/fsck against
        the secondary disk, then detach the VDI and start the target VM.
        """
        cfg = self.config
        if not cfg.openbsd_builder_vm_uuid:
            raise XOError(
                "openbsd.prepare",
                {"message": "XCPNG_OPENBSD_BUILDER_VM_UUID is required for OpenBSD VMs"},
            )
        if not cfg.openbsd_builder_ssh_host:
            raise XOError(
                "openbsd.prepare",
                {"message": "XCPNG_OPENBSD_BUILDER_SSH_HOST is required for OpenBSD VMs"},
            )

        async with self._openbsd_builder_lock:
            builder_uuid = cfg.openbsd_builder_vm_uuid
            attach_vbd_uuid: str | None = None
            log.info(
                "openbsd_prepare_start",
                vm=vm_uuid,
                builder=builder_uuid,
                root_vdi=root_vdi_uuid,
                disk_bytes=disk_bytes,
            )

            try:
                await self._ensure_vm_halted(builder_uuid)
                await self._xo_call(
                    "vm.attachDisk",
                    vm=builder_uuid,
                    vdi=root_vdi_uuid,
                    position=str(cfg.openbsd_builder_attach_position),
                    mode="RW",
                    bootable=False,
                )
                attach_vbd_uuid = await self._find_vbd(builder_uuid, root_vdi_uuid)

                await self._xo_call("vm.start", id=builder_uuid)
                await self._wait_for_vm_power_state(builder_uuid, "Running", timeout=60)
                await self._wait_for_openbsd_builder_ssh()
                await self._run_openbsd_builder_prep(cfg.openbsd_builder_disk_device)

                log.info("openbsd_prepare_done", vm=vm_uuid, root_vdi=root_vdi_uuid)

            finally:
                try:
                    await self._ensure_vm_halted(builder_uuid)
                finally:
                    if attach_vbd_uuid:
                        await self._delete_vbd(attach_vbd_uuid)

    async def _ensure_vm_halted(self, vm_uuid: str) -> None:
        vm = await self._xo_get_object(vm_uuid)
        if vm and vm.get("power_state") != "Halted":
            await self._xo_call("vm.stop", id=vm_uuid, force=True)
            await self._wait_for_vm_power_state(vm_uuid, "Halted", timeout=120)

    async def _wait_for_vm_power_state(
        self,
        vm_uuid: str,
        expected: str,
        *,
        timeout: int,
    ) -> None:
        elapsed = 0
        while elapsed < timeout:
            vm = await self._xo_get_object(vm_uuid)
            if vm and vm.get("power_state") == expected:
                return
            await asyncio.sleep(2)
            elapsed += 2
        raise XOError(
            "vm.waitPowerState",
            {"message": f"VM {vm_uuid} did not reach {expected} within {timeout}s"},
        )

    async def _find_vbd(self, vm_uuid: str, vdi_uuid: str) -> str:
        vbds = await self._xo_objects(type="VBD", VM=vm_uuid)
        for vbd_uuid, vbd in vbds.items():
            if vbd.get("VDI") == vdi_uuid:
                return vbd_uuid
        raise XOError(
            "vbd.find",
            {"message": f"No VBD found for VM {vm_uuid} and VDI {vdi_uuid}"},
        )

    async def _delete_vbd(self, vbd_uuid: str) -> None:
        try:
            await self._xo_call("vbd.disconnect", id=vbd_uuid)
        except Exception:
            pass
        await self._xo_call("vbd.delete", id=vbd_uuid)

    async def _wait_for_openbsd_builder_ssh(self) -> None:
        timeout = self.config.openbsd_builder_ssh_timeout_seconds
        elapsed = 0
        while elapsed < timeout:
            try:
                await self._run_ssh(["true"], timeout=10)
                return
            except Exception:
                await asyncio.sleep(5)
                elapsed += 5
        raise XOError(
            "openbsd.builder.ssh",
            {"message": f"OpenBSD builder SSH was not ready within {timeout}s"},
        )

    async def _run_openbsd_builder_prep(self, disk_device: str) -> None:
        script = r"""
set -eu
disk="$1"

case "$disk" in
  sd[0-9]|wd[0-9]) ;;
  *) echo "unsupported OpenBSD disk device: $disk" >&2; exit 64 ;;
esac

cd /dev
sh MAKEDEV "$disk" >/dev/null 2>&1 || true
cd /

if mount | grep -Eq "/dev/${disk}[a-p][[:space:]]"; then
  echo "refusing to resize mounted disk ${disk}" >&2
  mount >&2
  exit 65
fi

total_sectors=$(disklabel "$disk" | awk '/total sectors:/ { print $3; exit }')
if [ -z "$total_sectors" ]; then
  echo "could not read total sectors for ${disk}" >&2
  exit 66
fi

# Expand the outer OpenBSD MBR partition to the end of the VDI. The default
# answers preserve the existing A6 type, non-CHS mode, and offset, then '*'
# selects all remaining sectors.
printf 'edit 3\n\n\n\n*\nwrite\nquit\n' | fdisk -e "$disk"

# Expand the OpenBSD disklabel boundary and root partition a to the MBR end.
# The blank answers preserve the current offset/fstype/fsize/bsize/cpg.
printf 'b\n\n*\nm a\n\n*\n\n\n\n\nw\nq\n' | disklabel -E "$disk"

growfs -y "/dev/r${disk}a"
fsck_ffs -fy "/dev/r${disk}a"
disklabel "$disk"
"""
        command = ["sh", "-s", "--", disk_device]
        if self.config.openbsd_builder_ssh_user != "root":
            command = ["doas", *command]
        await self._run_ssh(command, stdin=script.encode())

    async def _run_ssh(
        self,
        remote_command: list[str],
        *,
        stdin: bytes | None = None,
        timeout: int = 300,
    ) -> tuple[str, str]:
        cfg = self.config
        ssh_target = f"{cfg.openbsd_builder_ssh_user}@{cfg.openbsd_builder_ssh_host}"
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "IdentitiesOnly=yes",
        ]
        if cfg.openbsd_builder_ssh_key_path:
            cmd.extend(["-i", str(Path(cfg.openbsd_builder_ssh_key_path).expanduser())])
        cmd.append(ssh_target)
        cmd.extend(remote_command)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if proc.returncode != 0:
            raise XOError(
                "openbsd.builder.ssh",
                {
                    "message": f"SSH command failed with exit {proc.returncode}",
                    "stderr": err[-4000:],
                },
            )
        return out, err

    async def get_vm_ipv6(self, vm_uuid: str) -> str | None:
        """
        Read VM's IPv6 address from the XO object cache.

        Requires xe-guest-utilities running in the VM (same as XAPI path —
        XO populates `addresses` from VM_guest_metrics.get_networks).
        """
        vm = await self._xo_get_object(vm_uuid)
        if not vm:
            return None

        addresses = vm.get("addresses") or {}
        for key, addr in sorted(addresses.items()):
            if "/ipv6/" in key and not addr.startswith("fe80"):
                return addr

        return None

    async def get_vm_power_state(self, vm_uuid: str) -> str:
        """Get VM power state: Running, Halted, Paused, Suspended."""
        vm = await self._xo_get_object(vm_uuid)
        if not vm:
            raise XOError("get_vm_power_state", {"message": f"VM {vm_uuid} not found"})
        return vm.get("power_state", "Unknown")

    async def start_vm(self, vm_uuid: str) -> None:
        await self._xo_call("vm.start", id=vm_uuid)

    async def reboot_vm(self, vm_uuid: str) -> None:
        """Hard reboot a VM."""
        await self._xo_call("vm.restart", id=vm_uuid, force=True)

    async def shutdown_vm(self, vm_uuid: str) -> None:
        """Clean shutdown."""
        await self._xo_call("vm.stop", id=vm_uuid)

    async def suspend_vm(self, vm_uuid: str) -> None:
        """Hard stop — used for expired VMs in grace period."""
        await self._xo_call("vm.stop", id=vm_uuid, force=True)

    async def destroy_vm(self, vm_uuid: str) -> None:
        """Destroy a VM and all associated VDIs."""
        await self._xo_call("vm.delete", id=vm_uuid)
        log.info("vm_destroyed", uuid=vm_uuid)

    async def list_templates(self) -> dict[str, str]:
        """Return {name: uuid} for all VM templates."""
        templates = await self._xo_objects(type="VM-template")
        return {
            record["name_label"]: uuid
            for uuid, record in templates.items()
            if record.get("name_label")
        }

    async def close(self) -> None:
        await self.logout()
