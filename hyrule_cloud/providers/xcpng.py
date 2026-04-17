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
from typing import Any

import structlog
import websockets

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.models import VM_SPECS, VMSize

log = structlog.get_logger()

_xo_req_id = count(1)


class XOError(Exception):
    """Raised when XO JSON-RPC returns an error."""

    def __init__(self, method: str, error: dict) -> None:
        self.method = method
        self.error = error
        super().__init__(f"XO {method} failed: {error}")


class XCPNGProvider:
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
            await self._resize_vm(vm_uuid, specs)
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

    async def _resize_vm(self, vm_uuid: str, specs: dict) -> None:
        """Set CPU, memory, and disk to match a size tier via XO."""
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
            break

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
