"""
XCP-NG provider via Xen Orchestra + XAPI.

VM creation (clone, cloud-init, disk, network) goes through XO's JSON-RPC
WebSocket API — it handles CloudConfigDrive creation correctly.

Guest metrics polling and simple lifecycle ops (reboot, shutdown) go through
XAPI XML-RPC directly since they're straightforward and don't need XO.

XO API: https://docs.xen-orchestra.com/
XAPI docs: https://xapi-project.github.io/xen-api/
"""

from __future__ import annotations

import asyncio
import json
import ssl
import xmlrpc.client
from itertools import count
from typing import Any

import httpx
import structlog
import websockets

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.models import VM_SPECS, VMSize

log = structlog.get_logger()

_xo_req_id = count(1)


class XAPIError(Exception):
    """Raised when XAPI returns an error."""

    def __init__(self, method: str, error_description: list[str]) -> None:
        self.method = method
        self.error_description = error_description
        super().__init__(f"XAPI {method} failed: {error_description}")


class XOError(Exception):
    """Raised when XO JSON-RPC returns an error."""

    def __init__(self, method: str, error: dict) -> None:
        self.method = method
        self.error = error
        super().__init__(f"XO {method} failed: {error}")


class XCPNGProvider:
    """
    Hybrid XO + XAPI client for XCP-NG.

    XO handles complex operations (VM creation with cloud-init).
    XAPI handles simple queries (guest metrics, power state).
    """

    def __init__(self, config: XCPNGConfig) -> None:
        self.config = config
        self._session_ref: str | None = None

        # XAPI httpx client for XML-RPC
        self._http = httpx.AsyncClient(
            base_url=config.host,
            verify=config.verify_ssl,
            timeout=120.0,
        )

        # XO WebSocket state
        self._xo_ws: websockets.WebSocketClientProtocol | None = None
        self._xo_ssl = ssl.create_default_context()
        if not config.verify_ssl:
            self._xo_ssl.check_hostname = False
            self._xo_ssl.verify_mode = ssl.CERT_NONE

    # --- XO JSON-RPC ---

    async def _xo_connect(self) -> None:
        """Connect and authenticate to XO WebSocket API."""
        self._xo_ws = await websockets.connect(
            self.config.xo_url, ssl=self._xo_ssl, max_size=50 * 1024 * 1024,
        )
        result = await self._xo_call(
            "session.signInWithToken", token=self.config.xo_token
        )
        log.info("xo_login_success", user=result.get("email"))

    async def _xo_call(self, method: str, **params: Any) -> Any:
        """Make a JSON-RPC call to XO, skipping notification messages."""
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

    # --- XAPI XML-RPC ---

    async def _call(self, method: str, *args: Any) -> Any:
        """Make an XML-RPC call to XAPI."""
        payload = xmlrpc.client.dumps(args, method, allow_none=True)
        resp = await self._http.post(
            "/", content=payload, headers={"Content-Type": "text/xml"},
        )
        resp.raise_for_status()
        result, _ = xmlrpc.client.loads(resp.content)

        if result and isinstance(result[0], dict):
            status_map = result[0]
            if status_map.get("Status") == "Failure":
                raise XAPIError(method, status_map.get("ErrorDescription", []))
            return status_map.get("Value")

        return result[0] if result else None

    async def login(self) -> str:
        """Authenticate to both XAPI and XO."""
        self._session_ref = await self._call(
            "session.login_with_password",
            self.config.username, self.config.password,
            "1.0", "hyrule-cloud",
        )
        log.info("xapi_login_success")

        if self.config.xo_token:
            await self._xo_connect()

        return self._session_ref

    async def logout(self) -> None:
        if self._session_ref:
            try:
                await self._call("session.logout", self._session_ref)
            except Exception:
                pass
            self._session_ref = None
        if self._xo_ws:
            await self._xo_ws.close()
            self._xo_ws = None

    @property
    def session(self) -> str:
        if not self._session_ref:
            raise RuntimeError("Not logged in to XAPI. Call login() first.")
        return self._session_ref

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
            # Adjust CPU, memory, disk to match size tier
            await self._resize_vm(vm_uuid, specs)

            # Start
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
        """Set CPU, memory, and disk to match a size tier via XAPI."""
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        vcpu = str(specs["vcpu"])
        memory_bytes = str(specs["memory_mb"] * 1024 * 1024)

        # cores-per-socket must divide VCPUs_max evenly
        platform = await self._call("VM.get_platform", self.session, vm_ref)
        platform["cores-per-socket"] = vcpu
        await self._call("VM.set_platform", self.session, vm_ref, platform)

        # VCPUs: order operations to maintain at_startup <= max
        current_max = await self._call("VM.get_VCPUs_max", self.session, vm_ref)
        if int(vcpu) > int(current_max):
            await self._call("VM.set_VCPUs_max", self.session, vm_ref, vcpu)
            await self._call("VM.set_VCPUs_at_startup", self.session, vm_ref, vcpu)
        else:
            await self._call("VM.set_VCPUs_at_startup", self.session, vm_ref, vcpu)
            await self._call("VM.set_VCPUs_max", self.session, vm_ref, vcpu)

        await self._call(
            "VM.set_memory_limits", self.session, vm_ref,
            memory_bytes, memory_bytes, memory_bytes, memory_bytes,
        )

        # Disk: only grow, never shrink
        vbds = await self._call("VM.get_VBDs", self.session, vm_ref)
        for vbd_ref in vbds:
            vbd_rec = await self._call("VBD.get_record", self.session, vbd_ref)
            if vbd_rec.get("type") == "Disk":
                vdi_ref = vbd_rec["VDI"]
                # Skip the CloudConfigDrive
                vdi_rec = await self._call("VDI.get_record", self.session, vdi_ref)
                if vdi_rec.get("name_label") == "XO CloudConfigDrive":
                    continue
                disk_bytes = specs["disk_gb"] * 1024 * 1024 * 1024
                current_size = int(vdi_rec["virtual_size"])
                if disk_bytes > current_size:
                    await self._call(
                        "VDI.resize", self.session, vdi_ref, str(disk_bytes)
                    )
                break

    async def get_vm_ipv6(self, vm_uuid: str) -> str | None:
        """
        Read VM's IPv6 address from guest metrics.

        Requires xe-guest-utilities running in the VM.
        """
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        metrics_ref = await self._call(
            "VM.get_guest_metrics", self.session, vm_ref
        )

        if metrics_ref == "OpaqueRef:NULL":
            return None

        try:
            networks = await self._call(
                "VM_guest_metrics.get_networks", self.session, metrics_ref
            )
        except XAPIError:
            return None

        for key, addr in sorted(networks.items()):
            if "/ipv6/" in key and not addr.startswith("fe80"):
                return addr

        return None

    async def get_vm_power_state(self, vm_uuid: str) -> str:
        """Get VM power state: Running, Halted, Paused, Suspended."""
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        return await self._call("VM.get_power_state", self.session, vm_ref)

    async def reboot_vm(self, vm_uuid: str) -> None:
        """Hard reboot a VM."""
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        await self._call("VM.hard_reboot", self.session, vm_ref)

    async def shutdown_vm(self, vm_uuid: str) -> None:
        """Clean shutdown."""
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        await self._call("VM.clean_shutdown", self.session, vm_ref)

    async def suspend_vm(self, vm_uuid: str) -> None:
        """Suspend a VM -- used for expired VMs in grace period."""
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        await self._call("VM.hard_shutdown", self.session, vm_ref)

    async def destroy_vm(self, vm_uuid: str) -> None:
        """Destroy a VM and all associated VDIs via XO."""
        await self._xo_call("vm.delete", id=vm_uuid)
        log.info("vm_destroyed", uuid=vm_uuid)

    async def list_templates(self) -> dict[str, str]:
        """Return {name: uuid} for all VM templates."""
        all_vms = await self._call("VM.get_all_records", self.session)
        templates = {}
        for ref, record in all_vms.items():
            if record.get("is_a_template") and not record.get("is_a_snapshot"):
                name = record.get("name_label", "")
                uuid = record.get("uuid", "")
                if name and uuid:
                    templates[name] = uuid
        return templates

    async def close(self) -> None:
        """Cleanup: logout and close connections."""
        await self.logout()
        await self._http.aclose()
