"""
XCP-NG XAPI provider.

Handles VM lifecycle operations against XCP-NG's XML-RPC API (XAPI).
All operations are async via httpx.

Cloud-init data is delivered via a NoCloud ISO (volume label "cidata")
created in-memory with pycdlib, uploaded as a VDI, and attached as a CD.

XAPI docs: https://xapi-project.github.io/xen-api/
"""

from __future__ import annotations

import io
import xmlrpc.client
from typing import Any

import httpx
import pycdlib
import structlog

from hyrule_cloud.config import XCPNGConfig
from hyrule_cloud.models import VM_SPECS, VMSize

log = structlog.get_logger()

CIDATA_VDI_SIZE = 2 * 1024 * 1024  # 2 MB — plenty for cloud-init config


class XAPIError(Exception):
    """Raised when XAPI returns an error."""

    def __init__(self, method: str, error_description: list[str]) -> None:
        self.method = method
        self.error_description = error_description
        super().__init__(f"XAPI {method} failed: {error_description}")


class XCPNGProvider:
    """
    Async client for XCP-NG's XAPI (XML-RPC).

    XAPI is synchronous XML-RPC under the hood. We wrap calls with httpx
    to avoid blocking the event loop, and manage session lifecycle.
    """

    def __init__(self, config: XCPNGConfig) -> None:
        self.config = config
        self._session_ref: str | None = None

        # httpx client for raw XML-RPC over HTTPS
        self._http = httpx.AsyncClient(
            base_url=config.host,
            verify=config.verify_ssl,
            timeout=120.0,  # VM operations can be slow
        )

    async def _call(self, method: str, *args: Any) -> Any:
        """
        Make an XML-RPC call to XAPI.

        XAPI returns {"Status": "Success", "Value": ...} or
        {"Status": "Failure", "ErrorDescription": [...]}.
        """
        payload = xmlrpc.client.dumps(args, method, allow_none=True)

        resp = await self._http.post(
            "/",
            content=payload,
            headers={"Content-Type": "text/xml"},
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
        """Authenticate and store session reference."""
        self._session_ref = await self._call(
            "session.login_with_password",
            self.config.username,
            self.config.password,
            "1.0",  # API version
            "hyrule-cloud",  # originator
        )
        log.info("xapi_login_success")
        return self._session_ref

    async def logout(self) -> None:
        if self._session_ref:
            try:
                await self._call("session.logout", self._session_ref)
            except Exception:
                pass  # best effort
            self._session_ref = None

    @property
    def session(self) -> str:
        if not self._session_ref:
            raise RuntimeError("Not logged in to XAPI. Call login() first.")
        return self._session_ref

    # --- NoCloud ISO ---

    @staticmethod
    def _build_cidata_iso(user_data: str, instance_id: str) -> bytes:
        """
        Build an ISO9660 image with volume label "cidata" containing
        user-data and meta-data files for cloud-init's NoCloud datasource.
        """
        iso = pycdlib.PyCdlib()
        iso.new(
            interchange_level=3,
            vol_ident="cidata",
            joliet=True,
        )

        meta_data = f"instance-id: {instance_id}\n"

        iso.add_fp(
            io.BytesIO(meta_data.encode()),
            len(meta_data.encode()),
            "/METADATA.;1",
            joliet_path="/meta-data",
        )
        iso.add_fp(
            io.BytesIO(user_data.encode()),
            len(user_data.encode()),
            "/USERDATA.;1",
            joliet_path="/user-data",
        )

        buf = io.BytesIO()
        iso.write_fp(buf)
        iso.close()
        return buf.getvalue()

    async def _create_cidata_vdi(
        self, sr_ref: str, user_data: str, instance_id: str
    ) -> str:
        """
        Create a small VDI containing a NoCloud ISO and upload it via XAPI HTTP.

        Returns the VDI opaque ref.
        """
        iso_bytes = self._build_cidata_iso(user_data, instance_id)

        # Create a VDI sized to hold the ISO (rounded up, minimum 2MB)
        vdi_size = max(CIDATA_VDI_SIZE, len(iso_bytes))
        vdi_ref = await self._call(
            "VDI.create",
            self.session,
            {
                "name_label": f"cidata-{instance_id}",
                "name_description": "cloud-init NoCloud config drive",
                "SR": sr_ref,
                "virtual_size": str(vdi_size),
                "type": "user",
                "sharable": False,
                "read_only": True,
                "other_config": {"config_drive": "true"},
                "xenstore_data": {},
                "sm_config": {},
                "tags": [],
            },
        )

        # Upload ISO data via XAPI HTTP import
        task_ref = await self._call(
            "task.create", self.session, f"import cidata {instance_id}", ""
        )
        try:
            resp = await self._http.put(
                "/import_raw_vdi",
                params={
                    "session_id": self.session,
                    "task_id": task_ref,
                    "vdi": vdi_ref,
                    "format": "raw",
                },
                content=iso_bytes,
                headers={"Content-Type": "application/octet-stream"},
            )
            resp.raise_for_status()
        except Exception:
            # Clean up VDI on upload failure
            try:
                await self._call("VDI.destroy", self.session, vdi_ref)
            except Exception:
                pass
            raise
        finally:
            try:
                await self._call("task.destroy", self.session, task_ref)
            except Exception:
                pass

        log.info("cidata_vdi_created", instance_id=instance_id, size=len(iso_bytes))
        return vdi_ref

    # --- Template Management ---

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

    async def get_template_ref(self, template_uuid: str) -> str:
        """Get opaque ref for a template by UUID."""
        return await self._call("VM.get_by_uuid", self.session, template_uuid)

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
        Clone a template and configure the resulting VM.

        Returns the new VM's UUID.

        Workflow:
        1. Clone template
        2. Set vCPU/memory per size tier
        3. Resize disk
        4. Create NoCloud ISO VDI and attach as CD
        5. Ensure network, start VM
        """
        specs = VM_SPECS[size]
        template_ref = await self.get_template_ref(template_uuid)

        # 1. Clone
        log.info("vm_clone_start", template=template_uuid, name=name_label)
        vm_ref = await self._call(
            "VM.clone", self.session, template_ref, name_label
        )

        try:
            await self._call("VM.set_is_a_template", self.session, vm_ref, False)

            # 2. CPU and memory
            vcpu = str(specs["vcpu"])
            memory_bytes = str(specs["memory_mb"] * 1024 * 1024)

            await self._call("VM.set_VCPUs_max", self.session, vm_ref, vcpu)
            await self._call("VM.set_VCPUs_at_startup", self.session, vm_ref, vcpu)
            await self._call(
                "VM.set_memory_limits",
                self.session,
                vm_ref,
                memory_bytes,  # static_min
                memory_bytes,  # static_max
                memory_bytes,  # dynamic_min
                memory_bytes,  # dynamic_max
            )

            # 3. Resize primary disk
            vbds = await self._call("VM.get_VBDs", self.session, vm_ref)
            for vbd_ref in vbds:
                vbd_rec = await self._call("VBD.get_record", self.session, vbd_ref)
                if vbd_rec.get("type") == "Disk":
                    vdi_ref = vbd_rec["VDI"]
                    disk_bytes = str(specs["disk_gb"] * 1024 * 1024 * 1024)
                    await self._call(
                        "VDI.resize", self.session, vdi_ref, disk_bytes
                    )
                    break

            # 4. Create NoCloud config drive and attach as CD
            vm_uuid = await self._call("VM.get_uuid", self.session, vm_ref)
            sr_ref = await self._call(
                "SR.get_by_uuid", self.session, self.config.default_sr_uuid
            )
            cidata_vdi_ref = await self._create_cidata_vdi(
                sr_ref, cloud_init_config, vm_uuid
            )
            # Find existing CD VBD or create one
            cd_vbd_ref = None
            for vbd_ref in vbds:
                vbd_rec = await self._call("VBD.get_record", self.session, vbd_ref)
                if vbd_rec.get("type") == "CD":
                    cd_vbd_ref = vbd_ref
                    break

            if cd_vbd_ref:
                # Eject any existing ISO, insert cidata
                try:
                    await self._call("VBD.eject", self.session, cd_vbd_ref)
                except XAPIError:
                    pass  # already empty
                await self._call("VBD.insert", self.session, cd_vbd_ref, cidata_vdi_ref)
            else:
                # Create a new CD VBD
                await self._call(
                    "VBD.create",
                    self.session,
                    {
                        "VM": vm_ref,
                        "VDI": cidata_vdi_ref,
                        "device": "",
                        "userdevice": "3",
                        "bootable": False,
                        "mode": "RO",
                        "type": "CD",
                        "unpluggable": True,
                        "empty": False,
                        "other_config": {},
                        "currently_attached": False,
                        "qos_algorithm_type": "",
                        "qos_algorithm_params": {},
                    },
                )

            # 5. Ensure network and start
            await self._ensure_network(vm_ref)

            log.info("vm_start", vm_ref=vm_ref)
            await self._call("VM.start", self.session, vm_ref, False, True)

            log.info("vm_created", uuid=vm_uuid, size=size.value, name=name_label)
            return vm_uuid

        except Exception:
            log.error("vm_create_failed", vm_ref=vm_ref, exc_info=True)
            try:
                await self.destroy_vm_by_ref(vm_ref)
            except Exception:
                log.error("vm_cleanup_failed", vm_ref=vm_ref, exc_info=True)
            raise

    async def _ensure_network(self, vm_ref: str) -> None:
        """Ensure VM has a VIF on the configured network."""
        target_network = self.config.default_network_uuid
        if not target_network:
            return

        network_ref = await self._call(
            "network.get_by_uuid", self.session, target_network
        )

        vifs = await self._call("VM.get_VIFs", self.session, vm_ref)
        for vif_ref in vifs:
            vif_network = await self._call("VIF.get_network", self.session, vif_ref)
            if vif_network == network_ref:
                return  # already connected

        vif_record = {
            "device": str(len(vifs)),
            "network": network_ref,
            "VM": vm_ref,
            "MAC": "",
            "MTU": "1500",
            "other_config": {},
            "qos_algorithm_type": "",
            "qos_algorithm_params": {},
        }
        await self._call("VIF.create", self.session, vif_record)

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
        """Destroy a VM and all associated VDIs."""
        vm_ref = await self._call("VM.get_by_uuid", self.session, vm_uuid)
        await self.destroy_vm_by_ref(vm_ref)

    async def destroy_vm_by_ref(self, vm_ref: str) -> None:
        """Destroy VM by opaque ref. Cleans up disks and config drives."""
        power_state = await self._call("VM.get_power_state", self.session, vm_ref)
        if power_state != "Halted":
            try:
                await self._call("VM.hard_shutdown", self.session, vm_ref)
            except XAPIError:
                pass

        vbds = await self._call("VM.get_VBDs", self.session, vm_ref)
        for vbd_ref in vbds:
            try:
                vbd_rec = await self._call("VBD.get_record", self.session, vbd_ref)
                vdi_ref = vbd_rec.get("VDI", "")
                if not vdi_ref or vdi_ref == "OpaqueRef:NULL":
                    continue

                if vbd_rec.get("type") == "Disk":
                    await self._call("VDI.destroy", self.session, vdi_ref)
                elif vbd_rec.get("type") == "CD":
                    # Destroy cidata VDIs we created; skip ISOs from ISO libraries
                    vdi_rec = await self._call("VDI.get_record", self.session, vdi_ref)
                    if vdi_rec.get("other_config", {}).get("config_drive") == "true":
                        await self._call("VDI.destroy", self.session, vdi_ref)
            except XAPIError:
                log.warning("vdi_destroy_failed", vbd_ref=vbd_ref, exc_info=True)

        await self._call("VM.destroy", self.session, vm_ref)
        log.info("vm_destroyed", vm_ref=vm_ref)

    async def close(self) -> None:
        """Cleanup: logout and close HTTP client."""
        await self.logout()
        await self._http.aclose()
