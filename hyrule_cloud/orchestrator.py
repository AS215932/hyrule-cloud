"""
VM lifecycle orchestrator.

Coordinates XCP-NG, DNS, Openprovider, and DB persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import VMRow
from hyrule_cloud.models import (
    CostBreakdown,
    DomainMode,
    VMCreateRequest,
    VMSize,
    VMStatus,
    generate_anon_management_token,
    generate_vm_id,
    hash_anon_management_token,
)
from hyrule_cloud.providers.cloudinit import render_cloud_init
from hyrule_cloud.providers.dns import DNSProvider
from hyrule_cloud.providers.openprovider import OpenproviderClient
from hyrule_cloud.providers.xcpng import XCPNGProvider

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(UTC)


class Orchestrator:
    def __init__(
        self,
        config: HyruleConfig,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self.config = config
        self.db = session_factory
        self.xcpng = XCPNGProvider(config.xcpng)
        self.dns = DNSProvider(config)
        self.openprovider = OpenproviderClient(config.openprovider)

        self._tasks: set[asyncio.Task] = set()

    async def startup(self) -> None:
        try:
            await self.xcpng.login()
        except Exception as exc:
            log.warning("xcpng_login_failed", error=str(exc))
        log.info("orchestrator_started")

    async def shutdown(self) -> None:
        try:
            await self.xcpng.close()
        except Exception:
            pass
        try:
            await self.openprovider.close()
        except Exception:
            pass
        log.info("orchestrator_shutdown")

    # --- Pricing ---

    def compute_price(self, request: VMCreateRequest) -> tuple[Decimal, CostBreakdown]:
        price_map = {
            VMSize.XS: self.config.payment.price_vm_xs,
            VMSize.SM: self.config.payment.price_vm_sm,
            VMSize.MD: self.config.payment.price_vm_md,
            VMSize.LG: self.config.payment.price_vm_lg,
        }

        vm_daily = price_map[request.size]
        vm_cost = vm_daily * request.duration_days

        domain_cost = Decimal("0")
        if request.domain_mode == DomainMode.CUSTOM and request.domain:
            domain_cost = self.config.payment.price_domain_markup

        total = vm_cost + domain_cost
        breakdown = CostBreakdown(
            vm_cost=f"${vm_cost:.2f}",
            domain_cost=f"${domain_cost:.2f}" if domain_cost > 0 else "$0.00 (auto subdomain)",
            total=f"${total:.2f}",
        )
        return total, breakdown

    # --- VM Lifecycle ---

    @staticmethod
    def _generate_hostname(vm_id: str) -> str:
        return hashlib.sha256(vm_id.encode()).hexdigest()[:8]

    async def create_vm(
        self,
        request: VMCreateRequest,
        owner_wallet: str,
        owner_account_id: str | None = None,
    ) -> tuple[VMRow, str]:
        """Create a VM record in DB and start background provisioning.

        Returns (row, anon_management_token). The token cleartext is shown
        ONCE to the caller and sha256-hashed at rest. When `owner_account_id`
        is supplied (logged-in checkout), the token is still issued (handy for
        operator support / detach-on-account-delete) but the API caller does
        not need it — account auth supersedes.
        """
        from sqlalchemy.exc import IntegrityError

        anon_token = generate_anon_management_token()
        anon_token_hash = hash_anon_management_token(anon_token)
        expires_at = _now() + timedelta(days=request.duration_days)
        total, _ = self.compute_price(request)

        # Retry on (vanishingly unlikely) vm_id collision. 131 bits of entropy
        # means a single retry is more than enough — but bound the loop anyway.
        for _attempt in range(5):
            vm_id = generate_vm_id()
            hostname_prefix = self._generate_hostname(vm_id)
            hostname = f"{hostname_prefix}.{self.config.deploy_domain}"

            row = VMRow(
                vm_id=vm_id,
                owner_wallet=owner_wallet,
                owner_account_id=owner_account_id,
                anon_management_token_hash=anon_token_hash,
                status=VMStatus.PROVISIONING,
                size=request.size,
                os=request.os,
                ipv6=None,
                hostname=hostname,
                ssh_pubkey=request.ssh_pubkey,
                open_ports=[22] + [p for p in request.open_ports if p != 22],
                setup_script=request.setup_script,
                domain_mode=request.domain_mode,
                domain=request.domain,
                expires_at=expires_at,
                cost_total=total,
            )

            try:
                async with self.db() as session:
                    session.add(row)
                    await session.commit()
                    await session.refresh(row)
                break
            except IntegrityError:
                log.warning("vm_id_collision_retry", attempt=_attempt)
                continue
        else:
            raise RuntimeError("vm_id collision retry exhausted")

        task = asyncio.create_task(self._provision_vm(vm_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return row, anon_token

    async def _provision_vm(self, vm_id: str) -> None:
        """Background provisioning: create VM, wait for IPv6, configure DNS."""
        try:
            log.info("provision_start", vm_id=vm_id)

            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                if not row:
                    return
                os_name = row.os
                size = row.size
                ssh_pubkey = row.ssh_pubkey
                open_ports = list(row.open_ports)
                setup_script = row.setup_script

            template_uuid = self.config.xcpng.templates.get(os_name)
            if not template_uuid:
                raise ValueError(f"Unknown OS template: {os_name}")

            cloud_config = render_cloud_init(
                os_name=os_name,
                hostname=self._generate_hostname(vm_id),
                ssh_pubkey=ssh_pubkey,
                open_ports=open_ports,
                setup_script=setup_script,
            )

            xcpng_uuid = await self.xcpng.create_vm(
                template_uuid=template_uuid,
                name_label=f"hyrule-{vm_id}",
                os_name=os_name,
                size=VMSize(size),
                cloud_init_config=cloud_config,
            )
            
            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                if row:
                    row.xcpng_uuid = xcpng_uuid
                    await session.commit()

            # Wait for IPv6 (outside DB session to avoid long-held connections)
            ipv6 = await self._wait_for_ipv6(xcpng_uuid, timeout=120)
            if not ipv6:
                raise TimeoutError("VM did not acquire IPv6 within 120s")

            # Create DNS
            subdomain = self._generate_hostname(vm_id)
            await self.dns.create_aaaa(subdomain, ipv6)

            # Update DB with final state
            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                if not row:
                    return
                row.ipv6 = ipv6
                row.status = VMStatus.READY
                # Block B: stamped here so /v1/stats/runtime can compute
                # avg(provisioned_at - created_at) across recent READY rows.
                row.provisioned_at = _now()

                if row.domain_mode == DomainMode.CUSTOM and row.domain:
                    await self._register_custom_domain(row)

                await session.commit()

            log.info("provision_complete", vm_id=vm_id, ipv6=ipv6)

        except Exception as e:
            log.error("provision_failed", vm_id=vm_id, error=str(e), exc_info=True)
            async with self.db() as session:
                await session.execute(
                    update(VMRow)
                    .where(VMRow.vm_id == vm_id)
                    .values(status=VMStatus.FAILED, error=str(e))
                )
                await session.commit()

    async def _wait_for_ipv6(self, xcpng_uuid: str, timeout: int = 120) -> str | None:
        elapsed = 0
        interval = 5
        while elapsed < timeout:
            ipv6 = await self.xcpng.get_vm_ipv6(xcpng_uuid)
            if ipv6:
                return ipv6
            await asyncio.sleep(interval)
            elapsed += interval
        return None

    async def _register_custom_domain(self, row: VMRow) -> None:
        if not row.domain or not row.ipv6:
            return
        parts = row.domain.rsplit(".", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid domain: {row.domain}")
        name, extension = parts
        await self.openprovider.register_domain(name, extension)
        await self.dns.create_record(row.domain, "AAAA", row.ipv6)

    # --- VM Management ---

    async def get_vm(self, vm_id: str) -> VMRow | None:
        async with self.db() as session:
            return await session.get(VMRow, vm_id)

    async def get_vm_for_wallet(self, vm_id: str, wallet: str) -> VMRow | None:
        async with self.db() as session:
            result = await session.execute(
                select(VMRow).where(VMRow.vm_id == vm_id, VMRow.owner_wallet == wallet)
            )
            return result.scalar_one_or_none()

    async def extend_vm(self, vm_id: str, days: int) -> VMRow | None:
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if not row or not row.expires_at:
                return None

            now = _now()
            base = max(row.expires_at, now)
            row.expires_at = base + timedelta(days=days)
            
            suspend_status = (row.status == VMStatus.SUSPENDED)
            xcpng_uuid = row.xcpng_uuid

            await session.commit()
            await session.refresh(row)
            
        if suspend_status and xcpng_uuid:
            power = await self.xcpng.get_vm_power_state(xcpng_uuid)
            if power == "Halted":
                await self.xcpng.start_vm(xcpng_uuid)
                
            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                if row:
                    row.status = VMStatus.RUNNING
                    await session.commit()
                    await session.refresh(row)

        log.info(
            "vm_extended",
            vm_id=vm_id,
            new_expiry=row.expires_at.isoformat() if row.expires_at else "none",
        )
        return row

    async def reboot_vm(self, vm_id: str) -> bool:
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if not row or not row.xcpng_uuid:
                return False
            xcpng_uuid = row.xcpng_uuid
            
        await self.xcpng.reboot_vm(xcpng_uuid)
        return True

    async def destroy_vm(self, vm_id: str) -> bool:
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if not row:
                return False
            xcpng_uuid = row.xcpng_uuid
            hostname = row.hostname

        if xcpng_uuid:
            await self.xcpng.destroy_vm(xcpng_uuid)

        if hostname:
            subdomain = self._generate_hostname(vm_id)
            try:
                await self.dns.delete_aaaa(subdomain)
            except Exception:
                log.warning("dns_cleanup_failed", vm_id=vm_id, exc_info=True)

        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row:
                row.status = VMStatus.DESTROYED
                row.destroyed_at = _now()
                await session.commit()

        log.info("vm_destroyed", vm_id=vm_id)
        return True

    # --- Expiry Management ---

    async def check_expiries(self) -> None:
        """Suspend expired VMs, destroy those past grace period."""
        now = _now()
        grace = timedelta(hours=self.config.vm_grace_period_hours)

        async with self.db() as session:
            result = await session.execute(
                select(VMRow).where(
                    VMRow.status.notin_([VMStatus.DESTROYED, VMStatus.FAILED]),
                    VMRow.expires_at.isnot(None),
                    VMRow.expires_at < now,
                )
            )
            expired_vms = []
            for r in result.scalars().all():
                expired_vms.append({
                    "vm_id": r.vm_id,
                    "expires_at": r.expires_at,
                    "status": r.status,
                    "xcpng_uuid": r.xcpng_uuid
                })

        for vm in expired_vms:
            if not vm["expires_at"]:
                continue

            if now > vm["expires_at"] + grace:
                log.info("vm_expiry_destroy", vm_id=vm["vm_id"])
                await self.destroy_vm(vm["vm_id"])
            elif vm["status"] != VMStatus.SUSPENDED:
                log.info("vm_expiry_suspend", vm_id=vm["vm_id"])
                if vm["xcpng_uuid"]:
                    try:
                        await self.xcpng.suspend_vm(vm["xcpng_uuid"])
                    except Exception:
                        log.warning("suspend_failed", vm_id=vm["vm_id"], exc_info=True)
                async with self.db() as session:
                    await session.execute(
                        update(VMRow)
                        .where(VMRow.vm_id == vm["vm_id"])
                        .values(status=VMStatus.SUSPENDED)
                    )
                    await session.commit()
