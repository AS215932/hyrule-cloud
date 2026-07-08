"""
VM lifecycle orchestrator.

Coordinates XCP-NG, DNS, Openprovider, and DB persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import IPv6Address, IPv6Network

import structlog
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import DomainRow, VMQuoteRow, VMRow
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.models import (
    CostBreakdown,
    DomainMode,
    DomainStatus,
    VMCreateRequest,
    VMSize,
    VMStatus,
    generate_anon_management_token,
    generate_vm_id,
)
from hyrule_cloud.providers.cloudinit import render_cloud_init
from hyrule_cloud.providers.dns import DNSProvider
from hyrule_cloud.providers.network_config import (
    RESERVED_PREFIX_INDEXES,
    customer_prefix_count,
    parse_dns_servers,
    prefix_for_index,
    prefix_index_candidate,
    render_debian_network_config,
    supports_static_network_config,
    validate_customer_network_settings,
    vm_address_for_prefix,
)
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
        # Fail fast on malformed customer-network settings: an operator typo
        # must surface at boot, not as a failed paid VM after the charge.
        validate_customer_network_settings(
            supernet=self.config.customer_ipv6_supernet,
            gateway=self.config.customer_ipv6_gateway,
            dns=self.config.customer_ipv6_dns,
        )
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

    def _customer_supernet(self) -> IPv6Network:
        return IPv6Network(self.config.customer_ipv6_supernet, strict=True)

    async def _allocate_customer_prefix(
        self,
        session: AsyncSession,
        vm_id: str,
    ) -> tuple[int, IPv6Network]:
        supernet = self._customer_supernet()
        result = await session.execute(
            select(VMRow.ipv6_prefix_index).where(VMRow.ipv6_prefix_index.isnot(None))
        )
        used = {int(index) for index in result.scalars().all()}
        used.update(RESERVED_PREFIX_INDEXES)

        total = customer_prefix_count(supernet)
        start = prefix_index_candidate(vm_id, supernet)
        for offset in range(total - len(RESERVED_PREFIX_INDEXES)):
            index = ((start - 1 + offset) % (total - 1)) + 1
            if index in used:
                continue
            return index, prefix_for_index(supernet, index)

        raise RuntimeError(f"No customer /64 prefixes available in {supernet}")

    async def create_vm(
        self,
        request: VMCreateRequest,
        owner_wallet: str,
        owner_account_id: str | None = None,
    ) -> tuple[VMRow, str]:
        """Create a VM record in DB and start background provisioning.

        Returns (row, anon_management_token). Block A0: the cleartext
        token is returned to the caller exactly once — it is never
        stored, only the sha256 lands on the row. Caller (POST
        /v1/vm/create) must surface it in the response body so the
        operator can save the management URL.

        Block A1 (Wave 2): `owner_account_id` is set when the caller has
        a session cookie. The VM still gets a management token — the
        token + the account both authorize management, redundancy is
        intentional so the operator can claim/transfer later.
        """
        # Defense in depth: routes and intent creation validate this before
        # charging, but create_vm is also reachable from settled intents
        # created before those checks existed. Refuse before persisting a row
        # so a paid order can never be accepted for an unprovisionable OS.
        from hyrule_cloud.services.launch_proof import use_real_provisioning

        if use_real_provisioning():
            if not self.config.xcpng.templates.get(request.os):
                raise ValueError(f"Unknown OS template: {request.os}")
            if not supports_static_network_config(request.os):
                raise ValueError(
                    f"OS template {request.os} is not supported for real VM provisioning yet"
                )

        expires_at = _now() + timedelta(days=request.duration_days)
        total, _ = self.compute_price(request)
        anon_token = generate_anon_management_token()

        for _ in range(5):
            vm_id = generate_vm_id()
            hostname_prefix = self._generate_hostname(vm_id)
            hostname = f"{hostname_prefix}.{self.config.deploy_domain}"

            async with self.db() as session:
                prefix_index, prefix = await self._allocate_customer_prefix(session, vm_id)
                row = VMRow(
                    vm_id=vm_id,
                    owner_wallet=owner_wallet,
                    owner_account_id=owner_account_id,
                    status=VMStatus.PROVISIONING,
                    anon_management_token_hash=hash_anon_token(anon_token),
                    size=request.size,
                    os=request.os,
                    ipv6=None,
                    ipv6_prefix_index=prefix_index,
                    ipv6_prefix=str(prefix),
                    hostname=hostname,
                    ssh_pubkey=request.ssh_pubkey,
                    open_ports=[22] + [p for p in request.open_ports if p != 22],
                    setup_script=request.setup_script,
                    domain_mode=request.domain_mode,
                    domain=request.domain,
                    expires_at=expires_at,
                    cost_total=total,
                )
                session.add(row)
                try:
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    log.warning("customer_ipv6_prefix_collision", vm_id=vm_id, prefix=str(prefix))
                    continue
                # Refresh to get server defaults
                await session.refresh(row)
                break
        else:
            raise RuntimeError("Could not allocate a unique customer IPv6 prefix")

        task = asyncio.create_task(self._provision_vm(vm_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return row, anon_token

    async def _provision_vm(self, vm_id: str) -> None:
        """Background provisioning: create VM, wait for IPv6, configure DNS.

        Issue #28: controlled simulation by default. Real XCP-NG / DNS only
        when HCP_LAUNCH_PROOF_REAL_XCPNG=1.
        """
        from hyrule_cloud.services.launch_proof import use_real_provisioning

        if not use_real_provisioning():
            await self._simulate_provisioning(vm_id)
            return

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
                ipv6_prefix = row.ipv6_prefix

            template_uuid = self.config.xcpng.templates.get(os_name)
            if not template_uuid:
                raise ValueError(f"Unknown OS template: {os_name}")
            if not supports_static_network_config(os_name):
                raise ValueError(f"Static network config is not supported for OS template: {os_name}")
            if not ipv6_prefix:
                raise ValueError(f"VM {vm_id} has no allocated IPv6 prefix")

            expected_ipv6 = str(vm_address_for_prefix(IPv6Network(ipv6_prefix, strict=True)))
            network_config = render_debian_network_config(
                address=expected_ipv6,
                prefix=ipv6_prefix,
                gateway=self.config.customer_ipv6_gateway,
                dns_servers=parse_dns_servers(self.config.customer_ipv6_dns),
                customer_supernet=self._customer_supernet(),
            )

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
                network_config=network_config,
            )
            
            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                if row:
                    row.xcpng_uuid = xcpng_uuid
                    await session.commit()

            # Wait for IPv6 (outside DB session to avoid long-held connections)
            ipv6 = await self._wait_for_ipv6(
                xcpng_uuid,
                timeout=120,
                expected_ipv6=expected_ipv6,
            )
            if not ipv6:
                raise TimeoutError(f"VM did not report expected IPv6 {expected_ipv6} within 120s")

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
                # Block B (Wave 2): timestamp the READY transition so
                # /v1/stats/runtime can roll a rolling avg over recent
                # provisioning durations.
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

    async def _simulate_provisioning(self, vm_id: str) -> None:
        """Controlled simulation of provisioning (issue #28).

        Skips XCP-NG, DNS, and Openprovider. Sets a fake IPv6 and flips
        the VM to READY after a short delay so the launch-proof contract
        can be exercised end-to-end without touching real infra.
        """
        import random

        log.info("provision_simulate_start", vm_id=vm_id)

        # Simulate brief provisioning work
        await asyncio.sleep(0.1)

        fake_ipv6 = f"2001:db8::{random.randint(0x1000, 0x9999):04x}"

        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if not row:
                return
            row.ipv6 = fake_ipv6
            row.status = VMStatus.READY
            row.provisioned_at = _now()
            meta = row.metadata_ or {}
            lp = meta.get("launch_proof", {})
            lp["dns_aaaa_verified"] = True
            lp["ssh_smoke_status"] = "passed"
            meta["launch_proof"] = lp
            row.metadata_ = meta
            await session.commit()

        log.info("provision_simulate_complete", vm_id=vm_id, ipv6=fake_ipv6)

    async def _wait_for_ipv6(
        self,
        xcpng_uuid: str,
        timeout: int = 120,
        expected_ipv6: str | None = None,
    ) -> str | None:
        elapsed = 0
        interval = 5
        expected = IPv6Address(expected_ipv6) if expected_ipv6 else None
        while elapsed < timeout:
            ipv6 = await self.xcpng.get_vm_ipv6(xcpng_uuid)
            if ipv6 and expected is None:
                return ipv6
            if ipv6 and expected is not None:
                try:
                    if IPv6Address(ipv6.split("/", 1)[0]) == expected:
                        return str(expected)
                except ValueError:
                    log.warning("vm_reported_invalid_ipv6", vm_uuid=xcpng_uuid, ipv6=ipv6)
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
        op_result = await self.openprovider.register_domain(name, extension)
        try:
            await self.openprovider.create_zone(row.domain)
        except Exception:
            log.warning("zone_create_fallback", zone=row.domain)
        await self.openprovider.create_zone_record(
            zone_name=row.domain,
            name="",
            rtype="AAAA",
            value=row.ipv6,
            ttl=300,
        )
        raw_openprovider_id = (
            op_result.get("id")
            or op_result.get("domain", {}).get("id")
            or op_result.get("data", {}).get("id")
        )
        try:
            openprovider_id = int(raw_openprovider_id) if raw_openprovider_id is not None else None
        except (TypeError, ValueError):
            openprovider_id = None
        async with self.db() as session:
            existing = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == row.domain))
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    DomainRow(
                        name=name,
                        extension=extension,
                        fqdn=row.domain,
                        vm_id=row.vm_id,
                        owner_wallet=row.owner_wallet,
                        owner_account_id=row.owner_account_id,
                        status=DomainStatus.ACTIVE,
                        openprovider_id=openprovider_id,
                    )
                )
            else:
                existing.vm_id = row.vm_id
                existing.status = DomainStatus.ACTIVE
                existing.openprovider_id = openprovider_id
            await session.commit()

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

    async def get_quote_for_vm(self, vm_id: str) -> VMQuoteRow | None:
        async with self.db() as session:
            result = await session.execute(
                select(VMQuoteRow).where(VMQuoteRow.vm_id == vm_id)
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
                # Release the customer /64 for reuse: the unique index on
                # ipv6_prefix_index would otherwise pin it to this dead row
                # forever and eventually exhaust the pool. Only safe here —
                # the guest and its DNS record are gone. FAILED rows keep the
                # prefix until destroyed, since a partially-provisioned guest
                # may still hold the address.
                row.ipv6_prefix_index = None
                row.ipv6_prefix = None
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
            expires_at = vm["expires_at"]
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)

            if now > expires_at + grace:
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
