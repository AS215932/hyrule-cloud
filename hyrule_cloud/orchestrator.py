"""
VM lifecycle orchestrator.

Coordinates XCP-NG, DNS, Openprovider, and DB persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import IPv6Address, IPv6Network
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import delete as sql_delete
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    CryptoIntentRow,
    DomainOrderRow,
    DomainRow,
    PaymentEventRow,
    VMQuoteRow,
    VMRow,
)
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.models import (
    CostBreakdown,
    CryptoIntentStatus,
    DomainMode,
    SSHSmokeStatus,
    VMCreateRequest,
    VMOrderResources,
    VMPriceBreakdown,
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
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.services.refunds import RefundService
from hyrule_cloud.services.vm_pricing import (
    billing_addons_from_snapshot,
    price_vm_order,
    resources_for_profile,
)

if TYPE_CHECKING:
    from hyrule_cloud.domains.service import DomainService

log = structlog.get_logger()

_VM_CAPACITY_ADVISORY_LOCK = 1213809714  # stable cross-worker PostgreSQL lock key


class VMCapacityError(RuntimeError):
    """The requested VM cannot fit within the configured live headroom."""


class AccountDisabledError(RuntimeError):
    """A VM reservation was fenced by its disabled owner account."""


def _now() -> datetime:
    return datetime.now(UTC)


def _looks_like_evm_wallet(value: str | None) -> bool:
    """Whether a string is a customer EVM refund address (0x + 40 hex).

    Native BTC/XMR intents carry a Hyrule-generated *deposit* address in
    owner_wallet, not a refund destination, so they must not be treated as an
    x402 refund payer — they refund through the intent REFUND_MANUAL path.
    """
    if not value or not value.startswith("0x") or len(value) != 42:
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


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
        self.domains: DomainService | None = None
        # Refund obligations for paid VMs that fail to provision. The ledger is
        # a thin writer over the session factory, so a dedicated instance here
        # is fine and keeps the constructor signature stable for callers/tests.
        self.refunds = RefundService(PaymentLedger(session_factory))

        self._tasks: set[asyncio.Task] = set()
        self._provisioning_vm_ids: set[str] = set()
        self._vm_capacity_reservation_lock = asyncio.Lock()

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
        priced = price_vm_order(request, self.config.payment)
        vm_cost = priced.total

        # Domain registration is a separate durable quote/order. A VM with
        # domain_mode=custom only attaches an already-active managed domain.
        domain_cost = Decimal("0")

        total = vm_cost + domain_cost
        breakdown = CostBreakdown(
            vm_cost=f"${vm_cost:.2f}",
            domain_cost=f"${domain_cost:.2f}" if domain_cost > 0 else "$0.00 (auto subdomain)",
            total=f"${total:.2f}",
        )
        return total, breakdown

    def price_order(self, request: VMCreateRequest):
        """Return the canonical profile, exact resources, and billing snapshot."""
        return price_vm_order(request, self.config.payment)

    async def ensure_vm_capacity(self, request: VMCreateRequest) -> None:
        """Raise before provisioning/payment when the exact VM cannot fit.

        Live XO usage is combined with DB reservations that do not have an XO
        UUID yet. RAM is not overcommitted; CPU follows the configured 2:1
        policy; memory and default-SR recovery margins remain untouched.
        """
        resources = request.resources or resources_for_profile(request.size)
        capacity = await self.xcpng.capacity()
        async with self.db() as session:
            pending = (
                await session.execute(
                    select(
                        func.coalesce(func.sum(VMRow.vcpu), 0),
                        func.coalesce(func.sum(VMRow.memory_mb), 0),
                        func.coalesce(func.sum(VMRow.disk_gb), 0),
                    ).where(
                        VMRow.status == VMStatus.PROVISIONING,
                        VMRow.xcpng_uuid.is_(None),
                    )
                )
            ).one()
        pending_vcpu, pending_memory_mb, pending_disk_gb = (
            int(value or 0) for value in pending
        )
        cpu_limit = int(
            Decimal(capacity.physical_vcpu) * self.config.xcpng.vcpu_overcommit_ratio
        )
        memory_headroom = self.config.xcpng.memory_headroom_mb * 1024**2
        storage_headroom = self.config.xcpng.storage_headroom_gb * 1024**3
        if capacity.allocated_vcpu + pending_vcpu + resources.vcpu > cpu_limit:
            raise VMCapacityError("insufficient vCPU capacity")
        if (
            capacity.free_memory_bytes
            - pending_memory_mb * 1024**2
            - resources.ram_mb * 1024**2
            < memory_headroom
        ):
            raise VMCapacityError("insufficient RAM capacity")
        if (
            capacity.free_storage_bytes
            - pending_disk_gb * 1024**3
            - resources.disk_gb * 1024**3
            < storage_headroom
        ):
            raise VMCapacityError("insufficient default-SR capacity")

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

    async def _insert_vm_row(
        self,
        request: VMCreateRequest,
        owner_wallet: str,
        owner_account_id: str | None = None,
        vm_id: str | None = None,
        pricing_snapshot: dict | None = None,
        legacy_billing: bool = False,
        payment_tx: str | None = None,
        retail_amount: Decimal | None = None,
        admin_waived: bool = False,
    ) -> tuple[VMRow, str]:
        """Persist a VM row and atomically claim a customer /64 (unique index).

        Does NOT start provisioning — callers decide when (create_vm does it
        immediately; reserve_vm defers until payment settles).
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

        # New unquoted orders arrive canonicalized by the route, but internal
        # callers and size-only clients also use this method. Durable snapshots
        # are already canonical and must never be rebound against current
        # prices: the base profile determines future extension pricing.
        # Legacy NULL snapshots deliberately bypass current catalog validation
        # so retired 80-GB disks remain provisionable and are never shrunk.
        if legacy_billing:
            resources = request.resources or resources_for_profile(request.size)
            canonical_request = request.model_copy(update={"resources": resources})
            total = Decimal(
                str(getattr(self.config.payment, f"price_vm_{request.size.value}", "0"))
            ) * request.duration_days
        elif pricing_snapshot is not None:
            snapshot = VMPriceBreakdown.model_validate(pricing_snapshot)
            resources = request.resources or resources_for_profile(request.size)
            if (
                snapshot.base_profile != request.size
                or snapshot.duration_days != request.duration_days
            ):
                raise ValueError("pricing snapshot does not match the VM order")
            base = resources_for_profile(snapshot.base_profile)
            expected_addons = (
                resources.vcpu - base.vcpu,
                resources.ram_mb - base.ram_mb,
                resources.disk_gb - base.disk_gb,
            )
            if min(expected_addons) < 0 or expected_addons != (
                snapshot.addon_vcpu,
                snapshot.addon_ram_mb,
                snapshot.addon_disk_gb,
            ):
                raise ValueError("pricing snapshot add-ons do not match the VM resources")
            canonical_request = request.model_copy(update={"resources": resources})
            total = Decimal(snapshot.total_usd)
        else:
            priced = price_vm_order(request, self.config.payment)
            canonical_request = priced.order
            resources = priced.resources
            pricing_snapshot = priced.pricing_snapshot
            total = priced.total
        request = canonical_request
        addon_vcpu, addon_ram_mb, addon_disk_gb = billing_addons_from_snapshot(
            pricing_snapshot
        )
        expires_at = _now() + timedelta(days=request.duration_days)
        anon_token = generate_anon_management_token()

        requested_vm_id = vm_id
        for _ in range(5):
            candidate_vm_id = requested_vm_id or generate_vm_id()
            hostname_prefix = self._generate_hostname(candidate_vm_id)
            hostname = f"{hostname_prefix}.{self.config.deploy_domain}"

            async with self.db() as session:
                if owner_account_id is not None:
                    owner = (
                        await session.execute(
                            select(AccountRow)
                            .where(AccountRow.account_id == owner_account_id)
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if owner is not None and owner.disabled_at is not None:
                        raise AccountDisabledError("VM owner account is disabled")
                if requested_vm_id:
                    existing = await session.get(VMRow, candidate_vm_id)
                    if existing is not None:
                        self._validate_replayed_vm(existing, request, owner_account_id)
                        self._apply_payment_billing(
                            existing,
                            retail_amount=retail_amount,
                            admin_waived=admin_waived,
                            payment_tx=payment_tx,
                        )
                        await session.commit()
                        return existing, ""
                prefix_index, prefix = await self._allocate_customer_prefix(
                    session, candidate_vm_id
                )
                row = VMRow(
                    vm_id=candidate_vm_id,
                    owner_wallet=owner_wallet,
                    owner_account_id=owner_account_id,
                    status=VMStatus.PROVISIONING,
                    anon_management_token_hash=hash_anon_token(anon_token),
                    size=request.size,
                    vcpu=resources.vcpu,
                    memory_mb=resources.ram_mb,
                    disk_gb=resources.disk_gb,
                    billing_addon_vcpu=addon_vcpu,
                    billing_addon_ram_mb=addon_ram_mb,
                    billing_addon_disk_gb=addon_disk_gb,
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
                    retail_cost_total=total,
                )
                self._apply_payment_billing(
                    row,
                    retail_amount=retail_amount,
                    admin_waived=admin_waived,
                    payment_tx=payment_tx,
                )
                session.add(row)
                try:
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    if requested_vm_id:
                        existing = await session.get(VMRow, candidate_vm_id)
                        if existing is not None:
                            self._validate_replayed_vm(existing, request, owner_account_id)
                            return existing, ""
                    log.warning(
                        "customer_ipv6_prefix_collision",
                        vm_id=candidate_vm_id,
                        prefix=str(prefix),
                    )
                    continue
                # Refresh to get server defaults
                await session.refresh(row)
                return row, anon_token

        raise RuntimeError("Could not allocate a unique customer IPv6 prefix")

    @staticmethod
    def _validate_replayed_vm(
        row: VMRow,
        request: VMCreateRequest,
        owner_account_id: str | None,
    ) -> None:
        if (
            row.owner_account_id != owner_account_id
            or VMSize(row.size) is not request.size
            or row.os != request.os
            or row.domain_mode != request.domain_mode
            or row.domain != request.domain
            or int(row.vcpu or 0) != (request.resources or resources_for_profile(request.size)).vcpu
            or int(row.memory_mb or 0)
            != (request.resources or resources_for_profile(request.size)).ram_mb
            or int(row.disk_gb or 0)
            != (request.resources or resources_for_profile(request.size)).disk_gb
        ):
            raise RuntimeError("planned VM id is already bound to another order")

    def _spawn_provisioning(self, vm_id: str) -> None:
        if vm_id in self._provisioning_vm_ids:
            return
        self._provisioning_vm_ids.add(vm_id)
        task = asyncio.create_task(self._provision_vm(vm_id))
        self._tasks.add(task)

        def completed(done: asyncio.Task) -> None:
            self._tasks.discard(done)
            self._provisioning_vm_ids.discard(vm_id)

        task.add_done_callback(completed)

    def start_provisioning(self, vm_id: str) -> None:
        """Kick off background provisioning for an already-created VM row.

        Used by callers that need to establish a link to the row (e.g. a native
        crypto intent setting its vm_id) BEFORE provisioning can fail, so the
        failure path can always find the paying record.
        """
        self._spawn_provisioning(vm_id)

    async def create_vm(
        self,
        request: VMCreateRequest,
        owner_wallet: str,
        owner_account_id: str | None = None,
        vm_id: str | None = None,
        start_provisioning: bool = True,
        pricing_snapshot: dict | None = None,
        legacy_billing: bool = False,
        payment_tx: str | None = None,
        retail_amount: Decimal | None = None,
        admin_waived: bool = False,
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

        ``start_provisioning=False`` returns the row WITHOUT spawning the
        background task so the caller can first link the row to its paying
        record, then call ``start_provisioning(vm_id)``.
        """
        row, anon_token = await self._insert_vm_row(
            request,
            owner_wallet,
            owner_account_id,
            vm_id=vm_id,
            pricing_snapshot=pricing_snapshot,
            legacy_billing=legacy_billing,
            payment_tx=payment_tx,
            retail_amount=retail_amount,
            admin_waived=admin_waived,
        )
        if start_provisioning:
            self._spawn_provisioning(row.vm_id)
        return row, anon_token

    async def reserve_vm(
        self,
        request: VMCreateRequest,
        owner_account_id: str | None = None,
        vm_id: str | None = None,
        pricing_snapshot: dict | None = None,
        legacy_billing: bool = False,
    ) -> tuple[VMRow, str]:
        """Reserve a VM row + customer /64 BEFORE payment settles.

        The unique prefix index makes the reservation atomic across workers,
        closing the capacity-check→charge→allocate race: a request that is
        about to be charged holds its /64 through settlement. Reservations
        carry owner_wallet="" and no provisioning task; the caller must
        activate_vm_reservation() on payment success or
        release_vm_reservation() on failure. Abandoned reservations (crash
        mid-payment) are purged by check_expiries.
        """
        return await self._insert_vm_row(
            request,
            owner_wallet="",
            owner_account_id=owner_account_id,
            vm_id=vm_id,
            pricing_snapshot=pricing_snapshot,
            legacy_billing=legacy_billing,
        )

    async def reserve_vm_with_capacity(
        self,
        request: VMCreateRequest,
        owner_account_id: str | None = None,
        vm_id: str | None = None,
        pricing_snapshot: dict | None = None,
        legacy_billing: bool = False,
    ) -> tuple[VMRow, str]:
        """Check live capacity and durably reserve the VM as one operation.

        A process-local lock covers SQLite/tests and a PostgreSQL advisory lock
        serializes the check→insert boundary across production workers. Planned
        VM IDs are replay-safe: an existing matching row represents no new
        capacity and is returned without charging admission a second time.
        """
        if vm_id is not None:
            async with self.db() as session:
                existing = await session.get(VMRow, vm_id)
            if existing is not None:
                self._validate_replayed_vm(existing, request, owner_account_id)
                return existing, ""

        from hyrule_cloud.services.launch_proof import use_real_provisioning

        async with self._serialize_vm_capacity_transition():
            if vm_id is not None:
                async with self.db() as session:
                    existing = await session.get(VMRow, vm_id)
                if existing is not None:
                    self._validate_replayed_vm(existing, request, owner_account_id)
                    return existing, ""
            if use_real_provisioning():
                await self.ensure_vm_capacity(request)
            return await self.reserve_vm(
                request,
                owner_account_id=owner_account_id,
                vm_id=vm_id,
                pricing_snapshot=pricing_snapshot,
                legacy_billing=legacy_billing,
            )

    @asynccontextmanager
    async def _serialize_vm_capacity_transition(self) -> AsyncIterator[None]:
        """Serialize admission and pending→XO capacity ownership changes.

        The process lock covers SQLite/tests. PostgreSQL's session advisory lock
        extends the same boundary across API and worker processes.
        """
        async with self._vm_capacity_reservation_lock:
            async with self.db() as lock_session:
                postgres = lock_session.get_bind().dialect.name == "postgresql"
                if postgres:
                    await lock_session.execute(
                        text("SELECT pg_advisory_lock(:lock_key)"),
                        {"lock_key": _VM_CAPACITY_ADVISORY_LOCK},
                    )
                try:
                    yield
                finally:
                    if postgres:
                        await lock_session.execute(
                            text("SELECT pg_advisory_unlock(:lock_key)"),
                            {"lock_key": _VM_CAPACITY_ADVISORY_LOCK},
                        )

    async def activate_vm_reservation(
        self,
        vm_id: str,
        owner_wallet: str,
        payment_tx: str | None = None,
        *,
        start_provisioning: bool = True,
        retail_amount: Decimal | None = None,
        admin_waived: bool = False,
    ) -> VMRow | None:
        """Attach the settled payment to a reservation and start provisioning.

        Pass start_provisioning=False to let the caller link a quote to the VM
        first: provisioning can fail immediately, and the refund path needs the
        locked quote amount, so the link must be committed before it starts.
        """
        async with self.db() as session:
            # Account disable takes the account lock before touching owned VMs.
            # Read the reservation only to discover its owner, then acquire the
            # same locks in that order so settlement cannot deadlock with (or
            # slip past) an administrative disable.
            candidate = await session.get(VMRow, vm_id)
            if candidate is None:
                return None
            expected_owner_account_id = candidate.owner_account_id
            if expected_owner_account_id is not None:
                owner = (
                    await session.execute(
                        select(AccountRow)
                        .where(AccountRow.account_id == expected_owner_account_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if owner is None or owner.disabled_at is not None:
                    raise AccountDisabledError("VM owner account is disabled")
            row = (
                await session.execute(
                    select(VMRow).where(VMRow.vm_id == vm_id).with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            if row.owner_account_id != expected_owner_account_id:
                raise RuntimeError("VM reservation owner changed during payment")
            row.owner_wallet = owner_wallet
            self._apply_payment_billing(
                row,
                retail_amount=retail_amount,
                admin_waived=admin_waived,
                payment_tx=payment_tx,
            )
            await session.commit()
            await session.refresh(row)
        if start_provisioning:
            self._spawn_provisioning(vm_id)
        return row

    async def release_vm_reservation(self, vm_id: str) -> None:
        """Delete an unpaid reservation, freeing its /64 immediately."""
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None and not row.owner_wallet and row.status == VMStatus.PROVISIONING:
                domain = (
                    await session.execute(
                        select(DomainRow).where(DomainRow.vm_id == vm_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if domain is not None and domain.vm_ipv6 is None:
                    domain.vm_id = None
                await session.delete(row)
                await session.commit()

    async def _provision_vm(self, vm_id: str) -> None:
        """Background provisioning: create VM, wait for IPv6, configure DNS.

        Issue #28: controlled simulation by default. Real XCP-NG / DNS only
        when HCP_LAUNCH_PROOF_REAL_XCPNG=1.
        """
        from hyrule_cloud.services.launch_proof import use_real_provisioning

        # Issue #51: stamp when provisioning actually begins. created_at can
        # predate settlement by hours (crypto intents, reservations), so the
        # runtime stats measure the provision window from here. First write
        # wins — a retried provision keeps the original start.
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is None or str(row.status) != VMStatus.PROVISIONING.value:
                return
            if row.provision_started_at is None:
                row.provision_started_at = _now()
                await session.commit()

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
                resources = VMOrderResources(
                    vcpu=row.vcpu or resources_for_profile(VMSize(row.size)).vcpu,
                    ram_mb=row.memory_mb or resources_for_profile(VMSize(row.size)).ram_mb,
                    disk_gb=row.disk_gb or resources_for_profile(VMSize(row.size)).disk_gb,
                )
                ssh_pubkey = row.ssh_pubkey
                open_ports = list(row.open_ports)
                setup_script = row.setup_script
                ipv6_prefix = row.ipv6_prefix
                xcpng_uuid = row.xcpng_uuid

            template_uuid = self.config.xcpng.templates.get(os_name)
            if not template_uuid:
                raise ValueError(f"Unknown OS template: {os_name}")
            if not supports_static_network_config(os_name):
                raise ValueError(
                    f"Static network config is not supported for OS template: {os_name}"
                )
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

            if xcpng_uuid is None:
                # Admission snapshots and the pending→XO handoff share one
                # cross-process lock. No reservation can observe an XO snapshot
                # from before this clone while also excluding its now-tracked DB
                # row from pending capacity.
                async with self._serialize_vm_capacity_transition():
                    async with self.db() as session:
                        current = await session.get(VMRow, vm_id)
                        if current is None:
                            return
                        xcpng_uuid = current.xcpng_uuid
                    if xcpng_uuid is None:
                        name_label = f"hyrule-{vm_id}"
                        # XO may contain a clone whose create call completed before the
                        # process could durably store its UUID. It is not safe to adopt
                        # a possibly half-resized/half-started clone, so delete any
                        # untracked exact-label candidates and recreate cleanly.
                        stale_ids = await self.xcpng.find_vm_ids_by_name_label(name_label)
                        for stale_uuid in stale_ids:
                            log.warning(
                                "orphaned_vm_clone_replaced",
                                vm_id=vm_id,
                                xcpng_uuid=stale_uuid,
                            )
                            await self.xcpng.destroy_vm(stale_uuid)
                        xcpng_uuid = await self.xcpng.create_vm(
                            template_uuid=template_uuid,
                            name_label=name_label,
                            os_name=os_name,
                            size=VMSize(size),
                            resources=resources,
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

            # Launch proof (issue #28): measure instead of inferring — probe
            # TCP :22 and confirm the AAAA on the authoritative server. An
            # unreachable sshd doesn't fail the VM, but the customer-visible
            # proof reports it honestly.
            ssh_ok, dns_verified = await asyncio.gather(
                self._probe_ssh(ipv6),
                self.dns.verify_aaaa(subdomain, ipv6),
            )

            # Update DB with final state
            custom_domain: str | None = None
            custom_account_id: str | None = None
            async with self.db() as session:
                row = (
                    await session.execute(
                        select(VMRow).where(VMRow.vm_id == vm_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None:
                    return
                admin_suspended = row.suspension_reason in {
                    "account_disabled",
                    "manual_admin",
                }
                if admin_suspended:
                    # Serialize with account re-enablement while the row lock is
                    # held: a disabled account must never observe a newly built
                    # provider VM transition through READY.
                    await self.xcpng.suspend_vm(xcpng_uuid)
                row.ipv6 = ipv6
                row.status = VMStatus.SUSPENDED if admin_suspended else VMStatus.READY
                # Block B (Wave 2): timestamp the READY transition so
                # /v1/stats/runtime can roll a rolling avg over recent
                # provisioning durations.
                row.provisioned_at = _now()
                meta = dict(row.metadata_ or {})
                lp = dict(meta.get("launch_proof", {}))
                lp["ssh_smoke_status"] = (
                    SSHSmokeStatus.PASSED.value if ssh_ok else SSHSmokeStatus.FAILED.value
                )
                lp["dns_aaaa_verified"] = bool(dns_verified)
                meta["launch_proof"] = lp
                row.metadata_ = meta

                if row.domain_mode == DomainMode.CUSTOM and row.domain:
                    custom_domain = row.domain
                    custom_account_id = row.owner_account_id

                await session.commit()

            # A DNS control-plane outage must not turn a healthy, paid VM into
            # a refund. The VM is already READY; attachment is retryable and
            # leaves the managed-domain lifecycle as the source of truth.
            if custom_domain:
                try:
                    await self._register_custom_domain(
                        vm_id=vm_id,
                        domain=custom_domain,
                        ipv6=ipv6,
                        owner_account_id=custom_account_id,
                    )
                except Exception:
                    log.exception(
                        "custom_domain_attachment_failed",
                        vm_id=vm_id,
                        domain=custom_domain,
                    )
                    try:
                        assert custom_account_id is not None and self.domains is not None
                        await self.domains.enqueue_vm_attachment(
                            custom_account_id,
                            custom_domain,
                            vm_id,
                            ipv6,
                        )
                    except Exception:
                        log.exception(
                            "custom_domain_attachment_retry_enqueue_failed",
                            vm_id=vm_id,
                            domain=custom_domain,
                        )

            log.info("provision_complete", vm_id=vm_id, ipv6=ipv6)

        except Exception as e:
            log.error("provision_failed", vm_id=vm_id, error=str(e), exc_info=True)
            owner_wallet, amount, payment_tx, settled = "", None, None, None
            async with self.db() as session:
                row = await session.get(VMRow, vm_id)
                if row is not None:
                    row.status = VMStatus.FAILED
                    row.error = str(e)
                    owner_wallet = row.owner_wallet
                    amount = row.cost_total
                    payment_tx = row.payment_tx
                if payment_tx:
                    # The authoritative charge: what x402 actually settled for
                    # this VM (amount + chain), not the possibly-recomputed
                    # VMRow.cost_total.
                    settled = (
                        await session.execute(
                            select(PaymentEventRow)
                            .where(
                                PaymentEventRow.tx_hash == payment_tx,
                                PaymentEventRow.event_type == "settled",
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                await session.commit()
            if self.domains is not None:
                try:
                    await self.domains.release_vm_attachment_claim(vm_id)
                except Exception:
                    log.exception("custom_domain_claim_release_failed", vm_id=vm_id)
            await self._record_vm_refund(
                vm_id, owner_wallet, amount, payment_tx, settled, reason=str(e)
            )

    async def _record_vm_refund(
        self,
        vm_id: str,
        owner_wallet: str,
        amount: Decimal | None,
        payment_tx: str | None,
        settled: PaymentEventRow | None,
        *,
        reason: str,
    ) -> None:
        """Record the refund owed for a failed paid VM.

        Prefer the settled x402 ledger row (authoritative amount + network +
        asset). A native BTC/XMR intent has no such row and carries a deposit
        address, not an EVM refund destination, so it's recorded through the
        intent's REFUND_MANUAL path instead — never dropped.
        """
        if settled is not None:
            await self.refunds.record_owed(
                resource_path="/v1/vm/create",
                # A settled charge exists — record the obligation even if the
                # SDK didn't expose a payer address; the tx/network metadata let
                # the operator investigate rather than dropping the debt.
                payer=settled.payer_wallet or "unknown",
                amount=settled.amount_usd,
                network=settled.network,
                asset=settled.asset,
                original_tx=payment_tx,
                reason=reason,
                vm_id=vm_id,
            )
            return
        if _looks_like_evm_wallet(owner_wallet):
            # An x402 charge whose settled ledger row was lost (best-effort
            # write). Prefer the locked quote amount actually charged over the
            # VM's recomputed cost_total — they diverge if pricing changed during
            # the quote TTL, exactly the ledger-missing path this covers.
            quote = await self.get_quote_for_vm(vm_id)
            charged = quote.amount_usd if quote is not None else amount
            await self.refunds.record_owed(
                resource_path="/v1/vm/create",
                payer=owner_wallet,
                amount=charged,
                original_tx=payment_tx,
                reason=reason,
                vm_id=vm_id,
            )
            return
        # No x402 charge and a non-EVM owner: a native BTC/XMR intent whose VM
        # failed after it was already marked PROVISIONED. Flip it to
        # REFUND_MANUAL and record the debt (native refunds are sent by the
        # operator, not auto-EVM) so a paid customer is never silently dropped.
        if await self._record_native_refund(vm_id, reason=reason):
            return
        is_dev_bypass = bool(payment_tx and payment_tx.startswith("dev_bypass"))
        is_admin_bypass = bool(payment_tx and payment_tx.startswith("admin_bypass"))
        was_charged = bool(payment_tx) or (amount is not None and amount > 0)
        if was_charged and not is_dev_bypass and not is_admin_bypass:
            # A charge settled but couldn't be attributed to an EVM wallet or a
            # native intent — e.g. the SDK settled exposing neither a payer
            # ("unknown") NOR a tx string AND the best-effort settled ledger row
            # was lost. A positive charged amount (not just a tx) is enough to owe
            # a refund; record it against the locked quote (or cost_total) so a
            # paid failure is never dropped from the worklist. Dev-bypass
            # "payments" (tx=dev_bypass_*) charged nothing, so must NOT create a
            # phantom refund_owed row polluting the worklist/metrics.
            quote = await self.get_quote_for_vm(vm_id)
            charged = quote.amount_usd if quote is not None else amount
            await self.refunds.record_owed(
                resource_path="/v1/vm/create",
                payer=owner_wallet or "unknown",
                amount=charged,
                original_tx=payment_tx or None,
                reason=reason,
                vm_id=vm_id,
            )
            return
        # Free subdomain VM (nothing charged) with no linked intent.
        log.info("vm_refund_not_recorded_here", vm_id=vm_id, owner_wallet=owner_wallet or None)

    async def mark_vm_failed(self, vm_id: str, error: str) -> None:
        """Terminally fail a VM row that will never be provisioned.

        Used when a paid create errors after the row was inserted/activated but
        before the background provisioner was scheduled. Such a row sits in
        PROVISIONING with a non-empty owner_wallet, which the reservation sweeper
        (unpaid rows only, owner_wallet == "") never reclaims — so without this
        it pins its customer /64 and keeps counting as live until expiry.
        """
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None and row.status not in (VMStatus.DESTROYED, VMStatus.FAILED):
                domain = (
                    await session.execute(
                        select(DomainRow).where(DomainRow.vm_id == vm_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if domain is not None and domain.vm_ipv6 is None:
                    domain.vm_id = None
                row.status = VMStatus.FAILED
                row.error = error
                # Free the customer /64: _allocate_customer_prefix counts any
                # non-null prefix index as used and check_expiries skips FAILED
                # rows, so leaving these set would pin the prefix forever. Nothing
                # was provisioned yet, so there is no guest/DNS to tear down.
                row.ipv6_prefix_index = None
                row.ipv6_prefix = None
                await session.commit()

    async def persist_charged_amount(self, vm_id: str, amount: Decimal) -> None:
        """Persist the locked, actually-charged quote amount onto the VM.

        VMRow.cost_total is otherwise recomputed from current pricing, which can
        drift from what was charged during the quote TTL. Writing the locked
        amount here — before the best-effort quote link — means a later refund is
        accurate even if the link fails and the settled ledger row was lost.
        """
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None:
                row.cost_total = amount
                row.retail_cost_total = amount
                row.billing_mode = "charged"
                await session.commit()

    async def persist_payment_billing(
        self,
        vm_id: str,
        retail_amount: Decimal,
        *,
        admin_waived: bool,
        payment_tx: str | None = None,
    ) -> None:
        """Persist retail value separately from money actually charged."""
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row is not None:
                Orchestrator._apply_payment_billing(
                    row,
                    retail_amount=retail_amount,
                    admin_waived=admin_waived,
                    payment_tx=payment_tx,
                )
                await session.commit()

    @staticmethod
    def _apply_payment_billing(
        row: VMRow,
        *,
        retail_amount: Decimal | None,
        admin_waived: bool,
        payment_tx: str | None,
    ) -> None:
        """Apply settlement metadata as part of the caller's DB transaction."""
        if retail_amount is not None:
            dev_bypass = bool(payment_tx and payment_tx.startswith("dev_bypass"))
            row.retail_cost_total = retail_amount
            row.cost_total = Decimal("0") if admin_waived or dev_bypass else retail_amount
            row.billing_mode = (
                "admin_waived"
                if admin_waived
                else "dev_bypass"
                if dev_bypass
                else "charged"
            )
        if payment_tx:
            row.payment_tx = payment_tx

    async def record_create_failure_refund(
        self,
        *,
        owner_wallet: str,
        payment_tx: str | None,
        charged_amount: Decimal | None,
        reason: str,
        vm_id: str | None = None,
    ) -> None:
        """Record the refund owed when a paid /v1/vm/create fails synchronously.

        The background provisioner (_provision_vm) owns the normal refund path,
        but it is only scheduled after the reservation/allocation succeeds. A
        failure between settlement and that scheduling (reservation swept then
        create hits capacity, activation raises, ...) would otherwise charge the
        customer with no refund record. Prefer the authoritative settled ledger
        row (amount + network + asset); else fall back to the locked quote amount
        actually charged. Dev-bypass "payments" charged nothing, so are skipped.
        """
        # Only dev-bypass is skipped — it charged nothing. A real settlement that
        # exposes no transaction string (middleware stores `settlement.transaction
        # or ""`) still charged the customer, so it must still be refunded using
        # payer + amount.
        if payment_tx and payment_tx.startswith(("dev_bypass", "admin_bypass")):
            return
        settled = None
        if payment_tx:
            async with self.db() as session:
                settled = (
                    await session.execute(
                        select(PaymentEventRow)
                        .where(
                            PaymentEventRow.tx_hash == payment_tx,
                            PaymentEventRow.event_type == "settled",
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
        if settled is not None:
            await self.refunds.record_owed(
                resource_path="/v1/vm/create",
                payer=settled.payer_wallet or owner_wallet or "unknown",
                amount=settled.amount_usd,
                network=settled.network,
                asset=settled.asset,
                original_tx=payment_tx,
                reason=reason,
                vm_id=vm_id,
            )
            return
        await self.refunds.record_owed(
            resource_path="/v1/vm/create",
            payer=owner_wallet or "unknown",
            amount=charged_amount,
            original_tx=payment_tx,
            reason=reason,
            vm_id=vm_id,
        )

    async def _record_native_refund(self, vm_id: str, *, reason: str) -> bool:
        """Transition a failed native-intent VM's intent to REFUND_MANUAL and
        record the owed refund. Returns False when no native intent is linked to
        this VM (e.g. a free subdomain VM)."""
        async with self.db() as session:
            intent = (
                await session.execute(
                    select(CryptoIntentRow.intent_id).where(CryptoIntentRow.vm_id == vm_id).limit(1)
                )
            ).scalar_one_or_none()
        if intent is None:
            return False
        return await self.record_native_intent_refund(intent, reason=reason, vm_id=vm_id)

    async def record_native_intent_refund(
        self, intent_id: str, *, reason: str, vm_id: str | None = None
    ) -> bool:
        """Flip a paid native intent to REFUND_MANUAL and record the owed refund.

        Works even when no VM row exists yet — used both from _provision_vm (VM
        failed after PROVISIONED) and from the intent service's failure path
        (create_vm raised before a vm_id was ever linked, so the settled funds
        would otherwise get no refund_owed row).

        ATOMIC: the terminal status flip and the refund_owed ledger row are
        written in a single transaction, so a terminal REFUND_MANUAL status can
        never be committed without its obligation (a transient ledger failure
        rolls back both, leaving the intent to be retried). Idempotent on the
        obligation: an intent already REFUND_MANUAL with its row present is a
        no-op, while one missing its row (e.g. an older best-effort write that
        was lost) has it recreated.
        """
        async with self.db() as session:
            intent = await session.get(CryptoIntentRow, intent_id)
            if intent is None:
                return False
            already_owed = (
                await session.execute(
                    select(PaymentEventRow.event_id)
                    .where(
                        PaymentEventRow.event_type == "refund_owed",
                        PaymentEventRow.payer_wallet == intent_id,
                    )
                    .limit(1)
                )
            ).scalar_one_or_none() is not None
            order_changed = False
            if intent.resource_type == "domain_order" and intent.resource_id:
                order = await session.get(DomainOrderRow, intent.resource_id)
                if order is not None and order.status == "awaiting_payment":
                    # Keep the customer-facing resource consistent with the
                    # intent and refund obligation in this same transaction. A
                    # failed settlement handoff must not leave an unpayable
                    # order appearing to wait forever for payment.
                    order.status = "refund_due"
                    order.paid_at = intent.paid_at or _now()
                    order.payer = intent.intent_id
                    order.payment_tx = intent.tx_hash
                    order.payment_network = "native"
                    order.payment_asset = intent.asset
                    order.error_code = reason[:64]
                    order.error_detail = "Native payment settled, but fulfillment handoff failed."
                    order_changed = True
            if intent.status == CryptoIntentStatus.REFUND_MANUAL and already_owed:
                if order_changed:
                    await session.commit()
                return False  # fully recorded — don't double-owe
            # payer is the intent_id (a bounded reference the operator resolves to
            # the REFUND_MANUAL intent) — NOT the deposit address, which for XMR
            # can exceed payer_wallet's column width; the address rides in extra.
            # amount_usd is the quote; overpay/late re-quote can mean the customer
            # sent more on-chain, so surface the received crypto amount so a manual
            # refund isn't silently short.
            event = None
            if not already_owed:
                event = self.refunds.build_owed_event(
                    resource_path=(
                        "/v1/domains/orders"
                        if intent.resource_type == "domain_order"
                        else "/v1/vm/create"
                    ),
                    payer=intent_id,
                    amount=intent.amount_usd,
                    network="native",
                    asset=intent.asset,
                    original_tx=intent.tx_hash,
                    reason=reason,
                    vm_id=vm_id,
                    extra={
                        "intent_id": intent_id,
                        "native_deposit_address": intent.address,
                        "native_refund_address": intent.refund_address,
                        "resource_type": intent.resource_type,
                        "resource_id": intent.resource_id,
                        "amount_received_crypto": (
                            str(intent.amount_received_crypto)
                            if intent.amount_received_crypto is not None
                            else None
                        ),
                    },
                )
            if intent.status != CryptoIntentStatus.REFUND_MANUAL:
                log.warning(
                    "native_intent_refund_manual",
                    vm_id=vm_id,
                    intent_id=intent_id,
                    asset=intent.asset,
                    reason=reason,
                )
                intent.status = CryptoIntentStatus.REFUND_MANUAL
            if event is not None:
                session.add(event)
            await session.commit()
        return True

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

        async with self.db() as session:
            row = (
                await session.execute(
                    select(VMRow).where(VMRow.vm_id == vm_id).with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                return
            # Keep the simulated address consistent with the allocated
            # customer /64 — the status API exposes both, and an address
            # outside the assigned prefix would be visibly wrong data.
            if row.ipv6_prefix:
                fake_ipv6 = str(vm_address_for_prefix(IPv6Network(row.ipv6_prefix, strict=True)))
            else:
                fake_ipv6 = f"2001:db8::{random.randint(0x1000, 0x9999):04x}"
            row.ipv6 = fake_ipv6
            row.status = (
                VMStatus.SUSPENDED
                if row.suspension_reason in {"account_disabled", "manual_admin"}
                else VMStatus.READY
            )
            row.provisioned_at = _now()
            meta = row.metadata_ or {}
            lp = meta.get("launch_proof", {})
            lp["dns_aaaa_verified"] = True
            lp["ssh_smoke_status"] = "passed"
            meta["launch_proof"] = lp
            row.metadata_ = meta
            await session.commit()

        log.info("provision_simulate_complete", vm_id=vm_id, ipv6=fake_ipv6)

    async def _probe_ssh(
        self,
        ipv6: str,
        *,
        timeout_seconds: int = 90,
        interval_seconds: int = 5,
        port: int = 22,
    ) -> bool:
        """TCP reachability probe of the VM's sshd for the launch proof.

        sshd usually comes up after the IPv6 address appears (cloud-init is
        still running), so keep retrying until a monotonic deadline —
        blackholed connect attempts burn wall-clock too, and must not extend
        the window beyond timeout_seconds. Connectivity only — no SSH
        handshake, no credentials.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while True:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ipv6, port), timeout=5)
                writer.close()
                await writer.wait_closed()
                return True
            except (TimeoutError, OSError):
                if loop.time() + interval_seconds >= deadline:
                    return False
                await asyncio.sleep(interval_seconds)

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

    async def _register_custom_domain(
        self,
        *,
        vm_id: str,
        domain: str,
        ipv6: str,
        owner_account_id: str | None,
    ) -> None:
        if self.domains is None or owner_account_id is None:
            raise ValueError("custom domains require an authenticated managed-domain account")
        await self.domains.attach_vm(owner_account_id, domain, vm_id, ipv6)

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
            result = await session.execute(select(VMQuoteRow).where(VMQuoteRow.vm_id == vm_id))
            return result.scalar_one_or_none()

    async def extend_vm(self, vm_id: str, days: int) -> VMRow | None:
        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if (
                not row
                or not row.expires_at
                or row.suspension_reason in {"account_disabled", "manual_admin"}
            ):
                return None

            now = _now()
            base = max(row.expires_at, now)
            row.expires_at = base + timedelta(days=days)

            suspend_status = row.status == VMStatus.SUSPENDED
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
            status = str(row.status)
            domain_mode = row.domain_mode
            domain = row.domain
            owner_account_id = row.owner_account_id

        # Track whether every user of the deterministic ::2 address is
        # verifiably gone; the /64 is only released when they are. A
        # quarantined prefix costs one pool slot; releasing early could hand
        # a stale DNS name or a still-running guest to the next customer.
        cleanup_ok = True

        if xcpng_uuid:
            await self.xcpng.destroy_vm(xcpng_uuid)
        elif status == str(VMStatus.PROVISIONING):
            # Mid-provision race: the clone may exist without xcpng_uuid
            # having been recorded yet — the guest could still come up on
            # this prefix after we look.
            cleanup_ok = False

        if hostname:
            subdomain = self._generate_hostname(vm_id)
            try:
                await self.dns.delete_aaaa(subdomain)
            except Exception:
                log.warning("dns_cleanup_failed", vm_id=vm_id, exc_info=True)
                cleanup_ok = False

        if domain_mode == DomainMode.CUSTOM and domain:
            other_cleanup_ok = cleanup_ok
            try:
                if self.domains is None or owner_account_id is None:
                    raise RuntimeError("managed-domain cleanup is unavailable for this VM")
                await self.domains.detach_vm(owner_account_id, domain, vm_id)
            except Exception:
                log.warning(
                    "custom_domain_dns_cleanup_failed",
                    vm_id=vm_id,
                    domain=domain,
                    exc_info=True,
                )
                cleanup_ok = False
                if self.domains is not None and owner_account_id is not None:
                    try:
                        await self.domains.enqueue_vm_detachment(
                            owner_account_id,
                            domain,
                            vm_id,
                            release_prefix=other_cleanup_ok,
                        )
                    except Exception:
                        log.exception(
                            "custom_domain_cleanup_retry_enqueue_failed",
                            vm_id=vm_id,
                            domain=domain,
                        )

        async with self.db() as session:
            row = await session.get(VMRow, vm_id)
            if row:
                row.status = VMStatus.DESTROYED
                row.destroyed_at = _now()
                if cleanup_ok:
                    # Release the customer /64 for reuse: the unique index on
                    # ipv6_prefix_index would otherwise pin it to this dead
                    # row forever and eventually exhaust the pool.
                    row.ipv6_prefix_index = None
                    row.ipv6_prefix = None
                else:
                    log.warning(
                        "customer_prefix_quarantined",
                        vm_id=vm_id,
                        prefix=row.ipv6_prefix,
                        reason="cleanup incomplete — stale DNS or guest may still use the address",
                    )
                await session.commit()

        log.info("vm_destroyed", vm_id=vm_id)
        return True

    async def release_destroyed_prefix(self, vm_id: str) -> None:
        """Release a quarantined /64 after its deferred cleanup converges."""
        async with self.db() as session:
            row = (
                await session.execute(
                    select(VMRow).where(VMRow.vm_id == vm_id).with_for_update()
                )
            ).scalar_one_or_none()
            if row is not None and str(row.status) == VMStatus.DESTROYED.value:
                row.ipv6_prefix_index = None
                row.ipv6_prefix = None
                await session.commit()

    # --- Expiry Management ---

    async def check_expiries(self) -> None:
        """Suspend expired VMs, destroy those past grace period."""
        now = _now()
        grace = timedelta(hours=self.config.vm_grace_period_hours)

        # Purge abandoned pre-payment reservations (a crash between
        # reserve_vm and settlement leaves an unpaid placeholder pinning a
        # /64). Live reservations are seconds old; 15 minutes is generous.
        async with self.db() as session:
            stale_reservations = list(
                await session.scalars(
                    select(VMRow.vm_id).where(
                        VMRow.owner_wallet == "",
                        VMRow.status == VMStatus.PROVISIONING,
                        VMRow.created_at < now - timedelta(minutes=15),
                    )
                )
            )
            if stale_reservations:
                await session.execute(
                    update(DomainRow)
                    .where(
                        DomainRow.vm_id.in_(stale_reservations),
                        DomainRow.vm_ipv6.is_(None),
                    )
                    .values(vm_id=None)
                )
                await session.execute(
                    sql_delete(VMRow).where(
                        VMRow.vm_id.in_(stale_reservations),
                        VMRow.owner_wallet == "",
                        VMRow.status == VMStatus.PROVISIONING,
                    )
                )
            await session.commit()

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
                expired_vms.append(
                    {
                        "vm_id": r.vm_id,
                        "expires_at": r.expires_at,
                        "status": r.status,
                        "xcpng_uuid": r.xcpng_uuid,
                    }
                )

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
                        .values(
                            status=VMStatus.SUSPENDED,
                            suspension_reason="expired",
                            suspended_by_account_id=None,
                        )
                    )
                    await session.commit()
