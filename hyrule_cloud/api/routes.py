"""
FastAPI routes for Hyrule Cloud API.

x402-gated endpoints use PaymentGate.check_payment() which returns
either a 402 Response or the payer's wallet address.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from decimal import Decimal
from ipaddress import IPv6Network
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy import update as _sql_update
from sqlalchemy.exc import IntegrityError

from hyrule_cloud.db import DomainRow, VMQuoteRow, VMRow
from hyrule_cloud.middleware.anon_token import (
    anon_management_token,
    can_manage_vm,
    hash_anon_token,
)
from hyrule_cloud.middleware.auth import current_account
from hyrule_cloud.middleware.x402 import PaymentGate
from hyrule_cloud.models import (
    VM_SPECS,
    AcceptedPaymentMethods,
    DNSRecord,
    DNSRecordType,
    DomainCheckResponse,
    DomainMode,
    DomainRegisterRequest,
    DomainRegisterResponse,
    DomainStatus,
    FirewallState,
    GenericActionResponse,
    NetworkRequest,
    NetworkResponse,
    OSListResponse,
    OSTemplate,
    PricingResponse,
    ProxyMode,
    QuoteEvmMethod,
    QuoteStatus,
    VMCreateRequest,
    VMCreateResponse,
    VMExtendRequest,
    VMLogEvent,
    VMLogsResponse,
    VMProduct,
    VMProductsResponse,
    VMPublicStatusResponse,
    VMQuoteRequest,
    VMQuoteResponse,
    VMSize,
    VMStatus,
    VMStatusResponse,
    generate_domain_management_token,
)
from hyrule_cloud.providers.network_config import (
    RESERVED_PREFIX_INDEXES,
    customer_prefix_count,
    supports_static_network_config,
)
from hyrule_cloud.services.launch_proof import build_launch_proof
from hyrule_cloud.services.quotes import (
    QuoteConflictError,
    QuoteExistsError,
    claim_quote,
    create_quote,
    get_quote,
    is_expired,
    link_quote_vm,
)
from hyrule_cloud.state import AppState, get_app_state

log = structlog.get_logger()

router = APIRouter(prefix="/v1")

_domain_registration_locks: dict[str, asyncio.Lock] = {}


def _domain_registration_lock(key: str) -> asyncio.Lock:
    lock = _domain_registration_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _domain_registration_locks[key] = lock
    return lock


@asynccontextmanager
async def _domain_registration_guard(fqdn: str, client_order_id: str | None):
    keys = {f"domain:{fqdn}"}
    if client_order_id:
        keys.add(f"client:{client_order_id}")
    locks = [_domain_registration_lock(key) for key in sorted(keys)]
    for lock in locks:
        await lock.acquire()
    try:
        yield
    finally:
        for lock in reversed(locks):
            lock.release()


def get_orch(app_state: AppState = Depends(get_app_state)):
    return app_state.orchestrator

def get_cfg(app_state: AppState = Depends(get_app_state)):
    return app_state.config

def get_gate(app_state: AppState = Depends(get_app_state)):
    return app_state.payment_gate

def get_network(app_state: AppState = Depends(get_app_state)):
    return app_state.network_provider


# --- Quote helpers (issue #14) ---


_NATIVE_ASSETS = ("BTC", "XMR")


def _native_payment_assets(app_state: AppState) -> list[str]:
    configured = [asset.upper() for asset in getattr(app_state, "native_payment_assets", [])]
    return [asset for asset in _NATIVE_ASSETS if asset in configured]


def _accepted_payment_methods(cfg, app_state: AppState) -> AcceptedPaymentMethods:
    """Single source of truth for what a quote can be paid with: enabled EVM
    chains from config + native (BTC/XMR) iff the intent rail is wired."""
    evm = [
        QuoteEvmMethod(key=n.key, caip2=n.caip2, asset=n.asset, chain_id=n.chain_id)
        for n in cfg.payment.enabled_networks()
    ]
    native = _native_payment_assets(app_state)
    return AcceptedPaymentMethods(evm=evm, native=native)


def _split_domain(domain: str) -> tuple[str, str, str]:
    fqdn = domain.strip().lower().rstrip(".")
    if not fqdn or ".." in fqdn or "." not in fqdn:
        raise HTTPException(400, "domain must be a fully-qualified name")
    name, extension = fqdn.rsplit(".", 1)
    if not name or not extension:
        raise HTTPException(400, "domain must be a fully-qualified name")
    return name, extension, fqdn


def _domain_from_parts(
    *,
    domain: str | None = None,
    name: str | None = None,
    extension: str | None = None,
) -> tuple[str, str, str]:
    if domain:
        return _split_domain(domain)
    if name and extension:
        return _split_domain(f"{name}.{extension}")
    raise HTTPException(400, "domain required")


def _domain_management_token(request: Request) -> str | None:
    auth = (request.headers.get("authorization") or "").strip()
    if auth:
        scheme, _, credential = auth.partition(" ")
        if scheme.lower() == "bearer" and credential.strip().startswith("hyr_dom_"):
            return credential.strip()
    return None


async def _domain_price(
    orch,
    cfg,
    fqdn: str,
) -> tuple[str, str, str, Decimal | None, Decimal, Decimal, bool]:
    name, extension, _ = _split_domain(fqdn)
    check = await orch.openprovider.check_domain(name, extension)
    if check.get("status") != "free":
        raise HTTPException(409, f"Domain {fqdn} is not available")
    registrar = check.get("price")
    registrar_price = Decimal(str(registrar)) if registrar is not None else Decimal("10")
    markup = cfg.payment.price_domain_markup
    total = registrar_price + markup
    currency = str(check.get("currency") or "USD")
    return name, extension, currency, registrar_price, markup, total, bool(check.get("is_premium"))


async def _compute_vm_price(orch, cfg, order: VMCreateRequest) -> tuple[Decimal, Any]:
    total, breakdown = orch.compute_price(order)
    if order.domain_mode == DomainMode.CUSTOM and order.domain:
        _, _, _, registrar_price, markup, _, _ = await _domain_price(orch, cfg, order.domain)
        domain_total = registrar_price + markup
        total = total - markup + domain_total
        breakdown.domain_cost = f"${domain_total:.2f}"
        breakdown.total = f"${total:.2f}"
    return total, breakdown


async def _enforce_paid_vm_cap(orch, cfg) -> None:
    cap = int(getattr(cfg, "max_paid_active_vms", 0) or 0)
    if cap <= 0:
        return
    async with orch.db() as session:
        result = await session.execute(
            select(func.count())
            .select_from(VMRow)
            .where(
                VMRow.status.notin_([VMStatus.DESTROYED, VMStatus.FAILED]),
                VMRow.owner_wallet != "",
            )
        )
    if int(result.scalar() or 0) >= cap:
        raise HTTPException(503, "Soft-launch VM capacity reached")


def _quote_to_response(row: VMQuoteRow, cfg, app_state: AppState) -> VMQuoteResponse:
    status = QuoteStatus(row.status)
    if status == QuoteStatus.CREATED and is_expired(row):
        status = QuoteStatus.EXPIRED
    return VMQuoteResponse(
        quote_id=row.quote_id,
        status=status,
        order_payload=VMCreateRequest(**row.order_payload),
        amount_usd=str(row.amount_usd),
        accepted_payment_methods=_accepted_payment_methods(cfg, app_state),
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


def _vm_create_response(
    row: VMRow, request: Request, management_token: str | None
) -> VMCreateResponse:
    base_url = str(request.base_url).rstrip("/")
    return VMCreateResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        status_url=f"{base_url}/v1/vm/{row.vm_id}/status",
        estimated_ready_seconds=60,
        management_token=management_token,
        management_url=(
            f"{base_url}/v1/vm/{row.vm_id}?token={management_token}"
            if management_token
            else None
        ),
    )


def _real_provisioning_enabled() -> bool:
    from hyrule_cloud.services.launch_proof import use_real_provisioning

    return use_real_provisioning()


def _vm_service_open(gate: object) -> bool:
    """Whether the paid VM service may take money right now.

    Real VM provisioning is the last launch step (HCP_LAUNCH_PROOF_REAL_XCPNG=1).
    Until then the app still boots — it serves the network-intel, proxy, and
    domain services — but the live x402 gate must not charge, nor hand out a
    crypto deposit address, for a VM we can only simulate. Test doubles (fake
    gates) keep the simulated flow so the suite still exercises provisioning,
    mirroring the reservation-through-payment guard in create_vm.
    """
    return _real_provisioning_enabled() or not isinstance(gate, PaymentGate)


def _require_vm_service_open(gate: object) -> None:
    if not _vm_service_open(gate):
        raise HTTPException(503, "VM provisioning is not yet generally available")


def _validate_vm_order(order: VMCreateRequest, cfg) -> None:
    if order.domain_mode == DomainMode.CUSTOM and not order.domain:
        raise HTTPException(400, "domain required when domain_mode=custom")

    for port in order.open_ports:
        if port in cfg.blocked_ports:
            raise HTTPException(400, f"Port {port} is blocked by policy")

    if _real_provisioning_enabled():
        if not supports_static_network_config(order.os):
            raise HTTPException(
                400,
                f"OS template {order.os} is not supported for real VM provisioning yet",
            )
        # An OS name without a configured template UUID would only fail inside
        # Orchestrator.create_vm — after payment. Refuse it here.
        templates = getattr(getattr(cfg, "xcpng", None), "templates", None) or {}
        if not templates.get(order.os):
            raise HTTPException(
                400,
                f"OS template {order.os} is not available on this deployment",
            )


async def _enforce_prefix_capacity(orch, cfg) -> None:
    """Refuse new paid VM orders when the customer /64 pool is exhausted.

    Runs BEFORE the payment gate: prefix allocation happens in create_vm after
    the charge, so without this check the next order on a full pool would be
    charged and then fail.
    """
    try:
        supernet = IPv6Network(cfg.customer_ipv6_supernet, strict=True)
    except (AttributeError, ValueError):
        return  # startup validation owns config errors; don't mask them here
    usable = customer_prefix_count(supernet) - len(RESERVED_PREFIX_INDEXES)
    async with orch.db() as session:
        result = await session.execute(
            select(func.count())
            .select_from(VMRow)
            .where(VMRow.ipv6_prefix_index.isnot(None))
        )
    if int(result.scalar() or 0) >= usable:
        raise HTTPException(503, "No customer IPv6 capacity available right now")


# --- Block B (Wave 2): runtime metrics ---

# 20s TTL cache: the DB count + provisioned-at query is cheap but not free,
# and the endpoint can be hit several times per page-load by polling
# dashboards. Per-process; on a multi-worker deploy each worker has its own.
# Tests reset this directly via `_RUNTIME_CACHE.clear()`.
from cachetools import TTLCache as _TTLCache

_RUNTIME_CACHE: _TTLCache = _TTLCache(maxsize=2, ttl=20)


@router.get("/stats/runtime")
async def get_runtime_stats(
    request: Request,
    orch = Depends(get_orch),
) -> dict:
    """Per-process live runtime metrics.

    Source is labelled `api-process-local-rolling-window` because the
    deque is per-worker (uvicorn runs one event loop per worker; we don't
    aggregate). Fleet-wide stats land in Block H via Prometheus on `mon`.

    Fields always present (with sensible fallbacks when no samples exist
    yet):
      - api_p50_ms: p50 of the last 1000 requests, milliseconds
      - api_p50_source: provenance label
      - sample_count: how many samples back the p50
      - live_vms: VMs currently READY
      - build_queue: VMs currently PROVISIONING
      - avg_provision_seconds: rolling avg of (provisioned_at - created_at)
        over the last 50 READY VMs (None if no provisioned_at data)
      - updated_at: ISO8601 UTC when computed
    """
    from datetime import UTC, datetime

    from sqlalchemy import func as sa_func
    from sqlalchemy import select

    from hyrule_cloud.db import VMRow
    from hyrule_cloud.models import VMStatus

    cached = _RUNTIME_CACHE.get("runtime")
    if cached is not None:
        return cached

    metrics = getattr(request.app.state, "metrics", None)
    p50 = metrics.percentile(0.5) if metrics is not None else None
    sample_count = metrics.sample_count() if metrics is not None else 0

    live_vms = 0
    build_queue = 0
    avg_provision_seconds = None
    try:
        async with orch.db() as db:
            counts = await db.execute(
                select(VMRow.status, sa_func.count()).group_by(VMRow.status)
            )
            for status, c in counts.all():
                # `live_vms` counts everything that's not destroyed/failed —
                # both READY and still-PROVISIONING contribute (a VM in the
                # build queue still consumes hypervisor resources).
                if status in (VMStatus.READY, VMStatus.PROVISIONING):
                    live_vms += c
                if status == VMStatus.PROVISIONING:
                    build_queue = c
            # Rolling avg over the last 50 provisioned VMs.
            recent = await db.execute(
                select(VMRow.created_at, VMRow.provisioned_at)
                .where(VMRow.provisioned_at.is_not(None))
                .order_by(VMRow.provisioned_at.desc())
                .limit(50)
            )
            durations = [
                (p - c).total_seconds()
                for c, p in recent.all() if c is not None and p is not None
            ]
            if durations:
                avg_provision_seconds = round(sum(durations) / len(durations), 1)
    except Exception as exc:
        log.warning("runtime_stats_db_failed", error=str(exc))

    payload = {
        "api_p50_ms": p50 if p50 is not None else 0,
        "api_p50_source": "api-process-local-rolling-window",
        "api_p50_sample_count": sample_count,
        "live_vms": live_vms,
        "build_queue": build_queue,
        "avg_provision_seconds": avg_provision_seconds,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    _RUNTIME_CACHE["runtime"] = payload
    return payload


# --- Block H (Wave 5): fleet-wide network stats from Prometheus on `mon` ---

_NETWORK_CACHE: dict[str, object] = {"value": None, "expires_at": 0.0}
_NETWORK_TTL_SECONDS = 30
_NETWORK_STATIC_FALLBACK: dict[str, Any] = {
    # Hard-coded fleet truth as of the last operator review. Drifts slowly;
    # update this dict via PR if BGP topology or transit set changes.
    "bgp_peers_established": None,
    "ipv6_prefixes_announced": 3,
    "nat64_sessions_active": None,
    "transit_providers": ["AS34872", "AS210233"],
}


@router.get("/stats/network")
async def get_network_stats(request: Request):
    """Live fleet truth (BGP peers, IPv6 prefixes, NAT64 sessions) from
    Prometheus on `mon`. Fail-soft: a missing/unreachable Prometheus returns
    the static fallback shape with _source="fallback" — never a 500."""
    import time as _time
    from datetime import UTC
    from datetime import datetime as _dt

    now = _time.time()
    cached = _NETWORK_CACHE.get("value")
    if cached is not None and now < float(_NETWORK_CACHE["expires_at"]):
        return cached

    app_state: AppState = request.app.state._typed_state
    cfg = app_state.config
    prom_url = getattr(cfg, "prometheus_url", "") or ""

    body: dict[str, Any] = {
        "bgp_peers_established": _NETWORK_STATIC_FALLBACK["bgp_peers_established"],
        "ipv6_prefixes_announced": _NETWORK_STATIC_FALLBACK["ipv6_prefixes_announced"],
        "nat64_sessions_active": _NETWORK_STATIC_FALLBACK["nat64_sessions_active"],
        "transit_providers": list(_NETWORK_STATIC_FALLBACK["transit_providers"]),
        "_source": "fallback",
        "updated_at": _dt.now(UTC).isoformat(),
    }

    if prom_url:
        from hyrule_cloud.providers.prometheus import PrometheusClient

        client = PrometheusClient(prom_url)
        # PromQL queries — written so a missing exporter cleanly returns None
        # rather than raising; the endpoint then keeps the static fallback for
        # that one field while still labelling _source live for the rest.
        try:
            bgp = await client.query_scalar('count(bgp_peer_state == 1)')
            if bgp is None:
                # FRR exporter alternative metric name
                bgp = await client.query_scalar('count(frr_bgp_peer_state{state="Established"})')
            prefixes = await client.query_scalar('count(count by (prefix) (bgp_prefix_received))')
            nat64 = await client.query_scalar('sum(nat64_sessions_active)')
        finally:
            await client.aclose()

        live_count = 0
        if bgp is not None:
            body["bgp_peers_established"] = int(bgp)
            live_count += 1
        if prefixes is not None:
            body["ipv6_prefixes_announced"] = int(prefixes)
            live_count += 1
        if nat64 is not None:
            body["nat64_sessions_active"] = int(nat64)
            live_count += 1

        if live_count > 0:
            body["_source"] = f"prometheus-{prom_url}"

    _NETWORK_CACHE["value"] = body
    _NETWORK_CACHE["expires_at"] = now + _NETWORK_TTL_SECONDS
    return body


# --- Free endpoints ---


@router.get("/payments/networks")
async def get_payment_networks(
    cfg = Depends(get_cfg),
    app_state: AppState = Depends(get_app_state),
) -> dict:
    """Block C (Wave 3): the canonical list of supported payment chains.

    The frontend chain selector and any agent SDK that wants to know what
    chains we accept reads from here — NEVER hardcodes the list client-side
    (per feedback_verified_payment_chains.md). Operators can flip a chain
    off via Vault (PAYMENT_PAYMENT_NETWORKS__N__enabled=false) and the
    frontend picks it up on the next poll without a redeploy.

    Shape: `{ networks: [...], native: [...], receiver_address, facilitator_url }`. Each
    network dict carries the CAIP-2 identifier (canonical for x402 v2), the
    EIP-712 domain shape (so the wallet adapter doesn't have to bake one
    in), and the explorer URL for the post-pay receipt link.
    """
    native = _native_payment_assets(app_state)
    return {
        "networks": [
            {
                "key": n.key,
                "display_name": n.display_name,
                "caip2": n.caip2,
                "family": n.family,
                "chain_id": n.chain_id,
                "asset": n.asset,
                "token_address": n.token_address,
                "token_decimals": n.token_decimals,
                "eip712_domain": n.eip712_domain,
                "native_currency": n.native_currency,
                "rpc_url": n.rpc_url,
                "block_explorer_url": n.block_explorer_url,
                "testnet": n.testnet,
            }
            for n in cfg.payment.enabled_networks()
        ],
        "native": native,
        "receiver_address": cfg.payment.receiver_address,
        "facilitator_url": cfg.payment.facilitator_url,
    }


@router.get("/pricing", response_model=PricingResponse)
async def get_pricing(cfg = Depends(get_cfg)) -> PricingResponse:
    return PricingResponse(
        vm_prices={
            "xs (1vCPU/1GB/10GB)": f"${cfg.payment.price_vm_xs}/day",
            "sm (1vCPU/1GB/20GB)": f"${cfg.payment.price_vm_sm}/day",
            "md (2vCPU/2GB/40GB)": f"${cfg.payment.price_vm_md}/day",
            "lg (4vCPU/4GB/80GB)": f"${cfg.payment.price_vm_lg}/day",
        },
        domain_auto=f"$0.00 (subdomain under {cfg.deploy_domain})",
        proxy_prices={
            "direct": f"${cfg.payment.price_proxy_direct}/request",
            "tor": f"${cfg.payment.price_proxy_tor}/request",
            "i2p": f"${cfg.payment.price_proxy_i2p}/request",
            "yggdrasil": f"${cfg.payment.price_proxy_yggdrasil}/request",
        } if hasattr(PricingResponse, '__annotations__') and 'proxy_prices' in PricingResponse.__annotations__ else {}
    )


_VM_PRODUCT_NAMES = {
    VMSize.XS: "Starter",
    VMSize.SM: "Basic",
    VMSize.MD: "Standard",
    VMSize.LG: "Performance",
}


@router.get("/products/vms", response_model=VMProductsResponse)
async def get_vm_products(request: Request, cfg=Depends(get_cfg)) -> VMProductsResponse:
    """Issue #14: machine-readable VM catalog (specs + daily price per size) so
    agents get the product list without scraping the /services HTML. Sourced from
    VM_SPECS + the configured per-size prices (the same source as /v1/pricing)."""
    products = [
        VMProduct(
            size=size,
            name=_VM_PRODUCT_NAMES.get(size, size.value),
            vcpu=VM_SPECS[size]["vcpu"],
            ram_mb=VM_SPECS[size]["memory_mb"],
            disk_gb=VM_SPECS[size]["disk_gb"],
            price_usd_day=str(getattr(cfg.payment, f"price_vm_{size.value}")),
        )
        for size in VMSize
    ]
    base_url = str(request.base_url).rstrip("/")
    return VMProductsResponse(products=products, os_templates_url=f"{base_url}/v1/os/list")


@router.get("/os/list", response_model=OSListResponse)
async def list_os_templates(cfg = Depends(get_cfg)) -> OSListResponse:
    names = list(cfg.xcpng.templates)
    if not names:
        names = ["debian-13", "alpine-3.21", "freebsd-14"]
    if _real_provisioning_enabled():
        names = [name for name in names if supports_static_network_config(name)]
    descriptions = {
        "debian-13": "Debian 13 (Trixie)",
        "alpine-3.21": "Alpine Linux 3.21",
        "freebsd-14": "FreeBSD 14.2",
    }
    templates = [
        OSTemplate(
            name=name,
            description=descriptions.get(name, f"OS template: {name}"),
            default=(name == "debian-13"),
        )
        for name in names
    ]
    return OSListResponse(templates=templates)


# Common dep that loads the VM and enforces management authority in one
# place. Authority sources (in order of preference):
#   - Block A1 (Wave 2): caller's session cookie resolves to an account
#     that matches the VM's `owner_account_id` (or caller is admin).
#   - Block A0 (Wave 1): caller presented a valid anon management token
#     via `Authorization: Bearer hyr_vm_<...>` or `?token=`.
# 404 (not 403) on bad/absent authority to avoid leaking VM existence to
# random vm_id guessers — same shape as "VM not found".
async def _vm_for_management(
    vm_id: str,
    request: Request,
    orch = Depends(get_orch),
    account = Depends(current_account),
):
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    # Account-ownership path (A1).
    if account is not None and row.owner_account_id is not None:
        if account.account_id == row.owner_account_id or getattr(account, "is_admin", False):
            return row
    # Anon-token path (A0). Still valid for ownerless rows AND for
    # account-owned rows — the management token is the bearer credential
    # the order flow handed out; sessions add a second path, they don't
    # remove the first.
    presented = anon_management_token(request)
    if can_manage_vm(row, presented):
        return row
    raise HTTPException(404, "VM not found")


# Block A0: public sanitized status view. Returns minimal fields needed
# for an order-status page — NO ssh, NO firewall, NO error detail. Any
# caller can fetch this for any vm_id; pre-A0 frontends keep working
# because the legacy `/vm/{id}` URL is still in their templates and now
# returns 404 unless the caller has a token. Status pages should switch
# to `/status`.
@router.get("/vm/{vm_id}/status", response_model=VMPublicStatusResponse)
async def get_vm_public_status(
    vm_id: str, orch = Depends(get_orch),
) -> VMPublicStatusResponse:
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    quote = None
    if hasattr(orch, "get_quote_for_vm"):
        quote = await orch.get_quote_for_vm(vm_id)
    lp = build_launch_proof(row, quote_row=quote)
    return VMPublicStatusResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        ipv6=row.ipv6,
        ipv6_prefix=getattr(row, "ipv6_prefix", None),
        hostname=row.hostname,
        expires_at=row.expires_at,
        launch_proof_status=lp["launch_proof_status"],
        payment_status=lp["payment_status"],
        dns_aaaa_verified=lp["dns_aaaa_verified"],
        ssh_smoke_status=lp["ssh_smoke_status"],
        rollback_available=lp["rollback_available"],
        operator_message=lp["operator_message"],
        customer_message=lp["customer_message"],
    )


# Block A0: management-gated full view. Was the only `GET /vm/{id}` route
# pre-A0 (open to anyone who knew the vm_id). Now requires the anon
# management token.
@router.get("/vm/{vm_id}", response_model=VMStatusResponse)
async def get_vm_status(
    row = Depends(_vm_for_management),
) -> VMStatusResponse:
    firewall = None
    if row.open_ports:
        firewall = FirewallState(inbound_allow=list(row.open_ports))

    is_ready = row.hostname and row.status == VMStatus.READY

    return VMStatusResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        ipv6=row.ipv6,
        ipv6_prefix=getattr(row, "ipv6_prefix", None),
        hostname=row.hostname,
        ssh=f"ssh root@{row.hostname}" if is_ready else None,
        expires_at=row.expires_at,
        firewall=firewall,
        error=row.error,
    )


@router.get("/vm/{vm_id}/logs", response_model=VMLogsResponse)
async def get_vm_logs(
    row = Depends(_vm_for_management),
) -> VMLogsResponse:
    return VMLogsResponse(
        vm_id=row.vm_id,
        status=row.status,
        events=[
            VMLogEvent(ts=row.created_at.isoformat(), event="provisioning_started"),
        ],
        error=row.error,
    )


# --- x402-gated endpoints ---


@router.post("/vm/create")
async def create_vm(
    body: VMCreateRequest,
    request: Request,
    orch = Depends(get_orch),
    cfg = Depends(get_cfg),
    gate = Depends(get_gate),
    # Block A1 (Wave 2): if the caller has a session cookie, the new VM is
    # attached to their account so it shows up on /dashboard immediately
    # without a separate claim step. Anon callers (account=None) get the
    # A0 management-token flow unchanged.
    account = Depends(current_account),
):
    # Issue #14: when a durable quote_id is supplied, the stored spec is
    # authoritative and the price is locked to the quote. Otherwise this is the
    # legacy compute-price-from-body flow, unchanged.
    quote_row: VMQuoteRow | None = None
    order = body
    if body.quote_id:
        quote_row = await get_quote(orch.db, body.quote_id)
        if quote_row is None:
            raise HTTPException(404, "Quote not found")
        if QuoteStatus(quote_row.status) == QuoteStatus.CONSUMED:
            # Idempotent replay: a VM was already provisioned from this quote —
            # return it rather than charging/provisioning again. The one-shot
            # management token was revealed at first creation and is not re-issued.
            if quote_row.vm_id:
                async with orch.db() as session:
                    existing_vm = await session.get(VMRow, quote_row.vm_id)
                if existing_vm is not None:
                    return _vm_create_response(existing_vm, request, management_token=None)
            # Claimed but not yet linked → the winner is mid-provision.
            raise HTTPException(409, "Quote is being provisioned; poll the VM status")
        if is_expired(quote_row):
            raise HTTPException(409, "Quote expired; create a new one")
        if QuoteStatus(quote_row.status) != QuoteStatus.CREATED:
            raise HTTPException(409, "Quote is not payable")
        # Tamper / price-lock guard: the body must match the stored spec exactly.
        if body.model_dump(mode="json", exclude={"quote_id"}) != quote_row.order_payload:
            raise HTTPException(422, "Order body does not match the quote")
        order = VMCreateRequest(**quote_row.order_payload)

    # Closed until real provisioning is enabled — never charge for a simulated
    # VM. Placed after the consumed-quote replay above so an already-paid,
    # already-provisioned order can still be recovered when the service is shut.
    _require_vm_service_open(gate)

    _validate_vm_order(order, cfg)

    await _enforce_paid_vm_cap(orch, cfg)
    await _enforce_prefix_capacity(orch, cfg)

    # Price-lock: a quote-bound create charges the amount quoted to the user,
    # not a recomputation (which could drift). The breakdown is still recomputed
    # for the 402 body's informational cost_breakdown.
    computed, breakdown = await _compute_vm_price(orch, cfg, order)
    total = quote_row.amount_usd if quote_row is not None else computed
    specs = VM_SPECS[order.size]

    # Reservation-through-payment: a request that is about to be CHARGED
    # atomically claims its VM row + customer /64 (unique index) BEFORE the
    # facilitator settles, so a concurrent purchase can never leave a paid
    # order without capacity. Unpaid discovery requests (no payment header)
    # skip this and just receive the 402. Fake gates in tests may not expose
    # has_payment_credentials — they keep the legacy allocate-after-payment path.
    reservation_row: VMRow | None = None
    reservation_token: str | None = None
    # isinstance on purpose: reservation semantics are coupled to the real
    # gate; test doubles (mocks / X-Mock-Paid fakes) keep the legacy
    # allocate-after-payment path.
    if isinstance(gate, PaymentGate) and gate.has_payment_credentials(request):
        try:
            reservation_row, reservation_token = await orch.reserve_vm(
                order, owner_account_id=account.account_id if account else None
            )
        except RuntimeError:
            raise HTTPException(503, "No customer IPv6 capacity available right now")

    result = await gate.check_payment(
        request,
        amount=total,
        description=f"Hyrule Cloud VM ({order.size.value}) for {order.duration_days} days",
        extra_body={
            "cost_breakdown": breakdown.model_dump(),
            "specs": {**specs, "ipv6": True, "ipv4": False, "region": "eu-west"},
            "estimated_provision_time_seconds": 60,
        },
    )

    if isinstance(result, Response):
        # No/invalid payment yet (402) — the quote stays CREATED so the EVM
        # 402→sign→retry round-trip can post again with the same quote_id.
        if reservation_row is not None:
            await orch.release_vm_reservation(reservation_row.vm_id)
        return result

    wallet = result
    # Issue #14 / Sourcery (#16): claim the quote atomically BEFORE provisioning
    # so two concurrent paid creates for the same quote can't each provision a VM
    # — only the winner of the CREATED → CONSUMED flip proceeds.
    if quote_row is not None and not await claim_quote(orch.db, quote_row.quote_id):
        # Lost the race: another paid create already claimed the quote. Return the
        # VM it provisioned (idempotent); if it's still mid-provision, the caller
        # polls the status URL.
        if reservation_row is not None:
            await orch.release_vm_reservation(reservation_row.vm_id)
        latest = await get_quote(orch.db, quote_row.quote_id)
        if latest is not None and latest.vm_id:
            async with orch.db() as session:
                existing_vm = await session.get(VMRow, latest.vm_id)
            if existing_vm is not None:
                return _vm_create_response(existing_vm, request, management_token=None)
        raise HTTPException(409, "Quote is being provisioned; poll the VM status")

    if reservation_row is not None:
        activated = await orch.activate_vm_reservation(
            reservation_row.vm_id,
            owner_wallet=wallet,
            payment_tx=getattr(request.state, "payment_tx", None),
        )
        if activated is not None:
            row, management_token = activated, reservation_token
        else:
            # Reservation vanished (e.g. sweeper raced an extremely slow
            # payment) — fall back to allocate-after-payment.
            row, management_token = await orch.create_vm(
                order, owner_wallet=wallet,
                owner_account_id=account.account_id if account else None,
            )
            row.payment_tx = getattr(request.state, "payment_tx", None)
    else:
        row, management_token = await orch.create_vm(
            order, owner_wallet=wallet,
            owner_account_id=account.account_id if account else None,
        )
        row.payment_tx = getattr(request.state, "payment_tx", None)
    if quote_row is not None:
        await link_quote_vm(orch.db, quote_row.quote_id, row.vm_id)

    # Block A0: status_url is the public sanitized view; management_url embeds
    # the one-time anon token. The UI must surface management_url prominently
    # with a save-this-once warning — it cannot be retrieved again.
    return _vm_create_response(row, request, management_token)


@router.post("/vm/quote", response_model=VMQuoteResponse, status_code=201)
async def create_vm_quote(
    body: VMQuoteRequest,
    request: Request,
    orch=Depends(get_orch),
    cfg=Depends(get_cfg),
    gate=Depends(get_gate),
    account=Depends(current_account),
) -> Response:
    """Issue #14: price a VM order once and persist it as a durable quote.

    Returns a `quote_id` the UI/agent pays against — it survives review-page
    reloads and mobile wallet handoffs and locks the price for its TTL.
    Idempotent on `client_order_id`: same key + same spec returns the existing
    quote (200); same key + a different spec is a 409 conflict.
    """
    # Don't lock a price for a VM that can't be provisioned yet (simulation).
    _require_vm_service_open(gate)

    order = body.order_payload
    _validate_vm_order(order, cfg)

    total, _ = await _compute_vm_price(orch, cfg, order)
    app_state = get_app_state(request)
    try:
        row = await create_quote(
            session_factory=orch.db,
            order_payload=order,
            amount_usd=total,
            client_order_id=body.client_order_id,
            owner_account_id=(account.account_id if account is not None else None),
        )
    except QuoteExistsError as exc:
        # Idempotent replay — return the existing quote with 200, not 201.
        return JSONResponse(
            _quote_to_response(exc.existing, cfg, app_state).model_dump(mode="json"),
            status_code=200,
        )
    except QuoteConflictError as exc:
        raise HTTPException(
            409,
            f"client_order_id already used for a different order (quote {exc.existing.quote_id})",
        )
    return JSONResponse(
        _quote_to_response(row, cfg, app_state).model_dump(mode="json"),
        status_code=201,
    )


@router.get("/vm/quote/{quote_id}", response_model=VMQuoteResponse)
async def get_vm_quote(
    quote_id: str,
    request: Request,
    orch=Depends(get_orch),
    cfg=Depends(get_cfg),
    account=Depends(current_account),
) -> VMQuoteResponse:
    """Restore a durable quote by id (reload-safe). Expired quotes still return
    200 with status=expired so the UI can render a restart state."""
    row = await get_quote(orch.db, quote_id)
    if row is None:
        raise HTTPException(404, "Quote not found")
    # Account-owned quotes are only visible to the owner (or admin) — 404 (not
    # 403) to avoid leaking existence, mirroring the intent GET guard.
    if row.owner_account_id is not None and (
        account is None
        or (account.account_id != row.owner_account_id and not account.is_admin)
    ):
        raise HTTPException(404, "Quote not found")
    return _quote_to_response(row, cfg, get_app_state(request))


@router.post("/vm/{vm_id}/extend")
async def extend_vm(
    vm_id: str,
    body: VMExtendRequest,
    request: Request,
    row = Depends(_vm_for_management),
    orch = Depends(get_orch),
    cfg = Depends(get_cfg),
    gate = Depends(get_gate),
):
    # Block A0: row already loaded + management-gated by the dep above.
    # vm_id (path param) is used downstream in the payment description /
    # response shape.

    # A simulated VM must not be charged to extend either — same guard as
    # create/quote/intent. Refuse before check_payment so no money moves.
    _require_vm_service_open(gate)

    price_map = {
        VMSize.XS: cfg.payment.price_vm_xs,
        VMSize.SM: cfg.payment.price_vm_sm,
        VMSize.MD: cfg.payment.price_vm_md,
        VMSize.LG: cfg.payment.price_vm_lg,
    }
    total = price_map[VMSize(row.size)] * body.days

    result = await gate.check_payment(
        request,
        amount=total,
        description=f"Extend VM {vm_id} by {body.days} days",
        extra_body={
            "vm_id": vm_id,
            "current_expiry": row.expires_at.isoformat() if row.expires_at else None,
            "extension_days": body.days,
        },
    )

    if isinstance(result, Response):
        return result

    updated = await orch.extend_vm(vm_id, body.days)
    if not updated:
        raise HTTPException(500, "Failed to extend VM")

    return {
        "vm_id": vm_id,
        "new_expiry": updated.expires_at.isoformat() if updated.expires_at else None,
        "status": updated.status,
    }


@router.post("/vm/{vm_id}/reboot", response_model=GenericActionResponse)
async def reboot_vm(
    vm_id: str,
    row = Depends(_vm_for_management),
    orch = Depends(get_orch),
) -> GenericActionResponse:
    # Block A0: management dep ensures caller has the token.
    if not await orch.reboot_vm(vm_id):
        raise HTTPException(404, "VM not found or not running")
    return GenericActionResponse(status="ok", message=f"VM {vm_id} is rebooting")


@router.delete("/vm/{vm_id}", response_model=GenericActionResponse)
async def destroy_vm(
    vm_id: str,
    row = Depends(_vm_for_management),
    orch = Depends(get_orch),
) -> GenericActionResponse:
    # Block A0: management dep ensures caller has the token.
    if not await orch.destroy_vm(vm_id):
        raise HTTPException(404, "VM not found")
    return GenericActionResponse(status="ok", message=f"VM {vm_id} destroyed")


@router.get("/domain/check", response_model=DomainCheckResponse)
async def check_domain(
    domain: str | None = Query(default=None),
    name: str | None = Query(default=None),
    extension: str | None = Query(default=None),
    orch=Depends(get_orch),
    cfg=Depends(get_cfg),
) -> DomainCheckResponse:
    """Check if a domain is available for purchase."""
    name, extension, fqdn = _domain_from_parts(domain=domain, name=name, extension=extension)
    check = await orch.openprovider.check_domain(name, extension)
    registrar = check.get("price")
    registrar_price = (
        Decimal(str(registrar))
        if registrar is not None
        else (Decimal("10") if check.get("status") == "free" else None)
    )
    markup = cfg.payment.price_domain_markup
    total = registrar_price + markup if registrar_price is not None else None
    return DomainCheckResponse(
        domain=fqdn,
        available=(check.get("status") == "free"),
        registrar_price=str(registrar_price) if registrar_price is not None else None,
        markup=str(markup),
        total=str(total) if total is not None else None,
        currency=str(check.get("currency") or "USD"),
        premium=bool(check.get("is_premium")),
        price=str(total) if total is not None else None,
    )


@router.post("/domain/register", response_model=DomainRegisterResponse)
async def register_domain(
    body: DomainRegisterRequest,
    request: Request,
    orch=Depends(get_orch),
    cfg=Depends(get_cfg),
    gate=Depends(get_gate),
    account=Depends(current_account),
) -> DomainRegisterResponse:
    """
    Buy a DNS zone: register the domain via Openprovider and create a DNS zone.
    Domain management is owner-gated by session account or one-time anon token.
    """
    name, extension, fqdn = _domain_from_parts(
        domain=body.domain,
        name=body.name,
        extension=body.extension,
    )

    async with _domain_registration_guard(fqdn, body.client_order_id):
        async with orch.db() as session:
            existing = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
            ).scalar_one_or_none()
            if existing is not None:
                if body.client_order_id and existing.client_order_id == body.client_order_id:
                    return DomainRegisterResponse(
                        domain=fqdn,
                        status=DomainStatus(existing.status),
                        management_url=f"/v1/zone/records?zone={fqdn}",
                        message="Domain registration already exists",
                    )
                raise HTTPException(409, f"Domain {fqdn} is already managed")
            if body.client_order_id:
                existing_key = (
                    await session.execute(
                        select(DomainRow).where(DomainRow.client_order_id == body.client_order_id)
                    )
                ).scalar_one_or_none()
                if existing_key is not None:
                    raise HTTPException(409, "client_order_id already used for a different domain")

        _, _, currency, registrar_price, markup, total, _ = await _domain_price(orch, cfg, fqdn)

        result = await gate.check_payment(
            request,
            amount=total,
            description=f"Register domain {fqdn}",
            extra_body={
                "domain": fqdn,
                "registrar_cost": str(registrar_price),
                "markup": str(markup),
                "duration_years": body.duration_years,
                "client_order_id": body.client_order_id,
            },
        )

        if isinstance(result, Response):
            return result

        wallet = result
        token = generate_domain_management_token() if account is None else None
        async with orch.db() as session:
            row = DomainRow(
                name=name,
                extension=extension,
                fqdn=fqdn,
                owner_wallet=wallet,
                owner_account_id=(account.account_id if account is not None else None),
                anon_management_token_hash=(hash_anon_token(token) if token else None),
                status=DomainStatus.REGISTERING,
                client_order_id=body.client_order_id,
                registrar_price=registrar_price,
                markup=markup,
                total_price=total,
                currency=currency,
                payment_tx=getattr(request.state, "payment_tx", None),
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                log.warning("domain_registration_reservation_conflict", domain=fqdn, error=str(exc))
                raise HTTPException(409, f"Domain {fqdn} is already managed") from exc

        try:
            op_result = await orch.openprovider.register_domain(name, extension, period=body.duration_years)
            try:
                await orch.openprovider.create_zone(fqdn)
            except Exception:
                log.warning("zone_create_fallback", zone=fqdn)

            if body.ipv6:
                await orch.openprovider.create_zone_record(
                    zone_name=fqdn,
                    name="",
                    rtype="AAAA",
                    value=body.ipv6,
                    ttl=300,
                )
        except Exception as e:
            log.error("domain_registration_failed", domain=fqdn, error=str(e))
            async with orch.db() as session:
                await session.execute(
                    _sql_update(DomainRow)
                    .where(DomainRow.fqdn == fqdn)
                    .values(status=DomainStatus.FAILED.value, error=str(e))
                )
                await session.commit()
            raise HTTPException(502, f"Domain registration failed: {e}") from e

        raw_openprovider_id = (
            op_result.get("id")
            or op_result.get("domain", {}).get("id")
            or op_result.get("data", {}).get("id")
        )
        try:
            openprovider_id = int(raw_openprovider_id) if raw_openprovider_id is not None else None
        except (TypeError, ValueError):
            openprovider_id = None
        async with orch.db() as session:
            await session.execute(
                _sql_update(DomainRow)
                .where(DomainRow.fqdn == fqdn)
                .values(
                    status=DomainStatus.ACTIVE.value,
                    openprovider_id=openprovider_id,
                    error=None,
                )
            )
            await session.commit()

    return DomainRegisterResponse(
        domain=fqdn,
        status=DomainStatus.ACTIVE,
        management_token=token,
        management_url=f"/v1/zone/records?zone={fqdn}",
        message=f"Domain {fqdn} registered",
    )


async def _domain_for_management(
    *,
    zone: str,
    request: Request,
    orch,
    account,
) -> DomainRow:
    _, _, fqdn = _split_domain(zone)
    async with orch.db() as session:
        row = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "Domain not found")
        if account is not None and row.owner_account_id is not None:
            if account.account_id == row.owner_account_id or getattr(account, "is_admin", False):
                return row
        token = _domain_management_token(request)
        if row.anon_management_token_hash and token:
            if row.anon_management_token_hash == hash_anon_token(token):
                return row
    raise HTTPException(404, "Domain not found")


@router.get("/zone/records")
async def list_zone_records(
    zone: str,
    request: Request,
    orch=Depends(get_orch),
    account=Depends(current_account),
) -> dict:
    await _domain_for_management(zone=zone, request=request, orch=orch, account=account)
    return {"zone": zone, "records": await orch.openprovider.list_zone_records(zone)}


@router.post("/zone/record", response_model=GenericActionResponse)
async def create_zone_record(
    zone: str,
    body: DNSRecord,
    request: Request,
    orch=Depends(get_orch),
    account=Depends(current_account),
) -> GenericActionResponse:
    """Create a DNS record in a zone managed by Hyrule Cloud."""
    await _domain_for_management(zone=zone, request=request, orch=orch, account=account)
    try:
        await orch.openprovider.create_zone_record(
            zone_name=zone,
            name=body.name,
            rtype=body.type.value,
            value=body.value,
            ttl=body.ttl,
            prio=body.prio,
        )
    except Exception as e:
        log.error("zone_record_create_failed", zone=zone, error=str(e), exc_info=True)
        raise HTTPException(500, f"Failed to create record: {e}")

    fqdn = f"{body.name}.{zone}" if body.name else zone
    return GenericActionResponse(status="ok", message=f"Record {body.type.value} created for {fqdn}")


@router.delete("/zone/record", response_model=GenericActionResponse)
async def delete_zone_record(
    zone: str,
    name: str,
    type: str,
    request: Request,
    orch=Depends(get_orch),
    account=Depends(current_account),
):
    """Delete a DNS record from a zone managed by Hyrule Cloud."""
    await _domain_for_management(zone=zone, request=request, orch=orch, account=account)
    try:
        rtype = DNSRecordType(type.upper())
    except ValueError:
        raise HTTPException(400, f"Unsupported record type: {type}")

    try:
        await orch.openprovider.delete_zone_record(
            zone_name=zone,
            name=name,
            rtype=rtype.value,
        )
    except Exception as e:
        log.error("zone_record_delete_failed", zone=zone, error=str(e), exc_info=True)
        raise HTTPException(500, f"Failed to delete record: {e}")

    fqdn = f"{name}.{zone}" if name else zone
    return GenericActionResponse(status="ok", message=f"Record {rtype.value} deleted for {fqdn}")

@router.post("/network/request", response_model=NetworkResponse)
async def proxy_network_request(body: NetworkRequest, request: Request, cfg = Depends(get_cfg), gate = Depends(get_gate), provider = Depends(get_network)):
    price_map = {
        ProxyMode.DIRECT: cfg.payment.price_proxy_direct,
        ProxyMode.TOR: cfg.payment.price_proxy_tor,
        ProxyMode.I2P: cfg.payment.price_proxy_i2p,
        ProxyMode.YGGDRASIL: cfg.payment.price_proxy_yggdrasil,
    }
    amount = price_map[body.proxy_mode]

    mode_status = await provider.mode_status(body.proxy_mode)
    if not mode_status.available:
        reason = mode_status.reason or "network proxy mode unavailable"
        raise HTTPException(503, f"Proxy mode {body.proxy_mode.value} unavailable: {reason}")

    result = await gate.check_payment(
        request,
        amount=amount,
        description=f"Network Proxy Request ({body.proxy_mode.value}) to {body.url}",
        extra_body={
            "url": body.url,
            "proxy_mode": body.proxy_mode.value,
        }
    )

    if isinstance(result, Response):
        return result

    # payment valid, proceed
    resp = await provider.execute_request(body)
    
    if resp.error and resp.status_code in [400, 403]:
        raise HTTPException(resp.status_code, resp.error)
        
    return resp
from hyrule_cloud.db import CryptoIntentRow
from hyrule_cloud.models import CryptoIntentRequest, CryptoIntentResponse, CryptoIntentStatus
from hyrule_cloud.services.intents import (
    IntentExistsError,
    create_intent,
    get_intent_by_client_order_id,
)

# Intent states that carry no committed payment: a same-key replay only
# re-serves the deposit address. While the VM service is closed (simulation)
# such a replay must respect the closed-service guard rather than re-advertise a
# deposit for a VM that can't be real-provisioned. Every other state (settled,
# provisioning, or terminal recovery) always resolves so a deposit is never
# orphaned.
_INTENT_AWAITING_STATUSES = frozenset(
    {
        CryptoIntentStatus.CREATED,
        CryptoIntentStatus.WAITING_PAYMENT,
        CryptoIntentStatus.PENDING,
    }
)


def _intent_awaiting_payment(row: CryptoIntentRow) -> bool:
    """True only for intents with no funds in flight — safe to refuse while the
    VM service is closed.

    An awaiting-status intent can already carry an *unconfirmed* deposit: the
    poller records ``amount_received_crypto`` (and ``tx_hash``) before
    confirmations clear, keeping status at ``WAITING_PAYMENT`` (see
    ``services/intents.py``). Any received amount or tx hash means the customer
    has already sent crypto, so the replay must resolve rather than 503 — never
    strand a paid-but-unconfirmed deposit.
    """
    try:
        status = CryptoIntentStatus(row.status)
    except ValueError:
        return False
    if status not in _INTENT_AWAITING_STATUSES:
        return False
    # Funds already seen on-chain (even unconfirmed) make it recoverable.
    if getattr(row, "amount_received_crypto", None):
        return False
    return not getattr(row, "tx_hash", None)


def _intent_to_response(row: CryptoIntentRow, request: Request | None = None) -> CryptoIntentResponse:
    """Render a CryptoIntentRow as the public response. Builds management_url
    from request.base_url when the one-shot cleartext is present."""
    from hyrule_cloud.providers.native_crypto import NativeCryptoProvider

    qr_uri = None
    try:
        qr_uri = NativeCryptoProvider.build_uri(row.asset, row.address, row.amount_crypto)
    except Exception:
        pass

    mgmt_url = None
    if row.vm_id and row.anon_token_cleartext and request is not None:
        base = str(request.base_url).rstrip("/")
        mgmt_url = f"{base}/v1/vm/{row.vm_id}?token={row.anon_token_cleartext}"

    return CryptoIntentResponse(
        intent_id=row.intent_id,
        asset=row.asset,
        address=row.address,
        amount_crypto=str(row.amount_crypto),
        amount_usd=str(row.amount_usd) if row.amount_usd is not None else None,
        rate_snapshot=str(row.rate_snapshot) if row.rate_snapshot is not None else None,
        rate_valid_until=row.rate_valid_until,
        status=CryptoIntentStatus(row.status),
        confirmations=row.confirmations or 0,
        amount_received_crypto=(
            str(row.amount_received_crypto) if row.amount_received_crypto is not None else None
        ),
        qr_code_uri=qr_uri,
        expires_at=row.expires_at,
        vm_id=row.vm_id,
        management_token=row.anon_token_cleartext,
        management_url=mgmt_url,
    )


@router.post("/intent/create", response_model=CryptoIntentResponse)
async def create_crypto_intent(
    body: CryptoIntentRequest,
    request: Request,
    orch=Depends(get_orch),
    cfg=Depends(get_cfg),
    gate=Depends(get_gate),
    account=Depends(current_account),
) -> CryptoIntentResponse:
    """Block E: open a payment intent for BTC or XMR.

    Idempotent on `client_order_id`: repeated POSTs with the same key return
    the existing intent unchanged (no second deposit address is allocated).
    """
    asset = body.asset.upper()
    if asset not in ("BTC", "XMR"):
        raise HTTPException(400, "Unsupported asset. Use BTC or XMR.")

    # Idempotent replay FIRST: a retry with a known client_order_id must
    # return the original intent even if capacity/validation state changed
    # since — the deposit address may already be funded.
    existing_intent = (
        await get_intent_by_client_order_id(orch.db, body.client_order_id)
        if body.client_order_id
        else None
    )
    # A committed intent (funds received / provisioning / terminal recovery)
    # always resolves so a deposit is never orphaned — even after the VM service
    # closes. One still awaiting payment falls through to the guard below so a
    # closed service never re-issues a deposit address for a simulated VM.
    if existing_intent is not None and not _intent_awaiting_payment(existing_intent):
        return _intent_to_response(existing_intent, request)

    # Closed until real provisioning is enabled: don't hand out (or re-hand-out)
    # a deposit address for a VM we can only simulate.
    _require_vm_service_open(gate)

    if existing_intent is not None:
        return _intent_to_response(existing_intent, request)

    # Same validation as the x402 create path — including the real-mode OS
    # support check, so an unsupported order is rejected BEFORE a deposit
    # address is handed out, not after the customer's crypto settles.
    _validate_vm_order(body.order_payload, cfg)

    await _enforce_paid_vm_cap(orch, cfg)
    await _enforce_prefix_capacity(orch, cfg)
    total, _ = await _compute_vm_price(orch, cfg, body.order_payload)

    app_state: AppState = get_app_state(request)
    provider = getattr(app_state, "native_crypto", None)
    rates = getattr(app_state, "rate_provider", None)
    if provider is None or rates is None or asset not in _native_payment_assets(app_state):
        raise HTTPException(503, f"{asset} payments are not configured")

    try:
        row = await create_intent(
            session_factory=orch.db,
            provider=provider,
            rates=rates,
            asset=asset,
            order_payload=body.order_payload,
            amount_usd=total,
            client_order_id=body.client_order_id,
            owner_account_id=(account.account_id if account is not None else None),
        )
    except IntentExistsError as exc:
        # Idempotent replay: return the existing intent verbatim
        return _intent_to_response(exc.existing, request)
    except RuntimeError as exc:
        log.error("intent_create_failed", error=str(exc))
        raise HTTPException(503, "Could not create payment intent")

    return _intent_to_response(row, request)


@router.get("/intent/{intent_id}", response_model=CryptoIntentResponse)
async def get_crypto_intent_status(
    intent_id: str,
    request: Request,
    orch=Depends(get_orch),
    account=Depends(current_account),
) -> CryptoIntentResponse:
    """Returns current intent state. On the first GET after PROVISIONED, the
    one-shot `anon_token_cleartext` column is included in the response AND
    immediately nulled so subsequent GETs cannot re-reveal it."""
    async with orch.db() as session:
        row = await session.get(CryptoIntentRow, intent_id)
        if row is None:
            raise HTTPException(404, "Intent not found")
        # Account-owned intents are only visible to the owner (or admin) —
        # 404 (not 403) to avoid leaking existence.
        if row.owner_account_id is not None:
            if account is None or (
                account.account_id != row.owner_account_id and not account.is_admin
            ):
                raise HTTPException(404, "Intent not found")
        # One-shot reveal: atomically clear the token under a NOT NULL guard so
        # two concurrent GETs can't both reveal it. Only the caller whose UPDATE
        # actually matches a row (rowcount == 1) returns the cleartext we read
        # above; later callers match zero rows and respond without it. (Can't use
        # UPDATE ... RETURNING here — that returns the post-update NULL value.)
        revealed = row.anon_token_cleartext
        if revealed is not None:
            result = await session.execute(
                _sql_update(CryptoIntentRow)
                .where(
                    CryptoIntentRow.intent_id == intent_id,
                    CryptoIntentRow.anon_token_cleartext.is_not(None),
                )
                .values(anon_token_cleartext=None)
            )
            await session.commit()
            row.anon_token_cleartext = revealed if result.rowcount == 1 else None

    return _intent_to_response(row, request)
