"""
FastAPI routes for Hyrule Cloud API.

x402-gated endpoints use PaymentGate.check_payment() which returns
either a 402 Response or the payer's wallet address.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from hyrule_cloud.db import VMQuoteRow, VMRow
from hyrule_cloud.middleware.anon_token import (
    anon_management_token,
    can_manage_vm,
)
from hyrule_cloud.middleware.auth import current_account
from hyrule_cloud.models import (
    VM_SPECS,
    AcceptedPaymentMethods,
    DNSRecord,
    DNSRecordType,
    DomainCheckResponse,
    DomainMode,
    DomainRegisterRequest,
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
)
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


def get_orch(app_state: AppState = Depends(get_app_state)):
    return app_state.orchestrator

def get_cfg(app_state: AppState = Depends(get_app_state)):
    return app_state.config

def get_gate(app_state: AppState = Depends(get_app_state)):
    return app_state.payment_gate

def get_network(app_state: AppState = Depends(get_app_state)):
    return app_state.network_provider


# --- Quote helpers (issue #14) ---


def _accepted_payment_methods(cfg, app_state: AppState) -> AcceptedPaymentMethods:
    """Single source of truth for what a quote can be paid with: enabled EVM
    chains from config + native (BTC/XMR) iff the intent rail is wired."""
    evm = [
        QuoteEvmMethod(key=n.key, caip2=n.caip2, asset=n.asset, chain_id=n.chain_id)
        for n in cfg.payment.enabled_networks()
    ]
    native: list[str] = []
    if getattr(app_state, "native_crypto", None) and getattr(app_state, "rate_provider", None):
        native = ["BTC", "XMR"]
    return AcceptedPaymentMethods(evm=evm, native=native)


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
async def get_payment_networks(cfg = Depends(get_cfg)) -> dict:
    """Block C (Wave 3): the canonical list of supported payment chains.

    The frontend chain selector and any agent SDK that wants to know what
    chains we accept reads from here — NEVER hardcodes the list client-side
    (per feedback_verified_payment_chains.md). Operators can flip a chain
    off via Vault (PAYMENT_PAYMENT_NETWORKS__N__enabled=false) and the
    frontend picks it up on the next poll without a redeploy.

    Shape: `{ networks: [...], receiver_address, facilitator_url }`. Each
    network dict carries the CAIP-2 identifier (canonical for x402 v2), the
    EIP-712 domain shape (so the wallet adapter doesn't have to bake one
    in), and the explorer URL for the post-pay receipt link.
    """
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
        "receiver_address": cfg.payment.receiver_address,
        "facilitator_url": cfg.payment.facilitator_url,
    }


@router.get("/pricing", response_model=PricingResponse)
async def get_pricing(cfg = Depends(get_cfg)) -> PricingResponse:
    return PricingResponse(
        vm_prices={
            "xs (1vCPU/512MB/10GB)": f"${cfg.payment.price_vm_xs}/day",
            "sm (1vCPU/1GB/20GB)": f"${cfg.payment.price_vm_sm}/day",
            "md (2vCPU/2GB/40GB)": f"${cfg.payment.price_vm_md}/day",
            "lg (4vCPU/4GB/80GB)": f"${cfg.payment.price_vm_lg}/day",
        },
        domain_auto=f"$0.00 (subdomain under {cfg.deploy_domain})",
        vpn_per_day=f"${cfg.payment.price_vpn}/day",
        proxy_prices={
            "direct": f"${cfg.payment.price_proxy_direct}/request",
            "tor": f"${cfg.payment.price_proxy_tor}/request",
            "residential": f"${cfg.payment.price_proxy_residential}/request",
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
    templates = [
        OSTemplate(name=name, description=f"OS template: {name}", default=(name == "debian-13"))
        for name in cfg.xcpng.templates
    ]
    if not templates:
        templates = [
            OSTemplate(name="debian-13", description="Debian 13 (Trixie)", default=True),
            OSTemplate(name="alpine-3.21", description="Alpine Linux 3.21"),
            OSTemplate(name="freebsd-14", description="FreeBSD 14.2"),
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
    return VMPublicStatusResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        ipv6=row.ipv6,
        hostname=row.hostname,
        expires_at=row.expires_at,
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

    if order.domain_mode == DomainMode.CUSTOM and not order.domain:
        raise HTTPException(400, "domain required when domain_mode=custom")

    for port in order.open_ports:
        if port in cfg.blocked_ports:
            raise HTTPException(400, f"Port {port} is blocked by policy")

    # Price-lock: a quote-bound create charges the amount quoted to the user,
    # not a recomputation (which could drift). The breakdown is still recomputed
    # for the 402 body's informational cost_breakdown.
    computed, breakdown = orch.compute_price(order)
    total = quote_row.amount_usd if quote_row is not None else computed
    specs = VM_SPECS[order.size]

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
        return result

    wallet = result
    # Issue #14 / Sourcery (#16): claim the quote atomically BEFORE provisioning
    # so two concurrent paid creates for the same quote can't each provision a VM
    # — only the winner of the CREATED → CONSUMED flip proceeds.
    if quote_row is not None and not await claim_quote(orch.db, quote_row.quote_id):
        # Lost the race: another paid create already claimed the quote. Return the
        # VM it provisioned (idempotent); if it's still mid-provision, the caller
        # polls the status URL.
        latest = await get_quote(orch.db, quote_row.quote_id)
        if latest is not None and latest.vm_id:
            async with orch.db() as session:
                existing_vm = await session.get(VMRow, latest.vm_id)
            if existing_vm is not None:
                return _vm_create_response(existing_vm, request, management_token=None)
        raise HTTPException(409, "Quote is being provisioned; poll the VM status")

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
    account=Depends(current_account),
) -> Response:
    """Issue #14: price a VM order once and persist it as a durable quote.

    Returns a `quote_id` the UI/agent pays against — it survives review-page
    reloads and mobile wallet handoffs and locks the price for its TTL.
    Idempotent on `client_order_id`: same key + same spec returns the existing
    quote (200); same key + a different spec is a 409 conflict.
    """
    order = body.order_payload
    if order.domain_mode == DomainMode.CUSTOM and not order.domain:
        raise HTTPException(400, "domain required when domain_mode=custom")
    for port in order.open_ports:
        if port in cfg.blocked_ports:
            raise HTTPException(400, f"Port {port} is blocked by policy")

    total, _ = orch.compute_price(order)
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
async def check_domain(name: str, extension: str, orch = Depends(get_orch)) -> DomainCheckResponse:
    """Check if a DNS zone (domain) is available for purchase."""
    check = await orch.openprovider.check_domain(name, extension)
    return DomainCheckResponse(
        domain=f"{name}.{extension}",
        available=(check.get("status") == "free"),
        price=str(check.get("price")) if check.get("price") else None,
    )


@router.post("/domain/register", response_model=GenericActionResponse)
async def register_domain(body: DomainRegisterRequest, name: str, extension: str, ipv6: str | None = None, request: Request=None, orch = Depends(get_orch), cfg = Depends(get_cfg), gate = Depends(get_gate)):
    """
    Buy a DNS zone: register the domain via Openprovider and create an
    authoritative DNS zone. After purchase, the agent can manage records
    via POST /v1/zone/record and DELETE /v1/zone/record.
    """
    if not name or not extension:
        raise HTTPException(400, "name and extension required")

    check = await orch.openprovider.check_domain(name, extension)
    if check["status"] != "free":
        raise HTTPException(409, f"Domain {name}.{extension} is not available")

    op_price = check.get("price") or Decimal("10")
    total = op_price + cfg.payment.price_domain_markup

    result = await gate.check_payment(
        request,
        amount=total,
        description=f"Register domain {name}.{extension}",
        extra_body={
            "domain": f"{name}.{extension}",
            "registrar_cost": str(op_price),
            "markup": str(cfg.payment.price_domain_markup),
        },
    )

    if isinstance(result, Response):
        return result

    try:
        await orch.openprovider.register_domain(name, extension)
    except Exception as e:
        log.error("domain_registration_failed", error=str(e))
        raise HTTPException(500, f"Domain registration failed: {e}")

    fqdn = f"{name}.{extension}"
    try:
        await orch.openprovider.create_zone(fqdn)
    except Exception:
        log.warning("zone_create_fallback", zone=fqdn)
        
    if ipv6:
        await orch.dns.create_record(fqdn, "AAAA", ipv6)

    return GenericActionResponse(status="ok", message=f"Domain {fqdn} registered")


@router.post("/zone/record", response_model=GenericActionResponse)
async def create_zone_record(zone: str, body: DNSRecord, orch = Depends(get_orch)) -> GenericActionResponse:
    """Create a DNS record in a zone managed by Hyrule Cloud."""
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
    orch = Depends(get_orch),
):
    """Delete a DNS record from a zone managed by Hyrule Cloud."""
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
        ProxyMode.RESIDENTIAL: cfg.payment.price_proxy_residential,
    }
    amount = price_map[body.proxy_mode]

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
    
    if resp.error and resp.status_code in [400, 403, 501]:
        raise HTTPException(resp.status_code, resp.error)
        
    return resp

from sqlalchemy import update as _sql_update

from hyrule_cloud.db import CryptoIntentRow
from hyrule_cloud.models import CryptoIntentRequest, CryptoIntentResponse, CryptoIntentStatus
from hyrule_cloud.services.intents import IntentExistsError, create_intent


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
    account=Depends(current_account),
) -> CryptoIntentResponse:
    """Block E: open a payment intent for BTC or XMR.

    Idempotent on `client_order_id`: repeated POSTs with the same key return
    the existing intent unchanged (no second deposit address is allocated).
    """
    asset = body.asset.upper()
    if asset not in ("BTC", "XMR"):
        raise HTTPException(400, "Unsupported asset. Use BTC or XMR.")

    if body.order_payload.domain_mode.value == "custom" and not body.order_payload.domain:
        raise HTTPException(400, "domain required when domain_mode=custom")
    for port in body.order_payload.open_ports:
        if port in cfg.blocked_ports:
            raise HTTPException(400, f"Port {port} is blocked by policy")

    total, _ = orch.compute_price(body.order_payload)

    app_state: AppState = get_app_state(request)
    provider = getattr(app_state, "native_crypto", None)
    rates = getattr(app_state, "rate_provider", None)
    if provider is None or rates is None:
        raise HTTPException(503, "Native crypto provider not configured")

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
