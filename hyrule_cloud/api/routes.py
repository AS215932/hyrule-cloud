"""
FastAPI routes for Hyrule Cloud API.

x402-gated endpoints use PaymentGate.check_payment() which returns
either a 402 Response or the payer's wallet address.
"""

from __future__ import annotations

from datetime import UTC
from decimal import Decimal
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response

from hyrule_cloud.db import AccountRow, VMRow
from hyrule_cloud.middleware.auth import current_account, enforce_api_key_scope
from hyrule_cloud.models import (
    VM_SPECS,
    ApiKeyScope,
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
    VMCreateRequest,
    VMCreateResponse,
    VMDetailResponse,
    VMExtendRequest,
    VMLogEvent,
    VMLogsResponse,
    VMPublicStatusResponse,
    VMSize,
    VMStatus,
    verify_anon_management_token,
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


# --- Authorization helpers ---
#
# Two concepts, never collapsed: view (sanitized public status) vs management
# (logs, reboot, extend, delete, full detail). See feedback_security_split.md.
#
# A0 introduced these with the `account` parameter stubbed. A1 wires it for
# real via the `current_account` FastAPI dependency.


def can_view_public_status(vm: VMRow, account: AccountRow | None = None) -> bool:
    """Sanitized status view: vm_id, status, OS, expiry, hostname, IPv6, ssh hint."""
    if getattr(vm, "owner_account_id", None) is None:
        return True
    if account is None:
        return False
    return (
        account.account_id == vm.owner_account_id
        or bool(account.is_admin)
    )


def can_manage_vm(
    vm: VMRow,
    account: AccountRow | None = None,
    anon_token: str | None = None,
) -> bool:
    """Destructive or revealing: logs, reboot, extend, delete, full detail."""
    if account is not None and (
        account.account_id == getattr(vm, "owner_account_id", None)
        or bool(account.is_admin)
    ):
        return True
    # Anon-ownerless VM: management requires the one-time token issued at create.
    # Legacy VMs (anon_management_token_hash IS NULL) cannot be managed until claimed.
    if getattr(vm, "owner_account_id", None) is None:
        return verify_anon_management_token(anon_token, vm.anon_management_token_hash)
    return False


def anon_management_token_dep(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> str | None:
    """Extract a hyr_vm_ token from Authorization: Bearer ... or ?token=...

    Returns None if no token is present or if the bearer is not a hyr_vm_ token
    (we ignore other bearer schemes here; auth bearers like hyr_sk_ are
    handled by the account-auth dependency in A1).
    """
    if token and token.startswith("hyr_vm_"):
        return token
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value.startswith("hyr_vm_"):
            return value
    return None


# --- Free endpoints ---


@router.get("/payments/networks")
async def get_payment_networks(cfg = Depends(get_cfg)):
    """Block C: single source of truth for the chain selector.

    The frontend MUST read this rather than hardcoding networks client-side
    (see feedback_verified_payment_chains.md). New chains land here only
    after scripts/verify_facilitator.py passes against their facilitator URL.

    Block H: EVM-only fields (chain_id, eip712_domain) are omitted for SVM
    entries; the `family` field tells payment.js which adapter to dispatch to.
    """
    def _network_json(n):
        entry = {
            "key": n.key,
            "display_name": n.display_name,
            "caip2": n.caip2,
            "family": n.family,
            "asset": n.asset,
            "token_address": n.token_address,
            "token_decimals": n.token_decimals,
            "rpc_url": n.rpc_url,
            "block_explorer_url": n.block_explorer_url,
            "testnet": n.testnet,
        }
        if n.family == "evm":
            entry["chain_id"] = n.chain_id
            entry["eip712_domain"] = {
                "name": n.eip712_domain_name,
                "version": n.eip712_domain_version,
            }
        return entry

    return {
        "networks": [_network_json(n) for n in cfg.payment.networks],
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


# --- Block B: live runtime metrics ---
#
# Per-process p50 (from middleware/metrics.py), plus DB counts and an avg
# provision time computed over the most recent N READY rows. Wrapped in a
# 20s in-process TTL cache so the homepage can poll without thrashing the
# DB. The `api_p50_source` field labels the latency number as per-process,
# not fleet-wide; a real Prometheus-backed fleet metric is plan Block H.


_RUNTIME_CACHE: dict[str, object] = {"value": None, "expires_at": 0.0}
_RUNTIME_TTL_SECONDS = 20
_RECENT_READY_SAMPLE = 50


@router.get("/stats/runtime")
async def get_runtime_stats(request: Request):
    import time as _time
    from datetime import datetime as _dt

    from sqlalchemy import func as _func
    from sqlalchemy import select as _select

    now = _time.time()
    cached = _RUNTIME_CACHE.get("value")
    if cached is not None and now < float(_RUNTIME_CACHE["expires_at"]):
        return cached

    app_state: AppState = request.app.state._typed_state
    recorder = getattr(request.app.state, "metrics", None)

    # Latency: per-process rolling-window p50. None when there are no samples
    # yet (cold start) — frontend will substitute a fallback.
    api_p50 = recorder.percentile(0.5) if recorder is not None else None
    sample_count = recorder.sample_count() if recorder is not None else 0

    # Counts + avg-provision computed in one short transaction.
    sess_factory = getattr(app_state, "session_factory", None)
    if sess_factory is None and hasattr(app_state, "orchestrator"):
        sess_factory = getattr(app_state.orchestrator, "db", None)

    live_vms = 0
    build_queue = 0
    avg_provision_seconds: int | None = None

    if sess_factory is not None:
        async with sess_factory() as session:
            # live = anything not destroyed and not failed
            live_q = await session.execute(
                _select(_func.count()).select_from(VMRow).where(
                    VMRow.status.notin_([VMStatus.DESTROYED, VMStatus.FAILED])
                )
            )
            live_vms = int(live_q.scalar() or 0)

            queue_q = await session.execute(
                _select(_func.count()).select_from(VMRow).where(
                    VMRow.status == VMStatus.PROVISIONING
                )
            )
            build_queue = int(queue_q.scalar() or 0)

            # Avg over the most recent N rows that actually carry a
            # provisioned_at timestamp. Older legacy rows without the column
            # set simply don't contribute.
            recent_q = await session.execute(
                _select(VMRow.created_at, VMRow.provisioned_at)
                .where(VMRow.provisioned_at.isnot(None))
                .order_by(VMRow.provisioned_at.desc())
                .limit(_RECENT_READY_SAMPLE)
            )
            durations: list[float] = []
            for created_at, provisioned_at in recent_q.all():
                if created_at is None or provisioned_at is None:
                    continue
                delta = (provisioned_at - created_at).total_seconds()
                if delta > 0:
                    durations.append(delta)
            if durations:
                avg_provision_seconds = int(round(sum(durations) / len(durations)))

    body = {
        "api_p50_ms": api_p50,
        "api_p50_source": "api-process-local-rolling-window",
        "api_p50_sample_count": sample_count,
        "build_queue": build_queue,
        "live_vms": live_vms,
        "avg_provision_seconds": avg_provision_seconds,
        "updated_at": _dt.now(UTC).isoformat(),
    }
    _RUNTIME_CACHE["value"] = body
    _RUNTIME_CACHE["expires_at"] = now + _RUNTIME_TTL_SECONDS
    return body


# --- Block H: live fleet network stats from Prometheus on the `mon` VM ---
#
# Reads BGP peer / prefix / NAT64 metrics from the central Prometheus and
# falls back to a static shape (with _source="fallback") if the scrape target
# is unreachable, so the public /transparency page never serves a 500.
# 30s TTL is enough — these change on the order of minutes.

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
    import time as _time
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
        bgp = await client.query_scalar('count(bgp_peer_state == 1)')
        if bgp is None:
            # FRR exporter alternative metric name
            bgp = await client.query_scalar('count(frr_bgp_peer_state{state="Established"})')
        prefixes = await client.query_scalar('count(count by (prefix) (bgp_prefix_received))')
        nat64 = await client.query_scalar('sum(nat64_sessions_active)')

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


@router.get("/vm/{vm_id}/status", response_model=VMPublicStatusResponse)
async def get_vm_public_status(
    vm_id: str,
    request: Request,
    orch = Depends(get_orch),
    account: AccountRow | None = Depends(current_account),
) -> VMPublicStatusResponse:
    """Public sanitized status. Anon-owned VMs are visible by vm_id (preserves
    one-shot anon checkout UX). Account-owned VMs require the owning account —
    to a non-owner the response is indistinguishable from a missing VM.
    """
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    if not can_view_public_status(row, account=account):
        # 404 not 403 — do not leak existence of account-owned VMs
        raise HTTPException(404, "VM not found")
    enforce_api_key_scope(request, ApiKeyScope.VM_READ.value)

    is_ready = row.hostname and row.status == VMStatus.READY
    return VMPublicStatusResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        os=row.os,
        ipv6=row.ipv6,
        hostname=row.hostname,
        ssh=f"ssh root@{row.hostname}" if is_ready else None,
        expires_at=row.expires_at,
        error=row.error,
    )


@router.get("/vm/{vm_id}", response_model=VMDetailResponse)
async def get_vm_detail(
    vm_id: str,
    request: Request,
    orch = Depends(get_orch),
    anon_token: str | None = Depends(anon_management_token_dep),
    account: AccountRow | None = Depends(current_account),
) -> VMDetailResponse:
    """Full VM detail. Management-gated. Anon VMs require the one-time token,
    account-owned VMs require the matching session/API key.

    Legacy VMs (no anon_management_token_hash) return 404 — they must be claimed
    via the A1 claim flow to regain management visibility.
    """
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    if not can_manage_vm(row, account=account, anon_token=anon_token):
        raise HTTPException(404, "VM not found")
    # Detail view is a management read. vm:read is sufficient; we treat the
    # extra fields (firewall, pubkey, payment_tx) as "details for owners",
    # not as separately-scoped data.
    enforce_api_key_scope(request, ApiKeyScope.VM_READ.value)

    firewall = None
    if row.open_ports:
        firewall = FirewallState(inbound_allow=list(row.open_ports))

    is_ready = row.hostname and row.status == VMStatus.READY
    is_legacy = row.anon_management_token_hash is None and getattr(row, "owner_account_id", None) is None

    return VMDetailResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        os=row.os,
        ipv6=row.ipv6,
        hostname=row.hostname,
        ssh=f"ssh root@{row.hostname}" if is_ready else None,
        ssh_pubkey=row.ssh_pubkey or None,
        expires_at=row.expires_at,
        created_at=row.created_at,
        firewall=firewall,
        error=row.error,
        cost_total=f"${row.cost_total}" if row.cost_total is not None else None,
        owner_wallet=row.owner_wallet or None,
        payment_tx=row.payment_tx,
        has_anon_management_token=row.anon_management_token_hash is not None,
        is_legacy=is_legacy,
    )


@router.get("/vm/{vm_id}/logs", response_model=VMLogsResponse)
async def get_vm_logs(
    vm_id: str,
    request: Request,
    orch = Depends(get_orch),
    anon_token: str | None = Depends(anon_management_token_dep),
    account: AccountRow | None = Depends(current_account),
) -> VMLogsResponse:
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    if not can_manage_vm(row, account=account, anon_token=anon_token):
        raise HTTPException(404, "VM not found")
    enforce_api_key_scope(request, ApiKeyScope.VM_LOGS.value)
    return VMLogsResponse(
        vm_id=vm_id,
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
    account: AccountRow | None = Depends(current_account),
):
    # vm:create gate runs before payment so an under-scoped key 403s without
    # ever being asked to settle x402. (The plan's x402-vs-key model: key
    # proves "this account"; x402 proves "you paid". Both still required.)
    enforce_api_key_scope(request, ApiKeyScope.VM_CREATE.value)

    if body.domain_mode == DomainMode.CUSTOM and not body.domain:
        raise HTTPException(400, "domain required when domain_mode=custom")

    for port in body.open_ports:
        if port in cfg.blocked_ports:
            raise HTTPException(400, f"Port {port} is blocked by policy")

    total, breakdown = orch.compute_price(body)
    specs = VM_SPECS[body.size]

    result = await gate.check_payment(
        request,
        amount=total,
        description=f"Hyrule Cloud VM ({body.size.value}) for {body.duration_days} days",
        extra_body={
            "cost_breakdown": breakdown.model_dump(),
            "specs": {**specs, "ipv6": True, "ipv4": False, "region": "eu-west"},
            "estimated_provision_time_seconds": 60,
        },
    )

    if isinstance(result, Response):
        return result

    wallet = result
    row, anon_token = await orch.create_vm(
        body,
        owner_wallet=wallet,
        owner_account_id=(account.account_id if account is not None else None),
    )
    row.payment_tx = getattr(request.state, "payment_tx", None)

    base_url = str(request.base_url).rstrip("/")
    # Logged-in orders don't need an anon token — the dashboard is the management surface.
    # We only return the token to anon orders so the user can save it.
    if account is not None:
        return VMCreateResponse(
            vm_id=row.vm_id,
            status=VMStatus(row.status),
            status_url=f"{base_url}/v1/vm/{row.vm_id}/status",
            estimated_ready_seconds=60,
        )
    return VMCreateResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        status_url=f"{base_url}/v1/vm/{row.vm_id}/status",
        management_token=anon_token,
        management_url=f"{base_url}/v1/vm/{row.vm_id}?token={anon_token}",
        estimated_ready_seconds=60,
    )


@router.post("/vm/{vm_id}/extend")
async def extend_vm(
    vm_id: str,
    body: VMExtendRequest,
    request: Request,
    orch = Depends(get_orch),
    cfg = Depends(get_cfg),
    gate = Depends(get_gate),
    anon_token: str | None = Depends(anon_management_token_dep),
    account: AccountRow | None = Depends(current_account),
):
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    # Require management proof (account session OR anon token) BEFORE accepting
    # payment. Otherwise a stranger could pay to keep a malicious VM alive.
    if not can_manage_vm(row, account=account, anon_token=anon_token):
        raise HTTPException(404, "VM not found")
    enforce_api_key_scope(request, ApiKeyScope.VM_EXTEND.value)

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
    request: Request,
    orch = Depends(get_orch),
    anon_token: str | None = Depends(anon_management_token_dep),
    account: AccountRow | None = Depends(current_account),
) -> GenericActionResponse:
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    if not can_manage_vm(row, account=account, anon_token=anon_token):
        raise HTTPException(404, "VM not found")
    enforce_api_key_scope(request, ApiKeyScope.VM_POWER.value)
    if not await orch.reboot_vm(vm_id):
        raise HTTPException(404, "VM not found or not running")
    return GenericActionResponse(status="ok", message=f"VM {vm_id} is rebooting")


@router.delete("/vm/{vm_id}", response_model=GenericActionResponse)
async def destroy_vm(
    vm_id: str,
    request: Request,
    orch = Depends(get_orch),
    anon_token: str | None = Depends(anon_management_token_dep),
    account: AccountRow | None = Depends(current_account),
) -> GenericActionResponse:
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    if not can_manage_vm(row, account=account, anon_token=anon_token):
        raise HTTPException(404, "VM not found")
    enforce_api_key_scope(request, ApiKeyScope.VM_DESTROY.value)
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


# --- Block E: native crypto intents (BTC / XMR) ---

from sqlalchemy import update as _sql_update  # noqa: E402

from hyrule_cloud.db import CryptoIntentRow  # noqa: E402
from hyrule_cloud.models import (  # noqa: E402
    CryptoIntentRequest,
    CryptoIntentResponse,
    CryptoIntentStatus,
)
from hyrule_cloud.services.intents import IntentExistsError, create_intent  # noqa: E402


def _intent_to_response(row: CryptoIntentRow, request: Request | None = None) -> CryptoIntentResponse:
    """Render a CryptoIntentRow as the public response. Builds management_url
    from request.base_url when the one-shot cleartext is present."""
    from hyrule_cloud.providers.native_crypto import NativeCryptoProvider as _NCP

    qr_uri = None
    try:
        qr_uri = _NCP.build_uri(row.asset, row.address, row.amount_crypto)
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
    orch = Depends(get_orch),
    cfg = Depends(get_cfg),
    account: AccountRow | None = Depends(current_account),
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
    orch = Depends(get_orch),
    account: AccountRow | None = Depends(current_account),
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
        # One-shot reveal: snapshot cleartext, then NULL it.
        revealed = row.anon_token_cleartext
        if revealed is not None:
            await session.execute(
                _sql_update(CryptoIntentRow)
                .where(CryptoIntentRow.intent_id == intent_id)
                .values(anon_token_cleartext=None)
            )
            await session.commit()
            row.anon_token_cleartext = revealed  # local copy for the response

    return _intent_to_response(row, request)
