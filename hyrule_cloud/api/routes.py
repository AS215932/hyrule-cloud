"""
FastAPI routes for Hyrule Cloud API.

x402-gated endpoints use PaymentGate.check_payment() which returns
either a 402 Response or the payer's wallet address.
"""

from __future__ import annotations

from decimal import Decimal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from hyrule_cloud.middleware.anon_token import (
    anon_management_token,
    can_manage_vm,
)
from hyrule_cloud.middleware.auth import current_account
from hyrule_cloud.models import (
    VM_SPECS,
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
    VMExtendRequest,
    VMLogEvent,
    VMLogsResponse,
    VMPublicStatusResponse,
    VMSize,
    VMStatus,
    VMStatusResponse,
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
    row, management_token = await orch.create_vm(
        body, owner_wallet=wallet,
        owner_account_id=account.account_id if account else None,
    )
    row.payment_tx = getattr(request.state, "payment_tx", None)

    base_url = str(request.base_url).rstrip("/")
    # Block A0: status_url is the public sanitized view; management_url
    # embeds the one-time anon token. UI must surface management_url
    # prominently with a save-this-once warning — it cannot be retrieved
    # again.
    return VMCreateResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        status_url=f"{base_url}/v1/vm/{row.vm_id}/status",
        estimated_ready_seconds=60,
        management_token=management_token,
        management_url=(
            f"{base_url}/v1/vm/{row.vm_id}?token={management_token}"
        ),
    )


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

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from hyrule_cloud.db import CryptoIntentRow
from hyrule_cloud.models import CryptoIntentRequest, CryptoIntentResponse, CryptoIntentStatus


@router.post("/intent/create", response_model=CryptoIntentResponse)
async def create_crypto_intent(body: CryptoIntentRequest, orch = Depends(get_orch), cfg = Depends(get_cfg)):
    if body.asset.upper() not in ["BTC", "XMR", "ZEC"]:
        raise HTTPException(400, "Unsupported asset. Use BTC, XMR, or ZEC.")
    
    amount_usd = Decimal(body.amount_usd)
    from hyrule_cloud.providers.native_crypto import NativeCryptoProvider
    provider = NativeCryptoProvider(cfg)
    rate = provider.get_exchange_rate(body.asset)
    amount_crypto = amount_usd / rate
    
    intent_id = str(uuid.uuid4())
    bip32_index = None
    if body.asset.upper() == "BTC":
        async with orch.db() as session:
            # Simple simulation for MAX index logic
            from sqlalchemy import func
            res = await session.execute(select(func.max(CryptoIntentRow.bip32_index)).where(CryptoIntentRow.asset == "BTC"))
            max_idx = res.scalar() or 0
            bip32_index = max_idx + 1
        address = provider.generate_btc_address(bip32_index)
    elif body.asset.upper() == "XMR":
        address, bip32_index = provider.generate_xmr_address()
        
    expires_at = datetime.now(UTC) + timedelta(minutes=60)
    
    row = CryptoIntentRow(
        intent_id=intent_id,
        asset=body.asset.upper(),
        amount_usd=amount_usd,
        amount_crypto=amount_crypto,
        address=address,
        bip32_index=bip32_index,
        expires_at=expires_at,
        status=CryptoIntentStatus.PENDING
    )
    
    async with orch.db() as session:
        session.add(row)
        await session.commit()
    
    return CryptoIntentResponse(
        intent_id=row.intent_id,
        asset=row.asset,
        amount_crypto=str(row.amount_crypto),
        address=row.address,
        status=CryptoIntentStatus.PENDING,
        expires_at=row.expires_at
    )

@router.get("/intent/{intent_id}", response_model=CryptoIntentResponse)
async def get_crypto_intent_status(intent_id: str, orch = Depends(get_orch)):
    async with orch.db() as session:
        q = select(CryptoIntentRow).where(CryptoIntentRow.intent_id == intent_id)
        res = await session.execute(q)
        row = res.scalar_one_or_none()
    
    if not row:
        raise HTTPException(404, "Intent not found")
        
    return CryptoIntentResponse(
        intent_id=row.intent_id,
        asset=row.asset,
        amount_crypto=str(row.amount_crypto),
        address=row.address,
        status=CryptoIntentStatus(row.status),
        expires_at=row.expires_at
    )
