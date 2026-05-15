"""
FastAPI routes for Hyrule Cloud API.

x402-gated endpoints use PaymentGate.check_payment() which returns
either a 402 Response or the payer's wallet address.
"""

from __future__ import annotations

from decimal import Decimal

import structlog
from fastapi import APIRouter, HTTPException, Request, Response, Depends

from hyrule_cloud.middleware.x402 import PaymentGate
from hyrule_cloud.state import get_app_state, AppState
from hyrule_cloud.models import (
    VM_SPECS,
    DomainMode,
    FirewallState,
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
    GenericActionResponse,
    DomainCheckResponse,
    DomainRegisterRequest,
    DNSRecord,
    DNSRecordType,
    VMSize,
    VMStatus,
    VMStatusResponse,
)

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


# --- Free endpoints ---


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


@router.get("/vm/{vm_id}", response_model=VMStatusResponse)
async def get_vm_status(vm_id: str, orch = Depends(get_orch)) -> VMStatusResponse:
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")

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
async def get_vm_logs(vm_id: str, orch = Depends(get_orch)) -> VMLogsResponse:
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
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
async def create_vm(body: VMCreateRequest, request: Request, orch = Depends(get_orch), cfg = Depends(get_cfg), gate = Depends(get_gate)):
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
    row = await orch.create_vm(body, owner_wallet=wallet)
    row.payment_tx = getattr(request.state, "payment_tx", None)

    base_url = str(request.base_url).rstrip("/")
    return VMCreateResponse(
        vm_id=row.vm_id,
        status=VMStatus(row.status),
        status_url=f"{base_url}/v1/vm/{row.vm_id}",
        estimated_ready_seconds=60,
    )


@router.post("/vm/{vm_id}/extend")
async def extend_vm(vm_id: str, body: VMExtendRequest, request: Request, orch = Depends(get_orch), cfg = Depends(get_cfg), gate = Depends(get_gate)):
    row = await orch.get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")

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
async def reboot_vm(vm_id: str, orch = Depends(get_orch)) -> GenericActionResponse:
    if not await orch.reboot_vm(vm_id):
        raise HTTPException(404, "VM not found or not running")
    return GenericActionResponse(status="ok", message=f"VM {vm_id} is rebooting")


@router.delete("/vm/{vm_id}", response_model=GenericActionResponse)
async def destroy_vm(vm_id: str, orch = Depends(get_orch)) -> GenericActionResponse:
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
    from hyrule_cloud.models import DNSRecordType
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

from hyrule_cloud.models import CryptoIntentRequest, CryptoIntentResponse, CryptoIntentStatus
from hyrule_cloud.db import CryptoIntentRow
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import uuid

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
        
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=60)
    
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
