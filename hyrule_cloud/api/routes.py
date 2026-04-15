"""
FastAPI routes for Hyrule Cloud API.

x402-gated endpoints use PaymentGate.check_payment() which returns
either a 402 Response or the payer's wallet address.
"""

from __future__ import annotations

from decimal import Decimal

import structlog
from fastapi import APIRouter, HTTPException, Request, Response

from hyrule_cloud.middleware.x402 import PaymentGate
from hyrule_cloud.models import (
    VM_SPECS,
    DomainMode,
    FirewallState,
    OSListResponse,
    OSTemplate,
    PricingResponse,
    VMCreateRequest,
    VMCreateResponse,
    VMExtendRequest,
    VMSize,
    VMStatus,
    VMStatusResponse,
)

log = structlog.get_logger()

router = APIRouter(prefix="/v1")


def _orch(request: Request):
    return request.app.state.orchestrator


def _cfg(request: Request):
    return request.app.state.config


def _gate(request: Request) -> PaymentGate:
    return request.app.state.payment_gate


# --- Free endpoints ---


@router.get("/pricing", response_model=PricingResponse)
async def get_pricing(request: Request) -> PricingResponse:
    cfg = _cfg(request)
    return PricingResponse(
        vm_prices={
            "xs (1vCPU/512MB/10GB)": f"${cfg.payment.price_vm_xs}/day",
            "sm (1vCPU/1GB/20GB)": f"${cfg.payment.price_vm_sm}/day",
            "md (2vCPU/2GB/40GB)": f"${cfg.payment.price_vm_md}/day",
            "lg (4vCPU/4GB/80GB)": f"${cfg.payment.price_vm_lg}/day",
        },
        domain_auto="$0.00 (subdomain under deploy.servify.network)",
        vpn_per_day=f"${cfg.payment.price_vpn}/day",
    )


@router.get("/os/list", response_model=OSListResponse)
async def list_os_templates(request: Request) -> OSListResponse:
    cfg = _cfg(request)
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
async def get_vm_status(vm_id: str, request: Request) -> VMStatusResponse:
    row = await _orch(request).get_vm(vm_id)
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


@router.get("/vm/{vm_id}/logs")
async def get_vm_logs(vm_id: str, request: Request):
    row = await _orch(request).get_vm(vm_id)
    if not row:
        raise HTTPException(404, "VM not found")
    return {
        "vm_id": vm_id,
        "status": row.status,
        "events": [
            {"ts": row.created_at.isoformat(), "event": "provisioning_started"},
        ],
        "error": row.error,
    }


# --- x402-gated endpoints ---


@router.post("/vm/create")
async def create_vm(body: VMCreateRequest, request: Request):
    orch = _orch(request)
    cfg = _cfg(request)
    gate = _gate(request)

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
async def extend_vm(vm_id: str, body: VMExtendRequest, request: Request):
    orch = _orch(request)
    cfg = _cfg(request)
    gate = _gate(request)

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


@router.post("/vm/{vm_id}/reboot")
async def reboot_vm(vm_id: str, request: Request):
    if not await _orch(request).reboot_vm(vm_id):
        raise HTTPException(404, "VM not found or not running")
    return {"vm_id": vm_id, "status": "rebooting"}


@router.delete("/vm/{vm_id}")
async def destroy_vm(vm_id: str, request: Request):
    if not await _orch(request).destroy_vm(vm_id):
        raise HTTPException(404, "VM not found")
    return {"vm_id": vm_id, "status": "destroyed"}


@router.get("/domain/check")
async def check_domain(name: str, extension: str, request: Request):
    return await _orch(request).openprovider.check_domain(name, extension)


@router.post("/domain/register")
async def register_domain(request: Request):
    cfg = _cfg(request)
    orch = _orch(request)
    gate = _gate(request)

    body = await request.json()
    name = body.get("name")
    extension = body.get("extension")
    ipv6 = body.get("ipv6")

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

    await orch.openprovider.register_domain(name, extension)

    if ipv6:
        fqdn = f"{name}.{extension}"
        await orch.dns.create_record(fqdn, "AAAA", ipv6)

    return {
        "domain": f"{name}.{extension}",
        "status": "registered",
        "nameservers": cfg.openprovider.nameservers,
        "tx_hash": getattr(request.state, "payment_tx", None),
    }


# --- DNS Zone endpoints ---


@router.get("/zone/check")
async def check_zone(name: str, extension: str, request: Request):
    """Check if a DNS zone (domain) is available for purchase."""
    orch = _orch(request)
    check = await orch.openprovider.check_domain(name, extension)
    return {
        "zone": f"{name}.{extension}",
        "status": check["status"],
        "price": str(check.get("price")) if check.get("price") else None,
        "is_premium": check.get("is_premium", False),
        "currency": check.get("currency", "USD"),
    }


@router.post("/zone/buy")
async def buy_zone(request: Request):
    """
    Buy a DNS zone: register the domain via Openprovider and create an
    authoritative DNS zone. After purchase, the agent can manage records
    via POST /v1/zone/record and DELETE /v1/zone/record.
    """
    cfg = _cfg(request)
    orch = _orch(request)
    gate = _gate(request)

    body = await request.json()
    name = body.get("name")
    extension = body.get("extension")

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
        description=f"Buy DNS zone {name}.{extension}",
        extra_body={
            "zone": f"{name}.{extension}",
            "registrar_cost": str(op_price),
            "markup": str(cfg.payment.price_domain_markup),
            "includes": "domain registration + authoritative DNS zone",
        },
    )

    if isinstance(result, Response):
        return result

    # Register the domain with our nameservers
    await orch.openprovider.register_domain(name, extension)

    # Create DNS zone on Openprovider
    fqdn = f"{name}.{extension}"
    try:
        await orch.openprovider.create_zone(fqdn)
    except Exception:
        log.warning("zone_create_fallback", zone=fqdn, exc_info=True)
        # Zone may already exist if domain was previously registered

    return {
        "zone": fqdn,
        "status": "active",
        "nameservers": cfg.openprovider.nameservers,
        "tx_hash": getattr(request.state, "payment_tx", None),
    }


@router.post("/zone/record")
async def create_zone_record(request: Request):
    """Create a DNS record in a zone managed by Hyrule Cloud."""
    orch = _orch(request)

    body = await request.json()
    zone = body.get("zone")
    name = body.get("name", "")
    rtype = body.get("type")
    value = body.get("value")
    ttl = body.get("ttl", 300)

    if not zone or not rtype or not value:
        raise HTTPException(400, "zone, type, and value are required")

    # Validate record type
    allowed_types = {"A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"}
    if rtype.upper() not in allowed_types:
        raise HTTPException(400, f"Unsupported record type: {rtype}. Allowed: {allowed_types}")

    try:
        prio = body.get("prio") or body.get("priority")
        await orch.openprovider.create_zone_record(
            zone_name=zone,
            name=name,
            rtype=rtype.upper(),
            value=value,
            ttl=ttl,
            prio=int(prio) if prio is not None else None,
        )
    except Exception as e:
        log.error("zone_record_create_failed", zone=zone, error=str(e), exc_info=True)
        raise HTTPException(500, f"Failed to create record: {e}")

    fqdn = f"{name}.{zone}" if name else zone
    return {
        "fqdn": fqdn,
        "type": rtype.upper(),
        "value": value,
        "ttl": ttl,
        "status": "created",
    }


@router.delete("/zone/record")
async def delete_zone_record(
    zone: str,
    name: str,
    type: str,
    request: Request,
):
    """Delete a DNS record from a zone managed by Hyrule Cloud."""
    orch = _orch(request)

    allowed_types = {"A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"}
    if type.upper() not in allowed_types:
        raise HTTPException(400, f"Unsupported record type: {type}. Allowed: {allowed_types}")

    try:
        await orch.openprovider.delete_zone_record(
            zone_name=zone,
            name=name,
            rtype=type.upper(),
        )
    except Exception as e:
        log.error("zone_record_delete_failed", zone=zone, error=str(e), exc_info=True)
        raise HTTPException(500, f"Failed to delete record: {e}")

    fqdn = f"{name}.{zone}" if name else zone
    return {
        "fqdn": fqdn,
        "type": type.upper(),
        "status": "deleted",
    }
