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
        domain_auto="$0.00 (subdomain under deploy.hyrule.cloud)",
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
