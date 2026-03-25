"""
Domain models for Hyrule Cloud resources.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field

# --- Enums ---


class VMSize(enum.StrEnum):
    XS = "xs"  # 1 vCPU, 512 MB, 10 GB
    SM = "sm"  # 1 vCPU, 1 GB, 20 GB
    MD = "md"  # 2 vCPU, 2 GB, 40 GB
    LG = "lg"  # 4 vCPU, 4 GB, 80 GB


class VMStatus(enum.StrEnum):
    PROVISIONING = "provisioning"
    READY = "ready"
    RUNNING = "running"
    SUSPENDED = "suspended"
    FAILED = "failed"
    DESTROYED = "destroyed"


class DomainMode(enum.StrEnum):
    AUTO = "auto"      # subdomain under deploy.hyrule.cloud
    CUSTOM = "custom"  # register via Openprovider


# --- VM Size Specifications ---


VM_SPECS: dict[VMSize, dict] = {
    VMSize.XS: {"vcpu": 1, "memory_mb": 512, "disk_gb": 10},
    VMSize.SM: {"vcpu": 1, "memory_mb": 1024, "disk_gb": 20},
    VMSize.MD: {"vcpu": 2, "memory_mb": 2048, "disk_gb": 40},
    VMSize.LG: {"vcpu": 4, "memory_mb": 4096, "disk_gb": 80},
}


# --- API Request/Response Models ---


class VMCreateRequest(BaseModel):
    duration_days: int = Field(ge=1, le=365, description="Hosting duration in days")
    size: VMSize = Field(default=VMSize.XS, description="VM size tier")
    os: str = Field(default="debian-13", description="OS template name")
    ssh_pubkey: str = Field(description="SSH public key for root access (ed25519 or rsa)")
    domain_mode: DomainMode = Field(default=DomainMode.AUTO)
    domain: str | None = Field(
        default=None,
        description="Domain to register (required when domain_mode=custom)",
    )
    open_ports: list[int] = Field(
        default_factory=lambda: [80, 443],
        description="Inbound TCP ports to allow (22 always included)",
    )
    setup_script: str | None = Field(
        default=None,
        description="Optional shell script to execute after boot via cloud-init",
    )


class VMCreateResponse(BaseModel):
    vm_id: str
    status: VMStatus
    status_url: str
    estimated_ready_seconds: int = 60


class VMStatusResponse(BaseModel):
    vm_id: str
    status: VMStatus
    ipv6: str | None = None
    hostname: str | None = None
    ssh: str | None = None
    expires_at: datetime | None = None
    firewall: FirewallState | None = None
    error: str | None = None
    cost_breakdown: CostBreakdown | None = None


class FirewallState(BaseModel):
    inbound_allow: list[int]
    policy: str = "deny"


class VMExtendRequest(BaseModel):
    days: int = Field(ge=1, le=365, description="Additional days to add")


class CostBreakdown(BaseModel):
    vm_cost: str
    domain_cost: str
    vpn_cost: str = "$0.00"
    total: str


class PricingResponse(BaseModel):
    vm_prices: dict[str, str]  # size -> $/day
    domain_auto: str
    vpn_per_day: str
    currency: str = "USDC"
    network: str = "Base (eip155:8453)"


class OSListResponse(BaseModel):
    templates: list[OSTemplate]


class OSTemplate(BaseModel):
    name: str
    description: str
    default: bool = False


# --- Internal State (DB-backed) ---


class VMRecord(BaseModel):
    """Internal record tracking a VM through its lifecycle."""

    vm_id: str = Field(default_factory=lambda: f"vm_{uuid.uuid4().hex[:12]}")
    xcpng_uuid: str | None = None  # XCP-NG VM UUID once created
    owner_wallet: str = ""  # wallet address that paid
    status: VMStatus = VMStatus.PROVISIONING
    size: VMSize = VMSize.XS
    os: str = "debian-13"
    ipv6: str | None = None
    hostname: str | None = None
    ssh_pubkey: str = ""
    open_ports: list[int] = Field(default_factory=lambda: [22, 80, 443])
    setup_script: str | None = None
    domain_mode: DomainMode = DomainMode.AUTO
    domain: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    destroyed_at: datetime | None = None
    error: str | None = None
    payment_tx: str | None = None  # on-chain tx hash
    cost_total: Decimal = Decimal("0")


# Forward ref resolution
VMStatusResponse.model_rebuild()
