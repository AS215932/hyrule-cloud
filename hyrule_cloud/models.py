"""
Domain models for Hyrule Cloud resources.
"""

from __future__ import annotations

import enum
import secrets
import string
import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field

# Block A0: widen vm_id from 48-bit hex (vm_<12 hex>) to ~131-bit base62
# (vm_<22 base62>). The legacy 48-bit space was borderline guessable; with
# management routes gated on a separate anon token, guessability is no
# longer the only defence, but a 131-bit id removes the surface entirely.
_BASE62_ALPHABET = string.ascii_letters + string.digits


def generate_vm_id() -> str:
    """Generate a fresh `vm_<22 base62>` id (~131 bits)."""
    return "vm_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(22))


def generate_anon_management_token() -> str:
    """Generate a one-time anon management token (`hyr_vm_<32 base62>`, ~190
    bits). Returned in cleartext to the caller of POST /v1/vm/create and
    NEVER stored — only the sha256 of it lands on the VM row.
    """
    return "hyr_vm_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(32))

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
    AUTO = "auto"      # subdomain under the configured deploy domain
    CUSTOM = "custom"  # register via Openprovider


class ProxyMode(enum.StrEnum):
    DIRECT = "direct"
    TOR = "tor"
    RESIDENTIAL = "residential"

class CryptoIntentStatus(enum.StrEnum):
    PENDING = "pending"
    PAID = "paid"
    EXPIRED = "expired"

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
    # Block A0: one-time anon management token for ownerless VMs. Returned
    # cleartext once at create time; only sha256 is stored. management_url
    # is the convenience link that embeds the token as a query param.
    management_token: str | None = None
    management_url: str | None = None


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


class VMPublicStatusResponse(BaseModel):
    """Sanitized public view returned by `GET /v1/vm/{id}/status`.

    Block A0: any caller (no token, no account) can fetch this for any
    vm_id. Reveals only the fields needed for an order-status page —
    NO ssh string, NO firewall config, NO provisioning error detail.
    """

    vm_id: str
    status: VMStatus
    ipv6: str | None = None
    hostname: str | None = None
    expires_at: datetime | None = None


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
    proxy_prices: dict[str, str] | None = None
    currency: str = "USDC"
    network: str = "Base (eip155:8453)"


class OSListResponse(BaseModel):
    templates: list[OSTemplate]


class OSTemplate(BaseModel):
    name: str
    description: str
    default: bool = False


class NetworkRequest(BaseModel):
    url: str = Field(description="The full URL to fetch")
    method: str = Field(default="GET", description="HTTP method (GET, POST, etc)")
    headers: dict[str, str] | None = Field(default=None, description="Custom headers")
    body: str | None = Field(default=None, description="Request body")
    proxy_mode: ProxyMode = Field(default=ProxyMode.DIRECT, description="Routing mode")
    timeout_seconds: int = Field(default=15, ge=1, le=60, description="Request timeout")


class NetworkResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_seconds: float
    proxy_mode: ProxyMode
    error: str | None = None


class CryptoIntentRequest(BaseModel):
    asset: str = Field(description="Asset symbol (BTC, XMR)")
    amount_usd: str = Field(description="USD amount to be converted")

class CryptoIntentResponse(BaseModel):
    intent_id: str
    asset: str
    amount_crypto: str
    address: str
    status: CryptoIntentStatus
    expires_at: datetime


# --- Internal State (DB-backed) ---


class VMRecord(BaseModel):
    """Internal record tracking a VM through its lifecycle."""

    vm_id: str = Field(default_factory=generate_vm_id)
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

class GenericActionResponse(BaseModel):
    status: str
    message: str | None = None

class DomainCheckResponse(BaseModel):
    domain: str
    available: bool
    price: str | None = None

class DomainRegisterRequest(BaseModel):
    duration_years: int = Field(default=1, ge=1, le=10)

class DNSRecordType(enum.StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"
    MX = "MX"
    NS = "NS"
    SRV = "SRV"

class DNSRecord(BaseModel):
    type: DNSRecordType
    name: str
    value: str
    ttl: int = 3600
    prio: int | None = None

class VMLogEvent(BaseModel):
    ts: str
    event: str

class VMLogsResponse(BaseModel):
    vm_id: str
    status: str
    events: list[VMLogEvent]
    error: str | None = None

# Rebuild all refs if needed
