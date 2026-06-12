"""
Domain models for Hyrule Cloud resources.
"""

from __future__ import annotations

import enum
import secrets
import string
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


def generate_domain_management_token() -> str:
    """Generate a one-time domain management token.

    Domain purchases can be ownerless like VM purchases, so they need the same
    bearer-token management model with a distinct prefix.
    """
    return "hyr_dom_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(32))


def generate_quote_id() -> str:
    """Generate a fresh `q_<22 base62>` durable-order-quote id (~131 bits)."""
    return "q_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(22))

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


class DomainStatus(enum.StrEnum):
    REGISTERING = "registering"
    ACTIVE = "active"
    FAILED = "failed"
    EXPIRED = "expired"


class CryptoIntentStatus(enum.StrEnum):
    """Block E: full payment-intent state machine for BTC/XMR.

    Wave 2 ships the enum values up-front (matches alembic 004 dead
    schema). The intent-engine code that actually transitions through
    these states is gated behind HYR_FEATURES_INTENT_ENGINE and lands
    in Wave 4.

    Happy path:  CREATED → WAITING_PAYMENT → SETTLED → PROVISIONING → PROVISIONED
    Error/edge:  UNDERPAID | OVERPAID | LATE_PAID | EXPIRED | FAILED | REFUND_MANUAL
    """
    # Pre-Block-E values kept as aliases so any in-flight intent rows still
    # round-trip cleanly through the StrEnum on read.
    PENDING = "pending"
    PAID = "paid"

    CREATED = "CREATED"
    WAITING_PAYMENT = "WAITING_PAYMENT"
    UNDERPAID = "UNDERPAID"
    OVERPAID = "OVERPAID"
    LATE_PAID = "LATE_PAID"
    SETTLED = "SETTLED"
    EXPIRED = "EXPIRED"
    PROVISIONING = "PROVISIONING"
    PROVISIONED = "PROVISIONED"
    FAILED = "FAILED"
    REFUND_MANUAL = "REFUND_MANUAL"


class QuoteStatus(enum.StrEnum):
    """Durable order-quote lifecycle (issue #14).

    created  → active, payable, not expired (the only payable state).
    consumed → a VM was provisioned from it; terminal. Repeat creates with the
               same quote_id are idempotent (return the original VM).
    expired  → past expires_at; terminal for creation. GET still surfaces it so
               the UI can render an "expired, start over" state.
    """

    CREATED = "created"
    CONSUMED = "consumed"
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
    quote_id: str | None = Field(
        default=None,
        max_length=36,
        description=(
            "Optional durable quote id from POST /v1/vm/quote. When set, the "
            "server provisions the spec stored on the quote at the quote-locked "
            "price; the rest of this body must match that stored spec. Omit for "
            "the legacy compute-price-from-body flow."
        ),
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


class VMQuoteRequest(BaseModel):
    """Durable order quote (issue #14). `order_payload` is the full VM spec; the
    server prices it once and stores it so the UI/agent can pay against a stable
    `quote_id` that survives review-page reloads and mobile wallet handoffs."""

    order_payload: VMCreateRequest = Field(description="The VM spec to price and store.")
    client_order_id: str | None = Field(
        default=None,
        max_length=64,
        description="Idempotency key. Same key + same spec returns the same quote.",
    )


class QuoteEvmMethod(BaseModel):
    key: str
    caip2: str
    asset: str
    chain_id: int | None = None


class AcceptedPaymentMethods(BaseModel):
    """Single source of truth, derived from live backend config: enabled EVM
    chains + whether the native (BTC/XMR) intent rail is wired."""

    evm: list[QuoteEvmMethod] = Field(default_factory=list)
    native: list[str] = Field(default_factory=list)


class VMQuoteResponse(BaseModel):
    quote_id: str
    status: QuoteStatus
    order_payload: VMCreateRequest
    amount_usd: str
    currency: str = "USD"
    accepted_payment_methods: AcceptedPaymentMethods
    created_at: datetime
    expires_at: datetime


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


class VMProduct(BaseModel):
    """One machine-readable VM tier (issue #14): specs + daily price."""

    size: VMSize
    name: str
    vcpu: int
    ram_mb: int
    disk_gb: int
    price_usd_day: str


class VMProductsResponse(BaseModel):
    """Agent-facing VM catalog so non-browser clients get specs + pricing
    without scraping the /services HTML."""

    currency: str = "USD"
    billing: str = "prepaid-daily"
    products: list[VMProduct]
    os_templates_url: str


class OSListResponse(BaseModel):
    templates: list[OSTemplate]


class OSTemplate(BaseModel):
    name: str
    description: str
    default: bool = False


class NetworkRequest(BaseModel):
    url: str = Field(max_length=2048, description="The full URL to fetch")
    method: str = Field(default="GET", description="HTTP method: GET, HEAD, or POST")
    headers: dict[str, str] | None = Field(default=None, description="Custom headers")
    body: str | None = Field(default=None, max_length=65536, description="Request body")
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
    """Block E: payment-intent creation. `order_payload` carries the full VM
    spec so the orchestrator can provision on settlement without re-asking
    the client. `client_order_id` is the idempotency key."""

    asset: str = Field(description="Asset symbol: BTC or XMR")
    order_payload: VMCreateRequest = Field(
        description="The VM spec to provision once the payment settles."
    )
    client_order_id: str | None = Field(
        default=None,
        max_length=64,
        description="Idempotency key. Repeated POSTs with the same key return the same intent.",
    )


class CryptoIntentResponse(BaseModel):
    """Block E intent shape returned by both /v1/intent/create and /v1/intent/{id}.

    Once status == PROVISIONED, `vm_id`, `management_token`, `management_url`
    mirror the A0 anon-checkout response so the frontend can stash the token
    identically.
    """

    intent_id: str
    asset: str
    address: str
    amount_crypto: str
    amount_usd: str | None = None
    rate_snapshot: str | None = None
    rate_valid_until: datetime | None = None
    status: CryptoIntentStatus
    confirmations: int = 0
    amount_received_crypto: str | None = None
    qr_code_uri: str | None = None   # bitcoin:<addr>?amount=<x> or monero:<addr>?tx_amount=<x>
    expires_at: datetime
    vm_id: str | None = None
    management_token: str | None = None
    management_url: str | None = None


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
    registrar_price: str | None = None
    markup: str | None = None
    total: str | None = None
    currency: str = "USD"
    premium: bool = False
    price: str | None = None

class DomainRegisterRequest(BaseModel):
    domain: str | None = Field(default=None, min_length=3, max_length=253)
    name: str | None = Field(default=None, max_length=128)
    extension: str | None = Field(default=None, max_length=32)
    duration_years: int = Field(default=1, ge=1, le=10)
    ipv6: str | None = Field(default=None, max_length=64)
    client_order_id: str | None = Field(default=None, max_length=64)


class DomainRegisterResponse(BaseModel):
    domain: str
    status: DomainStatus
    management_token: str | None = None
    management_url: str | None = None
    message: str | None = None

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
