"""
Domain models for Hyrule Cloud resources.
"""

from __future__ import annotations

import enum
import secrets
import string
from datetime import UTC, datetime
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


def generate_diagnostic_request_id() -> str:
    """Generate a fresh diagnostic request id for synchronous network checks."""
    return "diag_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(22))


def generate_diagnostic_job_id() -> str:
    """Generate a fresh generic async diagnostic job id."""
    return "job_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(22))


def generate_diagnostic_job_access_token() -> str:
    """Generate a one-time cleartext token for ownerless diagnostic jobs."""
    return "hyr_job_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(32))


# --- Enums ---


class VMSize(enum.StrEnum):
    XS = "xs"  # 1 vCPU, 1 GB, 10 GB
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


class LaunchProofStatus(enum.StrEnum):
    """Issue #28: customer-visible launch-proof contract states."""

    ACCEPTED = "accepted"
    PAYMENT_REQUIRED = "payment_required"
    PROVISIONING = "provisioning"
    PROVISIONED = "provisioned"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PaymentStatus(enum.StrEnum):
    """Issue #28: payment status for the launch-proof contract."""

    PAID = "paid"
    PAYMENT_REQUIRED = "payment_required"
    NOT_REQUIRED = "not_required"


class SSHSmokeStatus(enum.StrEnum):
    """Issue #28: SSH smoke-test result for the launch-proof contract."""

    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"


class DomainMode(enum.StrEnum):
    AUTO = "auto"      # subdomain under the configured deploy domain
    CUSTOM = "custom"  # register via Openprovider


class ProxyMode(enum.StrEnum):
    DIRECT = "direct"
    TOR = "tor"
    I2P = "i2p"
    YGGDRASIL = "yggdrasil"


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
    # 512 MB is below the debian-13 template's inherited memory floor (XCP-NG
    # rejects the shrink with MEMORY_CONSTRAINT_VIOLATION_ORDER) and OOMs on
    # cloud-init/apt anyway; 1 GB is the smallest viable Debian tier.
    VMSize.XS: {"vcpu": 1, "memory_mb": 1024, "disk_gb": 10},
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
    ipv6_prefix: str | None = None
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

    Issue #28: enriched with launch-proof contract fields so a customer
    can follow a VM from quote acceptance through provisioned/failed.
    """

    vm_id: str
    status: VMStatus
    ipv6: str | None = None
    ipv6_prefix: str | None = None
    hostname: str | None = None
    expires_at: datetime | None = None
    # Launch-proof contract fields (issue #28)
    launch_proof_status: LaunchProofStatus | None = None
    payment_status: PaymentStatus | None = None
    dns_aaaa_verified: bool = False
    ssh_smoke_status: SSHSmokeStatus = SSHSmokeStatus.NOT_RUN
    rollback_available: bool = False
    operator_message: str | None = None
    customer_message: str | None = None


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


# --- Network intelligence / BGP / MX / Agent Mail API contracts ---


class SourceStatus(enum.StrEnum):
    OK = "ok"
    INFO = "info"
    STALE = "stale"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    UNKNOWN = "unknown"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"
    SOURCE_NOT_CONFIGURED = "source_not_configured"
    RATE_LIMITED = "rate_limited"


class SourceHealth(BaseModel):
    status: SourceStatus | str = Field(description="ok, stale, degraded, unavailable, error, or source_not_configured")
    age_seconds: int | None = None
    message: str | None = None
    checked_at: datetime | None = None
    source_url: str | None = None


class DiagnosticStatus(enum.StrEnum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    ERROR = "error"


class DiagnosticTargetType(enum.StrEnum):
    DOMAIN = "domain"
    HOST = "host"
    URL = "url"
    IP = "ip"
    PREFIX = "prefix"
    ASN = "asn"
    PHONE_NUMBER = "phone_number"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"


class DiagnosticVantage(enum.StrEnum):
    EXTMON = "extmon"
    AS215932 = "as215932"
    GLOBALPING = "globalping"
    RIPE_ATLAS = "ripe_atlas"
    SYSTEM = "system"


class DiagnosticAddressFamily(enum.StrEnum):
    AUTO = "auto"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class DiagnosticTarget(BaseModel):
    input: str
    normalized: str | None = None
    type: DiagnosticTargetType = DiagnosticTargetType.UNKNOWN


class DiagnosticFinding(BaseModel):
    severity: DiagnosticStatus
    code: str
    message: str
    evidence: dict[str, object] = Field(default_factory=dict)
    recommendation: str | None = None


class DiagnosticResponse(BaseModel):
    request_id: str = Field(default_factory=generate_diagnostic_request_id)
    status: DiagnosticStatus
    summary: str
    target: DiagnosticTarget
    findings: list[DiagnosticFinding] = Field(default_factory=list)
    sources: dict[str, SourceHealth] = Field(default_factory=dict)
    partial: bool = False
    raw: dict[str, object] | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DiagnosticJobStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class DiagnosticJobKind(enum.StrEnum):
    WEB_REPORT = "web_report"
    WEB_TLS_DEEP = "web_tls_deep"
    PATH_REPORT = "path_report"
    VOIP_REPORT = "voip_report"
    THREAT_REPORT = "threat_report"
    MX_MAIL_DELIVERY = "mx_mail_delivery"


class DiagnosticJobResponse(BaseModel):
    job_id: str = Field(default_factory=generate_diagnostic_job_id)
    job_access_token: str | None = None
    service: str
    kind: DiagnosticJobKind | str
    status: DiagnosticJobStatus
    status_url: str | None = None
    download_url: str | None = None
    charged_amount_usd: str | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None


class DiagnosticJobResultResponse(DiagnosticJobResponse):
    result: DiagnosticResponse | dict[str, object] | None = None
    artifact: dict[str, object] | None = None


class QuoteLineItem(BaseModel):
    name: str
    quantity: int = 1
    unit_price_usd: str


class PaidEndpointQuote(BaseModel):
    amount_usd: str
    currency: str = "USD"
    billable_units: list[QuoteLineItem]
    paid_endpoint: str


class CapabilityEndpoint(BaseModel):
    path: str
    method: str
    paid: bool = False
    description: str


class ProductCapabilityResponse(BaseModel):
    service: str
    version: str = "2026-06-13"
    purpose: str
    separation_of_concerns: str | None = None
    free_endpoints: list[CapabilityEndpoint] = Field(default_factory=list)
    paid_endpoints: list[CapabilityEndpoint] = Field(default_factory=list)


class WebCheck(enum.StrEnum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    CERT = "cert"
    HEADERS = "headers"
    CDN_WAF = "cdn_waf"
    DOWN = "down"


class WebTLSDeepCheck(enum.StrEnum):
    PROTOCOL_VERSIONS = "protocol_versions"
    CIPHER_SUITES = "cipher_suites"
    CERTIFICATE_CHAIN = "certificate_chain"
    OCSP = "ocsp"
    HSTS = "hsts"
    CAA = "caa"
    SECURITY_HEADERS = "security_headers"


class WebCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    checks: list[WebCheck] = Field(default_factory=lambda: [WebCheck.DNS, WebCheck.HTTP, WebCheck.TLS, WebCheck.CERT, WebCheck.HEADERS, WebCheck.CDN_WAF])
    vantages: list[DiagnosticVantage] = Field(default_factory=lambda: [DiagnosticVantage.EXTMON])
    timeout_ms: int = Field(default=10000, ge=500, le=60000)
    include_raw: bool = False


class WebReportRequest(WebCheckRequest):
    profile: str = "web_reachability"


class WebTLSDeepRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    scan_profile: str = "ssl_labs_style"
    checks: list[WebTLSDeepCheck] = Field(default_factory=lambda: [check for check in WebTLSDeepCheck])
    include_raw: bool = False


class WebPricingResponse(BaseModel):
    check_usd: str
    tls_deep_usd: str


class PathProbeKind(enum.StrEnum):
    PING = "ping"
    TRACE = "trace"
    MTR = "mtr"
    ASYMMETRY = "asymmetry"


class PathReportCheck(enum.StrEnum):
    PING = "ping"
    TRACEROUTE = "traceroute"
    MTR = "mtr"
    BGP = "bgp"
    RPKI = "rpki"
    ROUTER_TABLE = "router_table"


# Each path endpoint's default vantage set, hoisted to a module constant so the
# manifest/capabilities/discovery gates can reference the SAME defaults without
# calling FieldInfo.default_factory (mypy strict types it as possibly-None /
# wrong-arity). These stay the single source of truth for the field defaults.
# The defaults probe from AS215932 (the vantage only this operator owns), so
# path/ping and path/report auto-list exactly when the prober is deployed.
PATH_PROBE_DEFAULT_VANTAGES: list[DiagnosticVantage] = [DiagnosticVantage.AS215932]
PATH_REPORT_DEFAULT_VANTAGES: list[DiagnosticVantage] = [
    DiagnosticVantage.AS215932,
    DiagnosticVantage.EXTMON,
]


class PathProbeRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    probe: PathProbeKind = PathProbeKind.PING
    address_family: DiagnosticAddressFamily = DiagnosticAddressFamily.AUTO
    vantages: list[DiagnosticVantage] = Field(
        default_factory=lambda: list(PATH_PROBE_DEFAULT_VANTAGES)
    )
    count: int = Field(default=4, ge=1, le=20)
    timeout_ms: int = Field(default=10000, ge=500, le=60000)


class PathReportRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    address_family: DiagnosticAddressFamily = DiagnosticAddressFamily.AUTO
    vantages: list[DiagnosticVantage] = Field(
        default_factory=lambda: list(PATH_REPORT_DEFAULT_VANTAGES)
    )
    checks: list[PathReportCheck] = Field(default_factory=lambda: [PathReportCheck.PING, PathReportCheck.TRACEROUTE, PathReportCheck.MTR, PathReportCheck.BGP, PathReportCheck.RPKI, PathReportCheck.ROUTER_TABLE])
    max_duration_seconds: int = Field(default=60, ge=5, le=300)
    include_raw: bool = False


class PathPricingResponse(BaseModel):
    probe_usd: str
    report_usd: str


class PathVantagesResponse(BaseModel):
    vantages: list[dict[str, object]]


class PortProtocol(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"


class PortProfile(enum.StrEnum):
    CUSTOM = "custom"
    SSH = "ssh"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    SUBMISSION = "submission"
    IMAP = "imap"
    POP3 = "pop3"
    SIP = "sip"
    SIPS = "sips"


class PortCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    port: int = Field(ge=1, le=65535)
    protocol: PortProtocol = PortProtocol.TCP
    profile: PortProfile = PortProfile.CUSTOM
    vantage: DiagnosticVantage = DiagnosticVantage.EXTMON
    timeout_ms: int = Field(default=5000, ge=500, le=30000)
    include_banner: bool = False


class PortAllowedResponse(BaseModel):
    tcp_ports: list[int]
    udp_ports: list[int] = Field(default_factory=list)
    note: str = "Single declared service checks only; broad port scanning is not supported."


class PortPricingResponse(BaseModel):
    check_usd: str


class NATIPResponse(BaseModel):
    ip: str
    ip_version: int
    # Scope of the server-observed caller address: cgnat | private | global |
    # non_global. cgnat_likely is true only for 100.64.0.0/10 addresses.
    classification: str | None = None
    cgnat_likely: bool | None = None
    asn: int | None = None
    reverse_dns: list[str] = Field(default_factory=list)
    headers_seen: dict[str, str | None] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NATPortForwardCheckRequest(PortCheckRequest):
    pass


class NATPricingResponse(BaseModel):
    port_forward_check_usd: str
    what_is_my_ip_usd: str = "0"


class ThreatSubjectType(enum.StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    CERT = "cert"
    URL = "url"


class ThreatView(enum.StrEnum):
    RBL = "rbl"
    CT = "ct"
    RDAP = "rdap"
    WHOIS = "whois"
    DNS = "dns"
    REPUTATION = "reputation"


class ThreatSubject(BaseModel):
    type: ThreatSubjectType
    value: str


class ThreatLookupRequest(BaseModel):
    subject: ThreatSubject
    views: list[ThreatView] = Field(default_factory=lambda: [ThreatView.RBL, ThreatView.CT, ThreatView.RDAP, ThreatView.WHOIS, ThreatView.DNS, ThreatView.REPUTATION])
    include_raw: bool = False


class ThreatSourcesResponse(BaseModel):
    sources: dict[str, SourceHealth]
    policy: str = "Open/public sources are used first; licensed and owner-verified sources are disabled until configured."


class ThreatPricingResponse(BaseModel):
    lookup_usd: str


class VoIPCheck(enum.StrEnum):
    SIP_DNS = "sip_dns"
    SIP_OPTIONS = "sip_options"
    SIP_TLS = "sip_tls"
    STUN_TURN = "stun_turn"
    NUMBER_INTEL = "number_intel"
    CNAM = "cnam"
    SPAM_REPUTATION = "spam_reputation"
    E911 = "e911"


class VoIPCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    checks: list[VoIPCheck] = Field(default_factory=lambda: [VoIPCheck.SIP_DNS, VoIPCheck.SIP_TLS])
    sip_port: int = Field(default=5061, ge=1, le=65535)
    timeout_ms: int = Field(default=10000, ge=500, le=60000)
    include_raw: bool = False


class VoIPNumberLookupRequest(BaseModel):
    number: str = Field(min_length=3, max_length=32)
    country: str | None = Field(default=None, max_length=2)
    checks: list[VoIPCheck] = Field(default_factory=lambda: [VoIPCheck.NUMBER_INTEL, VoIPCheck.CNAM, VoIPCheck.SPAM_REPUTATION, VoIPCheck.E911])
    include_raw: bool = False


class VoIPPricingResponse(BaseModel):
    check_usd: str
    number_lookup_usd: str


class VoIPSourcesResponse(BaseModel):
    sources: dict[str, SourceHealth]


class BGPSubjectType(enum.StrEnum):
    PREFIX = "prefix"
    IP = "ip"
    ASN = "asn"


class BGPDataset(enum.StrEnum):
    PUBLIC_ROUTING = "public_routing"
    RPKI = "rpki"
    PEERINGDB = "peeringdb"
    AS215932_ROUTER_TABLES = "as215932_router_tables"


class BGPView(enum.StrEnum):
    ORIGINS = "origins"
    VISIBILITY = "visibility"
    RPKI = "rpki"
    PATHS = "paths"
    ANNOUNCED_PREFIXES = "announced_prefixes"
    PEERINGDB = "peeringdb"
    ROUTER_ROUTES = "router_routes"
    RAW_SOURCE_PAYLOADS = "raw_source_payloads"


class BGPTimeMode(enum.StrEnum):
    LATEST = "latest"
    AT = "at"
    RANGE = "range"


class BGPSubject(BaseModel):
    type: BGPSubjectType
    value: str | int = Field(description="CIDR prefix, IP address, or ASN/AS-prefixed ASN")


class BGPTimeSelector(BaseModel):
    mode: BGPTimeMode = BGPTimeMode.LATEST
    at: datetime | None = None
    from_time: datetime | None = None
    until_time: datetime | None = None
    max_age_seconds: int = Field(default=900, ge=0, le=86400)


class BGPFilters(BaseModel):
    match: str = Field(default="exact", description="exact, covering, covered, or best")
    routers: list[str] = Field(default_factory=list)
    include_raw: bool = False


class BGPAssertions(BaseModel):
    expected_origin_asns: list[int] = Field(default_factory=list)
    expected_rpki: str | None = Field(default=None, description="valid, invalid, not_found, or unknown")


class BGPLookupRequest(BaseModel):
    subject: BGPSubject
    datasets: list[BGPDataset] = Field(
        default_factory=lambda: [BGPDataset.PUBLIC_ROUTING, BGPDataset.RPKI]
    )
    views: list[BGPView] = Field(default_factory=lambda: [BGPView.ORIGINS, BGPView.RPKI])
    sources: list[str] = Field(default_factory=lambda: ["auto"])
    time: BGPTimeSelector = Field(default_factory=BGPTimeSelector)
    filters: BGPFilters = Field(default_factory=BGPFilters)
    assertions: BGPAssertions = Field(default_factory=BGPAssertions)
    limit: int = Field(default=500, ge=1, le=100000)


class BGPOriginObservation(BaseModel):
    asn: int
    rpki: str | None = None
    sources: list[str] = Field(default_factory=list)


class BGPResolvedSubject(BaseModel):
    routed: bool | None = None
    best_prefix: str | None = None
    observed_origin_asns: list[int] = Field(default_factory=list)
    origins: list[BGPOriginObservation] = Field(default_factory=list)


class BGPLookupResponse(BaseModel):
    request_id: str
    subject: dict[str, str | int]
    resolved: BGPResolvedSubject = Field(default_factory=BGPResolvedSubject)
    results: dict[str, object] = Field(default_factory=dict)
    assertions: dict[str, object] = Field(default_factory=dict)
    sources: dict[str, SourceHealth] = Field(default_factory=dict)
    partial: bool = False
    charged_amount_usd: str | None = None
    generated_at: datetime


class BGPStatusResponse(BaseModel):
    status: str
    scope: str = "as215932"
    monitored: dict[str, object]
    routing: dict[str, object]
    sources: dict[str, str]
    updated_at: datetime


class BGPSourcesResponse(BaseModel):
    sources: dict[str, SourceHealth]
    updated_at: datetime


class BGPPricingResponse(BaseModel):
    public_latest_lookup_usd: str
    router_table_lookup_usd: str
    bgpstream_update_hour_usd: str
    bgpstream_rib_usd: str
    router_snapshot_download_usd: str


class BGPSnapshotSummary(BaseModel):
    snapshot_id: str
    kind: str = "router_table"
    router: str | None = None
    created_at: datetime
    expires_at: datetime | None = None
    formats: list[str] = Field(default_factory=lambda: ["normalized_jsonl.gz"])
    size_bytes: int | None = None
    sha256: str | None = None


class BGPSnapshotListResponse(BaseModel):
    snapshots: list[BGPSnapshotSummary] = Field(default_factory=list)


class BGPStreamRecordType(enum.StrEnum):
    UPDATES = "updates"
    RIBS = "ribs"


class BGPStreamJobRequest(BaseModel):
    subject: BGPSubject
    projects: list[str] = Field(default_factory=lambda: ["routeviews", "ris"])
    record_type: BGPStreamRecordType = BGPStreamRecordType.UPDATES
    from_time: datetime | None = None
    until_time: datetime | None = None
    collectors: list[str] = Field(default_factory=list)
    limit: int = Field(default=100000, ge=1, le=1000000)


class BGPJobStatus(enum.StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class BGPJobResponse(BaseModel):
    job_id: str
    job_access_token: str | None = None
    status: BGPJobStatus
    charged_amount_usd: str | None = None
    status_url: str | None = None
    download_url: str | None = None
    error: str | None = None
    created_at: datetime
    expires_at: datetime | None = None


class IPLookupView(enum.StrEnum):
    GEO = "geo"
    ASN = "asn"
    RDNS = "rdns"
    RDAP = "rdap"
    WHOIS = "whois"
    REPUTATION = "reputation"
    BGP = "bgp"


class IPLookupRequest(BaseModel):
    address: str
    views: list[IPLookupView] = Field(
        # geo stays out of the default until a real provider is configured;
        # requesting it explicitly 501s before charging (see api/ip.py).
        default_factory=lambda: [IPLookupView.ASN, IPLookupView.RDNS]
    )
    max_age_seconds: int = Field(default=3600, ge=0, le=604800)


class IPGeoResult(BaseModel):
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    source: str | None = None


class IPNetworkResult(BaseModel):
    asn: int | None = None
    asn_name: str | None = None
    isp: str | None = None
    prefix: str | None = None
    registry: str | None = None


class IPReputationListing(BaseModel):
    provider: str
    listed: bool
    detail: str | None = None


class IPReputationResult(BaseModel):
    listed: bool = False
    lists_checked: int = 0
    listings: list[IPReputationListing] = Field(default_factory=list)


class IPLookupResponse(BaseModel):
    request_id: str
    address: str
    geo: IPGeoResult | None = None
    network: IPNetworkResult | None = None
    reverse_dns: list[str] = Field(default_factory=list)
    rdap: dict[str, object] | None = None
    whois: dict[str, object] | None = None
    reputation: IPReputationResult | None = None
    bgp: dict[str, object] | None = None
    sources: dict[str, str] = Field(default_factory=dict)
    partial: bool = False
    generated_at: datetime


class IPPricingResponse(BaseModel):
    lookup_usd: str


class DNSLookupRecordType(enum.StrEnum):
    A = "A"
    AAAA = "AAAA"
    CAA = "CAA"
    CNAME = "CNAME"
    DNSKEY = "DNSKEY"
    DS = "DS"
    MX = "MX"
    NAPTR = "NAPTR"
    NS = "NS"
    PTR = "PTR"
    SOA = "SOA"
    SRV = "SRV"
    TXT = "TXT"
    TLSA = "TLSA"
    ANY = "ANY"


class DNSLookupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: DNSLookupRecordType = DNSLookupRecordType.A
    resolver: str = "system"
    dnssec: bool = False
    trace: bool = False
    timeout_ms: int = Field(default=3000, ge=500, le=30000)


class DNSQuestion(BaseModel):
    name: str
    type: str


class DNSRecordAnswer(BaseModel):
    name: str
    type: str
    ttl: int | None = None
    value: str


class DNSSECResult(BaseModel):
    validated: bool | None = None
    chain_status: str | None = None
    detail: str | None = None


class DNSLookupResponse(BaseModel):
    request_id: str
    question: DNSQuestion
    answers: list[DNSRecordAnswer] = Field(default_factory=list)
    authority: list[DNSRecordAnswer] = Field(default_factory=list)
    additional: list[DNSRecordAnswer] = Field(default_factory=list)
    rcode: str
    dnssec: DNSSECResult | None = None
    resolver: str
    trace: list[dict[str, object]] = Field(default_factory=list)
    generated_at: datetime


class DNSPricingResponse(BaseModel):
    lookup_usd: str


class DNSPropagationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: DNSLookupRecordType = DNSLookupRecordType.A
    expected: list[str] = Field(default_factory=list)
    resolvers: list[str] = Field(default_factory=lambda: ["cloudflare", "google", "quad9", "system"])
    authoritative: bool = True
    timeout_ms: int = Field(default=3000, ge=500, le=30000)


class DNSAuthorityCompareRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    type: DNSLookupRecordType = DNSLookupRecordType.A
    authoritative: bool = True
    recursive_resolvers: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    timeout_ms: int = Field(default=3000, ge=500, le=30000)


class DNSDiagnosticResponse(DiagnosticResponse):
    pass


class RegistrySubjectType(enum.StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    PREFIX = "prefix"
    ASN = "asn"
    ENTITY = "entity"


class RegistrySubject(BaseModel):
    type: RegistrySubjectType
    value: str | int


class RDAPLookupRequest(BaseModel):
    subject: RegistrySubject
    include_raw: bool = False
    max_age_seconds: int = Field(default=86400, ge=0, le=2592000)


class RDAPLookupResponse(BaseModel):
    request_id: str
    subject: RegistrySubject
    registry: str | None = None
    bootstrap_url: str | None = None
    parsed: dict[str, object] = Field(default_factory=dict)
    raw: dict[str, object] | None = None
    generated_at: datetime


class WhoisLookupRequest(BaseModel):
    subject: RegistrySubject
    include_raw: bool = False
    max_age_seconds: int = Field(default=86400, ge=0, le=2592000)


class WhoisLookupResponse(BaseModel):
    request_id: str
    subject: RegistrySubject
    registry: str | None = None
    server: str | None = None
    parsed: dict[str, object] = Field(default_factory=dict)
    raw: str | None = None
    redacted: bool = True
    generated_at: datetime


class RegistryPricingResponse(BaseModel):
    rdap_lookup_usd: str
    whois_lookup_usd: str


class MailBounceClassification(enum.StrEnum):
    POLICY_REJECTION = "policy_rejection"
    AUTH_FAILURE = "auth_failure"
    MAILBOX_FULL = "mailbox_full"
    RATE_LIMITED = "rate_limited"
    DNS_FAILURE = "dns_failure"
    TLS_FAILURE = "tls_failure"
    UNKNOWN = "unknown"


class MailBounceContext(BaseModel):
    sender_domain: str | None = None
    recipient_domain: str | None = None


class MailBounceParseRequest(BaseModel):
    message: str = Field(min_length=1, max_length=262144)
    context: MailBounceContext = Field(default_factory=MailBounceContext)


class MailBounceParseResponse(BaseModel):
    status: DiagnosticStatus
    classification: MailBounceClassification
    smtp_status: str | None = None
    remote_mta: str | None = None
    probable_causes: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    evidence: dict[str, object] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MailRecordRecommendation(BaseModel):
    type: DNSLookupRecordType
    name: str
    value: str
    ttl: int = 3600
    purpose: str
    notes: str | None = None


class MXTool(enum.StrEnum):
    A = "a"
    AAAA = "aaaa"
    ARIN = "arin"
    ASN = "asn"
    BIMI = "bimi"
    BLACKLIST = "blacklist"
    CNAME = "cname"
    DKIM = "dkim"
    DMARC = "dmarc"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    MTA_STS = "mta-sts"
    MX = "mx"
    PING = "ping"
    PTR = "ptr"
    SMTP = "smtp"
    SOA = "soa"
    SPF = "spf"
    TCP = "tcp"
    TLSRPT = "tlsrpt"
    TRACE = "trace"
    TXT = "txt"
    WHOIS = "whois"


class MXStatus(enum.StrEnum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    ERROR = "error"


class MXCheckOptions(BaseModel):
    timeout_ms: int = Field(default=5000, ge=500, le=60000)
    include_raw: bool = False
    dkim_selectors: list[str] = Field(default_factory=list)
    smtp_starttls: bool = True
    include_recommendations: bool = True
    port: int | None = Field(default=None, ge=1, le=65535)


class MXCheckRequest(BaseModel):
    tool: MXTool | None = None
    target: str | None = Field(default=None, min_length=1, max_length=2048)
    command: str | None = Field(
        default=None,
        description="SuperTool-compatible command, e.g. mx:example.com or blacklist:8.8.8.8",
    )
    options: MXCheckOptions = Field(default_factory=MXCheckOptions)


class MXFinding(BaseModel):
    severity: MXStatus
    code: str
    message: str
    evidence: dict[str, object] = Field(default_factory=dict)
    recommendation: str | None = None


class MXCheckResponse(BaseModel):
    request_id: str
    tool: MXTool
    target: str
    status: MXStatus
    summary: str
    findings: list[MXFinding] = Field(default_factory=list)
    raw: dict[str, object] | None = None
    sources: dict[str, str] = Field(default_factory=dict)
    generated_at: datetime


class MXProfile(enum.StrEnum):
    MAIL_DELIVERY = "mail_delivery"
    DOMAIN_HEALTH = "domain_health"
    REPUTATION = "reputation"
    CONNECTIVITY = "connectivity"


class MXJobRequest(BaseModel):
    profile: MXProfile = MXProfile.MAIL_DELIVERY
    target: str = Field(min_length=1, max_length=2048)
    checks: list[MXTool] = Field(default_factory=list)
    options: MXCheckOptions = Field(default_factory=MXCheckOptions)


class MXJobStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class MXJobResponse(BaseModel):
    job_id: str
    job_access_token: str | None = None
    status: MXJobStatus
    target: str
    profile: MXProfile
    status_url: str | None = None
    download_url: str | None = None
    results: list[MXCheckResponse] = Field(default_factory=list)
    # Concrete records derived from the observed lookups (never placeholders);
    # empty when options.include_recommendations is false or nothing applies.
    recommendations: list[MailRecordRecommendation] = Field(default_factory=list)
    error: str | None = None
    created_at: datetime
    expires_at: datetime | None = None


class MXToolDescription(BaseModel):
    tool: MXTool
    target: str
    description: str
    active_probe: bool = False


class MXToolsResponse(BaseModel):
    tools: list[MXToolDescription]
    disclaimer: str = "Hyrule implements compatible diagnostics internally and is not affiliated with MXToolbox."


class MXPricingResponse(BaseModel):
    single_check_usd: str
    mail_delivery_report_usd: str


# Rebuild all refs if needed
