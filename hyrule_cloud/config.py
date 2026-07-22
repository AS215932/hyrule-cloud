"""
Hyrule Cloud configuration.

All secrets and tunables loaded from environment variables or .env file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True)
class PaymentNetwork:
    """Frozen description of a single x402-supported payment chain (Block C).

    The `key` is the short stable identifier used as the URL slug, the JSON
    key on /v1/payments/networks, and the value of `network_key` in EIP-712
    payment payloads. The `caip2` is the canonical chain identifier for
    x402 v2 (`eip155:<chain_id>` for EVM, `solana:<genesis-hash>` for SVM);
    the facilitator's `/supported` advertises chains in CAIP-2 form so the
    smoke test in scripts/verify_facilitator.py keys on it.

    Frontend MUST read this list from /v1/payments/networks. Never hardcode
    a chain in the browser bundle — that's [[feedback_verified_payment_chains]].
    """

    key: str
    display_name: str
    caip2: str
    family: str  # "evm" | "svm" — frontend picks the JS adapter on this
    chain_id: int | None  # bare EVM chainId for the EIP-712 domain
    asset: str  # "USDC"
    token_address: str  # contract address (EVM) or mint (SVM)
    token_decimals: int
    eip712_domain: dict[str, str] = field(default_factory=dict)  # name + version
    # Native gas token shape for wallet_addEthereumChain ({name, symbol,
    # decimals}). Sourced from here rather than hardcoded ETH in the JS
    # adapter — Polygon's native is POL, not ETH, so a baked-in default would
    # mis-add the chain to the wallet (per [[feedback_verified_payment_chains]]).
    native_currency: dict[str, str | int] = field(
        default_factory=lambda: {"name": "Ether", "symbol": "ETH", "decimals": 18}
    )
    rpc_url: str = ""
    block_explorer_url: str = ""
    testnet: bool = False
    enabled: bool = True


# Default chain list. Both the default facilitator (payai) and Coinbase CDP
# advertise all three chains; what gates `enabled=True` is a live paid canary
# per chain (`scripts/x402_canary.py dns --network <caip2>`) per
# [[feedback_verified_payment_chains]] — we only advertise what verifies.
#
# World and Solana are intentionally omitted until Wave 5 (Block H) wires
# the SVM scheme; adding them here without the JS adapter shipping would
# mislead the frontend's chain selector.
_DEFAULT_NETWORKS: list[PaymentNetwork] = [
    PaymentNetwork(
        key="base",
        display_name="Base",
        caip2="eip155:8453",
        family="evm",
        chain_id=8453,
        asset="USDC",
        token_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        token_decimals=6,
        eip712_domain={"name": "USD Coin", "version": "2"},
        rpc_url="https://mainnet.base.org",
        block_explorer_url="https://basescan.org",
        testnet=False,
        enabled=True,
    ),
    PaymentNetwork(
        key="polygon",
        display_name="Polygon",
        caip2="eip155:137",
        family="evm",
        chain_id=137,
        asset="USDC",
        token_address="0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
        token_decimals=6,
        eip712_domain={"name": "USD Coin", "version": "2"},
        native_currency={"name": "POL", "symbol": "POL", "decimals": 18},
        rpc_url="https://polygon-rpc.com",
        block_explorer_url="https://polygonscan.com",
        testnet=False,
        enabled=True,
    ),
    PaymentNetwork(
        key="arbitrum",
        display_name="Arbitrum",
        caip2="eip155:42161",
        family="evm",
        chain_id=42161,
        asset="USDC",
        token_address="0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        token_decimals=6,
        eip712_domain={"name": "USD Coin", "version": "2"},
        rpc_url="https://arb1.arbitrum.io/rpc",
        block_explorer_url="https://arbiscan.io",
        testnet=False,
        enabled=True,
    ),
]


class XCPNGConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XCPNG_", env_file=".env", extra="ignore")

    # Xen Orchestra — all XCP-NG operations go through XO JSON-RPC.
    # XO has mgmt-side access to XAPI (dom0 10.0.0.1); dom0 stays underlay-only.
    xo_url: str = "wss://xcp-ng.internal/api/"
    xo_token: str = ""
    xo_verify_ssl: bool = False

    default_sr_uuid: str = ""
    default_network_uuid: str = ""
    templates: dict[str, str] = Field(default_factory=dict)

    # OpenBSD root disks cannot be grown while mounted. For OpenBSD templates,
    # the provider attaches the newly cloned root VDI to this dedicated builder
    # VM before first boot and grows it with native OpenBSD tools.
    openbsd_builder_vm_uuid: str = ""
    openbsd_builder_ssh_host: str = ""
    openbsd_builder_ssh_user: str = "svag"
    openbsd_builder_ssh_key_path: str = ""
    openbsd_builder_disk_device: str = "sd1"
    openbsd_builder_attach_position: str = "1"
    openbsd_builder_ssh_timeout_seconds: int = 120

    # Admission control mirrors the current single-host operating policy: CPU
    # may be committed 2:1, RAM is never overcommitted, and a small recovery
    # margin stays free on both host memory and the default SR.
    vcpu_overcommit_ratio: Decimal = Field(default=Decimal("2.0"), ge=Decimal("1"))
    memory_headroom_mb: int = Field(default=2048, ge=0)
    storage_headroom_gb: int = Field(default=20, ge=0)


class OpenproviderConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPENPROVIDER_", env_file=".env", extra="ignore")

    api_url: str = "https://api.openprovider.eu/v1beta"
    username: str = ""
    password: str = ""
    owner_handle: str = ""
    admin_handle: str = ""
    tech_handle: str = ""
    billing_handle: str = ""
    nameservers: list[str] = Field(
        default_factory=lambda: ["ns1.hyrule.host", "ns2.hyrule.host"]
    )


class DomainConfig(BaseSettings):
    """Managed-domain product configuration.

    Read-only discovery is available independently from purchasing.  The
    three launch switches deliberately fail closed: setting only
    ``DOMAIN_PURCHASES_ENABLED=true`` is insufficient to accept money before
    legal and tax review have been recorded by the operator.
    """

    model_config = SettingsConfigDict(env_prefix="DOMAIN_", env_file=".env", extra="ignore")

    enabled: bool = True
    purchases_enabled: bool = False
    legal_approved: bool = False
    tax_approved: bool = False
    terms_version: str = "2026-07-15"

    quote_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    catalog_sync_seconds: int = Field(default=21600, ge=300, le=86400)
    catalog_max_age_seconds: int = Field(default=86400, ge=600, le=604800)
    worker_poll_seconds: int = Field(default=5, ge=1, le=60)
    renewal_window_days: int = Field(default=60, ge=1, le=180)
    renewal_due_days: int = Field(default=30, ge=1, le=180)
    job_lock_timeout_seconds: int = Field(default=900, ge=60, le=7200)
    provider_reconcile_delay_seconds: int = Field(default=60, ge=5, le=3600)

    markup_percent: Decimal = Field(default=Decimal("0.25"), ge=Decimal("0"))
    markup_min_usd: Decimal = Field(default=Decimal("3.00"), ge=Decimal("0"))
    tld_allowlist: list[str] = Field(default_factory=list)
    account_allowlist: list[str] = Field(default_factory=list)

    managed_nameservers: list[str] = Field(
        default_factory=lambda: ["ns1.hyrule.host", "ns2.hyrule.host"]
    )
    soa_mname: str = "ns1.hyrule.host"
    soa_rname: str = "hostmaster.hyrule.host"

    iana_root_db_url: str = "https://www.iana.org/domains/root/db"
    dns_control_url: str = ""
    dns_control_secret: str = ""
    dns_control_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)

    # Fernet key used only for short-lived, one-time transfer auth-code
    # storage. An empty key disables transfer-out rather than storing a secret
    # in plaintext.
    authcode_fernet_key: str = ""
    openprovider_webhook_secret: str = ""

    max_dns_rrsets: int = Field(default=500, ge=1, le=5000)
    max_dns_changes: int = Field(default=100, ge=1, le=500)
    transfer_challenge_ttl_seconds: int = Field(default=300, ge=60, le=900)
    transfer_authcode_ttl_seconds: int = Field(default=900, ge=60, le=3600)


class PaymentConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PAYMENT_", env_file=".env", extra="ignore")

    receiver_address: str = ""
    facilitator_url: str = "https://facilitator.payai.network"

    # Block C (Wave 3): the rich PaymentNetwork list. Keyed list rather than a
    # dict so iteration order matches the order operators set in Vault. This
    # is the SINGLE source of truth — `networks` below is derived.
    payment_networks: list[PaymentNetwork] = Field(
        default_factory=lambda: list(_DEFAULT_NETWORKS),
    )

    def enabled_networks(self) -> list[PaymentNetwork]:
        """Return only chains where `enabled=True`. Operators can flip a chain
        off via Vault without redeploying — the frontend's chain selector
        picks up the change on the next /v1/payments/networks poll."""
        return [n for n in self.payment_networks if n.enabled]

    @property
    def networks(self) -> list[dict[str, str]]:
        """Legacy shape: list of {"network": "eip155:8453", "asset": "USDC", ...}.
        Kept so the x402 SDK's PaymentMiddlewareASGI initialisation keeps
        working unchanged. Derived (not stored) so it cannot drift from
        `payment_networks` — per Sourcery cloud#7 review: operators that
        flip `enabled=False` on a chain should see the SDK config update
        automatically without a second knob to flip."""
        return [
            {"network": n.caip2, "asset": n.asset, "scheme": "exact"}
            for n in self.enabled_networks()
        ]

    btc_xpub: str = ""
    xmr_viewkey: str = ""
    xmr_rpc_url: str = "http://127.0.0.1:18088/json_rpc"
    require_native: bool = False

    price_vm_xs: Decimal = Decimal("0.20")
    price_vm_sm: Decimal = Decimal("0.40")
    price_vm_md: Decimal = Decimal("0.60")
    price_vm_lg: Decimal = Decimal("0.80")
    price_vm_addon_vcpu: Decimal = Decimal("0.10")
    price_vm_addon_ram_gb: Decimal = Decimal("0.15")
    price_vm_addon_disk_10gb: Decimal = Decimal("0.05")
    price_domain_markup: Decimal = Decimal("1.00")
    
    price_proxy_direct: Decimal = Decimal("0.01")
    price_proxy_tor: Decimal = Decimal("0.05")
    price_proxy_i2p: Decimal = Decimal("0.05")
    price_proxy_yggdrasil: Decimal = Decimal("0.03")

    # Reverse-SSH tunnel: hourly lease rate. Total = hours * this rate.
    price_tunnel_hourly: Decimal = Decimal("0.05")

    # Network intelligence / agentic support API prices. These are contract
    # defaults; route implementations can compute dynamic prices around them.
    price_bgp_lookup: Decimal = Decimal("0.005")
    price_bgp_router_query: Decimal = Decimal("0.01")
    price_bgpstream_hour: Decimal = Decimal("0.05")
    price_bgpstream_rib: Decimal = Decimal("0.10")
    price_bgp_router_table: Decimal = Decimal("0.10")
    price_ip_lookup: Decimal = Decimal("0.003")
    price_dns_lookup: Decimal = Decimal("0.001")
    price_rdap_lookup: Decimal = Decimal("0.003")
    price_whois_lookup: Decimal = Decimal("0.005")
    price_mx_check: Decimal = Decimal("0.005")
    price_mx_report: Decimal = Decimal("0.03")
    price_web_check: Decimal = Decimal("0.005")
    price_web_tls_deep: Decimal = Decimal("0.10")
    price_path_probe: Decimal = Decimal("0.005")
    price_path_report: Decimal = Decimal("0.05")
    price_port_check: Decimal = Decimal("0.003")
    price_nat_port_forward_check: Decimal = Decimal("0.005")
    price_threat_lookup: Decimal = Decimal("0.01")
    price_voip_check: Decimal = Decimal("0.01")
    price_voip_number_lookup: Decimal = Decimal("0.05")

    # Dev bypass: set to a non-empty string to allow skipping payment
    # via X-DEV-BYPASS header. NEVER set in production.
    dev_bypass_secret: str = ""


class HyruleConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HYRULE_", env_file=".env", extra="ignore")

    deploy_domain: str = "deploy.hyrule.host"

    # Canonical public origin used for x402 ResourceInfo URLs in 402 responses.
    # Behind the Caddy TLS proxy the raw request URL is http://<backend>, which
    # is the wrong canonical resource identity for Bazaar/x402scan indexing.
    public_base_url: str = "https://cloud.hyrule.host"

    # Launch guard: when true, the app refuses to start unless real XCP-NG
    # provisioning is enabled (HCP_LAUNCH_PROOF_REAL_XCPNG=1) and the payment
    # dev bypass is disabled. Set in production so a config regression can
    # never silently charge real USDC for simulated VMs.
    require_real_provisioning: bool = False

    # Block H (Wave 5): Prometheus on `mon` for /v1/stats/network fleet truth.
    # Empty = static fallback (CI / local dev).
    prometheus_url: str = ""

    # Bearer token mon's Prometheus presents to scrape /metrics (payments
    # ledger aggregates). Empty = endpoint disabled; 8402 is publicly
    # reachable behind Caddy, so never expose the exporter unauthenticated.
    metrics_token: str = ""

    # Internal Go sidecar for x402-gated /v1/network/request execution.
    # Hyrule Cloud verifies/settles x402; the sidecar performs egress.
    network_proxy_url: str = "http://127.0.0.1:8450"
    network_proxy_token: str = ""
    network_proxy_health_ttl_seconds: int = 15

    # Reverse-SSH tunnel daemon (hyrule-tunnel-proxy), co-located on netproxy.
    # Cloud verifies/settles x402 and mints leases via this internal control API.
    tunnel_proxy_url: str = "http://127.0.0.1:8452"
    tunnel_proxy_token: str = ""
    tunnel_proxy_health_ttl_seconds: int = 15
    tunnel_min_hours: int = 1
    tunnel_max_hours: int = 720
    tunnel_grace_period_minutes: int = 15
    # Public endpoint advertised for tunnels (matches the daemon's config).
    tunnel_endpoint_host: str = "tun.hyrule.host"
    # STUN test target for the /v1/voip/check STUN arm; empty keeps it stubbed.
    stun_test_host: str = ""

    # Block F (Wave 5): origin bound into wallet-recovery challenges. Per-env so
    # staging / alternate domains emit a matching origin without a code change.
    recovery_origin: str = "https://hyrule.host"

    # DNS (RFC 2136)
    dns_server: str = ""
    dns_tsig_key: str = ""
    dns_tsig_algo: str = "hmac-sha256"

    # VM lifecycle
    vm_grace_period_hours: int = 48
    max_paid_active_vms: int = 0
    max_duration_days: int = 365
    max_ports: int = 10
    blocked_ports: list[int] = Field(
        default_factory=lambda: [25, 465, 587]
    )

    # Cloud-init template directory
    templates_dir: Path = Path("templates")

    # Customer VM IPv6 allocation. The current customer L2 is one shared
    # XCP-NG network, so Hyrule injects static guest network-config instead of
    # relying on RA/DHCPv6.
    customer_ipv6_supernet: str = "2a0c:b641:b51::/48"
    customer_ipv6_gateway: str = "2a0c:b641:b51::1"
    customer_ipv6_dns: str = "2a0c:b641:b51::1"

    # Network intelligence / BGP data storage
    bgp_data_enabled: bool = True
    bgp_data_dir: Path = Path("/var/lib/hyrule-cloud/bgp")
    bgp_ingest_token: str = ""

    # Database (Postgres)
    database_url: str = "postgresql+asyncpg://hyrule:hyrule@localhost/hyrule"

    # --- Block A1 / B (Wave 2): auth + metrics ---
    # 32-byte hex; if blank, sessions still work but per-IP pepper is
    # process-local (rotates on restart). Vault populates in production.
    ip_prefix_pepper: str = ""

    # --- Feature flags: Wave 2 schema lands ahead of feature code, gated
    # by these so the dormant code paths can't accidentally activate.
    # Flipped to true in the Wave that ships the corresponding feature:
    #   HYR_FEATURES_API_KEYS         — Wave 3 (Block D)
    #   HYR_FEATURES_INTENT_ENGINE    — Wave 4 (Block E)
    #   HYR_FEATURES_WALLET_RECOVERY  — Wave 5 (Block F)
    features_api_keys: bool = False
    features_intent_engine: bool = False
    features_wallet_recovery: bool = False

    # Sub-configs
    xcpng: XCPNGConfig = Field(default_factory=XCPNGConfig)
    openprovider: OpenproviderConfig = Field(default_factory=OpenproviderConfig)
    domain: DomainConfig = Field(default_factory=DomainConfig)
    payment: PaymentConfig = Field(default_factory=PaymentConfig)
