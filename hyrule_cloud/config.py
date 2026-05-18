"""
Hyrule Cloud configuration.

All secrets and tunables loaded from environment variables or .env file.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# --- Block C: payment network catalog ---


@dataclass(frozen=True)
class PaymentNetwork:
    """A single payment network the API accepts for x402 settlement.

    Verified-only: a network MUST pass `scripts/verify_facilitator.py` against
    its facilitator URL before being default-enabled. See
    feedback_verified_payment_chains.md for the gating rule.

    Covers both EVM (eip155:*) and Solana (solana:*) families. EVM-specific
    fields (chain_id, eip712_domain_*) are None for SVM entries.
    """

    key: str                       # "base"
    display_name: str              # "Base"
    caip2: str                     # x402 v2 network identifier: "eip155:8453" or "solana:<genesis>"
    asset: str                     # "USDC"
    token_address: str             # Contract address (EVM) / SPL mint (Solana)
    token_decimals: int            # USDC = 6; locked to the on-chain decimals
    rpc_url: str                   # Public RPC URL; embedded in wallet_addEthereumChain / Solana cluster
    block_explorer_url: str        # Public block explorer
    chain_id: int | None = None              # EVM only — used by wallet_switchEthereumChain
    eip712_domain_name: str | None = None    # EVM only — EIP-712 domain.name (USDC = "USD Coin")
    eip712_domain_version: str | None = None # EVM only — EIP-712 domain.version
    facilitator_url: str = ""      # Per-chain facilitator override (empty = use PaymentConfig.facilitator_url)
    testnet: bool = False

    @property
    def family(self) -> str:
        """`"evm"` for eip155:*, `"svm"` for solana:*. Used to branch scheme registration + frontend dispatch."""
        prefix = self.caip2.split(":", 1)[0]
        if prefix == "eip155":
            return "evm"
        if prefix == "solana":
            return "svm"
        return "unknown"


# USDC mainnet contracts, verified against Circle's official documentation as
# of 2026-05-16. Pre-launch the smoke-test script must confirm each contract
# can settle an x402 testnet payment via Coinbase's CDP facilitator.
PAYMENT_NETWORKS_CATALOG: dict[str, PaymentNetwork] = {
    "base": PaymentNetwork(
        key="base",
        display_name="Base",
        caip2="eip155:8453",
        chain_id=8453,
        asset="USDC",
        token_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        token_decimals=6,
        eip712_domain_name="USD Coin",
        eip712_domain_version="2",
        rpc_url="https://mainnet.base.org",
        block_explorer_url="https://basescan.org",
    ),
    "polygon": PaymentNetwork(
        key="polygon",
        display_name="Polygon",
        caip2="eip155:137",
        chain_id=137,
        asset="USDC",
        # Native Circle-issued USDC (not the legacy USDC.e bridged token)
        token_address="0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
        token_decimals=6,
        eip712_domain_name="USD Coin",
        eip712_domain_version="2",
        rpc_url="https://polygon-rpc.com",
        block_explorer_url="https://polygonscan.com",
    ),
    "arbitrum": PaymentNetwork(
        key="arbitrum",
        display_name="Arbitrum One",
        caip2="eip155:42161",
        chain_id=42161,
        asset="USDC",
        token_address="0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        token_decimals=6,
        eip712_domain_name="USD Coin",
        eip712_domain_version="2",
        rpc_url="https://arb1.arbitrum.io/rpc",
        block_explorer_url="https://arbiscan.io",
    ),
    # --- Feature-flagged ---
    "world": PaymentNetwork(
        key="world",
        display_name="World Chain",
        caip2="eip155:480",
        chain_id=480,
        asset="USDC",
        # TODO(verify_facilitator): confirm USDC address on World mainnet before enabling
        token_address="0x79A02482A880bCE3F13e09Da970dC34db4CD24d1",
        token_decimals=6,
        eip712_domain_name="USD Coin",
        eip712_domain_version="2",
        rpc_url="https://worldchain-mainnet.g.alchemy.com/public",
        block_explorer_url="https://worldscan.org",
    ),
    # Solana (Block H) — CAIP-2 + USDC mint sourced from
    # x402.mechanisms.svm.constants (SDK v2.10). Settled by Coinbase CDP
    # facilitator via ExactSvmScheme (V2-only — no V1 server scheme exists).
    # Mainnet only, matching the EVM catalog's mainnet-only convention.
    # Devnet/testnet entries live as test fixtures, not in the production catalog.
    "solana": PaymentNetwork(
        key="solana",
        display_name="Solana",
        caip2="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",   # SOLANA_MAINNET_CAIP2
        asset="USDC",
        token_address="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC_MAINNET_ADDRESS
        token_decimals=6,
        rpc_url="https://api.mainnet-beta.solana.com",
        block_explorer_url="https://solscan.io",
    ),
}

# Default-enabled at v1 — per Coinbase CDP facilitator support
# (https://docs.cdp.coinbase.com/x402/network-support). Optimism, Ethereum
# mainnet, Avalanche, BSC, Linea, Gnosis, HyperEVM, Tron all deferred to a
# self-hosted facilitator path; see plan Block H.
_DEFAULT_ENABLED_KEYS: tuple[str, ...] = ("base", "polygon", "arbitrum")


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
        default_factory=lambda: ["ns1.servify.network", "ns2.servify.network"]
    )


class PaymentConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PAYMENT_", env_file=".env", extra="ignore")

    receiver_address: str = ""
    facilitator_url: str = "https://x402.org/facilitator"

    # Feature flags for non-default networks. World/Solana are deferred until
    # facilitator support is verified end-to-end on staging.
    enable_world: bool = False
    enable_svm: bool = False

    @property
    def networks(self) -> list[PaymentNetwork]:
        """The list of currently-enabled payment networks.

        Default-enabled keys are hard-coded (`_DEFAULT_ENABLED_KEYS`); feature
        flags add the rest. The PaymentGate iterates this list to register
        schemes + build the multi-chain 402 `accepts` body.
        """
        out: list[PaymentNetwork] = [PAYMENT_NETWORKS_CATALOG[k] for k in _DEFAULT_ENABLED_KEYS]
        if self.enable_world:
            out.append(PAYMENT_NETWORKS_CATALOG["world"])
        if self.enable_svm:
            out.append(PAYMENT_NETWORKS_CATALOG["solana"])
        return out

    btc_xpub: str = ""
    xmr_viewkey: str = ""

    price_vm_xs: Decimal = Decimal("0.05")
    price_vm_sm: Decimal = Decimal("0.10")
    price_vm_md: Decimal = Decimal("0.20")
    price_vm_lg: Decimal = Decimal("0.40")
    price_vpn: Decimal = Decimal("0.02")
    price_domain_markup: Decimal = Decimal("1.00")
    
    price_proxy_direct: Decimal = Decimal("0.01")
    price_proxy_tor: Decimal = Decimal("0.05")
    price_proxy_residential: Decimal = Decimal("0.20")

    # Dev bypass: set to a non-empty string to allow skipping payment
    # via X-DEV-BYPASS header. NEVER set in production.
    dev_bypass_secret: str = ""


class HyruleConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HYRULE_", env_file=".env", extra="ignore")

    deploy_domain: str = "deploy.hyrule.host"

    # Block H: Prometheus on the `mon` VM, queried by /v1/stats/network for
    # live fleet metrics (BGP peers, IPv6 prefixes, NAT64 sessions). Empty
    # disables the endpoint and serves only the static-fallback shape.
    prometheus_url: str = "http://[2a0c:b641:b50:2::50]:9090"

    # DNS (RFC 2136)
    dns_server: str = ""
    dns_tsig_key: str = ""
    dns_tsig_algo: str = "hmac-sha256"

    # VM lifecycle
    vm_grace_period_hours: int = 48
    max_duration_days: int = 365
    max_ports: int = 10
    blocked_ports: list[int] = Field(
        default_factory=lambda: [25, 465, 587]
    )

    # Cloud-init template directory
    templates_dir: Path = Path("templates")

    # Database (Postgres)
    database_url: str = "postgresql+asyncpg://hyrule:hyrule@localhost/hyrule"

    # Sub-configs
    xcpng: XCPNGConfig = Field(default_factory=XCPNGConfig)
    openprovider: OpenproviderConfig = Field(default_factory=OpenproviderConfig)
    payment: PaymentConfig = Field(default_factory=PaymentConfig)
