"""
Hyrule Cloud configuration.

All secrets and tunables loaded from environment variables or .env file.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    network: str = "eip155:8453"
    asset: str = "USDC"

    price_vm_xs: Decimal = Decimal("0.05")
    price_vm_sm: Decimal = Decimal("0.10")
    price_vm_md: Decimal = Decimal("0.20")
    price_vm_lg: Decimal = Decimal("0.40")
    price_vpn: Decimal = Decimal("0.02")
    price_domain_markup: Decimal = Decimal("1.00")

    # Dev bypass: set to a non-empty string to allow skipping payment
    # via X-DEV-BYPASS header. NEVER set in production.
    dev_bypass_secret: str = ""


class HyruleConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HYRULE_", env_file=".env", extra="ignore")

    deploy_domain: str = "deploy.servify.network"

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
