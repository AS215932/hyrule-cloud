from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Portable JSON: PG gets ARRAY(Integer) / JSONB for performance; SQLite (tests
# only — production is always Postgres) falls back to generic JSON columns.
# This keeps production schema unchanged while letting unit tests use an
# in-memory engine without testcontainers.
_INT_ARRAY = ARRAY(Integer).with_variant(JSON(), "sqlite")
_JSONB = JSONB().with_variant(JSON(), "sqlite")

from hyrule_cloud.models import (
    CryptoIntentStatus,
    DomainMode,
    DomainStatus,
    QuoteStatus,
    VMSize,
    VMStatus,
)


class Base(AsyncAttrs, DeclarativeBase):
    pass


class VMRow(Base):
    """Persistent VM record."""

    __tablename__ = "vms"

    # Primary key is our generated vm_id. New IDs: vm_<22 base62> (~131 bits).
    # Legacy: vm_<12 hex>. Column width covers both.
    vm_id: Mapped[str] = mapped_column(String(32), primary_key=True)

    # XCP-NG reference
    xcpng_uuid: Mapped[str | None] = mapped_column(String(64))

    # Ownership
    owner_wallet: Mapped[str] = mapped_column(String(64), index=True)

    # Account ownership (Block A1). When set, account auth supersedes
    # anon_management_token — the can_manage_vm helper checks account first.
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )

    # Anon-checkout management token (sha256 hex of the cleartext secret).
    # NULL on legacy VMs (created before A0) → management actions denied until claimed.
    # When an account claims a VM, this is rotated to NULL (account ownership supersedes).
    # When an account is detach-deleted, a fresh token is issued and shown to the user once.
    anon_management_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)

    # VM configuration
    status: Mapped[str] = mapped_column(
        Enum(
            VMStatus,
            name="vm_status",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=VMStatus.PROVISIONING,
    )
    size: Mapped[str] = mapped_column(
        Enum(
            VMSize,
            name="vm_size",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=VMSize.XS,
    )
    # Exact provisioned resources. Nullable at the ORM level so databases can
    # roll through the migration safely; migration 016 backfills every legacy
    # row before new writes begin.
    vcpu: Mapped[int | None] = mapped_column(Integer)
    memory_mb: Mapped[int | None] = mapped_column(Integer)
    disk_gb: Mapped[int | None] = mapped_column(Integer)
    # Add-on quantities are stored independently from exact resources. This is
    # what lets extensions use current catalog rates without reinterpreting
    # legacy machines (including retired 80-GB disks) as newly purchased add-ons.
    billing_addon_vcpu: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    billing_addon_ram_mb: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    billing_addon_disk_gb: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    os: Mapped[str] = mapped_column(String(64), default="debian-13")
    ipv6: Mapped[str | None] = mapped_column(String(64))
    ipv6_prefix_index: Mapped[int | None] = mapped_column(Integer)
    ipv6_prefix: Mapped[str | None] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(256))
    ssh_pubkey: Mapped[str] = mapped_column(Text, default="")

    # Firewall
    open_ports: Mapped[list[int]] = mapped_column(
        _INT_ARRAY,
        default=list,
    )

    # Optional setup script
    setup_script: Mapped[str | None] = mapped_column(Text)

    # Domain
    domain_mode: Mapped[str] = mapped_column(
        Enum(
            DomainMode,
            name="domain_mode",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=DomainMode.AUTO,
    )
    domain: Mapped[str | None] = mapped_column(String(256))

    # Lifecycle timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    # Issue #51: stamped when background provisioning actually begins.
    # created_at can predate settlement by hours (native crypto intents wait
    # for deposits; reservations predate payment), so the runtime stats must
    # measure the provision window from here, never from row birth.
    provision_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Block B: stamped by the orchestrator when status flips to READY. The
    # /v1/stats/runtime endpoint reports the median of
    # (provisioned_at - provision_started_at) over the most recent rows so the
    # homepage can show a live "avg provision" number instead of a hardcoded ~60s.
    provisioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Error tracking
    error: Mapped[str | None] = mapped_column(Text)

    # Payment
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    cost_total: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal("0"))

    # Extensible metadata
    metadata_: Mapped[dict | None] = mapped_column("metadata", _JSONB)

    __table_args__ = (
        Index("ix_vms_status_expires", "status", "expires_at"),
        Index("ix_vms_owner_status", "owner_wallet", "status"),
        Index("ix_vms_ipv6_prefix_index", "ipv6_prefix_index", unique=True),
        Index("ix_vms_ipv6_prefix", "ipv6_prefix", unique=True),
    )


class DomainRow(Base):
    """Registered domain tracking."""

    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    extension: Mapped[str] = mapped_column(String(32))
    fqdn: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    # Address written by the VM attachment flow. Keeping it separately lets
    # detach distinguish Hyrule's managed apex AAAA from a customer edit.
    vm_ipv6: Mapped[str | None] = mapped_column(String(64))
    owner_wallet: Mapped[str] = mapped_column(String(64), index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    anon_management_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(
        Enum(
            DomainStatus,
            name="domain_status",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=DomainStatus.REGISTERING,
    )
    client_order_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    openprovider_id: Mapped[int | None] = mapped_column()
    registrar_price: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    markup: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    total_price: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    currency: Mapped[str] = mapped_column(String(8), default="USD", server_default="USD")
    error: Mapped[str | None] = mapped_column(Text)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_tx: Mapped[str | None] = mapped_column(String(128))

    # Managed-domain v1 lifecycle. The registrar remains OpenProvider while
    # authoritative records live on Hyrule's Knot pair.
    provider_status: Mapped[str | None] = mapped_column(String(32))
    provider_operation_id: Mapped[str | None] = mapped_column(String(128))
    nameserver_mode: Mapped[str] = mapped_column(
        String(16), default="managed", server_default="managed"
    )
    nameservers: Mapped[list] = mapped_column(_JSONB, default=list)
    dnssec_mode: Mapped[str] = mapped_column(
        String(16), default="managed", server_default="managed"
    )
    dnssec_status: Mapped[str] = mapped_column(
        String(32), default="pending", server_default="pending"
    )
    ds_records: Mapped[list] = mapped_column(_JSONB, default=list)
    zone_revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    can_renew: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    transferred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_domains_status", "status"),)


class DomainTLDRow(Base):
    """Cached intersection of OpenProvider and IANA TLD metadata."""

    __tablename__ = "domain_tlds"

    tld: Mapped[str] = mapped_column(String(63), primary_key=True)
    iana_type: Mapped[str | None] = mapped_column(String(32), index=True)
    provider_status: Mapped[str | None] = mapped_column(String(32))
    eligible: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ineligible_reason: Mapped[str | None] = mapped_column(String(128))
    registration_cost: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    renewal_cost: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    currency: Mapped[str | None] = mapped_column(String(8))
    metadata_: Mapped[dict | None] = mapped_column("metadata", _JSONB)
    refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class DomainQuoteRow(Base):
    __tablename__ = "domain_quotes"

    quote_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    fqdn: Mapped[str] = mapped_column(String(253), index=True)
    action: Mapped[str] = mapped_column(String(16), index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    provider_cost: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    provider_currency: Mapped[str] = mapped_column(String(8))
    fx_rate: Mapped[Decimal] = mapped_column(Numeric(20, 10))
    provider_cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    hyrule_fee_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    tax_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal("0"))
    total_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    available: Mapped[bool] = mapped_column(Boolean)
    premium: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_snapshot: Mapped[dict | None] = mapped_column(_JSONB)
    terms_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DomainOrderRow(Base):
    __tablename__ = "domain_orders"

    order_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    quote_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("domain_quotes.quote_id", ondelete="RESTRICT"), index=True
    )
    fqdn: Mapped[str] = mapped_column(String(253), index=True)
    action: Mapped[str] = mapped_column(String(16), index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="RESTRICT"), index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128))
    # Wallet-native orders have no Hyrule account. The high-entropy capability
    # token is returned once and only its hash is used for later reads.
    management_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    management_token_ciphertext: Mapped[str | None] = mapped_column(Text)
    agent_idempotency_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="awaiting_payment", index=True)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    domain_amount_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    vm_amount_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal("0"))
    service_amount_usd: Mapped[Decimal] = mapped_column(
        Numeric(12, 6), default=Decimal("0"), server_default="0"
    )
    payment_method: Mapped[str] = mapped_column(String(8))
    payment_network: Mapped[str | None] = mapped_column(String(64))
    payment_asset: Mapped[str | None] = mapped_column(String(66))
    payer: Mapped[str | None] = mapped_column(String(128))
    payment_tx: Mapped[str | None] = mapped_column(String(128), index=True)
    payment_settlement_pending_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_authorization_fingerprint: Mapped[str | None] = mapped_column(String(64))
    payment_authorization_header: Mapped[str | None] = mapped_column(Text)
    refund_address: Mapped[str | None] = mapped_column(String(128))
    native_intent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("crypto_intents.intent_id", ondelete="SET NULL"), index=True
    )
    operation_id: Mapped[str | None] = mapped_column(String(32), index=True)
    provider_domain_id: Mapped[int | None] = mapped_column(Integer)
    provider_status: Mapped[str | None] = mapped_column(String(32))
    provider_response: Mapped[dict | None] = mapped_column(_JSONB)
    vm_quote_id: Mapped[str | None] = mapped_column(String(36), index=True)
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    on_domain_failure: Mapped[str] = mapped_column(
        String(24), default="keep_vm", server_default="keep_vm"
    )
    terms_version: Mapped[str] = mapped_column(String(64))
    terms_accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "owner_account_id", "idempotency_key", name="uq_domain_orders_account_idempotency"
        ),
        UniqueConstraint(
            "payment_authorization_fingerprint",
            name="uq_domain_orders_payment_authorization",
        ),
    )


class DomainOperationRow(Base):
    __tablename__ = "domain_operations"

    operation_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    fqdn: Mapped[str] = mapped_column(String(253), index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="CASCADE"), index=True
    )
    order_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("domain_orders.order_id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    request_payload: Mapped[dict | None] = mapped_column(_JSONB)
    result_payload: Mapped[dict | None] = mapped_column(_JSONB)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(Text)
    secret_ciphertext: Mapped[str | None] = mapped_column(Text)
    secret_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    secret_revealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DomainDNSRecordRow(Base):
    __tablename__ = "domain_dns_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fqdn: Mapped[str] = mapped_column(
        String(253), ForeignKey("domains.fqdn", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(253))
    type: Mapped[str] = mapped_column(String(16))
    ttl: Mapped[int] = mapped_column(Integer)
    values: Mapped[list] = mapped_column(_JSONB, default=list)
    # Lets product integrations merge and later remove only the RRsets they
    # own without clobbering records created by the customer or another service.
    managed_by: Mapped[str] = mapped_column(
        String(32), default="customer", server_default="customer"
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("fqdn", "name", "type", name="uq_domain_dns_rrset"),)


class DomainIdempotencyRow(Base):
    """Stored response for synchronous, account-scoped domain mutations."""

    __tablename__ = "domain_idempotency"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_account_id: Mapped[str] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    response_payload: Mapped[dict] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    __table_args__ = (
        UniqueConstraint(
            "owner_account_id",
            "kind",
            "idempotency_key",
            name="uq_domain_idempotency_account_kind_key",
        ),
    )


class DomainJobRow(Base):
    __tablename__ = "domain_jobs"

    job_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    resource_id: Mapped[str] = mapped_column(String(64), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(160), unique=True)
    payload: Mapped[dict | None] = mapped_column(_JSONB)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    locked_by: Mapped[str | None] = mapped_column(String(128))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AccountWalletRow(Base):
    __tablename__ = "account_wallets"

    wallet_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="CASCADE"), unique=True, index=True
    )
    address: Mapped[str] = mapped_column(String(42), unique=True, index=True)
    chain_id: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WalletChallengeRow(Base):
    __tablename__ = "wallet_challenges"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    action: Mapped[str] = mapped_column(String(24), index=True)
    address: Mapped[str] = mapped_column(String(42), index=True)
    chain_id: Mapped[int] = mapped_column(Integer)
    account_id: Mapped[str | None] = mapped_column(String(11), index=True)
    resource: Mapped[str | None] = mapped_column(String(253), index=True)
    message: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OpenproviderWebhookRow(Base):
    __tablename__ = "openprovider_webhooks"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_type: Mapped[str | None] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(_JSONB)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VPNTunnelRow(Base):
    """WireGuard VPN tunnel tracking."""

    __tablename__ = "vpn_tunnels"

    tunnel_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    owner_wallet: Mapped[str] = mapped_column(String(64), index=True)
    wg_pubkey: Mapped[str] = mapped_column(String(64))
    wg_endpoint: Mapped[str | None] = mapped_column(String(128))
    wg_config: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_tx: Mapped[str | None] = mapped_column(String(128))


class CryptoIntentRow(Base):
    """Tracking for native crypto payment intents (BTC/XMR).

    Block E expanded this from a simple PENDING/PAID/EXPIRED row to a full
    state machine with idempotency, rate snapshots, and the order payload
    carried through to provisioning.
    """

    __tablename__ = "crypto_intents"

    intent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset: Mapped[str] = mapped_column(String(8))
    amount_crypto: Mapped[Decimal] = mapped_column(Numeric(24, 12))
    amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    address: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(
        Enum(
            CryptoIntentStatus,
            name="crypto_intent_status",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=CryptoIntentStatus.CREATED,
    )
    bip32_index: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tx_hash: Mapped[str | None] = mapped_column(String(128))

    # --- Block E additions ---
    # Idempotency key from client; same key returns the same intent on POST.
    client_order_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    # Full VM creation spec carried through to the orchestrator on settlement.
    order_payload: Mapped[dict | None] = mapped_column(_JSONB)
    # Server-generated VM pricing snapshot. NULL identifies an intent created
    # before configurable resources shipped; those rows retain zero add-ons.
    pricing_snapshot: Mapped[dict | None] = mapped_column(_JSONB)
    # Rate at intent creation; payment must arrive before rate_valid_until OR
    # qualify under the LENIENT re-quote rule (see providers/native_crypto.py).
    rate_snapshot: Mapped[Decimal | None] = mapped_column(Numeric(20, 8))
    rate_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confirmations: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # What actually landed on-chain — may differ from amount_crypto (over/under-pay).
    amount_received_crypto: Mapped[Decimal | None] = mapped_column(Numeric(24, 12))
    # Exactly-once provisioning trigger: orchestrator pickup is gated by an
    # atomic UPDATE ... WHERE provisioning_triggered_at IS NULL RETURNING. A
    # stale VM handoff also advances this timestamp as its recovery lease.
    provisioning_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # XMR-specific: subaddress index inside the view-only wallet account.
    xmr_subaddr_index: Mapped[int | None] = mapped_column(Integer, unique=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Account ownership (A1 parity) — set when intent was created from a logged-in session.
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    # Replay-safe planned VM id, persisted before settlement reservation; once
    # provisioned it remains the link to the created VM.
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    # One-shot reveal: cleartext anon-management token created at provision time.
    # The next successful GET /v1/intent/{id} returns this AND nulls the column,
    # mirroring the A0 anon-checkout reveal pattern. Sha256 lives on VMRow.
    anon_token_cleartext: Mapped[str | None] = mapped_column(String(64))
    # Generic resource binding. Legacy rows default to VM; domain orders use
    # the same monitored receive-address machinery without pretending to be a
    # VM payload.
    resource_type: Mapped[str] = mapped_column(String(32), default="vm", server_default="vm")
    resource_id: Mapped[str | None] = mapped_column(String(64), index=True)
    refund_address: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        Index("ix_crypto_intents_status_expires", "status", "expires_at"),
        Index("ix_crypto_intents_asset_bip32", "asset", "bip32_index"),
    )


class PaymentEventRow(Base):
    """Append-only x402 payment ledger.

    One row per payment-gate outcome. This is the revenue source of truth
    that /metrics and the operator dashboard aggregate — resource rows
    (VMRow.payment_tx etc.) only carry the final settlement stamp.
    """

    __tablename__ = "payment_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    # required_402 | verify_failed | settle_failed | settled | dev_bypass
    event_type: Mapped[str] = mapped_column(String(16), index=True)
    resource_path: Mapped[str] = mapped_column(String(256))
    method: Mapped[str] = mapped_column(String(8))
    # vm | domain | network_proxy | network_intel | mail | other (from path)
    service_group: Mapped[str] = mapped_column(String(24), index=True)
    amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    # CAIP-2; solana:<genesis-hash> exceeds 32 chars, so size for the family
    network: Mapped[str | None] = mapped_column(String(64))
    asset: Mapped[str | None] = mapped_column(String(66))  # token address or symbol
    payer_wallet: Mapped[str | None] = mapped_column(String(64), index=True)
    tx_hash: Mapped[str | None] = mapped_column(String(128))
    facilitator_host: Mapped[str | None] = mapped_column(String(64))
    error_reason: Mapped[str | None] = mapped_column(String(256))
    extra: Mapped[dict | None] = mapped_column(_JSONB)

    __table_args__ = (Index("ix_payment_events_type_created", "event_type", "created_at"),)


class VMQuoteRow(Base):
    """Durable order quote (issue #14).

    The single order object the UI and agents pay against: priced once at
    creation, it survives review-page reloads and mobile wallet handoffs via its
    `quote_id`. Mirrors the CryptoIntentRow idempotency + order_payload pattern.

    Lifecycle: created → consumed (a VM was provisioned) | expired (TTL).
    """

    __tablename__ = "vm_quotes"

    quote_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # Full VM creation spec (a VMCreateRequest dump) carried through to create.
    order_payload: Mapped[dict] = mapped_column(_JSONB)
    # Price locked at quote creation; the 402 challenge uses this, not a recompute.
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    # Immutable, server-generated daily/base/add-on breakdown shown on review
    # pages and copied to native intents. NULL means a migrated legacy quote.
    pricing_snapshot: Mapped[dict | None] = mapped_column(_JSONB)
    status: Mapped[str] = mapped_column(
        Enum(
            QuoteStatus,
            name="vm_quote_status",
            create_constraint=True,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=QuoteStatus.CREATED,
    )
    # Idempotency key from the client; same key + same spec returns the same quote.
    client_order_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    # Account ownership (A1 parity) — set when created from a logged-in session.
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    # Set when the quote is consumed (links to the provisioned VM).
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_vm_quotes_status_expires", "status", "expires_at"),)


# --- Network intelligence / BGP / MX / Agent Mail tables ---


class BGPSourceStatusRow(Base):
    __tablename__ = "bgp_source_status"

    source_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown")
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict | None] = mapped_column(_JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BGPLookupCacheRow(Base):
    __tablename__ = "bgp_lookup_cache"

    cache_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(32), index=True)
    subject_value: Mapped[str] = mapped_column(String(256), index=True)
    request_hash: Mapped[str] = mapped_column(String(64), index=True)
    response: Mapped[dict] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class BGPSnapshotRow(Base):
    __tablename__ = "bgp_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    router: Mapped[str | None] = mapped_column(String(64), index=True)
    asn: Mapped[int | None] = mapped_column(Integer, index=True)
    prefix: Mapped[str | None] = mapped_column(String(128), index=True)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    artifact_format: Mapped[str | None] = mapped_column(String(64))
    sha256: Mapped[str | None] = mapped_column(String(64))
    compressed_size_bytes: Mapped[int | None] = mapped_column(Integer)
    payload: Mapped[dict | None] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class BGPJobRow(Base):
    __tablename__ = "bgp_jobs"

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    owner_wallet: Mapped[str | None] = mapped_column(String(64), index=True)
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    access_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    query: Mapped[dict] = mapped_column(_JSONB)
    price_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    claimed_by: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_snapshot_id: Mapped[str | None] = mapped_column(String(36), index=True)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class NetworkLookupCacheRow(Base):
    __tablename__ = "network_lookup_cache"

    cache_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    service: Mapped[str] = mapped_column(String(32), index=True)
    subject: Mapped[str] = mapped_column(String(512), index=True)
    response: Mapped[dict] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class DiagnosticJobRow(Base):
    """Generic async job row for x402 diagnostic evidence packs.

    Product namespaces (/v1/web, /v1/path, /v1/threat, /v1/voip,
    etc.) share this shape so job tokens, artifacts, expiry,
    and source metadata behave consistently.
    """

    __tablename__ = "diagnostic_jobs"

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    service: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str | None] = mapped_column(String(512), index=True)
    owner_wallet: Mapped[str | None] = mapped_column(String(64), index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    access_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    request: Mapped[dict] = mapped_column(_JSONB)
    result: Mapped[dict | None] = mapped_column(_JSONB)
    sources: Mapped[dict | None] = mapped_column(_JSONB)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    artifact_format: Mapped[str | None] = mapped_column(String(64))
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_size_bytes: Mapped[int | None] = mapped_column(Integer)
    price_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (
        Index("ix_diagnostic_jobs_service_status", "service", "status"),
        Index("ix_diagnostic_jobs_kind_status", "kind", "status"),
    )


class MXJobRow(Base):
    __tablename__ = "mx_jobs"

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    profile: Mapped[str] = mapped_column(String(64))
    owner_wallet: Mapped[str | None] = mapped_column(String(64), index=True)
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    access_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    request: Mapped[dict] = mapped_column(_JSONB)
    result: Mapped[dict | None] = mapped_column(_JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class MailAccountRow(Base):
    __tablename__ = "mail_accounts"

    mailbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    owner_wallet: Mapped[str | None] = mapped_column(String(64), index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    management_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    management_token_ciphertext: Mapped[str | None] = mapped_column(Text)
    plan: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    display_name: Mapped[str | None] = mapped_column(String(128))
    features: Mapped[dict | None] = mapped_column(_JSONB)
    backend: Mapped[str | None] = mapped_column(String(64))
    backend_id: Mapped[str | None] = mapped_column(String(128))
    backend_credential_ciphertext: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(253), index=True)
    local_part: Mapped[str | None] = mapped_column(String(64))
    domain_order_id: Mapped[str | None] = mapped_column(String(32), index=True)
    domain_authority_hash: Mapped[str | None] = mapped_column(String(64))
    quote_id: Mapped[str | None] = mapped_column(String(36), index=True)
    idempotency_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    terms_version: Mapped[str | None] = mapped_column(String(64))
    activation_amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    total_amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    capacity_reserved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    provision_claim_token: Mapped[str | None] = mapped_column(String(64))
    provision_claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    provision_retry_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    provision_next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    dns_cleanup_pending: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", index=True
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    grace_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provision_error: Mapped[str | None] = mapped_column(Text)
    suspended_reason: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    payment_network: Mapped[str | None] = mapped_column(String(64))
    payment_asset: Mapped[str | None] = mapped_column(String(66))
    payment_settlement_pending_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    payment_authorization_header: Mapped[str | None] = mapped_column(Text)


class MailDomainRow(Base):
    __tablename__ = "mail_domains"

    domain_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), index=True)
    required_dns: Mapped[list | None] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MailAliasRow(Base):
    __tablename__ = "mail_aliases"

    alias_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    destination: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MailIdentityRow(Base):
    __tablename__ = "mail_identities"

    identity_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    address: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str | None] = mapped_column(String(128))
    reply_to: Mapped[str | None] = mapped_column(String(320))
    verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MailAPIKeyRow(Base):
    __tablename__ = "mail_api_keys"

    key_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(64))
    scopes: Mapped[list] = mapped_column(_JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MailWebhookRow(Base):
    __tablename__ = "mail_webhooks"

    webhook_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    url: Mapped[str] = mapped_column(Text)
    events: Mapped[list] = mapped_column(_JSONB, default=list)
    secret_hash: Mapped[str | None] = mapped_column(String(64))
    secret_ciphertext: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    failure_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MailEventRow(Base):
    __tablename__ = "mail_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    message_id: Mapped[str | None] = mapped_column(String(128), index=True)
    payload: Mapped[dict | None] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class MailQuoteRow(Base):
    """Immutable, short-lived price and request snapshot.

    Send payloads are locked into their quote so the paid retry cannot switch
    recipients or content after the x402 amount was challenged.
    """

    __tablename__ = "mail_quotes"

    quote_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    mailbox_id: Mapped[str | None] = mapped_column(String(36), index=True)
    address: Mapped[str | None] = mapped_column(String(320), index=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    request_payload: Mapped[dict] = mapped_column(_JSONB)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6))
    domain_quote_id: Mapped[str | None] = mapped_column(String(32), index=True)
    terms_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MailRecipientRow(Base):
    __tablename__ = "mail_recipients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    recipient: Mapped[str] = mapped_column(String(320))
    first_sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("mailbox_id", "recipient", name="uq_mail_recipient_mailbox_address"),
    )


class MailSendRow(Base):
    __tablename__ = "mail_sends"

    send_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    quote_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    recipient: Mapped[str] = mapped_column(String(320), index=True)
    message_id: Mapped[str | None] = mapped_column(String(128), index=True)
    in_reply_to: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    amount_usd: Mapped[Decimal] = mapped_column(
        Numeric(12, 6), default=Decimal("0"), server_default="0"
    )
    payment_payer: Mapped[str | None] = mapped_column(String(64))
    payment_network: Mapped[str | None] = mapped_column(String(64))
    payment_asset: Mapped[str | None] = mapped_column(String(66))
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    payment_authorization_header: Mapped[str | None] = mapped_column(Text)
    payment_settlement_pending_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    error: Mapped[str | None] = mapped_column(Text)
    submission_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MailPaymentAuthorizationRow(Base):
    """Durable binding from one x402 authorization to one mail quote."""

    __tablename__ = "mail_payment_authorizations"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    quote_id: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    __table_args__ = (UniqueConstraint("quote_id", name="uq_mail_payment_authorization_quote"),)


class MailWebhookDeliveryRow(Base):
    __tablename__ = "mail_webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    webhook_id: Mapped[str] = mapped_column(String(36), index=True)
    event_id: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("webhook_id", "event_id", name="uq_mail_webhook_event"),)


class MailDeliveryLogRow(Base):
    __tablename__ = "mail_delivery_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    message_id: Mapped[str | None] = mapped_column(String(128), index=True)
    direction: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), index=True)
    remote: Mapped[str | None] = mapped_column(String(320))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class MailMessageIndexRow(Base):
    __tablename__ = "mail_message_index"

    mailbox_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    message_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    folder: Mapped[str] = mapped_column(String(64), index=True)
    sender: Mapped[str | None] = mapped_column(String(320))
    recipients: Mapped[list | None] = mapped_column(_JSONB)
    subject: Mapped[str | None] = mapped_column(Text)
    flags: Mapped[list | None] = mapped_column(_JSONB)
    has_attachments: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class MailQuarantineRow(Base):
    __tablename__ = "mail_quarantine"

    quarantine_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(36), index=True)
    message_id: Mapped[str] = mapped_column(String(128), index=True)
    reason: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict | None] = mapped_column(_JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# --- Session factory ---


def create_db_engine(database_url: str) -> AsyncEngine:
    """
    Create an async SQLAlchemy engine.

    For Postgres: postgresql+asyncpg://user:pass@host/db
    For dev/test: sqlite+aiosqlite:///hyrule.db
    """
    return create_async_engine(
        database_url,
        echo=False,
        pool_size=10,
        max_overflow=20,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    """Create all tables. Use Alembic migrations in production."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


import secrets


def generate_account_id() -> str:
    """H<10 hex chars> ≈ 41 bits. Random, no PII, no username collisions across users.

    Accounts are addressed by this opaque id; there is no concept of a chosen
    handle in v1 (see plan: no PII, no name-squatting).
    """
    return "H" + secrets.token_hex(5).upper()


class AccountRow(Base):
    """Anonymous account. No email, no PII. Auth is account_id + password."""

    __tablename__ = "accounts"

    account_id: Mapped[str] = mapped_column(
        String(11), primary_key=True, default=generate_account_id
    )
    # argon2id. Plain sha256 is rejected even for high-entropy secrets — recovery
    # codes (see recovery_code_hash) get the same treatment.
    password_hash: Mapped[str] = mapped_column(String(256))

    # One-time recovery code (argon2id-hashed). Issued at signup, single-use,
    # rotates on consumption. The cleartext is revealed ONCE; if the user
    # loses it AND has never settled an x402 payment, the account is unrecoverable.
    recovery_code_hash: Mapped[str | None] = mapped_column(String(256))
    recovery_code_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovery_code_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


class SessionRow(Base):
    """Opaque session token. Server-side, revocable. Cookie value is sha256-hashed at rest."""

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    user_agent: Mapped[str | None] = mapped_column(String(256))
    # sha256(/64 IPv6 prefix + pepper). Abuse-only; we do not store full IPs.
    ip_prefix_hash: Mapped[str | None] = mapped_column(String(64))


class ApiKeyRow(Base):
    """Scoped API key for programmatic VM management (Block D / Wave 3).

    The cleartext bearer (`hyr_sk_<32 base62>`) is revealed exactly ONCE at
    creation and never stored. `key_hash` is sha256(cleartext); high entropy
    means a fast hash is fine (same rationale as anon management tokens).

    Scopes are an explicit JSON list of `ApiKeyScope` values. The middleware
    enforces them on every API-key-authed request; cookie sessions are
    unrestricted (a session = full account access). API keys CANNOT be used
    for password changes, recovery rotation, or account deletion — those are
    browser-only via require_browser_session. See [[feedback_security_split]].
    """

    __tablename__ = "api_keys"

    key_id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid4
    account_id: Mapped[str] = mapped_column(
        String(11),
        ForeignKey("accounts.account_id", ondelete="CASCADE"),
        index=True,
    )
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(64))
    scopes: Mapped[list] = mapped_column(_JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RecoveryAttemptRow(Base):
    """Audit + rate-limit log for password recovery attempts (both code and wallet paths)."""

    __tablename__ = "recovery_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[str | None] = mapped_column(String(11), index=True)
    method: Mapped[str] = mapped_column(String(16))  # "code" | "wallet"
    success: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    ip_prefix_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class RecoveryChallengeRow(Base):
    """Server-side nonce store for wallet-signature recovery (Block F).

    DB-backed (not in-process) so the challenge survives across workers and a
    single-use marker (`used_at`) makes replay impossible even if a signed
    message leaks. The full challenge_text is what the user signs verbatim;
    we hold it server-side so the verify endpoint never has to trust client
    framing of nonce/timestamps.
    """

    __tablename__ = "recovery_challenges"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(11), index=True)
    challenge_text: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
