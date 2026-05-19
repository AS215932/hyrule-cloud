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
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Portable JSON: PG gets ARRAY(Integer) / JSONB for performance; SQLite (tests
# only — production is always Postgres) falls back to generic JSON columns.
# This keeps production schema unchanged while letting unit tests use an
# in-memory engine without testcontainers.
_INT_ARRAY = ARRAY(Integer).with_variant(JSON(), "sqlite")
_JSONB = JSONB().with_variant(JSON(), "sqlite")

from hyrule_cloud.models import CryptoIntentStatus, DomainMode, VMSize, VMStatus


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
        Enum(VMStatus, name="vm_status", create_constraint=True, values_callable=lambda e: [m.value for m in e]),
        default=VMStatus.PROVISIONING,
    )
    size: Mapped[str] = mapped_column(
        Enum(VMSize, name="vm_size", create_constraint=True, values_callable=lambda e: [m.value for m in e]),
        default=VMSize.XS,
    )
    os: Mapped[str] = mapped_column(String(64), default="debian-13")
    ipv6: Mapped[str | None] = mapped_column(String(64))
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
        Enum(DomainMode, name="domain_mode", create_constraint=True, values_callable=lambda e: [m.value for m in e]),
        default=DomainMode.AUTO,
    )
    domain: Mapped[str | None] = mapped_column(String(256))

    # Lifecycle timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    # Block B: stamped by the orchestrator when status flips to READY. The
    # /v1/stats/runtime endpoint averages (provisioned_at - created_at) over
    # the most recent rows so the homepage can show a live "avg provision"
    # number instead of a hardcoded ~60s.
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
    )


class DomainRow(Base):
    """Registered domain tracking."""

    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    extension: Mapped[str] = mapped_column(String(32))
    fqdn: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    owner_wallet: Mapped[str] = mapped_column(String(64), index=True)
    openprovider_id: Mapped[int | None] = mapped_column()
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payment_tx: Mapped[str | None] = mapped_column(String(128))


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
        Enum(CryptoIntentStatus, name="crypto_intent_status", create_constraint=True, values_callable=lambda e: [m.value for m in e]),
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
    # Rate at intent creation; payment must arrive before rate_valid_until OR
    # qualify under the LENIENT re-quote rule (see providers/native_crypto.py).
    rate_snapshot: Mapped[Decimal | None] = mapped_column(Numeric(20, 8))
    rate_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confirmations: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # What actually landed on-chain — may differ from amount_crypto (over/under-pay).
    amount_received_crypto: Mapped[Decimal | None] = mapped_column(Numeric(24, 12))
    # Exactly-once provisioning trigger: orchestrator pickup is gated by an
    # atomic UPDATE ... WHERE provisioning_triggered_at IS NULL RETURNING.
    provisioning_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # XMR-specific: subaddress index inside the view-only wallet account.
    xmr_subaddr_index: Mapped[int | None] = mapped_column(Integer, unique=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Account ownership (A1 parity) — set when intent was created from a logged-in session.
    owner_account_id: Mapped[str | None] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="SET NULL"), index=True
    )
    # Once provisioned, link back to the VM created on settlement.
    vm_id: Mapped[str | None] = mapped_column(String(32), index=True)
    # One-shot reveal: cleartext anon-management token created at provision time.
    # The next successful GET /v1/intent/{id} returns this AND nulls the column,
    # mirroring the A0 anon-checkout reveal pattern. Sha256 lives on VMRow.
    anon_token_cleartext: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_crypto_intents_status_expires", "status", "expires_at"),
        Index("ix_crypto_intents_asset_bip32", "asset", "bip32_index"),
    )


# --- Session factory ---


def create_db_engine(database_url: str):
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


def create_session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine) -> None:
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


class SessionRow(Base):
    """Opaque session token. Server-side, revocable. Cookie value is sha256-hashed at rest."""

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(11), ForeignKey("accounts.account_id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
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


# Block F (Wave 5) will add RecoveryChallengeRow here for wallet-signature
# password recovery. Wave 2 ships only the code-based recovery path, which
# does not need a server-side nonce store.
