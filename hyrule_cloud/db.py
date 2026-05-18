from __future__ import annotations



from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    DateTime,
    Enum,
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

from hyrule_cloud.models import DomainMode, VMSize, VMStatus, CryptoIntentStatus


class Base(AsyncAttrs, DeclarativeBase):
    pass


class VMRow(Base):
    """Persistent VM record."""

    __tablename__ = "vms"

    # Primary key is our generated vm_id (e.g. "vm_a1b2c3d4e5f6")
    vm_id: Mapped[str] = mapped_column(String(32), primary_key=True)

    # XCP-NG reference
    xcpng_uuid: Mapped[str | None] = mapped_column(String(64))

    # Ownership
    owner_wallet: Mapped[str] = mapped_column(String(64), index=True)

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
        ARRAY(Integer),
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
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Error tracking
    error: Mapped[str | None] = mapped_column(Text)

    # Payment
    payment_tx: Mapped[str | None] = mapped_column(String(128))
    cost_total: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal("0"))

    # Block A0: sha256 of the cleartext anon management token. NULL for
    # legacy pre-A0 rows (those are status-only — management routes refuse
    # them until claimed). Indexed for the rare lookup-by-token reverse
    # path (we always lookup by vm_id; token-only lookup would be ambiguous
    # and is not implemented).
    anon_management_token_hash: Mapped[str | None] = mapped_column(
        String(64), index=True,
    )

    # Extensible metadata
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB)

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
    """Tracking for native crypto payment intents."""

    __tablename__ = "crypto_intents"

    intent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset: Mapped[str] = mapped_column(String(8))
    amount_crypto: Mapped[Decimal] = mapped_column(Numeric(24, 12))
    amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6))
    address: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(
        Enum(CryptoIntentStatus, name="crypto_intent_status", create_constraint=True, values_callable=lambda e: [m.value for m in e]),
        default=CryptoIntentStatus.PENDING,
    )
    bip32_index: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tx_hash: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        Index("ix_crypto_intents_status_expires", "status", "expires_at"),
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
import string

def generate_account_id():
    return ''.join(secrets.choice(string.ascii_uppercase) for _ in range(10))

class AccountRow(Base):
    __tablename__ = "accounts"
    account_id: Mapped[str] = mapped_column(String(10), primary_key=True, default=generate_account_id)
    api_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
