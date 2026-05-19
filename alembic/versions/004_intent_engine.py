"""native crypto intent engine: state machine + idempotency + ownership link

Block E. Expands `CryptoIntentRow` from the toy PENDING/PAID/EXPIRED shape
into the full LENIENT-policy state machine: CREATED → WAITING_PAYMENT →
SETTLED → PROVISIONING → PROVISIONED, plus UNDERPAID/OVERPAID/LATE_PAID/
EXPIRED/FAILED/REFUND_MANUAL branches. Adds idempotency key, order payload
carry-through, rate snapshot, confirmations tracker, atomic provisioning
trigger, XMR subaddress index, account link, and VM back-reference.

Revision ID: 004
Revises: 003
Create Date: 2026-05-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# New status values to graft onto the existing crypto_intent_status enum.
_NEW_STATUS_VALUES = (
    "CREATED",
    "WAITING_PAYMENT",
    "UNDERPAID",
    "OVERPAID",
    "LATE_PAID",
    "SETTLED",
    "EXPIRED",          # already in pre-Block-E enum but listed for completeness
    "PROVISIONING",
    "PROVISIONED",
    "FAILED",
    "REFUND_MANUAL",
)


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # 1. Grow the Postgres enum to include all new status values.
    # Postgres `ALTER TYPE ... ADD VALUE` accepts only a string literal — it
    # cannot take a bind parameter — so we MUST interpolate. The values are
    # compile-time constants in _NEW_STATUS_VALUES; we re-validate against a
    # narrow allowlist so a future contributor adding a value with a quote or
    # other SQL metacharacter still gets a clear failure at migration time
    # rather than producing a malformed DDL string. (Sourcery flagged this as
    # SQL-injection — false positive given the constants, but the guard keeps
    # the static analyser and a future reader honest.)
    if dialect == "postgresql":
        import re
        valid_pat = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
        for v in _NEW_STATUS_VALUES:
            if not valid_pat.match(v):
                raise ValueError(f"Invalid crypto_intent_status value: {v!r}")
            op.execute(f"ALTER TYPE crypto_intent_status ADD VALUE IF NOT EXISTS '{v}'")

    # 2. Add new columns. JSONB on PG, generic JSON on SQLite (tests).
    json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")

    op.add_column("crypto_intents", sa.Column("client_order_id", sa.String(64), nullable=True))
    op.create_index(
        "ix_crypto_intents_client_order_id",
        "crypto_intents",
        ["client_order_id"],
        unique=True,
    )

    op.add_column("crypto_intents", sa.Column("order_payload", json_type, nullable=True))
    op.add_column("crypto_intents", sa.Column("rate_snapshot", sa.Numeric(20, 8), nullable=True))
    op.add_column("crypto_intents", sa.Column("rate_valid_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "crypto_intents",
        sa.Column("confirmations", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "crypto_intents",
        sa.Column("amount_received_crypto", sa.Numeric(24, 12), nullable=True),
    )
    op.add_column(
        "crypto_intents",
        sa.Column("provisioning_triggered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("crypto_intents", sa.Column("xmr_subaddr_index", sa.Integer, nullable=True))
    op.create_index(
        "ix_crypto_intents_xmr_subaddr_index",
        "crypto_intents",
        ["xmr_subaddr_index"],
        unique=True,
    )
    op.add_column("crypto_intents", sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "crypto_intents",
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_crypto_intents_owner_account_id", "crypto_intents", ["owner_account_id"])
    op.add_column("crypto_intents", sa.Column("vm_id", sa.String(32), nullable=True))
    op.create_index("ix_crypto_intents_vm_id", "crypto_intents", ["vm_id"])
    # One-shot reveal column for the anon management token cleartext (see db.py).
    op.add_column("crypto_intents", sa.Column("anon_token_cleartext", sa.String(64), nullable=True))

    op.create_index(
        "ix_crypto_intents_asset_bip32",
        "crypto_intents",
        ["asset", "bip32_index"],
    )


def downgrade() -> None:
    op.drop_index("ix_crypto_intents_asset_bip32", table_name="crypto_intents")
    op.drop_column("crypto_intents", "anon_token_cleartext")
    op.drop_index("ix_crypto_intents_vm_id", table_name="crypto_intents")
    op.drop_column("crypto_intents", "vm_id")
    op.drop_index("ix_crypto_intents_owner_account_id", table_name="crypto_intents")
    op.drop_column("crypto_intents", "owner_account_id")
    op.drop_column("crypto_intents", "last_scanned_at")
    op.drop_index("ix_crypto_intents_xmr_subaddr_index", table_name="crypto_intents")
    op.drop_column("crypto_intents", "xmr_subaddr_index")
    op.drop_column("crypto_intents", "provisioning_triggered_at")
    op.drop_column("crypto_intents", "amount_received_crypto")
    op.drop_column("crypto_intents", "confirmations")
    op.drop_column("crypto_intents", "rate_valid_until")
    op.drop_column("crypto_intents", "rate_snapshot")
    op.drop_column("crypto_intents", "order_payload")
    op.drop_index("ix_crypto_intents_client_order_id", table_name="crypto_intents")
    op.drop_column("crypto_intents", "client_order_id")
    # Note: Postgres does not support removing values from an enum cleanly.
    # Downgrade leaves the new status values present in the type definition
    # but unused; this is conventional and harmless.
