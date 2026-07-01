"""zcash x402 invoice primitives

Revision ID: 012
Revises: 011
Create Date: 2026-07-01
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "zcash_invoices",
        sa.Column("invoice_id", sa.String(36), primary_key=True),
        sa.Column("resource_url", sa.Text(), nullable=False),
        sa.Column("resource_hash", sa.String(80), nullable=False),
        sa.Column("network", sa.String(48), nullable=False),
        sa.Column("amount_zat", sa.String(32), nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6)),
        sa.Column("rate_snapshot", sa.Numeric(20, 8)),
        sa.Column("pay_to", sa.String(256), nullable=False),
        sa.Column("memo_hex", sa.Text(), nullable=False),
        sa.Column("merchant", sa.String(128)),
        sa.Column("pool", sa.String(32), nullable=False, server_default="orchard"),
        sa.Column("account", sa.Integer()),
        sa.Column("diversifier_index", sa.String(64)),
        sa.Column("min_confirmations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_timeout_seconds", sa.Integer(), nullable=False, server_default="180"),
        sa.Column("status", sa.String(32), nullable=False, server_default="created"),
        sa.Column("txid", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_zcash_invoices_expires_at", "zcash_invoices", ["expires_at"])
    op.create_index("ix_zcash_invoices_status_expires", "zcash_invoices", ["status", "expires_at"])
    op.create_index("ix_zcash_invoices_txid", "zcash_invoices", ["txid"])

    op.create_table(
        "zcash_payments",
        sa.Column("payment_id", sa.String(36), primary_key=True),
        sa.Column(
            "invoice_id",
            sa.String(36),
            sa.ForeignKey("zcash_invoices.invoice_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("txid", sa.String(128), nullable=False),
        sa.Column("network", sa.String(48), nullable=False),
        sa.Column("amount_zat", sa.String(32), nullable=False),
        sa.Column("confirmations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pool", sa.String(32)),
        sa.Column("memo_hex", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_zcash_payments_invoice_id_uq", "zcash_payments", ["invoice_id"], unique=True)
    op.create_index("ix_zcash_payments_txid_uq", "zcash_payments", ["txid"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_zcash_payments_txid_uq", table_name="zcash_payments")
    op.drop_index("ix_zcash_payments_invoice_id_uq", table_name="zcash_payments")
    op.drop_table("zcash_payments")
    op.drop_index("ix_zcash_invoices_txid", table_name="zcash_invoices")
    op.drop_index("ix_zcash_invoices_status_expires", table_name="zcash_invoices")
    op.drop_index("ix_zcash_invoices_expires_at", table_name="zcash_invoices")
    op.drop_table("zcash_invoices")
