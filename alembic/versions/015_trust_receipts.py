"""trust receipts

Revision ID: 015
Revises: 014
Create Date: 2026-07-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    existing_tables: set[str] = set()
    try:
        inspector = sa.inspect(bind)
        existing_tables = set(inspector.get_table_names())
    except sa.exc.NoInspectionAvailable:
        # Offline --sql mode has no live connection to inspect; emit the DDL.
        pass

    if "fulfillment_receipts" not in existing_tables:
        op.create_table(
            "fulfillment_receipts",
            sa.Column("receipt_id", sa.String(40), primary_key=True),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("resource_path", sa.String(256), nullable=False),
            sa.Column("method", sa.String(8), nullable=False),
            sa.Column("service_group", sa.String(24), nullable=False),
            sa.Column("outcome", sa.String(24), nullable=False),
            sa.Column("rail", sa.String(24), nullable=False),
            sa.Column("network", sa.String(64), nullable=True),
            sa.Column("amount_usd", sa.Numeric(12, 6), nullable=True),
            sa.Column("payer_wallet", sa.String(64), nullable=True),
            sa.Column("tx_hash", sa.String(128), nullable=True),
            sa.Column("payment_event_id", sa.String(36), nullable=True),
            sa.Column("quote_id", sa.String(36), nullable=True),
            sa.Column("vm_id", sa.String(32), nullable=True),
            sa.Column("intent_id", sa.String(36), nullable=True),
            sa.Column("job_id", sa.String(40), nullable=True),
            sa.Column("domain_fqdn", sa.String(256), nullable=True),
            sa.Column("agent_did", sa.String(256), nullable=True),
            sa.Column("key_id", sa.String(64), nullable=False),
            sa.Column("evm_signer", sa.String(42), nullable=True),
            sa.Column("evm_signature", sa.String(178), nullable=True),
            sa.Column("payload", JSONB().with_variant(sa.JSON(), "sqlite"), nullable=False),
            sa.Column("jws", sa.Text(), nullable=False),
        )
        op.create_index(
            "ix_fulfillment_receipts_created_at", "fulfillment_receipts", ["created_at"]
        )
        op.create_index(
            "ix_fulfillment_receipts_service_group", "fulfillment_receipts", ["service_group"]
        )
        op.create_index(
            "ix_fulfillment_receipts_payer_wallet", "fulfillment_receipts", ["payer_wallet"]
        )
        op.create_index(
            "ix_fulfillment_receipts_payment_event_id",
            "fulfillment_receipts",
            ["payment_event_id"],
        )
        op.create_index(
            "ix_fulfillment_receipts_vm_id_created",
            "fulfillment_receipts",
            ["vm_id", "created_at"],
        )
        op.create_index(
            "ix_fulfillment_receipts_intent_id", "fulfillment_receipts", ["intent_id"]
        )
        op.create_index(
            "ix_fulfillment_receipts_group_created",
            "fulfillment_receipts",
            ["service_group", "created_at"],
        )

    # Duplicate-settlement DETECTION index (deliberately not a unique
    # constraint: the ledger is best-effort/append-only and a facilitator may
    # legitimately batch settlements under one tx — uniqueness would silently
    # drop revenue-truth rows; /metrics gauges duplicates instead).
    existing_pe_indexes: set[str] = set()
    if existing_tables:
        try:
            existing_pe_indexes = {
                idx["name"]
                for idx in sa.inspect(bind).get_indexes("payment_events")
                if idx.get("name")
            }
        except Exception:
            pass
    if "ix_payment_events_tx_hash" not in existing_pe_indexes:
        op.create_index("ix_payment_events_tx_hash", "payment_events", ["tx_hash"])


def downgrade() -> None:
    op.drop_index("ix_payment_events_tx_hash", table_name="payment_events")
    op.drop_table("fulfillment_receipts")
