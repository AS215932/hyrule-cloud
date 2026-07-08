"""payments ledger

Revision ID: 013
Revises: 012
Create Date: 2026-07-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    try:
        inspector = sa.inspect(bind)
        if "payment_events" in inspector.get_table_names():
            return
    except sa.exc.NoInspectionAvailable:
        # Offline --sql mode has no live connection to inspect; emit the DDL.
        pass

    op.create_table(
        "payment_events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("resource_path", sa.String(256), nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("service_group", sa.String(24), nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6), nullable=True),
        sa.Column("network", sa.String(64), nullable=True),
        sa.Column("asset", sa.String(66), nullable=True),
        sa.Column("payer_wallet", sa.String(64), nullable=True),
        sa.Column("tx_hash", sa.String(128), nullable=True),
        sa.Column("facilitator_host", sa.String(64), nullable=True),
        sa.Column("error_reason", sa.String(256), nullable=True),
        sa.Column("extra", JSONB().with_variant(sa.JSON(), "sqlite"), nullable=True),
    )
    op.create_index("ix_payment_events_created_at", "payment_events", ["created_at"])
    op.create_index("ix_payment_events_event_type", "payment_events", ["event_type"])
    op.create_index("ix_payment_events_service_group", "payment_events", ["service_group"])
    op.create_index("ix_payment_events_payer_wallet", "payment_events", ["payer_wallet"])
    op.create_index(
        "ix_payment_events_type_created", "payment_events", ["event_type", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("payment_events")
