"""vm_quotes: durable order quotes (issue #14)

Creates the `vm_quotes` table + `vm_quote_status` enum. The durable order object
the UI and agents pay against: priced once at creation, it survives review-page
reloads and mobile wallet handoffs via its quote_id, and POST /v1/vm/create
consumes it at the locked price.

Additive only — no changes to existing tables, so existing clients are
unaffected and the downgrade cleanly drops the table + enum.

Revision ID: 008
Revises: 007
Create Date: 2026-05-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Values MATCH hyrule_cloud.models.QuoteStatus so an alembic-migrated DB and a
# create_all() DB (tests) produce the same enum.
_STATUS_VALUES = ("created", "consumed", "expired")


def upgrade() -> None:
    # JSONB on Postgres, generic JSON on SQLite (tests use create_all, not this
    # migration, but keep the variant for parity).
    json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")
    # sa.Enum inside create_table emits CREATE TYPE before CREATE TABLE on
    # Postgres and a CHECK constraint on SQLite — matching the model's
    # Enum(..., name="vm_quote_status").
    status_enum = sa.Enum(*_STATUS_VALUES, name="vm_quote_status")

    op.create_table(
        "vm_quotes",
        sa.Column("quote_id", sa.String(36), primary_key=True),
        sa.Column("order_payload", json_type, nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("status", status_enum, nullable=False),
        sa.Column("client_order_id", sa.String(64), nullable=True),
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("vm_id", sa.String(32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Model declares client_order_id unique=True+index=True → create_all renders
    # a unique index of this name. Match it so autogenerate stays quiet.
    op.create_index(
        "ix_vm_quotes_client_order_id", "vm_quotes", ["client_order_id"], unique=True
    )
    op.create_index("ix_vm_quotes_owner_account_id", "vm_quotes", ["owner_account_id"])
    op.create_index("ix_vm_quotes_vm_id", "vm_quotes", ["vm_id"])
    op.create_index("ix_vm_quotes_status_expires", "vm_quotes", ["status", "expires_at"])


def downgrade() -> None:
    op.drop_table("vm_quotes")
    # create_table auto-created the enum on Postgres; drop it explicitly so a
    # downgrade leaves no orphan type behind. checkfirst keeps SQLite happy.
    sa.Enum(name="vm_quote_status").drop(op.get_bind(), checkfirst=True)
