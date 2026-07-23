"""Reverse-SSH tunnel leases.

Revision ID: 017
Revises: 016
Create Date: 2026-07-22

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_JSONB = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reverse_tunnels",
        sa.Column("tunnel_id", sa.String(32), primary_key=True),
        sa.Column("owner_wallet", sa.String(64), nullable=False, server_default=""),
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
        ),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("allocated_port", sa.Integer(), nullable=False),
        sa.Column("endpoint_host", sa.String(128), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="2222"),
        sa.Column("allowlist_cidrs", _JSONB),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("idempotency_key", sa.String(64)),
        sa.Column("request_hash", sa.String(64)),
        sa.Column("settlement_header", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payment_tx", sa.String(128)),
    )
    op.create_index("ix_reverse_tunnels_owner_wallet", "reverse_tunnels", ["owner_wallet"])
    op.create_index("ix_reverse_tunnels_owner_account_id", "reverse_tunnels", ["owner_account_id"])
    op.create_index("ix_reverse_tunnels_token_hash", "reverse_tunnels", ["token_hash"])
    op.create_index(
        "ix_reverse_tunnels_idempotency_key",
        "reverse_tunnels",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index("ix_reverse_tunnels_status", "reverse_tunnels", ["status"])
    op.create_index("ix_reverse_tunnels_expires_at", "reverse_tunnels", ["expires_at"])
    op.create_index(
        "ix_reverse_tunnels_owner_status", "reverse_tunnels", ["owner_wallet", "status"]
    )


def downgrade() -> None:
    op.drop_index("ix_reverse_tunnels_idempotency_key", table_name="reverse_tunnels")
    op.drop_index("ix_reverse_tunnels_token_hash", table_name="reverse_tunnels")
    op.drop_index("ix_reverse_tunnels_owner_status", table_name="reverse_tunnels")
    op.drop_index("ix_reverse_tunnels_expires_at", table_name="reverse_tunnels")
    op.drop_index("ix_reverse_tunnels_status", table_name="reverse_tunnels")
    op.drop_index("ix_reverse_tunnels_owner_account_id", table_name="reverse_tunnels")
    op.drop_index("ix_reverse_tunnels_owner_wallet", table_name="reverse_tunnels")
    op.drop_table("reverse_tunnels")
