"""x401 shadow log + proof tokens

Revision ID: 016
Revises: 015
Create Date: 2026-07-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    existing_tables: set[str] = set()
    try:
        inspector = sa.inspect(bind)
        existing_tables = set(inspector.get_table_names())
    except sa.exc.NoInspectionAvailable:
        pass

    if "x401_proof_log" not in existing_tables:
        op.create_table(
            "x401_proof_log",
            sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("route", sa.String(256), nullable=False),
            sa.Column("method", sa.String(8), nullable=False),
            sa.Column("mode", sa.String(8), nullable=False),
            sa.Column("policy_tier", sa.String(16), nullable=False),
            sa.Column("decision", sa.String(24), nullable=False),
            sa.Column("reasons", JSONB().with_variant(sa.JSON(), "sqlite"), nullable=True),
            sa.Column("amount_usd", sa.Numeric(12, 6), nullable=True),
            sa.Column("payer_wallet", sa.String(64), nullable=True),
            sa.Column("agent_did", sa.String(256), nullable=True),
        )
        op.create_index("ix_x401_proof_log_created_at", "x401_proof_log", ["created_at"])
        op.create_index(
            "ix_x401_proof_log_route_created", "x401_proof_log", ["route", "created_at"]
        )

    if "x401_proof_tokens" not in existing_tables:
        op.create_table(
            "x401_proof_tokens",
            sa.Column("token_hash", sa.String(64), primary_key=True),
            sa.Column("quote_hash", sa.String(64), nullable=False),
            sa.Column("route", sa.String(256), nullable=False),
            sa.Column("method", sa.String(8), nullable=False),
            sa.Column("claims", JSONB().with_variant(sa.JSON(), "sqlite"), nullable=True),
            sa.Column("agent_did", sa.String(256), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_x401_proof_tokens_expires_at", "x401_proof_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("x401_proof_tokens")
    op.drop_table("x401_proof_log")
