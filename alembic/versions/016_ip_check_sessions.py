"""Short-lived agent/browser IP-check sessions and observations.

Revision ID: 016
Revises: 015
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_JSONB = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    json_empty = sa.text("'[]'::jsonb") if dialect == "postgresql" else sa.text("'[]'")
    op.create_table(
        "ip_check_sessions",
        sa.Column("session_id", sa.String(32), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("dns_label", sa.String(63), nullable=False, unique=True),
        sa.Column(
            "expected_dns_resolvers",
            _JSONB,
            nullable=False,
            server_default=json_empty,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ip_check_sessions_dns_label", "ip_check_sessions", ["dns_label"])
    op.create_index("ix_ip_check_sessions_expires_at", "ip_check_sessions", ["expires_at"])

    op.create_table(
        "ip_check_observations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.String(32),
            sa.ForeignKey("ip_check_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("address", sa.String(64)),
        sa.Column("family", sa.Integer()),
        sa.Column("details", _JSONB),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_ip_check_observations_session_id", "ip_check_observations", ["session_id"]
    )
    op.create_index("ix_ip_check_observations_kind", "ip_check_observations", ["kind"])
    op.create_index(
        "ix_ip_check_observations_observed_at",
        "ip_check_observations",
        ["observed_at"],
    )
    op.create_index(
        "ix_ip_check_observations_session_kind",
        "ip_check_observations",
        ["session_id", "kind"],
    )


def downgrade() -> None:
    op.drop_table("ip_check_observations")
    op.drop_table("ip_check_sessions")
