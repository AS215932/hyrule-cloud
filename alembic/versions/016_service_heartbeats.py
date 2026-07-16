"""service heartbeats

Revision ID: 016
Revises: 015
Create Date: 2026-07-17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_heartbeats",
        sa.Column("service_name", sa.String(64), primary_key=True),
        sa.Column("worker_id", sa.String(128), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
    )
    op.create_index(
        "ix_service_heartbeats_last_seen_at",
        "service_heartbeats",
        ["last_seen_at"],
    )


def downgrade() -> None:
    op.drop_table("service_heartbeats")
