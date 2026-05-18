"""Block B: vms.provisioned_at column for live avg-provision metric

Added so `/v1/stats/runtime` can compute a rolling average of
(provisioned_at - created_at) over the last N READY VMs. Backfills NULL —
old rows simply don't contribute to the average until they next provision.

Revision ID: 005
Revises: 004
Create Date: 2026-05-17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vms",
        sa.Column("provisioned_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vms", "provisioned_at")
