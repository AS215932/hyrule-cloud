"""Fence VM renewal once deletion has been claimed.

Revision ID: 021
Revises: 020
"""

import sqlalchemy as sa

from alembic import op

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vms", sa.Column("deletion_started_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # Never silently drop an active fence and allow a renewal of a deleting VM.
    bind = op.get_bind()
    pending = bind.execute(sa.text(
        "SELECT count(*) FROM vms WHERE deletion_started_at IS NOT NULL AND ("
        "status != 'destroyed' OR ipv6_prefix_index IS NOT NULL OR ipv6_prefix IS NOT NULL OR "
        "(xcpng_uuid IS NOT NULL AND "
        "COALESCE(metadata ->> 'provider_deleted_uuid', '') != xcpng_uuid))"
    )).scalar_one()
    if pending:
        raise RuntimeError("Resolve pending VM deletion claims before downgrade")
    op.drop_column("vms", "deletion_started_at")
