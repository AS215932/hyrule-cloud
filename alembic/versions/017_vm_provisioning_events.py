"""VM provisioning events (customer-visible /logs)

Revision ID: 017
Revises: 016
Create Date: 2026-07-24
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
    bind = op.get_bind()
    try:
        inspector = sa.inspect(bind)
        if "vm_events" in inspector.get_table_names():
            return
    except sa.exc.NoInspectionAvailable:
        # Offline --sql mode has no live connection to inspect; emit the DDL.
        pass

    op.create_table(
        "vm_events",
        sa.Column("event_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("vm_id", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("event", sa.String(48), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("detail", _JSONB, nullable=True),
    )
    op.create_index("ix_vm_events_vm_id", "vm_events", ["vm_id"])
    # The /logs read is always "one VM, chronological".
    op.create_index("ix_vm_events_vm_created", "vm_events", ["vm_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_vm_events_vm_created", table_name="vm_events")
    op.drop_index("ix_vm_events_vm_id", table_name="vm_events")
    op.drop_table("vm_events")
