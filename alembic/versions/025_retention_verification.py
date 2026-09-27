"""Persist bounded read-only retention verification evidence."""
import sqlalchemy as sa

from alembic import op

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vm_retention", sa.Column("last_verified_at", sa.DateTime(timezone=True)))
    op.add_column("vm_retention", sa.Column("verification_attempted_at", sa.DateTime(timezone=True)))
    op.add_column("vm_retention", sa.Column("verification_error", sa.String(64)))
    op.add_column("vm_retention", sa.Column("next_verification_at", sa.DateTime(timezone=True)))
    op.create_index("ix_vm_retention_next_verification_at", "vm_retention", ["next_verification_at"])


def downgrade() -> None:
    op.drop_index("ix_vm_retention_next_verification_at", table_name="vm_retention")
    for column in ("next_verification_at", "verification_error", "verification_attempted_at", "last_verified_at"):
        op.drop_column("vm_retention", column)
