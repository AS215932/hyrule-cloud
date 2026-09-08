"""Preserve VM disk recovery evidence independently of live resource rows."""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "024"
down_revision = "020"  # Reconcile pending 021/022/023 before combined promotion.
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vm_retention",
        sa.Column("vm_id", sa.String(32), primary_key=True),
        sa.Column("source_vm_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("owner_account_id", sa.String(11)),
        sa.Column("owner_wallet", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="prepared"),
        sa.Column("manifest", postgresql.JSONB(), nullable=False),
        sa.Column("restore_config", postgresql.JSONB(), nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("retained_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_vm_retention_retain_until", "vm_retention", ["retain_until"])


def downgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT EXISTS (SELECT 1 FROM vm_retention)")).scalar_one():
        raise RuntimeError("Preserve and reconcile VM retention records before downgrade")
    op.drop_table("vm_retention")
