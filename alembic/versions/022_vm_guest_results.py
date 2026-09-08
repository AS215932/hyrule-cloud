"""Durable authenticated guest completion receipts.

Based on current main (020); reconcile parent with any intervening migration
before merge, especially the pending VM deletion claim migration 021.
"""
import sqlalchemy as sa

from alembic import op

revision = "022"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vm_guest_results",
        sa.Column("vm_id", sa.String(32), sa.ForeignKey("vms.vm_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("generation", sa.String(32), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(16)),
        sa.Column("stage", sa.String(16)),
        sa.Column("exit_code", sa.Integer),
        sa.Column("received_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    active = op.get_bind().execute(sa.text(
        "SELECT 1 FROM vm_guest_results AS r JOIN vms AS v ON v.vm_id = r.vm_id "
        "WHERE v.status = 'provisioning' OR v.xcpng_uuid IS NULL LIMIT 1"
    )).scalar()
    if active is not None:
        raise RuntimeError("Refusing to remove guest receipts while provisioning or guest reconciliation is unresolved")
    op.drop_table("vm_guest_results")
