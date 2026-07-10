"""Issue #51: vms.provision_started_at for an honest provision metric

`/v1/stats/runtime` averaged (provisioned_at - created_at), but created_at
can predate settlement by hours (native crypto intents wait for deposits;
reservations predate payment), so payment-wait time polluted the advertised
"avg provision" number (observed 4720.3s in prod while real provisions
finish in seconds). The orchestrator now stamps provision_started_at when
background provisioning actually begins, and the stats endpoint reports the
median of (provisioned_at - provision_started_at).

Backfills NULL — old rows simply don't contribute to the metric (the 005
precedent), so the number self-heals with the next provisions.

Revision ID: 014
Revises: 013
Create Date: 2026-07-10
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "014"
down_revision: str | None = "013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    try:
        inspector = sa.inspect(bind)
        columns = {c["name"] for c in inspector.get_columns("vms")}
        if "provision_started_at" in columns:
            return
    except sa.exc.NoInspectionAvailable:
        # Offline --sql mode has no live connection to inspect; emit the DDL.
        pass

    op.add_column(
        "vms",
        sa.Column("provision_started_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vms", "provision_started_at")
