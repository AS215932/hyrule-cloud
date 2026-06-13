"""generic diagnostic job primitives

Revision ID: 011
Revises: 010
Create Date: 2026-06-13
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "diagnostic_jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("service", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("target", sa.String(512)),
        sa.Column("owner_wallet", sa.String(64)),
        sa.Column("owner_account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="SET NULL")),
        sa.Column("payment_tx", sa.String(128)),
        sa.Column("access_token_hash", sa.String(64)),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON()),
        sa.Column("sources", sa.JSON()),
        sa.Column("artifact_path", sa.Text()),
        sa.Column("artifact_format", sa.String(64)),
        sa.Column("artifact_sha256", sa.String(64)),
        sa.Column("artifact_size_bytes", sa.Integer()),
        sa.Column("price_usd", sa.Numeric(12, 6)),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
    )
    for col in [
        "service",
        "kind",
        "status",
        "target",
        "owner_wallet",
        "owner_account_id",
        "access_token_hash",
        "expires_at",
    ]:
        op.create_index(f"ix_diagnostic_jobs_{col}", "diagnostic_jobs", [col])
    op.create_index("ix_diagnostic_jobs_service_status", "diagnostic_jobs", ["service", "status"])
    op.create_index("ix_diagnostic_jobs_kind_status", "diagnostic_jobs", ["kind", "status"])


def downgrade() -> None:
    op.drop_index("ix_diagnostic_jobs_kind_status", table_name="diagnostic_jobs")
    op.drop_index("ix_diagnostic_jobs_service_status", table_name="diagnostic_jobs")
    for col in [
        "expires_at",
        "access_token_hash",
        "owner_account_id",
        "owner_wallet",
        "target",
        "status",
        "kind",
        "service",
    ]:
        op.drop_index(f"ix_diagnostic_jobs_{col}", table_name="diagnostic_jobs")
    op.drop_table("diagnostic_jobs")
