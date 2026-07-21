"""Agent Mail provisioning leases and bounded DNS retries.

Revision ID: 019
Revises: 018
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "019"
down_revision: str | None = "018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_accounts",
        sa.Column("provision_claim_token", sa.String(64)),
    )
    op.add_column(
        "mail_accounts",
        sa.Column("provision_claimed_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "mail_accounts",
        sa.Column(
            "provision_retry_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "mail_accounts",
        sa.Column("provision_next_attempt_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_mail_accounts_provision_claimed_at",
        "mail_accounts",
        ["provision_claimed_at"],
    )
    op.create_index(
        "ix_mail_accounts_provision_next_attempt_at",
        "mail_accounts",
        ["provision_next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_mail_accounts_provision_next_attempt_at",
        table_name="mail_accounts",
    )
    op.drop_index(
        "ix_mail_accounts_provision_claimed_at",
        table_name="mail_accounts",
    )
    op.drop_column("mail_accounts", "provision_next_attempt_at")
    op.drop_column("mail_accounts", "provision_retry_count")
    op.drop_column("mail_accounts", "provision_claimed_at")
    op.drop_column("mail_accounts", "provision_claim_token")
