"""Durable Agent Mail settlement and DNS cleanup state.

Revision ID: 021
Revises: 020
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "021"
down_revision: str | None = "020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_accounts",
        sa.Column(
            "dns_cleanup_pending",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "mail_accounts",
        sa.Column("payment_settlement_pending_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "mail_accounts",
        sa.Column("payment_settled_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_mail_accounts_dns_cleanup_pending",
        "mail_accounts",
        ["dns_cleanup_pending"],
    )
    op.create_index(
        "ix_mail_accounts_payment_settled_at",
        "mail_accounts",
        ["payment_settled_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_mail_accounts_payment_settled_at",
        table_name="mail_accounts",
    )
    op.drop_index(
        "ix_mail_accounts_dns_cleanup_pending",
        table_name="mail_accounts",
    )
    op.drop_column("mail_accounts", "payment_settled_at")
    op.drop_column("mail_accounts", "payment_settlement_pending_at")
    op.drop_column("mail_accounts", "dns_cleanup_pending")
