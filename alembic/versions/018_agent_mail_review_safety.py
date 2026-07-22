"""Agent Mail review safety invariants.

Revision ID: 018
Revises: 017
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "018"
down_revision: str | None = "017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mail_accounts",
        sa.Column("capacity_reserved_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_mail_accounts_capacity_reserved_at",
        "mail_accounts",
        ["capacity_reserved_at"],
    )
    op.create_table(
        "mail_payment_authorizations",
        sa.Column("fingerprint", sa.String(64), primary_key=True),
        sa.Column("quote_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_mail_payment_authorizations_quote_id",
        "mail_payment_authorizations",
        ["quote_id"],
    )
    op.create_index(
        "ix_mail_payment_authorizations_created_at",
        "mail_payment_authorizations",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_table("mail_payment_authorizations")
    op.drop_index("ix_mail_accounts_capacity_reserved_at", table_name="mail_accounts")
    op.drop_column("mail_accounts", "capacity_reserved_at")
