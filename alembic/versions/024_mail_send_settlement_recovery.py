"""Persist recoverable Agent Mail send settlements.

Revision ID: 024
Revises: 023
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "024"
down_revision: str | None = "023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("mail_sends", sa.Column("payment_payer", sa.String(64)))
    op.add_column("mail_sends", sa.Column("payment_network", sa.String(64)))
    op.add_column("mail_sends", sa.Column("payment_asset", sa.String(66)))
    op.add_column("mail_sends", sa.Column("payment_authorization_header", sa.Text()))
    op.add_column(
        "mail_sends",
        sa.Column("payment_settlement_pending_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "mail_sends",
        sa.Column("payment_settled_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_mail_sends_payment_settled_at",
        "mail_sends",
        ["payment_settled_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_mail_sends_payment_settled_at", table_name="mail_sends")
    op.drop_column("mail_sends", "payment_settled_at")
    op.drop_column("mail_sends", "payment_settlement_pending_at")
    op.drop_column("mail_sends", "payment_authorization_header")
    op.drop_column("mail_sends", "payment_asset")
    op.drop_column("mail_sends", "payment_network")
    op.drop_column("mail_sends", "payment_payer")
