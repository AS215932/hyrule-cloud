"""Persist fair retry scheduling for x402 recovery.

Revision ID: 027
Revises: 026
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "027"
down_revision: str | None = "026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "domain_orders",
        sa.Column("payment_recovery_next_attempt_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_domain_orders_payment_recovery_next_attempt_at",
        "domain_orders",
        ["payment_recovery_next_attempt_at"],
    )
    op.add_column(
        "mail_sends",
        sa.Column("payment_recovery_next_attempt_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_mail_sends_payment_recovery_next_attempt_at",
        "mail_sends",
        ["payment_recovery_next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_mail_sends_payment_recovery_next_attempt_at",
        table_name="mail_sends",
    )
    op.drop_column("mail_sends", "payment_recovery_next_attempt_at")
    op.drop_index(
        "ix_domain_orders_payment_recovery_next_attempt_at",
        table_name="domain_orders",
    )
    op.drop_column("domain_orders", "payment_recovery_next_attempt_at")
