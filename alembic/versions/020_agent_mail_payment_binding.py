"""Bind each Agent Mail quote to one payment authorization.

Revision ID: 020
Revises: 019
Create Date: 2026-07-21
"""

from collections.abc import Sequence

from alembic import op

revision: str = "020"
down_revision: str | None = "019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_mail_payment_authorization_quote",
        "mail_payment_authorizations",
        ["quote_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_mail_payment_authorization_quote",
        "mail_payment_authorizations",
        type_="unique",
    )
