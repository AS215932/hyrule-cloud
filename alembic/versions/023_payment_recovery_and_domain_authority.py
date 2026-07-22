"""Persist recoverable x402 authorizations and domain authority bindings.

Revision ID: 023
Revises: 022
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "023"
down_revision: str | None = "022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "domain_orders",
        sa.Column("payment_authorization_fingerprint", sa.String(64)),
    )
    op.add_column(
        "domain_orders",
        sa.Column("payment_authorization_header", sa.Text()),
    )
    op.create_unique_constraint(
        "uq_domain_orders_payment_authorization",
        "domain_orders",
        ["payment_authorization_fingerprint"],
    )
    op.add_column(
        "mail_accounts",
        sa.Column("domain_authority_hash", sa.String(64)),
    )
    op.add_column(
        "mail_accounts",
        sa.Column("payment_authorization_header", sa.Text()),
    )


def downgrade() -> None:
    op.drop_column("mail_accounts", "payment_authorization_header")
    op.drop_column("mail_accounts", "domain_authority_hash")
    op.drop_constraint(
        "uq_domain_orders_payment_authorization",
        "domain_orders",
        type_="unique",
    )
    op.drop_column("domain_orders", "payment_authorization_header")
    op.drop_column("domain_orders", "payment_authorization_fingerprint")
