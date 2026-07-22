"""Bind x402 authorizations across every paid resource.

Revision ID: 025
Revises: 024
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "025"
down_revision: str | None = "024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "payment_authorizations",
        sa.Column("fingerprint", sa.String(64), primary_key=True),
        sa.Column("resource_key", sa.String(256), nullable=False),
        sa.Column("resource_path", sa.String(256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_payment_authorizations_resource_key",
        "payment_authorizations",
        ["resource_key"],
    )
    op.create_index(
        "ix_payment_authorizations_created_at",
        "payment_authorizations",
        ["created_at"],
    )
    op.execute(
        sa.text(
            """
            INSERT INTO payment_authorizations
                (fingerprint, resource_key, resource_path, created_at)
            SELECT
                domain_orders.payment_authorization_fingerprint,
                CASE
                    WHEN accounts.quote_id IS NOT NULL
                        THEN 'domain_mail_bundle:' || accounts.quote_id || ':'
                            || domain_orders.order_id
                    ELSE 'domain_order:' || domain_orders.order_id
                END,
                CASE
                    WHEN accounts.quote_id IS NOT NULL THEN '/v1/mail/accounts'
                    ELSE '/v1/domains/orders'
                END,
                domain_orders.created_at
            FROM domain_orders
            LEFT JOIN mail_accounts AS accounts
                ON accounts.domain_order_id = domain_orders.order_id
            WHERE domain_orders.payment_authorization_fingerprint IS NOT NULL
            ON CONFLICT (fingerprint) DO NOTHING
            """
        )
    )
    op.execute(
        sa.text(
            """
            INSERT INTO payment_authorizations
                (fingerprint, resource_key, resource_path, created_at)
            SELECT
                bindings.fingerprint,
                CASE
                    WHEN accounts.domain_order_id IS NOT NULL
                        THEN 'domain_mail_bundle:' || bindings.quote_id || ':'
                            || accounts.domain_order_id
                    WHEN quotes.kind = 'send'
                        THEN 'mail_send:' || bindings.quote_id
                    ELSE 'mail_activation:' || bindings.quote_id
                END,
                CASE
                    WHEN quotes.kind = 'send' THEN '/v1/mail/messages/send'
                    ELSE '/v1/mail/accounts'
                END,
                bindings.created_at
            FROM mail_payment_authorizations AS bindings
            LEFT JOIN mail_quotes AS quotes ON quotes.quote_id = bindings.quote_id
            LEFT JOIN mail_accounts AS accounts ON accounts.quote_id = bindings.quote_id
            ON CONFLICT (fingerprint) DO NOTHING
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_payment_authorizations_created_at", table_name="payment_authorizations")
    op.drop_index("ix_payment_authorizations_resource_key", table_name="payment_authorizations")
    op.drop_table("payment_authorizations")
