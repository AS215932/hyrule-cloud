"""Public x402 domain-registration checkout intents.

Revision ID: 017
Revises: 016
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_registration_intents",
        sa.Column("registration_id", sa.String(32), primary_key=True),
        sa.Column("client_order_id", sa.String(128), nullable=False),
        sa.Column("fqdn", sa.String(253), nullable=False),
        sa.Column(
            "quote_id",
            sa.String(32),
            sa.ForeignKey("domain_quotes.quote_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "order_id",
            sa.String(32),
            sa.ForeignKey("domain_orders.order_id", ondelete="SET NULL"),
        ),
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
        ),
        sa.Column("payer_address", sa.String(42)),
        sa.Column("public_status_id", sa.String(32), nullable=False),
        sa.Column("payment_authorization_hash", sa.String(64)),
        sa.Column(
            "settlement_state",
            sa.String(24),
            nullable=False,
            server_default="awaiting_payment",
        ),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("client_order_id"),
        sa.UniqueConstraint("order_id"),
        sa.UniqueConstraint("public_status_id"),
    )
    for column in (
        "fqdn",
        "quote_id",
        "owner_account_id",
        "payer_address",
        "payment_authorization_hash",
        "settlement_state",
        "settled_at",
    ):
        op.create_index(
            f"ix_domain_registration_intents_{column}",
            "domain_registration_intents",
            [column],
        )


def downgrade() -> None:
    op.drop_table("domain_registration_intents")
