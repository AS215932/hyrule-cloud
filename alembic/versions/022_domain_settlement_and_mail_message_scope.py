"""Persist domain settlement intents and scope JMAP ids by mailbox.

Revision ID: 022
Revises: 021
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "domain_orders",
        sa.Column(
            "payment_settlement_pending_at",
            sa.DateTime(timezone=True),
        ),
    )
    op.drop_constraint(
        "mail_message_index_pkey",
        "mail_message_index",
        type_="primary",
    )
    op.create_primary_key(
        "mail_message_index_pkey",
        "mail_message_index",
        ["mailbox_id", "message_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "mail_message_index_pkey",
        "mail_message_index",
        type_="primary",
    )
    op.create_primary_key(
        "mail_message_index_pkey",
        "mail_message_index",
        ["message_id"],
    )
    op.drop_column("domain_orders", "payment_settlement_pending_at")
