"""Allow complete RFC Message-IDs in Agent Mail reply intents.

Revision ID: 026
Revises: 025
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_mail_sends_in_reply_to", table_name="mail_sends")
    op.alter_column(
        "mail_sends",
        "in_reply_to",
        existing_type=sa.String(128),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE mail_sends
            SET in_reply_to = LEFT(in_reply_to, 128)
            WHERE LENGTH(in_reply_to) > 128
            """
        )
    )
    op.alter_column(
        "mail_sends",
        "in_reply_to",
        existing_type=sa.Text(),
        type_=sa.String(128),
        existing_nullable=True,
    )
    op.create_index("ix_mail_sends_in_reply_to", "mail_sends", ["in_reply_to"])
