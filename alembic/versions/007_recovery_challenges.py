"""Block F: server-side nonce store for wallet-signature recovery.

DB-backed (not in-process) so the challenge survives across workers and a
single-use marker (`used_at`) makes replay impossible. The full challenge_text
is stored so verify never has to trust client framing of nonce/timestamps.

Revision ID: 007
Revises: 006
Create Date: 2026-05-17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "recovery_challenges",
        sa.Column("nonce", sa.String(64), primary_key=True),
        sa.Column("account_id", sa.String(11), nullable=False),
        sa.Column("challenge_text", sa.Text, nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_recovery_challenges_account_id", "recovery_challenges", ["account_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_recovery_challenges_account_id", table_name="recovery_challenges"
    )
    op.drop_table("recovery_challenges")
