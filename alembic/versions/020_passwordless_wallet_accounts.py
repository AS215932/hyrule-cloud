"""Allow wallet-only accounts to have no password.

An account created from a settled x402 payment (or a wallet login) has no
password: the buyer authenticates by signing a wallet challenge. Previously
such accounts were given a random argon2id hash nobody held, which is
indistinguishable from a real credential to anything reading the row.

Revision ID: 020
Revises: 019
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "020"
down_revision: str | None = "019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "accounts",
        "password_hash",
        existing_type=sa.String(256),
        nullable=True,
    )


def downgrade() -> None:
    # Rows with a NULL password cannot satisfy a NOT NULL constraint. Give them
    # an unusable placeholder rather than failing the downgrade or, worse,
    # deleting accounts: the string is not a valid argon2id PHC hash, so
    # verify_password() rejects every candidate against it. Those accounts keep
    # working through wallet login exactly as before.
    op.execute(
        "UPDATE accounts SET password_hash = '!wallet-only' WHERE password_hash IS NULL"
    )
    op.alter_column(
        "accounts",
        "password_hash",
        existing_type=sa.String(256),
        nullable=False,
    )
