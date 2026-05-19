"""Block D (Wave 3): scoped API keys for programmatic VM management.

Creates the `api_keys` table. Each row is one scoped bearer token an account
has issued; the cleartext `hyr_sk_<32 base62>` is revealed exactly once at
creation and never stored — we keep only sha256(cleartext) for lookup. Scopes
are an explicit JSON array of `ApiKeyScope` values; the auth middleware
enforces them per request.

Per [[feedback_security_split]]: API keys CANNOT perform destructive account
operations (password change, recovery rotation, account deletion). Those
endpoints require a browser session — the dependency is `require_browser_session`,
wired in Wave 2 and active from this wave onward.

Revision ID: 006
Revises: 005
Create Date: 2026-05-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # JSONB on Postgres, generic JSON on SQLite — same pattern as migration 003.
    json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")

    op.create_table(
        "api_keys",
        sa.Column("key_id", sa.String(36), primary_key=True),  # uuid4
        sa.Column(
            "account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("scopes", json_type, nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_table("api_keys")
