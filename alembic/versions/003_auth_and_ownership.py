"""auth subsystem + account-based VM ownership

Block A1. Adds:
- accounts (anonymous: account_id + password_hash + recovery_code_hash)
- sessions (opaque server-side tokens, sha256-hashed)
- recovery_attempts (audit + rate-limit log)
- vms.owner_account_id (FK to accounts; nullable to preserve anon orders)
- domains.owner_account_id, vpn_tunnels.owner_account_id

The toy AccountRow shipped in an earlier (un-migrated) revision is replaced;
existing dev databases without the toy schema upgrade cleanly. If a dev box has
the toy table, the alembic `create_table` for "accounts" will fail loudly —
drop it manually and re-run.

Revision ID: 003
Revises: 002
Create Date: 2026-05-16
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("account_id", sa.String(11), primary_key=True),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("recovery_code_hash", sa.String(256), nullable=True),
        sa.Column("recovery_code_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovery_code_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_admin", sa.Boolean, nullable=False, server_default="false"),
    )

    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("user_agent", sa.String(256), nullable=True),
        sa.Column("ip_prefix_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_sessions_account_id", "sessions", ["account_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table(
        "recovery_attempts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("account_id", sa.String(11), nullable=True),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("success", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("ip_prefix_hash", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_recovery_attempts_account_id", "recovery_attempts", ["account_id"])
    op.create_index("ix_recovery_attempts_ip_prefix_hash", "recovery_attempts", ["ip_prefix_hash"])
    op.create_index("ix_recovery_attempts_created_at", "recovery_attempts", ["created_at"])

    # Account-based VM ownership. Existing rows get NULL (preserves anon-by-token flow).
    op.add_column(
        "vms",
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_vms_owner_account_id", "vms", ["owner_account_id"])

    op.add_column(
        "domains",
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_domains_owner_account_id", "domains", ["owner_account_id"])

    op.add_column(
        "vpn_tunnels",
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_vpn_tunnels_owner_account_id", "vpn_tunnels", ["owner_account_id"])


def downgrade() -> None:
    op.drop_index("ix_vpn_tunnels_owner_account_id", table_name="vpn_tunnels")
    op.drop_column("vpn_tunnels", "owner_account_id")

    op.drop_index("ix_domains_owner_account_id", table_name="domains")
    op.drop_column("domains", "owner_account_id")

    op.drop_index("ix_vms_owner_account_id", table_name="vms")
    op.drop_column("vms", "owner_account_id")

    op.drop_index("ix_recovery_attempts_created_at", table_name="recovery_attempts")
    op.drop_index("ix_recovery_attempts_ip_prefix_hash", table_name="recovery_attempts")
    op.drop_index("ix_recovery_attempts_account_id", table_name="recovery_attempts")
    op.drop_table("recovery_attempts")

    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_account_id", table_name="sessions")
    op.drop_table("sessions")

    op.drop_table("accounts")
