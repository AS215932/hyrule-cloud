"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- VM status and size enums ---
    vm_status = postgresql.ENUM(
        "provisioning", "ready", "running", "suspended", "failed", "destroyed",
        name="vm_status",
        create_type=False,
    )
    vm_size = postgresql.ENUM(
        "xs", "sm", "md", "lg",
        name="vm_size",
        create_type=False,
    )
    domain_mode = postgresql.ENUM(
        "auto", "custom",
        name="domain_mode",
        create_type=False,
    )

    vm_status.create(op.get_bind(), checkfirst=True)
    vm_size.create(op.get_bind(), checkfirst=True)
    domain_mode.create(op.get_bind(), checkfirst=True)

    # --- VMs table ---
    op.create_table(
        "vms",
        sa.Column("vm_id", sa.String(32), primary_key=True),
        sa.Column("xcpng_uuid", sa.String(64), nullable=True),
        sa.Column("owner_wallet", sa.String(64), nullable=False, index=True),
        sa.Column("status", vm_status, nullable=False, server_default="provisioning"),
        sa.Column("size", vm_size, nullable=False, server_default="xs"),
        sa.Column("os", sa.String(64), nullable=False, server_default="debian-12"),
        sa.Column("ipv6", sa.String(64), nullable=True),
        sa.Column("hostname", sa.String(256), nullable=True),
        sa.Column("ssh_pubkey", sa.Text, nullable=False, server_default=""),
        sa.Column("open_ports", postgresql.ARRAY(sa.Integer), nullable=False),
        sa.Column("setup_script", sa.Text, nullable=True),
        sa.Column("domain_mode", domain_mode, nullable=False, server_default="auto"),
        sa.Column("domain", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("payment_tx", sa.String(128), nullable=True),
        sa.Column("cost_total", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_vms_status_expires", "vms", ["status", "expires_at"])
    op.create_index("ix_vms_owner_status", "vms", ["owner_wallet", "status"])

    # --- Domains table ---
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("extension", sa.String(32), nullable=False),
        sa.Column("fqdn", sa.String(256), nullable=False, unique=True, index=True),
        sa.Column("vm_id", sa.String(32), nullable=True, index=True),
        sa.Column("owner_wallet", sa.String(64), nullable=False, index=True),
        sa.Column("openprovider_id", sa.Integer, nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payment_tx", sa.String(128), nullable=True),
    )

    # --- VPN tunnels table ---
    op.create_table(
        "vpn_tunnels",
        sa.Column("tunnel_id", sa.String(32), primary_key=True),
        sa.Column("vm_id", sa.String(32), nullable=True, index=True),
        sa.Column("owner_wallet", sa.String(64), nullable=False, index=True),
        sa.Column("wg_pubkey", sa.String(64), nullable=False),
        sa.Column("wg_endpoint", sa.String(128), nullable=True),
        sa.Column("wg_config", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payment_tx", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("vpn_tunnels")
    op.drop_table("domains")
    op.drop_table("vms")

    op.execute("DROP TYPE IF EXISTS domain_mode")
    op.execute("DROP TYPE IF EXISTS vm_size")
    op.execute("DROP TYPE IF EXISTS vm_status")
