"""Exact VM resources and immutable pricing snapshots.

Revision ID: 016
Revises: 015
Create Date: 2026-07-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_JSONB = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vms", sa.Column("vcpu", sa.Integer()))
    op.add_column("vms", sa.Column("memory_mb", sa.Integer()))
    op.add_column("vms", sa.Column("disk_gb", sa.Integer()))
    for name in (
        "billing_addon_vcpu",
        "billing_addon_ram_mb",
        "billing_addon_disk_gb",
    ):
        op.add_column(
            "vms",
            sa.Column(name, sa.Integer(), nullable=False, server_default="0"),
        )

    # Preserve the resources actually sold under the retired catalog. Never
    # shrink a live disk as a side effect of changing the public profiles.
    op.execute(
        sa.text(
            "UPDATE vms SET "
            "vcpu = CASE size WHEN 'xs' THEN 1 WHEN 'sm' THEN 1 WHEN 'md' THEN 2 WHEN 'lg' THEN 4 END, "
            "memory_mb = CASE size WHEN 'xs' THEN 1024 WHEN 'sm' THEN 1024 WHEN 'md' THEN 2048 WHEN 'lg' THEN 4096 END, "
            "disk_gb = CASE size WHEN 'xs' THEN 10 WHEN 'sm' THEN 20 WHEN 'md' THEN 40 WHEN 'lg' THEN 80 END "
            "WHERE vcpu IS NULL"
        )
    )

    op.add_column("vm_quotes", sa.Column("pricing_snapshot", _JSONB))
    op.add_column("crypto_intents", sa.Column("pricing_snapshot", _JSONB))

    # In-flight legacy orders need an explicit resource snapshot before the
    # catalog definitions change. Their NULL pricing_snapshot deliberately
    # marks all historical add-on quantities as zero.
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for table in ("vm_quotes", "crypto_intents"):
            op.execute(
                sa.text(
                    f"UPDATE {table} SET order_payload = jsonb_set("
                    "order_payload, '{resources}', "
                    "CASE order_payload->>'size' "
                    "WHEN 'xs' THEN jsonb_build_object('vcpu',1,'ram_mb',1024,'disk_gb',10) "
                    "WHEN 'sm' THEN jsonb_build_object('vcpu',1,'ram_mb',1024,'disk_gb',20) "
                    "WHEN 'md' THEN jsonb_build_object('vcpu',2,'ram_mb',2048,'disk_gb',40) "
                    "WHEN 'lg' THEN jsonb_build_object('vcpu',4,'ram_mb',4096,'disk_gb',80) "
                    "END, true) "
                    "WHERE order_payload IS NOT NULL AND NOT (order_payload ? 'resources')"
                )
            )
    elif dialect == "sqlite":
        for table in ("vm_quotes", "crypto_intents"):
            op.execute(
                sa.text(
                    f"UPDATE {table} SET order_payload = json_set("
                    "order_payload, '$.resources', "
                    "CASE json_extract(order_payload, '$.size') "
                    "WHEN 'xs' THEN json_object('vcpu',1,'ram_mb',1024,'disk_gb',10) "
                    "WHEN 'sm' THEN json_object('vcpu',1,'ram_mb',1024,'disk_gb',20) "
                    "WHEN 'md' THEN json_object('vcpu',2,'ram_mb',2048,'disk_gb',40) "
                    "WHEN 'lg' THEN json_object('vcpu',4,'ram_mb',4096,'disk_gb',80) "
                    "END) WHERE order_payload IS NOT NULL "
                    "AND json_type(order_payload, '$.resources') IS NULL"
                )
            )


def downgrade() -> None:
    op.drop_column("crypto_intents", "pricing_snapshot")
    op.drop_column("vm_quotes", "pricing_snapshot")
    for name in (
        "billing_addon_disk_gb",
        "billing_addon_ram_mb",
        "billing_addon_vcpu",
        "disk_gb",
        "memory_mb",
        "vcpu",
    ):
        op.drop_column("vms", name)
