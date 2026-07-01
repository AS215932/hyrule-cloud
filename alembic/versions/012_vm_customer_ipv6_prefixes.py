"""vm customer ipv6 prefixes

Revision ID: 012
Revises: 011
Create Date: 2026-07-01
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {column["name"] for column in inspector.get_columns("vms")}
    existing_indexes = {index["name"] for index in inspector.get_indexes("vms")}

    if "ipv6_prefix_index" not in existing_columns:
        op.add_column("vms", sa.Column("ipv6_prefix_index", sa.Integer(), nullable=True))
    if "ipv6_prefix" not in existing_columns:
        op.add_column("vms", sa.Column("ipv6_prefix", sa.String(64), nullable=True))

    if "ix_vms_ipv6_prefix_index" not in existing_indexes:
        op.create_index("ix_vms_ipv6_prefix_index", "vms", ["ipv6_prefix_index"], unique=True)
    if "ix_vms_ipv6_prefix" not in existing_indexes:
        op.create_index("ix_vms_ipv6_prefix", "vms", ["ipv6_prefix"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_vms_ipv6_prefix", table_name="vms")
    op.drop_index("ix_vms_ipv6_prefix_index", table_name="vms")
    op.drop_column("vms", "ipv6_prefix")
    op.drop_column("vms", "ipv6_prefix_index")
