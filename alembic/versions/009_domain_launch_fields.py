"""domain launch ownership and pricing fields

Revision ID: 009
Revises: 008
Create Date: 2026-06-12
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUS_VALUES = ("registering", "active", "failed", "expired")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {column["name"] for column in inspector.get_columns("domains")}
    existing_indexes = {index["name"] for index in inspector.get_indexes("domains")}
    existing_fks = {fk["name"] for fk in inspector.get_foreign_keys("domains")}

    status_enum = sa.Enum(*_STATUS_VALUES, name="domain_status")
    status_enum.create(bind, checkfirst=True)

    def add_column_if_missing(column: sa.Column) -> None:
        if column.name not in existing_columns:
            op.add_column("domains", column)
            existing_columns.add(column.name)

    add_column_if_missing(sa.Column("owner_account_id", sa.String(11), nullable=True))
    add_column_if_missing(sa.Column("anon_management_token_hash", sa.String(64), nullable=True))
    add_column_if_missing(
        sa.Column(
            "status",
            status_enum,
            nullable=False,
            server_default="active",
        )
    )
    add_column_if_missing(sa.Column("client_order_id", sa.String(64), nullable=True))
    add_column_if_missing(sa.Column("registrar_price", sa.Numeric(12, 6), nullable=True))
    add_column_if_missing(sa.Column("markup", sa.Numeric(12, 6), nullable=True))
    add_column_if_missing(sa.Column("total_price", sa.Numeric(12, 6), nullable=True))
    add_column_if_missing(sa.Column("currency", sa.String(8), nullable=False, server_default="USD"))
    add_column_if_missing(sa.Column("error", sa.Text(), nullable=True))

    if "domains_owner_account_id_fkey" not in existing_fks:
        op.create_foreign_key(
            "domains_owner_account_id_fkey",
            "domains",
            "accounts",
            ["owner_account_id"],
            ["account_id"],
            ondelete="SET NULL",
        )
    if "ix_domains_owner_account_id" not in existing_indexes:
        op.create_index("ix_domains_owner_account_id", "domains", ["owner_account_id"])
    if "ix_domains_anon_management_token_hash" not in existing_indexes:
        op.create_index("ix_domains_anon_management_token_hash", "domains", ["anon_management_token_hash"])
    if "ix_domains_status" not in existing_indexes:
        op.create_index("ix_domains_status", "domains", ["status"])
    if "ix_domains_client_order_id" not in existing_indexes:
        op.create_index("ix_domains_client_order_id", "domains", ["client_order_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_domains_client_order_id", table_name="domains")
    op.drop_index("ix_domains_status", table_name="domains")
    op.drop_index("ix_domains_anon_management_token_hash", table_name="domains")
    op.drop_index("ix_domains_owner_account_id", table_name="domains")
    op.drop_constraint("domains_owner_account_id_fkey", "domains", type_="foreignkey")
    op.drop_column("domains", "error")
    op.drop_column("domains", "currency")
    op.drop_column("domains", "total_price")
    op.drop_column("domains", "markup")
    op.drop_column("domains", "registrar_price")
    op.drop_column("domains", "client_order_id")
    op.drop_column("domains", "status")
    op.drop_column("domains", "anon_management_token_hash")
    op.drop_column("domains", "owner_account_id")
    sa.Enum(name="domain_status").drop(op.get_bind(), checkfirst=True)
