"""Administrator console, payment waivers, and audit trail.

Revision ID: 017
Revises: 016
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_JSONB = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_VM_DEV_BYPASS_BACKFILL = sa.text(
    """
    UPDATE vms
    SET billing_mode = 'dev_bypass', cost_total = 0
    WHERE billing_mode IS NULL
      AND (
        payment_tx = 'dev_bypass_0x0'
        OR owner_wallet = '0xDEV_TEST_WALLET'
      )
    """
)
_VM_CHARGED_BACKFILL = sa.text(
    "UPDATE vms SET billing_mode = 'charged' WHERE billing_mode IS NULL"
)
_DOMAIN_ORDER_DEV_BYPASS_BACKFILL = sa.text(
    """
    UPDATE domain_orders
    SET billing_mode = 'dev_bypass'
    WHERE billing_mode IS NULL
      AND (
        payment_tx = 'dev_bypass_0x0'
        OR payment_network = 'dev-bypass'
        OR payer = '0xDEV_TEST_WALLET'
      )
    """
)
_DOMAIN_ORDER_CHARGED_BACKFILL = sa.text(
    "UPDATE domain_orders SET billing_mode = 'charged' WHERE billing_mode IS NULL"
)


def upgrade() -> None:
    op.add_column("accounts", sa.Column("disabled_at", sa.DateTime(timezone=True)))
    op.add_column("accounts", sa.Column("disabled_reason", sa.Text()))
    op.add_column("accounts", sa.Column("disabled_by_account_id", sa.String(11)))
    op.create_foreign_key(
        "fk_accounts_disabled_by",
        "accounts",
        "accounts",
        ["disabled_by_account_id"],
        ["account_id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_accounts_disabled_at", "accounts", ["disabled_at"])

    op.add_column("sessions", sa.Column("csrf_token_hash", sa.String(64)))
    op.add_column("sessions", sa.Column("admin_elevated_at", sa.DateTime(timezone=True)))
    op.add_column(
        "sessions",
        sa.Column("admin_step_up_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "sessions", sa.Column("admin_step_up_window_started_at", sa.DateTime(timezone=True))
    )

    op.add_column(
        "vms", sa.Column("billing_mode", sa.String(24), nullable=True)
    )
    op.add_column(
        "vms", sa.Column("retail_cost_total", sa.Numeric(12, 6), nullable=False, server_default="0")
    )
    op.execute("UPDATE vms SET retail_cost_total = cost_total")
    op.execute(_VM_DEV_BYPASS_BACKFILL)
    op.execute(_VM_CHARGED_BACKFILL)
    op.alter_column(
        "vms",
        "billing_mode",
        existing_type=sa.String(24),
        nullable=False,
        server_default="charged",
    )
    op.add_column("vms", sa.Column("suspension_reason", sa.String(32)))
    op.add_column("vms", sa.Column("suspended_by_account_id", sa.String(11)))
    op.create_foreign_key(
        "fk_vms_suspended_by",
        "vms",
        "accounts",
        ["suspended_by_account_id"],
        ["account_id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_vms_billing_mode", "vms", ["billing_mode"])
    op.create_index("ix_vms_suspension_reason", "vms", ["suspension_reason"])

    op.add_column(
        "domain_orders",
        sa.Column("billing_mode", sa.String(24), nullable=True),
    )
    # Historical development-bypass orders already carry durable payment
    # markers. Derive their non-charged mode before filling the remaining rows
    # or installing the non-null production default, otherwise later failures
    # can create refund obligations for money that never moved.
    op.execute(_DOMAIN_ORDER_DEV_BYPASS_BACKFILL)
    op.execute(_DOMAIN_ORDER_CHARGED_BACKFILL)
    op.alter_column(
        "domain_orders",
        "billing_mode",
        existing_type=sa.String(24),
        nullable=False,
        server_default="charged",
    )
    op.create_index("ix_domain_orders_billing_mode", "domain_orders", ["billing_mode"])

    op.add_column("payment_events", sa.Column("actor_account_id", sa.String(11)))
    op.create_index("ix_payment_events_actor_account_id", "payment_events", ["actor_account_id"])

    op.add_column("mail_accounts", sa.Column("suspension_reason", sa.String(32)))
    op.add_column("mail_accounts", sa.Column("suspended_by_account_id", sa.String(11)))
    op.create_foreign_key(
        "fk_mail_accounts_suspended_by",
        "mail_accounts",
        "accounts",
        ["suspended_by_account_id"],
        ["account_id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_mail_accounts_suspension_reason", "mail_accounts", ["suspension_reason"])

    op.create_table(
        "admin_audit",
        sa.Column("audit_id", sa.String(36), primary_key=True),
        sa.Column(
            "actor_account_id",
            sa.String(11),
            nullable=False,
        ),
        sa.Column("action", sa.String(96), nullable=False),
        sa.Column("target_type", sa.String(32)),
        sa.Column("target_id", sa.String(256)),
        sa.Column("reason", sa.Text()),
        sa.Column("details", _JSONB),
        sa.Column("succeeded", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("ip_prefix_hash", sa.String(64)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    for column in ("actor_account_id", "action", "target_type", "target_id", "created_at"):
        op.create_index(f"ix_admin_audit_{column}", "admin_audit", [column])

    op.create_table(
        "admin_operations",
        sa.Column("operation_id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column(
            "account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "actor_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("reason", sa.Text()),
        sa.Column("progress", _JSONB),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    for column in ("kind", "account_id", "status"):
        op.create_index(f"ix_admin_operations_{column}", "admin_operations", [column])

    op.create_table(
        "refund_resolutions",
        sa.Column("resolution_id", sa.String(36), primary_key=True),
        sa.Column(
            "payment_event_id",
            sa.String(36),
            sa.ForeignKey("payment_events.event_id", ondelete="SET NULL"),
        ),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6)),
        sa.Column("network", sa.String(64)),
        sa.Column("payer_wallet", sa.String(128)),
        sa.Column("external_reference", sa.String(256)),
        sa.Column("transaction_hash", sa.String(128)),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "actor_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("resource_type", "resource_id", name="uq_refund_resolution_resource"),
    )
    for column in (
        "payment_event_id",
        "resource_type",
        "resource_id",
        "status",
        "actor_account_id",
    ):
        op.create_index(f"ix_refund_resolutions_{column}", "refund_resolutions", [column])

    op.create_table(
        "admin_bypass_usage",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "actor_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("operation_class", sa.String(24), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "actor_account_id",
            "operation_class",
            "window_started_at",
            name="uq_admin_bypass_usage_window",
        ),
    )
    op.create_index(
        "ix_admin_bypass_usage_actor_account_id", "admin_bypass_usage", ["actor_account_id"]
    )
    op.create_index(
        "ix_admin_bypass_usage_window_started_at", "admin_bypass_usage", ["window_started_at"]
    )


def downgrade() -> None:
    op.drop_table("admin_bypass_usage")
    op.drop_table("refund_resolutions")
    op.drop_table("admin_operations")
    op.drop_table("admin_audit")

    op.drop_index("ix_mail_accounts_suspension_reason", table_name="mail_accounts")
    op.drop_constraint("fk_mail_accounts_suspended_by", "mail_accounts", type_="foreignkey")
    op.drop_column("mail_accounts", "suspended_by_account_id")
    op.drop_column("mail_accounts", "suspension_reason")

    op.drop_index("ix_payment_events_actor_account_id", table_name="payment_events")
    op.drop_column("payment_events", "actor_account_id")

    op.drop_index("ix_domain_orders_billing_mode", table_name="domain_orders")
    op.drop_column("domain_orders", "billing_mode")

    op.drop_index("ix_vms_suspension_reason", table_name="vms")
    op.drop_index("ix_vms_billing_mode", table_name="vms")
    op.drop_constraint("fk_vms_suspended_by", "vms", type_="foreignkey")
    op.drop_column("vms", "suspended_by_account_id")
    op.drop_column("vms", "suspension_reason")
    op.drop_column("vms", "retail_cost_total")
    op.drop_column("vms", "billing_mode")

    op.drop_column("sessions", "admin_step_up_window_started_at")
    op.drop_column("sessions", "admin_step_up_attempts")
    op.drop_column("sessions", "admin_elevated_at")
    op.drop_column("sessions", "csrf_token_hash")

    op.drop_index("ix_accounts_disabled_at", table_name="accounts")
    op.drop_constraint("fk_accounts_disabled_by", "accounts", type_="foreignkey")
    op.drop_column("accounts", "disabled_by_account_id")
    op.drop_column("accounts", "disabled_reason")
    op.drop_column("accounts", "disabled_at")
