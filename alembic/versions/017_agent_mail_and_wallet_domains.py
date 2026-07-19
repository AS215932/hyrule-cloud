"""Agent Mail and wallet-native domain orders.

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


def upgrade() -> None:
    op.alter_column("domain_orders", "owner_account_id", existing_type=sa.String(11), nullable=True)
    op.alter_column(
        "domain_operations", "owner_account_id", existing_type=sa.String(11), nullable=True
    )
    for column in (
        sa.Column("management_token_hash", sa.String(64)),
        sa.Column("management_token_ciphertext", sa.Text()),
        sa.Column("agent_idempotency_hash", sa.String(64)),
        sa.Column(
            "service_amount_usd",
            sa.Numeric(12, 6),
            nullable=False,
            server_default="0",
        ),
    ):
        op.add_column("domain_orders", column)
    op.create_index(
        "ix_domain_orders_management_token_hash",
        "domain_orders",
        ["management_token_hash"],
    )
    op.create_index(
        "uq_domain_orders_agent_idempotency_hash",
        "domain_orders",
        ["agent_idempotency_hash"],
        unique=True,
    )
    op.add_column(
        "domain_dns_records",
        sa.Column("managed_by", sa.String(32), nullable=False, server_default="customer"),
    )

    account_columns = (
        sa.Column("management_token_ciphertext", sa.Text()),
        sa.Column("backend_credential_ciphertext", sa.Text()),
        sa.Column("domain", sa.String(253)),
        sa.Column("local_part", sa.String(64)),
        sa.Column("domain_order_id", sa.String(32)),
        sa.Column("quote_id", sa.String(36)),
        sa.Column("idempotency_hash", sa.String(64)),
        sa.Column("terms_version", sa.String(64)),
        sa.Column("activation_amount_usd", sa.Numeric(12, 6)),
        sa.Column("total_amount_usd", sa.Numeric(12, 6)),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("grace_ends_at", sa.DateTime(timezone=True)),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("provision_error", sa.Text()),
        sa.Column("suspended_reason", sa.String(128)),
        sa.Column("payment_network", sa.String(64)),
        sa.Column("payment_asset", sa.String(66)),
    )
    for column in account_columns:
        op.add_column("mail_accounts", column)
    for name in ("domain", "domain_order_id", "quote_id", "grace_ends_at"):
        op.create_index(f"ix_mail_accounts_{name}", "mail_accounts", [name])
    op.create_index(
        "uq_mail_accounts_idempotency_hash",
        "mail_accounts",
        ["idempotency_hash"],
        unique=True,
    )

    for column in (
        sa.Column("secret_ciphertext", sa.Text()),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_delivered_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("mail_webhooks", column)

    op.create_table(
        "mail_quotes",
        sa.Column("quote_id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("mailbox_id", sa.String(36)),
        sa.Column("address", sa.String(320)),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("request_payload", _JSONB, nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("domain_quote_id", sa.String(32)),
        sa.Column("terms_version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
    )
    for name in (
        "kind",
        "status",
        "mailbox_id",
        "address",
        "domain_quote_id",
        "expires_at",
    ):
        op.create_index(f"ix_mail_quotes_{name}", "mail_quotes", [name])

    op.create_table(
        "mail_recipients",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("recipient", sa.String(320), nullable=False),
        sa.Column("first_sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("mailbox_id", "recipient", name="uq_mail_recipient_mailbox_address"),
    )
    op.create_index("ix_mail_recipients_mailbox_id", "mail_recipients", ["mailbox_id"])
    op.create_index("ix_mail_recipients_first_sent_at", "mail_recipients", ["first_sent_at"])

    op.create_table(
        "mail_sends",
        sa.Column("send_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("quote_id", sa.String(36), nullable=False, unique=True),
        sa.Column("recipient", sa.String(320), nullable=False),
        sa.Column("message_id", sa.String(128)),
        sa.Column("in_reply_to", sa.String(128)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("payment_tx", sa.String(128)),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
    )
    for name in (
        "mailbox_id",
        "quote_id",
        "recipient",
        "message_id",
        "in_reply_to",
        "status",
        "created_at",
    ):
        op.create_index(f"ix_mail_sends_{name}", "mail_sends", [name])

    op.create_table(
        "mail_webhook_deliveries",
        sa.Column("delivery_id", sa.String(36), primary_key=True),
        sa.Column("webhook_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("webhook_id", "event_id", name="uq_mail_webhook_event"),
    )
    for name in ("webhook_id", "event_id", "status", "next_attempt_at"):
        op.create_index(f"ix_mail_webhook_deliveries_{name}", "mail_webhook_deliveries", [name])


def downgrade() -> None:
    # Account-free orders cannot satisfy the pre-017 NOT NULL ownership
    # contract. Remove only those rows (and their nullable operations) before
    # restoring the old schema; account-owned history is preserved.
    op.execute(sa.text("DELETE FROM domain_operations WHERE owner_account_id IS NULL"))
    op.execute(sa.text("DELETE FROM domain_orders WHERE owner_account_id IS NULL"))
    op.drop_table("mail_webhook_deliveries")
    op.drop_table("mail_sends")
    op.drop_table("mail_recipients")
    op.drop_table("mail_quotes")
    for name in ("last_delivered_at", "failure_count", "status", "secret_ciphertext"):
        op.drop_column("mail_webhooks", name)
    for name in (
        "payment_asset",
        "payment_network",
        "suspended_reason",
        "provision_error",
        "deleted_at",
        "grace_ends_at",
        "activated_at",
        "total_amount_usd",
        "activation_amount_usd",
        "terms_version",
        "idempotency_hash",
        "quote_id",
        "domain_order_id",
        "local_part",
        "domain",
        "backend_credential_ciphertext",
        "management_token_ciphertext",
    ):
        op.drop_column("mail_accounts", name)
    op.drop_column("domain_dns_records", "managed_by")
    for name in (
        "service_amount_usd",
        "agent_idempotency_hash",
        "management_token_ciphertext",
        "management_token_hash",
    ):
        op.drop_column("domain_orders", name)
    op.alter_column(
        "domain_operations", "owner_account_id", existing_type=sa.String(11), nullable=False
    )
    op.alter_column(
        "domain_orders", "owner_account_id", existing_type=sa.String(11), nullable=False
    )
