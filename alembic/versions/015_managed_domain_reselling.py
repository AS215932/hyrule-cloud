"""Managed domain reselling, wallet auth, DNS, and durable jobs.

Revision ID: 015
Revises: 014
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

_JSONB = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # PostgreSQL enums cannot be altered through add_column. Existing domain
    # rows retain their values while the managed lifecycle gains pending,
    # renewal, and transfer states.
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for value in (
            "provider_pending",
            "renewal_due",
            "transfer_pending",
            "transferred",
        ):
            op.execute(f"ALTER TYPE domain_status ADD VALUE IF NOT EXISTS '{value}'")

    json_empty = sa.text("'[]'::jsonb") if dialect == "postgresql" else sa.text("'[]'")

    op.add_column("domains", sa.Column("provider_status", sa.String(32)))
    op.add_column("domains", sa.Column("provider_operation_id", sa.String(128)))
    op.add_column(
        "domains",
        sa.Column("nameserver_mode", sa.String(16), nullable=False, server_default="managed"),
    )
    op.add_column(
        "domains",
        sa.Column(
            "nameservers",
            _JSONB,
            nullable=False,
            server_default=json_empty,
        ),
    )
    op.add_column(
        "domains",
        sa.Column("dnssec_mode", sa.String(16), nullable=False, server_default="managed"),
    )
    op.add_column(
        "domains",
        sa.Column("dnssec_status", sa.String(32), nullable=False, server_default="pending"),
    )
    op.add_column(
        "domains",
        sa.Column(
            "ds_records",
            _JSONB,
            nullable=False,
            server_default=json_empty,
        ),
    )
    op.add_column(
        "domains", sa.Column("zone_revision", sa.Integer(), nullable=False, server_default="1")
    )
    op.add_column(
        "domains", sa.Column("can_renew", sa.Boolean(), nullable=False, server_default="false")
    )
    op.add_column("domains", sa.Column("transferred_at", sa.DateTime(timezone=True)))
    op.add_column(
        "domains",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.add_column(
        "crypto_intents",
        sa.Column("resource_type", sa.String(32), nullable=False, server_default="vm"),
    )
    op.add_column("crypto_intents", sa.Column("resource_id", sa.String(64)))
    op.add_column("crypto_intents", sa.Column("refund_address", sa.String(128)))
    op.create_index("ix_crypto_intents_resource_id", "crypto_intents", ["resource_id"])

    op.create_table(
        "domain_tlds",
        sa.Column("tld", sa.String(63), primary_key=True),
        sa.Column("iana_type", sa.String(32)),
        sa.Column("provider_status", sa.String(32)),
        sa.Column("eligible", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ineligible_reason", sa.String(128)),
        sa.Column("registration_cost", sa.Numeric(12, 6)),
        sa.Column("renewal_cost", sa.Numeric(12, 6)),
        sa.Column("currency", sa.String(8)),
        sa.Column("metadata", _JSONB),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_domain_tlds_iana_type", "domain_tlds", ["iana_type"])
    op.create_index("ix_domain_tlds_eligible", "domain_tlds", ["eligible"])
    op.create_index("ix_domain_tlds_refreshed_at", "domain_tlds", ["refreshed_at"])

    op.create_table(
        "domain_quotes",
        sa.Column("quote_id", sa.String(32), primary_key=True),
        sa.Column("fqdn", sa.String(253), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("owner_account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="SET NULL")),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("provider_cost", sa.Numeric(12, 6), nullable=False),
        sa.Column("provider_currency", sa.String(8), nullable=False),
        sa.Column("fx_rate", sa.Numeric(20, 10), nullable=False),
        sa.Column("provider_cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("hyrule_fee_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("tax_usd", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column("total_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("available", sa.Boolean(), nullable=False),
        sa.Column("premium", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("provider_snapshot", _JSONB),
        sa.Column("terms_version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
    )
    for column in ("fqdn", "action", "owner_account_id", "status", "expires_at"):
        op.create_index(f"ix_domain_quotes_{column}", "domain_quotes", [column])

    op.create_table(
        "domain_orders",
        sa.Column("order_id", sa.String(32), primary_key=True),
        sa.Column("quote_id", sa.String(32), sa.ForeignKey("domain_quotes.quote_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("fqdn", sa.String(253), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("owner_account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="RESTRICT"), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="awaiting_payment"),
        sa.Column("amount_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("domain_amount_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("vm_amount_usd", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column("payment_method", sa.String(8), nullable=False),
        sa.Column("payment_network", sa.String(64)),
        sa.Column("payment_asset", sa.String(16)),
        sa.Column("payer", sa.String(128)),
        sa.Column("payment_tx", sa.String(128)),
        sa.Column("refund_address", sa.String(128)),
        sa.Column("native_intent_id", sa.String(36), sa.ForeignKey("crypto_intents.intent_id", ondelete="SET NULL")),
        sa.Column("operation_id", sa.String(32)),
        sa.Column("provider_domain_id", sa.Integer()),
        sa.Column("provider_status", sa.String(32)),
        sa.Column("provider_response", _JSONB),
        sa.Column("vm_quote_id", sa.String(36)),
        sa.Column("vm_id", sa.String(32)),
        sa.Column("on_domain_failure", sa.String(24), nullable=False, server_default="keep_vm"),
        sa.Column("terms_version", sa.String(64), nullable=False),
        sa.Column("terms_accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("error_detail", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("paid_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("owner_account_id", "idempotency_key", name="uq_domain_orders_account_idempotency"),
    )
    for column in (
        "quote_id", "fqdn", "action", "owner_account_id", "status", "payment_tx",
        "native_intent_id", "operation_id", "vm_quote_id", "vm_id",
    ):
        op.create_index(f"ix_domain_orders_{column}", "domain_orders", [column])

    op.create_table(
        "domain_operations",
        sa.Column("operation_id", sa.String(32), primary_key=True),
        sa.Column("fqdn", sa.String(253), nullable=False),
        sa.Column("owner_account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="CASCADE"), nullable=False),
        sa.Column("order_id", sa.String(32), sa.ForeignKey("domain_orders.order_id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("request_payload", _JSONB),
        sa.Column("result_payload", _JSONB),
        sa.Column("error_code", sa.String(64)),
        sa.Column("error_detail", sa.Text()),
        sa.Column("secret_ciphertext", sa.Text()),
        sa.Column("secret_expires_at", sa.DateTime(timezone=True)),
        sa.Column("secret_revealed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    for column in ("fqdn", "owner_account_id", "order_id", "kind", "status"):
        op.create_index(f"ix_domain_operations_{column}", "domain_operations", [column])

    op.create_table(
        "domain_dns_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "fqdn",
            sa.String(253),
            sa.ForeignKey("domains.fqdn", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(253), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=False),
        sa.Column("values", _JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("fqdn", "name", "type", name="uq_domain_dns_rrset"),
    )
    op.create_index("ix_domain_dns_records_fqdn", "domain_dns_records", ["fqdn"])

    op.create_table(
        "domain_idempotency",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response_payload", _JSONB, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "owner_account_id",
            "kind",
            "idempotency_key",
            name="uq_domain_idempotency_account_kind_key",
        ),
    )
    op.create_index(
        "ix_domain_idempotency_owner_account_id",
        "domain_idempotency",
        ["owner_account_id"],
    )
    op.create_index(
        "ix_domain_idempotency_created_at", "domain_idempotency", ["created_at"]
    )

    op.create_table(
        "domain_jobs",
        sa.Column("job_id", sa.String(32), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.String(64), nullable=False),
        sa.Column("dedupe_key", sa.String(160), nullable=False, unique=True),
        sa.Column("payload", _JSONB),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.Column("locked_by", sa.String(128)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    for column in ("kind", "resource_id", "status", "available_at", "locked_at"):
        op.create_index(f"ix_domain_jobs_{column}", "domain_jobs", [column])

    op.create_table(
        "account_wallets",
        sa.Column("wallet_id", sa.String(36), primary_key=True),
        sa.Column("account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("address", sa.String(42), nullable=False, unique=True),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_account_wallets_account_id", "account_wallets", ["account_id"])
    op.create_index("ix_account_wallets_address", "account_wallets", ["address"])

    op.create_table(
        "wallet_challenges",
        sa.Column("nonce", sa.String(64), primary_key=True),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("address", sa.String(42), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.String(11)),
        sa.Column("resource", sa.String(253)),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
    )
    for column in ("action", "address", "account_id", "resource", "expires_at"):
        op.create_index(f"ix_wallet_challenges_{column}", "wallet_challenges", [column])

    op.create_table(
        "openprovider_webhooks",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("event_type", sa.String(64)),
        sa.Column("payload", _JSONB, nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_openprovider_webhooks_event_type", "openprovider_webhooks", ["event_type"])

    # Rows created by the retired singular API used OpenProvider-hosted DNS.
    # They must be explicitly migrated/claimed before the managed Knot mode is
    # enabled; defaulting them to managed would advertise state that does not
    # exist on the authoritative pair.
    op.execute(
        sa.text(
            "UPDATE domains SET nameserver_mode = 'external', "
            "dnssec_mode = 'off', dnssec_status = 'off'"
        )
    )


def downgrade() -> None:
    op.drop_index("ix_openprovider_webhooks_event_type", table_name="openprovider_webhooks")
    op.drop_table("openprovider_webhooks")
    op.drop_table("wallet_challenges")
    op.drop_table("account_wallets")
    op.drop_table("domain_jobs")
    op.drop_table("domain_idempotency")
    op.drop_table("domain_dns_records")
    op.drop_table("domain_operations")
    op.drop_table("domain_orders")
    op.drop_table("domain_quotes")
    op.drop_table("domain_tlds")

    op.drop_index("ix_crypto_intents_resource_id", table_name="crypto_intents")
    op.drop_column("crypto_intents", "refund_address")
    op.drop_column("crypto_intents", "resource_id")
    op.drop_column("crypto_intents", "resource_type")

    for column in (
        "updated_at", "transferred_at", "can_renew", "zone_revision", "ds_records",
        "dnssec_status", "dnssec_mode", "nameservers", "nameserver_mode",
        "provider_operation_id", "provider_status",
    ):
        op.drop_column("domains", column)
    # PostgreSQL enum values are intentionally retained; removing enum values
    # is unsafe when any historic row or replica may still reference them.
