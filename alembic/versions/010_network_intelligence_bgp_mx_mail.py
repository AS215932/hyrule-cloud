"""network intelligence, bgp, mx, and agent mail tables

Revision ID: 010
Revises: 009
Create Date: 2026-06-13
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> list[sa.Column]:
    return [sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now())]


def upgrade() -> None:
    op.create_table(
        "bgp_source_status",
        sa.Column("source_name", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("payload", sa.JSON()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "bgp_lookup_cache",
        sa.Column("cache_key", sa.String(128), primary_key=True),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_value", sa.String(256), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_bgp_lookup_cache_subject_type", "bgp_lookup_cache", ["subject_type"])
    op.create_index("ix_bgp_lookup_cache_subject_value", "bgp_lookup_cache", ["subject_value"])
    op.create_index("ix_bgp_lookup_cache_request_hash", "bgp_lookup_cache", ["request_hash"])
    op.create_index("ix_bgp_lookup_cache_expires_at", "bgp_lookup_cache", ["expires_at"])

    op.create_table(
        "bgp_snapshots",
        sa.Column("snapshot_id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("router", sa.String(64)),
        sa.Column("asn", sa.Integer()),
        sa.Column("prefix", sa.String(128)),
        sa.Column("artifact_path", sa.Text()),
        sa.Column("artifact_format", sa.String(64)),
        sa.Column("sha256", sa.String(64)),
        sa.Column("compressed_size_bytes", sa.Integer()),
        sa.Column("payload", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
    )
    for col in ["kind", "source", "router", "asn", "prefix", "created_at", "expires_at"]:
        op.create_index(f"ix_bgp_snapshots_{col}", "bgp_snapshots", [col])

    op.create_table(
        "bgp_jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("owner_wallet", sa.String(64)),
        sa.Column("payment_tx", sa.String(128)),
        sa.Column("access_token_hash", sa.String(64)),
        sa.Column("query", sa.JSON(), nullable=False),
        sa.Column("price_usd", sa.Numeric(12, 6)),
        sa.Column("claimed_by", sa.String(64)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("artifact_snapshot_id", sa.String(36)),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
    )
    for col in ["status", "owner_wallet", "access_token_hash", "artifact_snapshot_id", "expires_at"]:
        op.create_index(f"ix_bgp_jobs_{col}", "bgp_jobs", [col])

    op.create_table(
        "network_lookup_cache",
        sa.Column("cache_key", sa.String(128), primary_key=True),
        sa.Column("service", sa.String(32), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    for col in ["service", "subject", "expires_at"]:
        op.create_index(f"ix_network_lookup_cache_{col}", "network_lookup_cache", [col])

    op.create_table(
        "mx_jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("profile", sa.String(64), nullable=False),
        sa.Column("owner_wallet", sa.String(64)),
        sa.Column("payment_tx", sa.String(128)),
        sa.Column("access_token_hash", sa.String(64)),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON()),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
    )
    for col in ["status", "target", "owner_wallet", "access_token_hash", "expires_at"]:
        op.create_index(f"ix_mx_jobs_{col}", "mx_jobs", [col])

    op.create_table(
        "mail_accounts",
        sa.Column("mailbox_id", sa.String(36), primary_key=True),
        sa.Column("address", sa.String(320), nullable=False, unique=True),
        sa.Column("owner_wallet", sa.String(64)),
        sa.Column("owner_account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="SET NULL")),
        sa.Column("management_token_hash", sa.String(64)),
        sa.Column("plan", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(128)),
        sa.Column("features", sa.JSON()),
        sa.Column("backend", sa.String(64)),
        sa.Column("backend_id", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("payment_tx", sa.String(128)),
    )
    for col in ["address", "owner_wallet", "owner_account_id", "management_token_hash", "status", "expires_at"]:
        op.create_index(f"ix_mail_accounts_{col}", "mail_accounts", [col])

    op.create_table(
        "mail_domains",
        sa.Column("domain_id", sa.String(36), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False, unique=True),
        sa.Column("owner_account_id", sa.String(11), sa.ForeignKey("accounts.account_id", ondelete="SET NULL")),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("required_dns", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
    )
    for col in ["domain", "owner_account_id", "status"]:
        op.create_index(f"ix_mail_domains_{col}", "mail_domains", [col])

    op.create_table(
        "mail_aliases",
        sa.Column("alias_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("address", sa.String(320), nullable=False, unique=True),
        sa.Column("destination", sa.String(320), nullable=False),
        * _timestamps(),
    )
    op.create_index("ix_mail_aliases_mailbox_id", "mail_aliases", ["mailbox_id"])
    op.create_index("ix_mail_aliases_address", "mail_aliases", ["address"])

    op.create_table(
        "mail_identities",
        sa.Column("identity_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("address", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(128)),
        sa.Column("reply_to", sa.String(320)),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default="false"),
        * _timestamps(),
    )
    op.create_index("ix_mail_identities_mailbox_id", "mail_identities", ["mailbox_id"])
    op.create_index("ix_mail_identities_address", "mail_identities", ["address"])

    op.create_table(
        "mail_api_keys",
        sa.Column("key_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_mail_api_keys_mailbox_id", "mail_api_keys", ["mailbox_id"])
    op.create_index("ix_mail_api_keys_key_hash", "mail_api_keys", ["key_hash"])

    op.create_table(
        "mail_webhooks",
        sa.Column("webhook_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("secret_hash", sa.String(64)),
        * _timestamps(),
    )
    op.create_index("ix_mail_webhooks_mailbox_id", "mail_webhooks", ["mailbox_id"])

    op.create_table(
        "mail_events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("message_id", sa.String(128)),
        sa.Column("payload", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for col in ["mailbox_id", "type", "message_id", "created_at"]:
        op.create_index(f"ix_mail_events_{col}", "mail_events", [col])

    op.create_table(
        "mail_delivery_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("message_id", sa.String(128)),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("remote", sa.String(320)),
        sa.Column("detail", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for col in ["mailbox_id", "message_id", "status", "created_at"]:
        op.create_index(f"ix_mail_delivery_logs_{col}", "mail_delivery_logs", [col])

    op.create_table(
        "mail_message_index",
        sa.Column("message_id", sa.String(128), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("folder", sa.String(64), nullable=False),
        sa.Column("sender", sa.String(320)),
        sa.Column("recipients", sa.JSON()),
        sa.Column("subject", sa.Text()),
        sa.Column("flags", sa.JSON()),
        sa.Column("has_attachments", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for col in ["mailbox_id", "folder", "created_at"]:
        op.create_index(f"ix_mail_message_index_{col}", "mail_message_index", [col])

    op.create_table(
        "mail_quarantine",
        sa.Column("quarantine_id", sa.String(36), primary_key=True),
        sa.Column("mailbox_id", sa.String(36), nullable=False),
        sa.Column("message_id", sa.String(128), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("payload", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
    )
    for col in ["mailbox_id", "message_id", "created_at"]:
        op.create_index(f"ix_mail_quarantine_{col}", "mail_quarantine", [col])


def downgrade() -> None:
    for table in [
        "mail_quarantine",
        "mail_message_index",
        "mail_delivery_logs",
        "mail_events",
        "mail_webhooks",
        "mail_api_keys",
        "mail_identities",
        "mail_aliases",
        "mail_domains",
        "mail_accounts",
        "mx_jobs",
        "network_lookup_cache",
        "bgp_jobs",
        "bgp_snapshots",
        "bgp_lookup_cache",
        "bgp_source_status",
    ]:
        op.drop_table(table)
