"""native crypto intent engine: state machine + idempotency + ownership link

Block E. Creates `crypto_intents` and the `crypto_intent_status` enum in their
full LENIENT-policy shape: the toy pending/paid carry-overs plus the state
machine CREATED → WAITING_PAYMENT → SETTLED → PROVISIONING → PROVISIONED, with
UNDERPAID/OVERPAID/LATE_PAID/EXPIRED/FAILED/REFUND_MANUAL branches. Carries the
idempotency key, order payload, rate snapshot, confirmations tracker, atomic
provisioning trigger, XMR subaddress index, account link, and VM back-reference.

Self-contained: it does NOT assume the hand-applied db_patch toy table/enum.
Lands as dead schema in Wave 2; the engine code that reads it ships in Wave 4
behind HYR_FEATURES_INTENT_ENGINE.

Revision ID: 004
Revises: 003
Create Date: 2026-05-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection

from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Full crypto_intent_status value set: the legacy toy `pending`/`paid` plus the
# Block E state machine. Order MATCHES hyrule_cloud.models.CryptoIntentStatus so
# an alembic-migrated DB and a create_all() DB (tests) produce the same enum.
_STATUS_VALUES = (
    "pending",
    "paid",
    "CREATED",
    "WAITING_PAYMENT",
    "UNDERPAID",
    "OVERPAID",
    "LATE_PAID",
    "SETTLED",
    "EXPIRED",
    "PROVISIONING",
    "PROVISIONED",
    "FAILED",
    "REFUND_MANUAL",
)


def _legacy_toy_schema_present(bind: Connection) -> bool:
    """True if the hand-applied db_patch toy `crypto_intents` table or
    `crypto_intent_status` enum is still in the DB. Those predate the alembic
    chain; this migration creates both fresh, so they must be gone first."""
    if "crypto_intents" in sa.inspect(bind).get_table_names():
        return True
    if bind.dialect.name == "postgresql":
        row = bind.execute(
            sa.text("SELECT 1 FROM pg_type WHERE typname = 'crypto_intent_status'")
        ).first()
        return row is not None
    return False


def upgrade() -> None:
    # Fail fast with an actionable message if the legacy toy schema is still
    # present, rather than a cryptic "relation/type already exists". The only
    # environment that ever had it is `api`; playbooks/cloud_toy_cleanup.yml
    # drops the empty toy accounts + crypto_intents + crypto_intent_status and
    # is the documented pre-migration step.
    if _legacy_toy_schema_present(op.get_bind()):
        raise RuntimeError(
            "Legacy db_patch toy crypto_intents/crypto_intent_status detected. "
            "Run playbooks/cloud_toy_cleanup.yml (idempotent, refuses non-empty "
            "tables) before applying migration 004."
        )

    # The crypto_intents table + crypto_intent_status enum are CREATED here,
    # not extended. Earlier revisions of this migration assumed both already
    # existed from the hand-applied db_patch toy scripts on `api`; that made the
    # chain unappliable on a clean DB (disaster recovery, new env, alembic CI).
    # We now create the full Block E shape from scratch so 001→006 applies on
    # any empty database. This is dead schema until Wave 4 flips
    # HYR_FEATURES_INTENT_ENGINE; no code reads it before then.
    #
    # JSONB on Postgres, generic JSON on SQLite (tests use create_all, not this
    # migration, but keep the variant for parity).
    json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")

    # sa.Enum inside create_table emits CREATE TYPE before CREATE TABLE on
    # Postgres and a CHECK constraint on SQLite — matching the model's
    # Enum(..., name="crypto_intent_status"). Listing literal values (not user
    # input) sidesteps the ALTER TYPE string-interpolation the old revision
    # needed (and the Sourcery SQL-injection finding it carried).
    status_enum = sa.Enum(*_STATUS_VALUES, name="crypto_intent_status")

    op.create_table(
        "crypto_intents",
        sa.Column("intent_id", sa.String(36), primary_key=True),
        sa.Column("asset", sa.String(8), nullable=False),
        sa.Column("amount_crypto", sa.Numeric(24, 12), nullable=False),
        sa.Column("amount_usd", sa.Numeric(12, 6), nullable=True),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("status", status_enum, nullable=False),
        sa.Column("bip32_index", sa.Integer, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tx_hash", sa.String(128), nullable=True),
        # --- Block E additions ---
        sa.Column("client_order_id", sa.String(64), nullable=True),
        sa.Column("order_payload", json_type, nullable=True),
        sa.Column("rate_snapshot", sa.Numeric(20, 8), nullable=True),
        sa.Column("rate_valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmations", sa.Integer, nullable=False, server_default="0"),
        sa.Column("amount_received_crypto", sa.Numeric(24, 12), nullable=True),
        sa.Column("provisioning_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("xmr_subaddr_index", sa.Integer, nullable=True),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "owner_account_id",
            sa.String(11),
            sa.ForeignKey("accounts.account_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("vm_id", sa.String(32), nullable=True),
        # One-shot reveal column for the anon management token cleartext (see db.py).
        sa.Column("anon_token_cleartext", sa.String(64), nullable=True),
    )

    op.create_index("ix_crypto_intents_status_expires", "crypto_intents", ["status", "expires_at"])
    op.create_index("ix_crypto_intents_asset_bip32", "crypto_intents", ["asset", "bip32_index"])
    op.create_index(
        "ix_crypto_intents_client_order_id", "crypto_intents", ["client_order_id"], unique=True
    )
    # Model declares `unique=True` (no index=True) on xmr_subaddr_index, which
    # create_all renders as a unique CONSTRAINT, not an index. Match that exact
    # form/name so autogenerate stays quiet.
    op.create_unique_constraint(
        "crypto_intents_xmr_subaddr_index_key", "crypto_intents", ["xmr_subaddr_index"]
    )
    op.create_index("ix_crypto_intents_owner_account_id", "crypto_intents", ["owner_account_id"])
    op.create_index("ix_crypto_intents_vm_id", "crypto_intents", ["vm_id"])


def downgrade() -> None:
    op.drop_table("crypto_intents")
    # create_table auto-created the enum on Postgres; drop it explicitly so a
    # downgrade leaves no orphan type behind. checkfirst keeps SQLite happy.
    sa.Enum(name="crypto_intent_status").drop(op.get_bind(), checkfirst=True)
