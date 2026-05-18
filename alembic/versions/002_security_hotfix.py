"""security hotfix: anon management token for VM management gating

Block A0 of the hyrule-web ↔ hyrule-cloud integration. Adds the
sha256-hashed anon management token column so /logs, /reboot, /extend,
DELETE can be gated for anonymous (ownerless) VMs.

Legacy VMs created before this migration get NULL — management routes
deny by default; they must be claimed via the A1 claim flow to regain
management access.

Revision ID: 002
Revises: 001
Create Date: 2026-05-16
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vms",
        sa.Column("anon_management_token_hash", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_vms_anon_management_token_hash",
        "vms",
        ["anon_management_token_hash"],
    )


def downgrade() -> None:
    op.drop_index("ix_vms_anon_management_token_hash", table_name="vms")
    op.drop_column("vms", "anon_management_token_hash")
