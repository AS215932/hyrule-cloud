from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


def _migration_module():
    path = (
        Path(__file__).resolve().parent.parent
        / "alembic"
        / "versions"
        / "016_vm_configurable_resources.py"
    )
    spec = importlib.util.spec_from_file_location("migration_016", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_migration_016_backfills_retired_resources_without_repricing() -> None:
    engine = sa.create_engine("sqlite://")
    metadata = sa.MetaData()
    sa.Table(
        "vms",
        metadata,
        sa.Column("vm_id", sa.String, primary_key=True),
        sa.Column("size", sa.String, nullable=False),
    )
    for table_name, primary_key in (
        ("vm_quotes", "quote_id"),
        ("crypto_intents", "intent_id"),
    ):
        sa.Table(
            table_name,
            metadata,
            sa.Column(primary_key, sa.String, primary_key=True),
            sa.Column("order_payload", sa.JSON),
        )
    metadata.create_all(engine)

    order = {"duration_days": 1, "size": "lg", "ssh_pubkey": "ssh-ed25519 AAA"}
    with engine.begin() as connection:
        connection.execute(
            sa.text("INSERT INTO vms (vm_id, size) VALUES ('vm_legacy', 'lg')")
        )
        connection.execute(
            sa.text(
                "INSERT INTO vm_quotes (quote_id, order_payload) "
                "VALUES ('q_legacy', :payload)"
            ),
            {"payload": json.dumps(order)},
        )
        connection.execute(
            sa.text(
                "INSERT INTO crypto_intents (intent_id, order_payload) "
                "VALUES ('i_legacy', :payload)"
            ),
            {"payload": json.dumps(order)},
        )
        module = _migration_module()
        module.op = Operations(MigrationContext.configure(connection))
        module.upgrade()

        vm = connection.execute(
            sa.text(
                "SELECT vcpu, memory_mb, disk_gb, billing_addon_disk_gb "
                "FROM vms WHERE vm_id = 'vm_legacy'"
            )
        ).one()
        quote_payload = connection.execute(
            sa.text("SELECT order_payload FROM vm_quotes WHERE quote_id = 'q_legacy'")
        ).scalar_one()
        intent_payload = connection.execute(
            sa.text("SELECT order_payload FROM crypto_intents WHERE intent_id = 'i_legacy'")
        ).scalar_one()

    assert vm == (4, 4096, 80, 0)
    assert json.loads(quote_payload)["resources"]["disk_gb"] == 80
    assert json.loads(intent_payload)["resources"]["disk_gb"] == 80
    assert module.revision == "016"
    assert module.down_revision == "015"
