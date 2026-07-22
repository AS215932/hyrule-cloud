from __future__ import annotations

import importlib.util
from decimal import Decimal
from pathlib import Path

import sqlalchemy as sa


def _migration_module():
    path = (
        Path(__file__).resolve().parent.parent
        / "alembic"
        / "versions"
        / "017_admin_console.py"
    )
    spec = importlib.util.spec_from_file_location("migration_017", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_migration_017_backfills_legacy_dev_bypass_resources() -> None:
    module = _migration_module()
    engine = sa.create_engine("sqlite://")
    metadata = sa.MetaData()
    orders = sa.Table(
        "domain_orders",
        metadata,
        sa.Column("order_id", sa.String, primary_key=True),
        sa.Column("payment_tx", sa.String),
        sa.Column("payment_network", sa.String),
        sa.Column("payer", sa.String),
        sa.Column("billing_mode", sa.String),
    )
    vms = sa.Table(
        "vms",
        metadata,
        sa.Column("vm_id", sa.String, primary_key=True),
        sa.Column("owner_wallet", sa.String),
        sa.Column("payment_tx", sa.String),
        sa.Column("cost_total", sa.Numeric(12, 6)),
        sa.Column("retail_cost_total", sa.Numeric(12, 6)),
        sa.Column("billing_mode", sa.String),
    )
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            orders.insert(),
            [
                {
                    "order_id": "tx-marker",
                    "payment_tx": "dev_bypass_0x0",
                    "payment_network": None,
                    "payer": None,
                    "billing_mode": None,
                },
                {
                    "order_id": "network-marker",
                    "payment_tx": None,
                    "payment_network": "dev-bypass",
                    "payer": None,
                    "billing_mode": None,
                },
                {
                    "order_id": "payer-marker",
                    "payment_tx": None,
                    "payment_network": None,
                    "payer": "0xDEV_TEST_WALLET",
                    "billing_mode": None,
                },
                {
                    "order_id": "settled",
                    "payment_tx": "0xreal-settlement",
                    "payment_network": "eip155:8453",
                    "payer": "0xREAL_WALLET",
                    "billing_mode": None,
                },
            ],
        )
        connection.execute(module._DOMAIN_ORDER_DEV_BYPASS_BACKFILL)
        connection.execute(module._DOMAIN_ORDER_CHARGED_BACKFILL)
        connection.execute(
            vms.insert(),
            [
                {
                    "vm_id": "vm-dev",
                    "owner_wallet": "0xDEV_TEST_WALLET",
                    "payment_tx": "dev_bypass_0x0",
                    "cost_total": Decimal("1.25"),
                    "retail_cost_total": Decimal("1.25"),
                    "billing_mode": None,
                },
                {
                    "vm_id": "vm-paid",
                    "owner_wallet": "0xREAL_WALLET",
                    "payment_tx": "0xreal-settlement",
                    "cost_total": Decimal("2.50"),
                    "retail_cost_total": Decimal("2.50"),
                    "billing_mode": None,
                },
            ],
        )
        connection.execute(module._VM_DEV_BYPASS_BACKFILL)
        connection.execute(module._VM_CHARGED_BACKFILL)
        modes = dict(
            connection.execute(
                sa.select(orders.c.order_id, orders.c.billing_mode).order_by(orders.c.order_id)
            ).all()
        )
        vm_rows = {
            row.vm_id: row
            for row in connection.execute(
                sa.select(
                    vms.c.vm_id,
                    vms.c.billing_mode,
                    vms.c.cost_total,
                    vms.c.retail_cost_total,
                )
            )
        }

    assert modes == {
        "network-marker": "dev_bypass",
        "payer-marker": "dev_bypass",
        "settled": "charged",
        "tx-marker": "dev_bypass",
    }
    assert vm_rows["vm-dev"].billing_mode == "dev_bypass"
    assert vm_rows["vm-dev"].cost_total == Decimal("0.000000")
    assert vm_rows["vm-dev"].retail_cost_total == Decimal("1.250000")
    assert vm_rows["vm-paid"].billing_mode == "charged"
    assert vm_rows["vm-paid"].cost_total == Decimal("2.500000")
    assert module.revision == "017"
    assert module.down_revision == "016"
