"""Opt-in upgrade/backfill/rollback proof on an empty local PostgreSQL DB."""
import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = Path(__file__).resolve().parents[1]


def test_admin_postgres_migration_roundtrip():
    url = os.environ.get("HCP_ADMIN_MIGRATION_TEST_DATABASE_URL")
    if not url:
        pytest.skip("requires disposable admin_migration_test PostgreSQL")
    parsed = make_url(url)
    assert parsed.drivername == "postgresql+asyncpg"
    assert parsed.database == "admin_migration_test"
    assert parsed.host in (None, "localhost", "127.0.0.1", "::1")

    async def query(sql):
        engine = create_async_engine(url)
        try:
            async with engine.begin() as conn:
                result = await conn.execute(text(sql))
                return result.all() if result.returns_rows else []
        finally:
            await engine.dispose()

    def run(sql):
        return asyncio.run(query(sql))

    def migrate(direction, revision):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", direction, revision], cwd=ROOT,
            env=dict(os.environ, HYRULE_DATABASE_URL=url), capture_output=True,
            text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr

    assert run("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") == [(0,)]
    migrate("upgrade", "020")
    run("INSERT INTO accounts(account_id,password_hash) VALUES ('HTEST000001','fixture')")
    run("""INSERT INTO vms(vm_id,owner_wallet,owner_account_id,open_ports,cost_total)
        VALUES ('vm_paid','fixture','HTEST000001','{22}',2.50),
               ('vm_dev','0xDEV_TEST_WALLET','HTEST000001','{22}',1.25)""")
    migrate("upgrade", "head")
    assert run("SELECT version_num FROM alembic_version") == [('023',)]
    rows = run("SELECT vm_id,billing_mode,cost_total,retail_cost_total FROM vms ORDER BY vm_id")
    assert [(r[0], r[1], str(r[2]), str(r[3])) for r in rows] == [
        ('vm_dev', 'dev_bypass', '0.000000', '1.250000'),
        ('vm_paid', 'charged', '2.500000', '2.500000'),
    ]
    run("UPDATE vms SET suspension_reason='manual_admin' WHERE vm_id='vm_paid'")
    run("""INSERT INTO admin_audit(audit_id,actor_account_id,action)
        VALUES ('fixture-audit','HTEST000001','fixture.action')""")
    assert run("SELECT count(*) FROM admin_audit") == [(1,)]
    migrate("downgrade", "020")
    assert run("SELECT count(*) FROM vms") == [(2,)]
    assert run("SELECT count(*) FROM accounts") == [(1,)]
    assert run("SELECT count(*) FROM information_schema.columns WHERE table_name='vms' AND column_name='suspension_reason'") == [(0,)]
    migrate("upgrade", "head")
    assert run("SELECT version_num FROM alembic_version") == [('023',)]
    assert run("SELECT count(*) FROM vms") == [(2,)]
