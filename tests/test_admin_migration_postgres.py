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

    async def query(sql, params):
        engine = create_async_engine(url)
        try:
            async with engine.begin() as conn:
                result = await conn.execute(text(sql), params)
                return result.all() if result.returns_rows else []
        finally:
            await engine.dispose()

    def run(sql, params=None):
        return asyncio.run(query(sql, params or {}))

    def migrate(direction, revision, *, expected_error=None):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", direction, revision], cwd=ROOT,
            env=dict(os.environ, HYRULE_DATABASE_URL=url), capture_output=True,
            text=True, timeout=120,
        )
        if expected_error is not None:
            assert result.returncode != 0
            assert expected_error in result.stderr
        else:
            assert result.returncode == 0, result.stderr

    assert run("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") == [(0,)]
    migrate("upgrade", "020")
    run("INSERT INTO accounts(account_id,password_hash) VALUES ('HTEST000001','fixture')")
    run("""INSERT INTO vms(vm_id,owner_wallet,owner_account_id,open_ports,cost_total)
        VALUES ('vm_paid','fixture','HTEST000001','{22}',2.50),
               ('vm_dev','0xDEV_TEST_WALLET','HTEST000001','{22}',1.25)""")
    migrate("upgrade", "head")
    assert run("SELECT version_num FROM alembic_version") == [('025',)]
    rows = run("SELECT vm_id,billing_mode,cost_total,retail_cost_total FROM vms ORDER BY vm_id")
    assert [(r[0], r[1], str(r[2]), str(r[3])) for r in rows] == [
        ('vm_dev', 'dev_bypass', '0.000000', '1.250000'),
        ('vm_paid', 'charged', '2.500000', '2.500000'),
    ]
    run("UPDATE vms SET suspension_reason='manual_admin' WHERE vm_id='vm_paid'")
    run("""INSERT INTO admin_audit(audit_id,actor_account_id,action)
        VALUES ('fixture-audit','HTEST000001','fixture.action')""")
    assert run("SELECT count(*) FROM admin_audit") == [(1,)]
    run("UPDATE accounts SET disabled_at=now() WHERE account_id='HTEST000001'")
    migrate("downgrade", "020", expected_error="while accounts remain disabled")
    assert run("SELECT version_num FROM alembic_version") == [('025',)]
    assert run("SELECT count(*) FROM accounts WHERE disabled_at IS NOT NULL") == [(1,)]
    assert run("SELECT count(*) FROM admin_audit") == [(1,)]
    # Explicitly resolve the fixture's restriction before the ordinary rollback.
    run("UPDATE accounts SET disabled_at=NULL WHERE account_id='HTEST000001'")
    run("""INSERT INTO admin_operations(operation_id,kind,account_id,status)
        VALUES ('fixture-resume','resume_account_resources','HTEST000001','failed')""")
    migrate("downgrade", "020", expected_error="while account operations remain unresolved")
    run("UPDATE admin_operations SET status='completed' WHERE operation_id='fixture-resume'")
    run("UPDATE vms SET suspension_reason='account_disabled' WHERE vm_id='vm_paid'")
    migrate("downgrade", "020", expected_error="while account resumptions remain pending")
    run("UPDATE vms SET suspension_reason='manual_admin' WHERE vm_id='vm_paid'")
    for marker in ('null', '{}'):
        run("UPDATE vms SET metadata = CAST(:metadata AS jsonb) WHERE vm_id='vm_paid'",
            {"metadata": '{"extension_resume_pending":' + marker + '}'})
        migrate("downgrade", "020", expected_error="while paid VM resumptions remain pending")
        assert run("SELECT version_num FROM alembic_version") == [('023',)]
    run("UPDATE vms SET metadata='{}' WHERE vm_id='vm_paid'")
    run("UPDATE vms SET billing_mode='admin_waived' WHERE vm_id='vm_paid'")
    migrate("downgrade", "020", expected_error="while waived VMs remain actionable")
    run("UPDATE vms SET billing_mode='charged' WHERE vm_id='vm_paid'")
    run("""INSERT INTO domain_quotes(
        quote_id,fqdn,action,status,provider_cost,provider_currency,fx_rate,
        provider_cost_usd,hyrule_fee_usd,tax_usd,total_usd,available,premium,
        terms_version,expires_at)
        VALUES ('quote-waived','fixture.dev','register','consumed',1,'USD',1,1,0,0,1,
                true,false,'fixture',now()+interval '1 hour')""")
    run("""INSERT INTO domain_orders(
        order_id,quote_id,fqdn,action,owner_account_id,idempotency_key,status,
        amount_usd,domain_amount_usd,vm_amount_usd,payment_method,billing_mode,
        on_domain_failure,terms_version,terms_accepted_at)
        VALUES ('order-waived','quote-waived','fixture.dev','register','HTEST000001',
                'fixture-waived','failed',1,1,0,'x402','admin_waived','keep_vm',
                'fixture',now())""")
    migrate("downgrade", "020", expected_error="while waived domain orders remain actionable")
    run("UPDATE domain_orders SET status='active' WHERE order_id='order-waived'")
    migrate("downgrade", "020")
    assert run("SELECT count(*) FROM vms") == [(2,)]
    assert run("SELECT count(*) FROM accounts") == [(1,)]
    assert run("SELECT count(*) FROM information_schema.columns WHERE table_name='vms' AND column_name='suspension_reason'") == [(0,)]
    migrate("upgrade", "head")
    assert run("SELECT version_num FROM alembic_version") == [('025',)]
    assert run("SELECT count(*) FROM vms") == [(2,)]
