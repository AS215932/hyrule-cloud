"""Run the actual migration chain on an explicitly supplied disposable database."""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = Path(__file__).resolve().parents[1]


def test_postgres_migration_roundtrip() -> None:
    database_url = os.environ.get("HCP_MIGRATION_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicit disposable PostgreSQL migration database")
    url = make_url(database_url)
    assert url.drivername == "postgresql+asyncpg"
    assert url.database == "cloud_migration_test", "refusing a non-test database"
    assert url.host in (None, "localhost", "127.0.0.1", "::1"), "requires local test PostgreSQL"
    env = dict(os.environ, HYRULE_DATABASE_URL=database_url)

    async def state() -> tuple[set[str], set[str]]:
        engine = create_async_engine(database_url)
        try:
            async with engine.connect() as connection:
                tables = set(await connection.run_sync(lambda conn: inspect(conn).get_table_names()))
                revisions = set()
                if "alembic_version" in tables:
                    revisions = set((await connection.execute(text("SELECT version_num FROM alembic_version"))).scalars())
                return tables, revisions
        finally:
            await engine.dispose()

    def migrate(direction: str, revision: str) -> None:
        subprocess.run(
            [sys.executable, "-m", "alembic", direction, revision],
            cwd=ROOT, env=env, check=True, timeout=120,
        )

    tables, revisions = asyncio.run(state())
    assert not tables and not revisions, "requires a fresh empty database; never uses create_all"
    expected = set(ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_heads())
    assert len(expected) == 1, "migration history must have one head"
    migrate("upgrade", "head")
    tables, revisions = asyncio.run(state())
    assert revisions == expected
    assert "vms" in tables
    migrate("downgrade", "base")
    tables, revisions = asyncio.run(state())
    assert tables <= {"alembic_version"}
    assert not revisions
    # A second upgrade also catches leftover enum/type objects after downgrade.
    migrate("upgrade", "head")
    assert asyncio.run(state())[1] == expected
