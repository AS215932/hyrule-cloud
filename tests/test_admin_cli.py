from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from hyrule_cloud import admin_cli
from hyrule_cloud.db import (
    AccountRow,
    AdminAuditRow,
    create_db_engine,
    create_session_factory,
    init_db,
)


@pytest.mark.asyncio
async def test_concurrent_first_admin_bootstrap_creates_only_one(
    tmp_path,
    monkeypatch,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'admin-bootstrap.db'}"
    engine = create_db_engine(database_url)
    await init_db(engine)
    await engine.dispose()

    async def schema_already_initialized(_engine) -> None:
        return None

    monkeypatch.setattr(admin_cli, "init_db", schema_already_initialized)
    monkeypatch.setattr(
        admin_cli,
        "HyruleConfig",
        lambda: SimpleNamespace(database_url=database_url),
    )
    monkeypatch.setattr(
        admin_cli,
        "_read_password",
        lambda: "a sufficiently long bootstrap password",
    )

    results = await asyncio.gather(
        admin_cli._create_admin(allow_additional=False),
        admin_cli._create_admin(allow_additional=False),
        return_exceptions=True,
    )

    successes = [result for result in results if isinstance(result, tuple)]
    failures = [result for result in results if isinstance(result, RuntimeError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert "enabled Admin already exists" in str(failures[0])

    engine = create_db_engine(database_url)
    sessions = create_session_factory(engine)
    async with sessions() as session:
        account_count = int(await session.scalar(select(func.count()).select_from(AccountRow)) or 0)
        audits = list(await session.scalars(select(AdminAuditRow)))
    await engine.dispose()
    assert account_count == 1
    assert len(audits) == 1 and audits[0].action == "admin.bootstrap"
