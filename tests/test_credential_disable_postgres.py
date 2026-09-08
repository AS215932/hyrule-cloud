"""Opt-in PostgreSQL proof that credential issuance orders with account disable."""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import Request

from hyrule_cloud.api.admin import ReasonRequest, disable_account
from hyrule_cloud.api.auth import (
    ApiKeyCreateRequest,
    AuthLoginRequest,
    create_api_key_endpoint,
    login,
)
from hyrule_cloud.db import AccountRow, ApiKeyRow, SessionRow
from hyrule_cloud.services.passwords import hash_password


@pytest.mark.asyncio
async def test_credential_issuance_serializes_with_account_disable():
    url = os.getenv("HCP_CREDENTIAL_DISABLE_TEST_DATABASE_URL")
    if not url:
        pytest.skip("requires fresh local credential_disable_test PostgreSQL")
    parsed = make_url(url)
    assert parsed.drivername == "postgresql+asyncpg"
    assert parsed.database == "credential_disable_test"
    assert parsed.host in (None, "localhost", "127.0.0.1", "::1")
    names = ("credential-issuer-fixture", "credential-disable-fixture", "credential-observer-fixture")
    engines = [
        create_async_engine(url, connect_args={"server_settings": {"application_name": name}})
        for name in names
    ]
    observer = async_sessionmaker(engines[2], expire_on_commit=False)
    tasks: list[asyncio.Task] = []
    releases: list[asyncio.Event] = []

    async def blocked(name: str) -> None:
        async with asyncio.timeout(5):
            while True:
                async with engines[2].connect() as connection:
                    waiting = await connection.scalar(text(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                        "WHERE application_name=:name "
                        "AND cardinality(pg_blocking_pids(pid)) > 0)"
                    ), {"name": name})
                if waiting:
                    return
                await asyncio.sleep(0.02)

    try:
        async with engines[2].connect() as connection:
            assert await connection.scalar(text(
                "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
            )) == 0
        migrated = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=Path(__file__).resolve().parents[1],
            env=dict(os.environ, HYRULE_DATABASE_URL=url),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert migrated.returncode == 0, migrated.stderr
        password = "fixture credential password"
        actor = AccountRow(account_id="HADMIN00001", password_hash="fixture", is_admin=True)
        async with observer.begin() as session:
            session.add(actor)

        for index, (kind, issuance_first) in enumerate(
            (kind, first) for kind in ("login", "api_key") for first in (True, False)
        ):
            account_id = f"HCRED00000{index}"
            account = AccountRow(account_id=account_id, password_hash=hash_password(password))
            async with observer.begin() as session:
                session.add(account)
            entered = asyncio.Event()
            release = asyncio.Event()
            releases.append(release)

            class HeldCommitSession(AsyncSession):
                async def commit(self) -> None:
                    await self.flush()
                    entered.set()
                    await release.wait()
                    await super().commit()

            issuer_factory = async_sessionmaker(
                engines[0],
                expire_on_commit=False,
                class_=HeldCommitSession if issuance_first else AsyncSession,
            )
            disable_factory = async_sessionmaker(
                engines[1],
                expire_on_commit=False,
                class_=AsyncSession if issuance_first else HeldCommitSession,
            )
            request = Request({
                "type": "http", "method": "POST", "path": "/fixture",
                "scheme": "https", "headers": [], "client": ("127.0.0.1", 1234),
                "server": ("test", 443),
            })
            request.state.is_api_key = False
            issuer_state = SimpleNamespace(
                orchestrator=SimpleNamespace(db=issuer_factory),
                session_factory=issuer_factory,
            )

            async def issue():
                if kind == "login":
                    return await login(
                        AuthLoginRequest(account_id=account_id, password=password),
                        request,
                        Response(),
                        issuer_state,
                    )
                return await create_api_key_endpoint(
                    ApiKeyCreateRequest(name="fixture", scopes=["vm:read"]),
                    request,
                    account,
                    issuer_state,
                )

            async def disable():
                return await disable_account(
                    account_id,
                    ReasonRequest(reason="fixture disable"),
                    request,
                    actor,
                    SimpleNamespace(session_factory=disable_factory),
                )

            first = asyncio.create_task(issue() if issuance_first else disable())
            tasks.append(first)
            entered_wait = asyncio.create_task(entered.wait())
            done, _ = await asyncio.wait(
                {first, entered_wait}, timeout=5, return_when=asyncio.FIRST_COMPLETED
            )
            if first in done:
                await first
            assert entered_wait in done, "first transaction did not reach its commit fence"
            second = asyncio.create_task(disable() if issuance_first else issue())
            tasks.append(second)
            await blocked(names[1] if issuance_first else names[0])
            release.set()
            await asyncio.wait_for(first, 5)
            if issuance_first:
                await asyncio.wait_for(second, 5)
            else:
                with pytest.raises(HTTPException) as denied:
                    await asyncio.wait_for(second, 5)
                assert denied.value.status_code == 403
            async with observer() as session:
                stored = await session.get(AccountRow, account_id)
                assert stored is not None and stored.disabled_at is not None
                assert await session.scalar(
                    select(func.count()).select_from(SessionRow).where(
                        SessionRow.account_id == account_id
                    )
                ) == 0
                assert await session.scalar(
                    select(func.count()).select_from(ApiKeyRow).where(
                        ApiKeyRow.account_id == account_id,
                        ApiKeyRow.revoked_at.is_(None),
                    )
                ) == 0
    finally:
        for release in releases:
            release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for engine in engines:
            await engine.dispose()
