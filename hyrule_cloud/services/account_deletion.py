"""Serialize multi-transaction deletion with incoming ownership transfers."""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


async def lock_account_lifecycle(session: AsyncSession, account_id: str) -> None:
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        acquired = await session.scalar(text(
            "SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"
        ), {"key": "account-deletion:" + account_id})
        if not acquired:
            raise HTTPException(409, "Account deletion or ownership transfer is in progress; retry later")


@asynccontextmanager
async def account_deletion_guard(
    factory: async_sessionmaker[AsyncSession], account_id: str,
) -> AsyncIterator[None]:
    # A dedicated transaction spans provider calls and the short resource
    # transactions. It holds only an advisory lock, never account/VM row locks.
    # Transaction rollback on disconnect releases it for a safe retry.
    async with factory() as session, session.begin():
        await lock_account_lifecycle(session, account_id)
        yield
