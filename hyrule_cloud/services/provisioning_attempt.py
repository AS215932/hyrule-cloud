"""Cross-process exclusion for normal provisioning and restart recovery."""
from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from weakref import WeakValueDictionary

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

_local_locks: WeakValueDictionary[tuple[str, str], asyncio.Lock] = WeakValueDictionary()


@asynccontextmanager
async def provisioning_attempt(engine: AsyncEngine, vm_id: str) -> AsyncIterator[bool]:
    """Skip active attempts; transaction end/process loss releases ownership.

    Use a dedicated, non-pooled connection so a long guest wait cannot consume
    the API/receipt connection pool. Callers bound concurrent attempts separately.
    SQLite is for single-process development; PostgreSQL provides fleet exclusion.
    """
    if engine.dialect.name != 'postgresql':
        identity = (engine.url.render_as_string(hide_password=False), vm_id)
        lock = _local_locks.setdefault(identity, asyncio.Lock())
        if lock.locked():
            yield False
            return
        async with lock:
            yield True
        return

    key = int.from_bytes(hashlib.sha256(('hyrule-provision:' + vm_id).encode()).digest()[:8], signed=True)
    dedicated = create_async_engine(engine.url, poolclass=NullPool)
    try:
        async with dedicated.begin() as connection:
            acquired = await connection.scalar(text('SELECT pg_try_advisory_xact_lock(:key)'), {'key': key})
            if not acquired:
                yield False
                return
            owner = asyncio.current_task()

            async def watch_connection() -> None:
                try:
                    while True:
                        await asyncio.sleep(5)
                        await asyncio.wait_for(connection.execute(text('SELECT 1')), 5)
                except Exception:
                    # Stop local work if its database ownership connection dies.
                    # Cancellation cannot retract a provider request already sent.
                    if owner is not None:
                        owner.cancel()

            watcher = asyncio.create_task(watch_connection())
            try:
                yield True
            finally:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
    finally:
        await dedicated.dispose()
