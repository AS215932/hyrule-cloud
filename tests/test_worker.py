from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from hyrule_cloud import worker


@pytest.mark.asyncio
async def test_bulk_admin_operations_run_outside_main_scheduler(monkeypatch) -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    stop = asyncio.Event()
    calls = 0

    async def slow_admin_batch(_sessions, _orchestrator, *, limit: int) -> int:
        nonlocal calls
        calls += 1
        assert limit == 10
        started.set()
        await release.wait()
        return 1

    monkeypatch.setattr(worker, "process_admin_operations", slow_admin_batch)
    task = asyncio.create_task(
        worker._run_admin_operations_loop(
            stop,
            SimpleNamespace(),
            SimpleNamespace(),
        )
    )
    await asyncio.wait_for(started.wait(), timeout=1)

    # The slow provider batch is still active, but other scheduler work can run.
    scheduler_tick = asyncio.Event()
    asyncio.get_running_loop().call_soon(scheduler_tick.set)
    await asyncio.wait_for(scheduler_tick.wait(), timeout=1)
    assert not task.done()

    stop.set()
    release.set()
    await asyncio.wait_for(task, timeout=1)
    assert calls == 1
