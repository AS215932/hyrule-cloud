from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.models import VMCreateRequest, VMOrderResources, VMSize, VMStatus
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.xcpng import XCPNGCapacity


class _CapacityProvider:
    def __init__(self, capacity: XCPNGCapacity) -> None:
        self._capacity = capacity

    async def capacity(self) -> XCPNGCapacity:
        return self._capacity


async def _orchestrator_with_pending(
    capacity: XCPNGCapacity,
) -> tuple[Orchestrator, AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        session.add(
            VMRow(
                vm_id="vm_pending",
                owner_wallet="",
                status=VMStatus.PROVISIONING,
                size="md",
                vcpu=2,
                memory_mb=4096,
                disk_gb=20,
                xcpng_uuid=None,
                ssh_pubkey="ssh-ed25519 AAAA pending",
            )
        )
        await session.commit()

    orchestrator = object.__new__(Orchestrator)
    orchestrator.db = sessions
    orchestrator.xcpng = cast(Any, _CapacityProvider(capacity))
    orchestrator.config = cast(
        Any,
        SimpleNamespace(
            xcpng=SimpleNamespace(
                vcpu_overcommit_ratio=Decimal("2.0"),
                memory_headroom_mb=2048,
                storage_headroom_gb=20,
            )
        )
    )
    return orchestrator, engine


def _order() -> VMCreateRequest:
    return VMCreateRequest(
        duration_days=1,
        size=VMSize.MD,
        resources=VMOrderResources(vcpu=2, ram_mb=4096, disk_gb=20),
        ssh_pubkey="ssh-ed25519 AAAA order",
    )


@pytest.mark.asyncio
async def test_capacity_admits_exact_headroom_after_pending_reservation() -> None:
    orchestrator, engine = await _orchestrator_with_pending(
        XCPNGCapacity(
            physical_vcpu=4,
            allocated_vcpu=4,
            free_memory_bytes=10 * 1024**3,
            free_storage_bytes=60 * 1024**3,
        )
    )
    try:
        await orchestrator.ensure_vm_capacity(_order())
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("capacity", "message"),
    [
        (
            XCPNGCapacity(4, 5, 20 * 1024**3, 100 * 1024**3),
            "insufficient vCPU capacity",
        ),
        (
            XCPNGCapacity(8, 0, 9 * 1024**3, 100 * 1024**3),
            "insufficient RAM capacity",
        ),
        (
            XCPNGCapacity(8, 0, 20 * 1024**3, 59 * 1024**3),
            "insufficient default-SR capacity",
        ),
    ],
)
async def test_capacity_rejects_resource_exhaustion_after_pending_reservation(
    capacity: XCPNGCapacity,
    message: str,
) -> None:
    orchestrator, engine = await _orchestrator_with_pending(capacity)
    try:
        with pytest.raises(RuntimeError, match=message):
            await orchestrator.ensure_vm_capacity(_order())
    finally:
        await engine.dispose()
