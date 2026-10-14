from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.db import Base, VMGuestResultRow, VMRow
from hyrule_cloud.services.guest_result import (
    GuestResult,
    GuestResultRejectedError,
    accept_guest_result,
    prepare_guest_result,
)


@pytest.mark.asyncio
async def test_guest_receipt_is_scoped_durable_and_immutable(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'guest.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    deadline = datetime.now(UTC) + timedelta(minutes=10)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(vm_id="vm_test", owner_wallet="test"))
        async with factory.begin() as session:
            generation, token = await prepare_guest_result(session, "vm_test", deadline)
        failure = GuestResult(outcome="failed", stage="setup_script", exit_code=7)
        for vm_id, gen, supplied in (("vm_other", generation, token), ("vm_test", "0" * 32, token), ("vm_test", generation, "incorrect")):
            async with factory.begin() as session:
                with pytest.raises(GuestResultRejectedError) as error:
                    await accept_guest_result(session, vm_id, gen, supplied, failure)
                assert error.value.status_code == 404
        async with factory.begin() as session:
            await accept_guest_result(session, "vm_test", generation, token, failure)
        # New session represents retry after a receiver restart/lost response.
        async with factory.begin() as session:
            await accept_guest_result(session, "vm_test", generation, token, failure, now=deadline + timedelta(hours=1))
            row = await session.get(VMGuestResultRow, "vm_test")
            assert row.token_hash != token
            assert row.outcome == "failed" and row.exit_code == 7
            with pytest.raises(GuestResultRejectedError) as error:
                await accept_guest_result(session, "vm_test", generation, token, GuestResult(outcome="succeeded", stage="cloud_init", exit_code=0))
            assert error.value.status_code == 409
        async with factory.begin() as session:
            vm = await session.get(VMRow, "vm_test")
            vm.xcpng_uuid = "tracked-guest"
        async with factory.begin() as session:
            with pytest.raises(GuestResultRejectedError):
                await prepare_guest_result(session, "vm_test", deadline)
        async with factory.begin() as session:
            session.add(VMRow(vm_id="vm_late", owner_wallet="test"))
        async with factory.begin() as session:
            late_generation, late_token = await prepare_guest_result(session, "vm_late", deadline)
        async with factory.begin() as session:
            with pytest.raises(GuestResultRejectedError) as error:
                await accept_guest_result(session, "vm_late", late_generation, late_token, failure, now=deadline + timedelta(seconds=1))
            assert error.value.status_code == 410
    finally:
        await engine.dispose()


@pytest.mark.parametrize("payload", [
    {"outcome": "succeeded", "stage": "setup_script", "exit_code": 0},
    {"outcome": "failed", "stage": "cloud_init", "exit_code": 0},
    {"outcome": "failed", "stage": "cloud_init", "exit_code": -1},
    {"outcome": "failed", "stage": "cloud_init", "exit_code": 1, "logs": "private"},
])
def test_guest_result_rejects_ambiguous_or_unbounded_fields(payload):
    with pytest.raises(ValueError):
        GuestResult.model_validate(payload)


@pytest.mark.asyncio
async def test_guest_receipt_http_contract(tmp_path):
    from types import SimpleNamespace

    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from hyrule_cloud.api.routes import get_orch, router

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'http-guest.db'}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory.begin() as session:
            session.add(VMRow(vm_id="vm_http", owner_wallet="test"))
        async with factory.begin() as session:
            generation, token = await prepare_guest_result(session, "vm_http", datetime.now(UTC) + timedelta(minutes=10))
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_orch] = lambda: SimpleNamespace(db=factory)
        path = f"/v1/vm/vm_http/guest-result/{generation}"
        payload = {"outcome": "failed", "stage": "setup_script", "exit_code": 7}
        headers = {"Authorization": f"Bearer {token}"}
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            assert (await client.post(path, json=payload)).status_code == 404
            response = await client.post(path, json=payload, headers=headers)
            assert response.status_code == 204 and response.content == b""
            assert (await client.post(path, json=payload, headers=headers)).status_code == 204
            assert (await client.post(path, json={**payload, "exit_code": 8}, headers=headers)).status_code == 409
            assert (await client.post(path, json={**payload, "log": "not accepted"}, headers=headers)).status_code == 400
            assert (await client.post(path, content=b" " * 1025, headers={**headers, "Content-Type": "application/json"})).status_code == 413
        async with factory() as session:
            receipt = await session.get(VMGuestResultRow, "vm_http")
            assert receipt.exit_code == 7 and receipt.stage == "setup_script"
    finally:
        await engine.dispose()
