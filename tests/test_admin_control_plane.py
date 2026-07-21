from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
import pytest_asyncio
from fastapi import HTTPException, Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from x402.http import PAYMENT_SIGNATURE_HEADER

from hyrule_cloud.app import app
from hyrule_cloud.config import PaymentConfig
from hyrule_cloud.db import (
    AccountRow,
    AdminOperationRow,
    Base,
    MailAccountRow,
    PaymentEventRow,
    RefundResolutionRow,
    SessionRow,
    VMRow,
)
from hyrule_cloud.middleware.x402 import ADMIN_PAYMENT_MODE_HEADER, PaymentGate
from hyrule_cloud.services.admin_operations import process_admin_operations
from hyrule_cloud.services.passwords import hash_password
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.services.sessions import create_session
from hyrule_cloud.state import AppState
from tests.test_payment_gate_x402 import (
    PAYER,
    RECEIVER,
    _FakeServer,
    _payment_header,
    _request,
)


@pytest_asyncio.fixture
async def admin_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _admin_credentials(admin_factory, *, elevated: bool = False):
    async with admin_factory() as session:
        session.add(
            AccountRow(
                account_id="HAAAAAAAAAA",
                password_hash=hash_password("correct horse battery staple"),
                is_admin=True,
            )
        )
        await session.commit()
        credentials = await create_session(session, "HAAAAAAAAAA")
        if elevated:
            # Resolve by account rather than depending on token hash internals.
            row = (
                await session.execute(
                    select(SessionRow).where(SessionRow.account_id == "HAAAAAAAAAA")
                )
            ).scalar_one()
            row.admin_elevated_at = datetime.now(UTC)
            await session.commit()
    return credentials


def _browser_request(credentials, *, path: str, extra: dict[str, str] | None = None):
    headers = {
        "Cookie": f"hyr_sess={credentials.token}; hyr_csrf={credentials.csrf_token}",
        "X-CSRF-Token": credentials.csrf_token,
        **(extra or {}),
    }
    return _request(headers, path=path)


def _admin_gate(admin_factory, *, diagnostic_limit: int = 120) -> PaymentGate:
    gate = PaymentGate(
        PaymentConfig(
            receiver_address=RECEIVER,
            facilitator_url="https://facilitator.payai.network",
            dev_bypass_secret="",
        ),
        session_factory=admin_factory,
        admin_bypass_enabled=True,
        admin_diagnostic_limit=diagnostic_limit,
    )
    gate.server = _FakeServer()  # type: ignore[assignment]
    gate.ledger = PaymentLedger(admin_factory)
    return gate


@pytest.mark.asyncio
async def test_admin_diagnostic_waiver_is_auditable_and_not_a_settlement(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    gate = _admin_gate(admin_factory)
    request = _browser_request(credentials, path="/v1/dns/lookup")

    payer = await gate.check_payment(request, Decimal("0.01"), "DNS lookup")

    assert payer == "admin:HAAAAAAAAAA"
    assert request.state.payment_mode == "admin-bypass"
    assert request.state.payment_response_headers == {ADMIN_PAYMENT_MODE_HEADER: "admin-bypass"}
    async with admin_factory() as session:
        events = list(await session.scalars(select(PaymentEventRow)))
    assert [event.event_type for event in events] == ["admin_bypass"]
    assert events[0].actor_account_id == "HAAAAAAAAAA"
    assert events[0].amount_usd == Decimal("0.01")
    assert events[0].network == "admin-bypass"


@pytest.mark.asyncio
async def test_real_cost_waiver_requires_recent_password_step_up(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    gate = _admin_gate(admin_factory)
    request = _browser_request(credentials, path="/v1/vm/create")

    with pytest.raises(HTTPException) as exc:
        await gate.check_payment(request, Decimal("1.00"), "VM")

    assert exc.value.status_code == 403
    assert exc.value.detail == "admin_step_up_required"


@pytest.mark.asyncio
async def test_elevated_admin_can_waive_real_cost_without_settlement(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    gate = _admin_gate(admin_factory)
    server = gate.server
    request = _browser_request(credentials, path="/v1/vm/create")

    payer = await gate.check_payment(request, Decimal("1.00"), "VM")

    assert payer == "admin:HAAAAAAAAAA"
    assert request.state.payment_tx.startswith("admin_bypass_")
    assert server.settle_payment_calls == 0


@pytest.mark.asyncio
async def test_admin_waiver_requires_csrf_and_rejects_bearer_composition(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    gate = _admin_gate(admin_factory)
    no_csrf = _request(
        {"Cookie": f"hyr_sess={credentials.token}; hyr_csrf={credentials.csrf_token}"},
        path="/v1/dns/lookup",
    )
    with pytest.raises(HTTPException) as csrf_error:
        await gate.check_payment(no_csrf, Decimal("0.01"), "DNS lookup")
    assert csrf_error.value.status_code == 403

    bearer = _browser_request(
        credentials,
        path="/v1/dns/lookup",
        extra={"Authorization": "Bearer hyr_sk_untrusted"},
    )
    challenged = await gate.check_payment(bearer, Decimal("0.01"), "DNS lookup")
    assert isinstance(challenged, Response)
    assert challenged.status_code == 402


@pytest.mark.asyncio
async def test_real_payment_signature_wins_over_admin_waiver(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    server = _FakeServer()
    gate = _admin_gate(admin_factory)
    gate.server = server  # type: ignore[assignment]
    request = _browser_request(
        credentials,
        path="/v1/vm/create",
        extra={PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])},
    )

    payer = await gate.check_payment(request, Decimal("0.05"), "VM")

    assert payer == PAYER
    assert server.settle_payment_calls == 1
    async with admin_factory() as session:
        events = list(await session.scalars(select(PaymentEventRow)))
    assert [event.event_type for event in events] == ["settled"]


@pytest.mark.asyncio
async def test_admin_waiver_limit_is_database_enforced(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    gate = _admin_gate(admin_factory, diagnostic_limit=1)

    await gate.check_payment(
        _browser_request(credentials, path="/v1/dns/lookup"),
        Decimal("0.01"),
        "DNS lookup",
    )
    with pytest.raises(HTTPException) as exc:
        await gate.check_payment(
            _browser_request(credentials, path="/v1/dns/lookup"),
            Decimal("0.01"),
            "DNS lookup",
        )

    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_admin_overview_and_step_up_are_browser_only(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        session.add_all(
            [
                AccountRow(
                    account_id="HBBBBBBBBBB",
                    password_hash=hash_password("another sufficiently long password"),
                ),
                PaymentEventRow(
                    event_id="refund-resolved",
                    event_type="refund_owed",
                    resource_path="/v1/vm/create",
                    method="POST",
                    service_group="vm",
                    amount_usd=Decimal("1.00"),
                ),
                PaymentEventRow(
                    event_id="refund-open",
                    event_type="refund_owed",
                    resource_path="/v1/domains/orders",
                    method="POST",
                    service_group="domain",
                    amount_usd=Decimal("2.00"),
                ),
                RefundResolutionRow(
                    resolution_id="resolution-test",
                    payment_event_id="refund-resolved",
                    resource_type="vm",
                    resource_id="vm-resolved",
                    status="resolved",
                    amount_usd=Decimal("1.00"),
                    reason="completed externally",
                    actor_account_id="HAAAAAAAAAA",
                ),
                AdminOperationRow(
                    operation_id="operation-obsolete-resume",
                    kind="resume_account_resources",
                    account_id="HBBBBBBBBBB",
                    actor_account_id="HAAAAAAAAAA",
                    status="failed",
                    reason="old enable attempt",
                    error="provider unavailable",
                ),
            ]
        )
        await session.commit()

    state = AppState(
        config=SimpleNamespace(
            admin_step_up_seconds=600,
            admin_payment_bypass_enabled=True,
            admin_diagnostic_bypass_per_minute=120,
            admin_cost_bypass_per_hour=10,
        ),
        orchestrator=SimpleNamespace(db=admin_factory),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    previous = getattr(app.state, "_typed_state", None)
    app.state._typed_state = state
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://localhost"
        ) as client:
            client.cookies.set("hyr_sess", credentials.token)
            client.cookies.set("hyr_csrf", credentials.csrf_token)
            overview = await client.get("/v1/admin/overview")
            assert overview.status_code == 200
            assert overview.headers["cache-control"] == "no-store"
            assert overview.json()["accounts"]["admins"] == 1
            assert overview.json()["waivers"] == {
                "enabled": True,
                "diagnostic_limit_per_minute": 120,
                "real_cost_limit_per_hour": 10,
                "step_up_seconds": 600,
            }
            assert overview.json()["payments"]["refund_owed_count"] == 1

            missing_csrf = await client.post(
                "/v1/admin/step-up",
                json={"password": "correct horse battery staple"},
            )
            assert missing_csrf.status_code == 403

            elevated = await client.post(
                "/v1/admin/step-up",
                headers={"X-CSRF-Token": credentials.csrf_token},
                json={"password": "correct horse battery staple"},
            )
            assert elevated.status_code == 200

            disabled = await client.post(
                "/v1/admin/accounts/HBBBBBBBBBB/disable",
                headers={"X-CSRF-Token": credentials.csrf_token},
                json={"reason": "abuse investigation"},
            )
            assert disabled.status_code == 200
            assert disabled.json()["status"] == "disabled"

            obsolete_retry = await client.post(
                "/v1/admin/operations/operation-obsolete-resume/retry",
                headers={"X-CSRF-Token": credentials.csrf_token},
                json={"reason": "retry after account disable"},
            )
            assert obsolete_retry.status_code == 409

            delete_admin = await client.delete("/v1/me")
            assert delete_admin.status_code == 409
            assert "must be demoted" in delete_admin.json()["detail"]
    finally:
        if previous is None:
            delattr(app.state, "_typed_state")
        else:
            app.state._typed_state = previous


class _AdminXCPNG:
    def __init__(self) -> None:
        self.suspended: list[str] = []
        self.started: list[str] = []

    async def suspend_vm(self, vm_uuid: str) -> None:
        self.suspended.append(vm_uuid)

    async def start_vm(self, vm_uuid: str) -> None:
        self.started.append(vm_uuid)


@pytest.mark.asyncio
async def test_admin_resource_operations_are_resumable_and_preserve_provenance(
    admin_factory,
) -> None:
    xcpng = _AdminXCPNG()
    orchestrator = SimpleNamespace(xcpng=xcpng)
    async with admin_factory() as session:
        session.add_all(
            [
                AccountRow(
                    account_id="HAAAAAAAAAA",
                    password_hash=hash_password("correct horse battery staple"),
                    is_admin=True,
                ),
                AccountRow(
                    account_id="HBBBBBBBBBB",
                    password_hash=hash_password("another sufficiently long password"),
                ),
            ]
        )
        session.add_all(
            [
                VMRow(
                    vm_id="vm_active",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    xcpng_uuid="uuid-active",
                    status="running",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                VMRow(
                    vm_id="vm_manual",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    xcpng_uuid="uuid-manual",
                    status="suspended",
                    suspension_reason="manual_admin",
                ),
                MailAccountRow(
                    mailbox_id="mailbox-1",
                    address="agent@example.test",
                    owner_account_id="HBBBBBBBBBB",
                    plan="basic",
                    status="active",
                ),
                AdminOperationRow(
                    operation_id="operation-suspend",
                    kind="suspend_account_resources",
                    account_id="HBBBBBBBBBB",
                    actor_account_id="HAAAAAAAAAA",
                    reason="abuse response",
                ),
            ]
        )
        await session.commit()

    assert await process_admin_operations(admin_factory, orchestrator) == 1
    async with admin_factory() as session:
        active = await session.get(VMRow, "vm_active")
        manual = await session.get(VMRow, "vm_manual")
        mailbox = await session.get(MailAccountRow, "mailbox-1")
        operation = await session.get(AdminOperationRow, "operation-suspend")
        assert active is not None and str(active.status) == "suspended"
        assert active.suspension_reason == "account_disabled"
        assert manual is not None and manual.suspension_reason == "manual_admin"
        assert mailbox is not None and mailbox.suspension_reason == "account_disabled"
        assert operation is not None and operation.status == "completed"
        session.add(
            AdminOperationRow(
                operation_id="operation-resume",
                kind="resume_account_resources",
                account_id="HBBBBBBBBBB",
                actor_account_id="HAAAAAAAAAA",
                status="running",
                started_at=datetime.now(UTC) - timedelta(minutes=20),
                reason="review complete",
            )
        )
        await session.commit()

    # A crashed, stale running operation is reclaimed and safely replayed.
    assert await process_admin_operations(admin_factory, orchestrator) == 1
    async with admin_factory() as session:
        active = await session.get(VMRow, "vm_active")
        manual = await session.get(VMRow, "vm_manual")
        mailbox = await session.get(MailAccountRow, "mailbox-1")
        operation = await session.get(AdminOperationRow, "operation-resume")
        assert active is not None and str(active.status) == "running"
        assert active.suspension_reason is None
        assert manual is not None and manual.suspension_reason == "manual_admin"
        assert mailbox is not None and mailbox.status == "active"
        assert operation is not None and operation.status == "completed"

    assert xcpng.suspended == ["uuid-active"]
    assert xcpng.started == ["uuid-active"]


@pytest.mark.asyncio
async def test_admin_resource_operations_wait_for_same_account_operation(
    admin_factory,
) -> None:
    """A queued inverse operation must not overtake a live operation."""
    now = datetime.now(UTC)
    async with admin_factory() as session:
        session.add_all(
            [
                AccountRow(
                    account_id="HAAAAAAAAAA",
                    password_hash=hash_password("correct horse battery staple"),
                    is_admin=True,
                ),
                AccountRow(
                    account_id="HBBBBBBBBBB",
                    password_hash=hash_password("another sufficiently long password"),
                ),
                AdminOperationRow(
                    operation_id="operation-running",
                    kind="suspend_account_resources",
                    account_id="HBBBBBBBBBB",
                    actor_account_id="HAAAAAAAAAA",
                    status="running",
                    started_at=now,
                    reason="disable in progress",
                ),
                AdminOperationRow(
                    operation_id="operation-queued",
                    kind="resume_account_resources",
                    account_id="HBBBBBBBBBB",
                    actor_account_id="HAAAAAAAAAA",
                    status="queued",
                    reason="enable requested",
                ),
            ]
        )
        await session.commit()

    orchestrator = SimpleNamespace(xcpng=_AdminXCPNG())
    assert await process_admin_operations(admin_factory, orchestrator) == 0
    async with admin_factory() as session:
        queued = await session.get(AdminOperationRow, "operation-queued")
        assert queued is not None and queued.status == "queued"
