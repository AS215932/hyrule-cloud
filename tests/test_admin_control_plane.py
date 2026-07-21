from __future__ import annotations

from contextlib import asynccontextmanager
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

from hyrule_cloud.api.admin import (
    OwnershipTransferRequest,
    ReasonRequest,
    StepUpRequest,
    _assert_transfer_target,
    step_up,
    transfer_domain,
    transfer_vm,
    vm_action,
)
from hyrule_cloud.app import app
from hyrule_cloud.config import PaymentConfig
from hyrule_cloud.db import (
    AccountRow,
    AccountWalletRow,
    AdminAuditRow,
    AdminBypassUsageRow,
    AdminOperationRow,
    Base,
    DomainJobRow,
    DomainRow,
    MailAccountRow,
    PaymentEventRow,
    RefundResolutionRow,
    SessionRow,
    VMRow,
)
from hyrule_cloud.middleware.x402 import ADMIN_PAYMENT_MODE_HEADER, PaymentGate
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.services.admin_operations import (
    _apply_account_operation,
    process_admin_operations,
)
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


def _admin_gate(
    admin_factory,
    *,
    diagnostic_limit: int = 120,
    cost_limit: int = 10,
) -> PaymentGate:
    gate = PaymentGate(
        PaymentConfig(
            receiver_address=RECEIVER,
            facilitator_url="https://facilitator.payai.network",
            dev_bypass_secret="",
        ),
        session_factory=admin_factory,
        admin_bypass_enabled=True,
        admin_diagnostic_limit=diagnostic_limit,
        admin_cost_limit=cost_limit,
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
async def test_admin_waiver_fails_closed_when_audit_persistence_fails(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    gate = _admin_gate(admin_factory, diagnostic_limit=1)

    class FailingLedger:
        async def record(self, **kwargs) -> None:
            assert kwargs["required"] is True
            raise RuntimeError("payment_events unavailable")

    gate.ledger = FailingLedger()  # type: ignore[assignment]
    request = _browser_request(credentials, path="/v1/dns/lookup")

    with pytest.raises(HTTPException) as exc:
        await gate.check_payment(request, Decimal("0.01"), "DNS lookup")

    assert exc.value.status_code == 503
    assert exc.value.detail == "Admin waiver audit unavailable"
    assert not hasattr(request.state, "payment_mode")
    async with admin_factory() as session:
        assert list(await session.scalars(select(PaymentEventRow))) == []
        usage = (await session.scalars(select(AdminBypassUsageRow))).one()
        assert usage.count == 0

    # A recovered audit store can use the restored slot immediately.
    gate.ledger = PaymentLedger(admin_factory)
    retry = _browser_request(credentials, path="/v1/dns/lookup")
    assert await gate.check_payment(retry, Decimal("0.01"), "DNS lookup") == (
        "admin:HAAAAAAAAAA"
    )
    async with admin_factory() as session:
        usage = (await session.scalars(select(AdminBypassUsageRow))).one()
        assert usage.count == 1


@pytest.mark.asyncio
async def test_deferred_admin_waiver_fails_closed_when_audit_persistence_fails(
    admin_factory,
) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    gate = _admin_gate(admin_factory, cost_limit=1)
    request = _browser_request(credentials, path="/v1/network/request")

    verified = await gate.verify_only(request, Decimal("0.01"), "Network request")
    assert not isinstance(verified, Response)
    assert verified.admin_bypass is True
    async with admin_factory() as session:
        usage = (await session.scalars(select(AdminBypassUsageRow))).one()
        assert usage.count == 1

    class FailingLedger:
        async def record(self, **kwargs) -> None:
            assert kwargs["required"] is True
            raise RuntimeError("payment_events unavailable")

    gate.ledger = FailingLedger()  # type: ignore[assignment]
    with pytest.raises(HTTPException) as exc:
        await gate.settle_verified(request, verified)

    assert exc.value.status_code == 503
    assert exc.value.detail == "Admin waiver audit unavailable"
    assert not hasattr(request.state, "payment_mode")
    async with admin_factory() as session:
        usage = (await session.scalars(select(AdminBypassUsageRow))).one()
        assert usage.count == 0

    gate.ledger = PaymentLedger(admin_factory)
    retry = _browser_request(credentials, path="/v1/network/request")
    retry_verified = await gate.verify_only(retry, Decimal("0.01"), "Network request")
    assert not isinstance(retry_verified, Response)
    assert await gate.settle_verified(retry, retry_verified) is True
    async with admin_factory() as session:
        usage = (await session.scalars(select(AdminBypassUsageRow))).one()
        assert usage.count == 1


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
async def test_admin_waiver_usage_prunes_expired_windows(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    old_window = datetime.now(UTC) - timedelta(days=3)
    async with admin_factory() as session:
        session.add(
            AdminBypassUsageRow(
                actor_account_id="HAAAAAAAAAA",
                operation_class="diagnostic",
                window_started_at=old_window,
                count=99,
                updated_at=old_window,
            )
        )
        await session.commit()

    gate = _admin_gate(admin_factory)
    await gate.check_payment(
        _browser_request(credentials, path="/v1/dns/lookup"),
        Decimal("0.01"),
        "DNS lookup",
    )

    async with admin_factory() as session:
        windows = list(await session.scalars(select(AdminBypassUsageRow)))
    assert len(windows) == 1
    assert windows[0].count == 1


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
                VMRow(
                    vm_id="vm_disable_tokens",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="a" * 64,
                    status="ready",
                ),
                DomainRow(
                    name="disable-tokens",
                    extension="example",
                    fqdn="disable-tokens.example",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="b" * 64,
                    status="active",
                ),
                MailAccountRow(
                    mailbox_id="mail-disable-tokens",
                    address="disabled@example.test",
                    owner_account_id="HBBBBBBBBBB",
                    management_token_hash="c" * 64,
                    plan="basic",
                    status="active",
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
        payment_gate=_admin_gate(admin_factory),
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

            # The outer x402 middleware must ignore ordinary Admin pages, but
            # render waiver-only validation failures on actual paid routes.
            paid_without_csrf = await client.post("/v1/dns/lookup", json={})
            assert paid_without_csrf.status_code == 403
            assert paid_without_csrf.json()["detail"] == "CSRF validation failed"

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

            async with admin_factory() as session:
                disabled_vm = await session.get(VMRow, "vm_disable_tokens")
                disabled_domain = (
                    await session.execute(
                        select(DomainRow).where(
                            DomainRow.fqdn == "disable-tokens.example"
                        )
                    )
                ).scalar_one()
                disabled_mailbox = await session.get(
                    MailAccountRow, "mail-disable-tokens"
                )
            assert disabled_vm is not None and disabled_vm.anon_management_token_hash is None
            assert (
                disabled_domain is not None
                and disabled_domain.anon_management_token_hash is None
            )
            assert (
                disabled_mailbox is not None
                and disabled_mailbox.management_token_hash is None
            )

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


@pytest.mark.asyncio
async def test_admin_step_up_rate_limits_argon_checks_per_session(
    admin_factory,
    monkeypatch,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        session_row = (
            await session.execute(
                select(SessionRow).where(SessionRow.account_id == "HAAAAAAAAAA")
            )
        ).scalar_one()
        token_hash = session_row.token_hash
    assert actor is not None

    verification_calls = 0

    def fake_verify(_password_hash: str, password: str) -> bool:
        nonlocal verification_calls
        verification_calls += 1
        return password == "correct horse battery staple"

    monkeypatch.setattr("hyrule_cloud.api.admin.verify_password", fake_verify)
    state = AppState(
        config=SimpleNamespace(admin_step_up_seconds=600),
        orchestrator=SimpleNamespace(),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    request = _browser_request(credentials, path="/v1/admin/step-up")
    request.state.session_token_hash = token_hash

    for _ in range(5):
        with pytest.raises(HTTPException) as exc:
            await step_up(StepUpRequest(password="incorrect"), request, actor, state)
        assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        await step_up(
            StepUpRequest(password="correct horse battery staple"),
            request,
            actor,
            state,
        )
    assert exc.value.status_code == 429
    assert verification_calls == 5

    async with admin_factory() as session:
        row = await session.get(SessionRow, token_hash)
        assert row is not None
        row.admin_step_up_window_started_at = datetime.now(UTC) - timedelta(minutes=16)
        await session.commit()

    result = await step_up(
        StepUpRequest(password="correct horse battery staple"),
        request,
        actor,
        state,
    )
    assert result["status"] == "ok"
    assert verification_calls == 6
    async with admin_factory() as session:
        row = await session.get(SessionRow, token_hash)
        assert row is not None
        assert row.admin_step_up_attempts == 0
        assert row.admin_step_up_window_started_at is None


@pytest.mark.asyncio
async def test_transfers_rotate_credentials_and_preserve_audit_actor(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    xcpng = _AdminXCPNG()
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add_all(
            [
                AccountRow(
                    account_id="HBBBBBBBBBB",
                    password_hash=hash_password("another sufficiently long password"),
                ),
                AccountRow(
                    account_id="HCCCCCCCCCC",
                    password_hash=hash_password("third sufficiently long password"),
                ),
                AccountWalletRow(
                    wallet_id="target-wallet",
                    account_id="HCCCCCCCCCC",
                    address="0x1111111111111111111111111111111111111111",
                    chain_id=8453,
                ),
                VMRow(
                    vm_id="vm_transfer_direct",
                    owner_wallet="0x2222222222222222222222222222222222222222",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="a" * 64,
                    xcpng_uuid="uuid-transfer-direct",
                    status="suspended",
                    suspension_reason="account_disabled",
                    suspended_by_account_id="HAAAAAAAAAA",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                DomainRow(
                    name="direct",
                    extension="example",
                    fqdn="direct.example",
                    vm_id="vm_transfer_direct",
                    owner_wallet="0x2222222222222222222222222222222222222222",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="b" * 64,
                    status="active",
                ),
                VMRow(
                    vm_id="vm_transfer_attached",
                    owner_wallet="0x3333333333333333333333333333333333333333",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="c" * 64,
                    xcpng_uuid="uuid-transfer-attached",
                    status="suspended",
                    suspension_reason="account_disabled",
                    suspended_by_account_id="HAAAAAAAAAA",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                DomainRow(
                    name="attached",
                    extension="example",
                    fqdn="attached.example",
                    vm_id="vm_transfer_attached",
                    owner_wallet="0x3333333333333333333333333333333333333333",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="d" * 64,
                    status="active",
                ),
                VMRow(
                    vm_id="vm_transfer_manual",
                    owner_wallet="0x4444444444444444444444444444444444444444",
                    owner_account_id="HBBBBBBBBBB",
                    anon_management_token_hash="e" * 64,
                    xcpng_uuid="uuid-transfer-manual",
                    status="suspended",
                    suspension_reason="manual_admin",
                    suspended_by_account_id="HAAAAAAAAAA",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
            ]
        )
        await session.commit()

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(
            xcpng=xcpng,
            start_provisioning=lambda _vm_id: None,
        ),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    body = OwnershipTransferRequest(
        target_account_id="HCCCCCCCCCC",
        reason="customer-approved transfer",
    )
    await transfer_vm(
        "vm_transfer_direct",
        body,
        _browser_request(credentials, path="/v1/admin/vms/vm_transfer_direct/transfer"),
        actor,
        state,
    )
    await transfer_domain(
        "attached.example",
        body,
        _browser_request(credentials, path="/v1/admin/domains/attached.example/transfer"),
        actor,
        state,
    )
    await transfer_vm(
        "vm_transfer_manual",
        body,
        _browser_request(credentials, path="/v1/admin/vms/vm_transfer_manual/transfer"),
        actor,
        state,
    )

    target_wallet = "0x1111111111111111111111111111111111111111"
    async with admin_factory() as session:
        for vm_id in (
            "vm_transfer_direct",
            "vm_transfer_attached",
            "vm_transfer_manual",
        ):
            vm = await session.get(VMRow, vm_id)
            assert vm is not None and vm.owner_account_id == "HCCCCCCCCCC"
            assert vm.owner_wallet == target_wallet
            assert vm.anon_management_token_hash is None
        for fqdn in ("direct.example", "attached.example"):
            domain = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
            ).scalar_one()
            assert domain.owner_account_id == "HCCCCCCCCCC"
            assert domain.owner_wallet == target_wallet
            assert domain.anon_management_token_hash is None

        direct = await session.get(VMRow, "vm_transfer_direct")
        attached = await session.get(VMRow, "vm_transfer_attached")
        manual = await session.get(VMRow, "vm_transfer_manual")
        assert direct is not None and str(direct.status) == "running"
        assert direct.suspension_reason is None
        assert attached is not None and str(attached.status) == "running"
        assert attached.suspension_reason is None
        assert manual is not None and str(manual.status) == "suspended"
        assert manual.suspension_reason == "manual_admin"

        stored_actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert stored_actor is not None
        await session.delete(stored_actor)
        await session.commit()
        audits = list(await session.scalars(select(AdminAuditRow)))

    assert not AdminAuditRow.__table__.c.actor_account_id.foreign_keys
    assert {row.actor_account_id for row in audits} == {"HAAAAAAAAAA"}
    assert xcpng.started == ["uuid-transfer-direct", "uuid-transfer-attached"]


@pytest.mark.asyncio
async def test_transfers_block_active_domain_attachment_jobs(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add_all(
            [
                AccountRow(
                    account_id="HBBBBBBBBBB",
                    password_hash=hash_password("another sufficiently long password"),
                ),
                AccountRow(
                    account_id="HCCCCCCCCCC",
                    password_hash=hash_password("third sufficiently long password"),
                ),
                VMRow(
                    vm_id="vm_pending_attachment",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    status="ready",
                ),
                DomainRow(
                    name="pending-attachment",
                    extension="example",
                    fqdn="pending-attachment.example",
                    vm_id="vm_pending_attachment",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    status="active",
                ),
                DomainJobRow(
                    job_id="job_pending_attachment",
                    kind="attach_vm",
                    resource_id="vm_pending_attachment",
                    dedupe_key="attach_vm:vm_pending_attachment",
                    payload={
                        "owner_account_id": "HBBBBBBBBBB",
                        "fqdn": "pending-attachment.example",
                        "vm_id": "vm_pending_attachment",
                        "ipv6": "2001:db8::1",
                    },
                    status="queued",
                ),
            ]
        )
        await session.commit()

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    body = OwnershipTransferRequest(
        target_account_id="HCCCCCCCCCC",
        reason="customer-approved transfer",
    )
    with pytest.raises(HTTPException) as vm_error:
        await transfer_vm(
            "vm_pending_attachment",
            body,
            _browser_request(
                credentials,
                path="/v1/admin/vms/vm_pending_attachment/transfer",
            ),
            actor,
            state,
        )
    assert vm_error.value.status_code == 409

    with pytest.raises(HTTPException) as domain_error:
        await transfer_domain(
            "pending-attachment.example",
            body,
            _browser_request(
                credentials,
                path="/v1/admin/domains/pending-attachment.example/transfer",
            ),
            actor,
            state,
        )
    assert domain_error.value.status_code == 409


@pytest.mark.asyncio
async def test_vm_action_audit_is_durable_before_provider_dispatch(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id="vm_audit_dispatch",
                owner_wallet="0xowner",
                xcpng_uuid="provider-vm",
                status="running",
            )
        )
        await session.commit()

    class FailingOrchestrator:
        async def reboot_vm(self, vm_id: str) -> bool:
            async with admin_factory() as session:
                persisted = list(
                    await session.scalars(
                        select(AdminAuditRow).where(
                            AdminAuditRow.action == "vm.reboot.requested",
                            AdminAuditRow.target_id == vm_id,
                        )
                    )
                )
            assert len(persisted) == 1
            raise RuntimeError("provider unavailable")

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=FailingOrchestrator(),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    with pytest.raises(RuntimeError, match="provider unavailable"):
        await vm_action(
            "vm_audit_dispatch",
            "reboot",
            ReasonRequest(reason="operator retry"),
            _browser_request(
                credentials,
                path="/v1/admin/vms/vm_audit_dispatch/actions/reboot",
            ),
            actor,
            state,
        )


@pytest.mark.asyncio
async def test_transfer_target_eligibility_check_locks_account() -> None:
    target = AccountRow(account_id="HTARGETLOCK", password_hash="unused")

    class Result:
        def scalar_one_or_none(self):
            return target

    class Session:
        async def execute(self, statement):
            assert statement._for_update_arg is not None
            return Result()

    assert await _assert_transfer_target(Session(), target.account_id) is target


class _AdminXCPNG:
    def __init__(self) -> None:
        self.suspended: list[str] = []
        self.started: list[str] = []

    async def suspend_vm(self, vm_uuid: str) -> None:
        self.suspended.append(vm_uuid)

    async def start_vm(self, vm_uuid: str) -> None:
        self.started.append(vm_uuid)


@pytest.mark.asyncio
async def test_admin_start_rejects_account_disabled_vm(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id="vm_account_disabled",
                owner_wallet="0xowner",
                owner_account_id="HAAAAAAAAAA",
                xcpng_uuid="uuid-account-disabled",
                status="suspended",
                suspension_reason="account_disabled",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        await session.commit()

    xcpng = _AdminXCPNG()
    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(xcpng=xcpng),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    with pytest.raises(HTTPException) as exc:
        await vm_action(
            "vm_account_disabled",
            "start",
            ReasonRequest(reason="manual override"),
            _browser_request(
                credentials,
                path="/v1/admin/vms/vm_account_disabled/actions/start",
            ),
            actor,
            state,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "Account-disabled VMs must be resumed through account enable"
    assert xcpng.started == []
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_account_disabled")
        assert row is not None and str(row.status) == "suspended"
        assert row.suspension_reason == "account_disabled"
        assert list(await session.scalars(select(AdminAuditRow))) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "vm_status", "suspension_reason", "mail_status"),
    [
        ("suspend_account_resources", "running", None, "active"),
        (
            "resume_account_resources",
            "suspended",
            "account_disabled",
            "suspended",
        ),
    ],
)
async def test_admin_resource_operations_revalidate_ownership_under_lock(
    admin_factory,
    kind: str,
    vm_status: str,
    suspension_reason: str | None,
    mail_status: str,
) -> None:
    async with admin_factory() as session:
        session.add_all(
            [
                AccountRow(account_id="HOLDOWNERAA", password_hash="unused"),
                AccountRow(account_id="HNEWOWNERAAA", password_hash="unused"),
                VMRow(
                    vm_id="vm_transferred_after_snapshot",
                    owner_wallet="0xowner",
                    owner_account_id="HOLDOWNERAA",
                    xcpng_uuid="uuid-transferred",
                    status=vm_status,
                    suspension_reason=suspension_reason,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                MailAccountRow(
                    mailbox_id="mail_transferred_after_snapshot",
                    address="transfer-race@example.test",
                    owner_account_id="HOLDOWNERAA",
                    plan="basic",
                    status=mail_status,
                    suspension_reason=suspension_reason,
                ),
                AdminOperationRow(
                    operation_id="operation-transfer-race",
                    kind=kind,
                    account_id="HOLDOWNERAA",
                    actor_account_id="HNEWOWNERAAA",
                    reason="ownership race regression",
                ),
            ]
        )
        await session.commit()

    class TransferBeforeFirstResourceLock:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self):
            self.calls += 1
            if self.calls != 2:
                return admin_factory()

            @asynccontextmanager
            async def transfer_then_open():
                async with admin_factory() as mutation:
                    vm = await mutation.get(VMRow, "vm_transferred_after_snapshot")
                    mailbox = await mutation.get(
                        MailAccountRow,
                        "mail_transferred_after_snapshot",
                    )
                    assert vm is not None and mailbox is not None
                    vm.owner_account_id = "HNEWOWNERAAA"
                    mailbox.owner_account_id = "HNEWOWNERAAA"
                    await mutation.commit()
                async with admin_factory() as locked:
                    yield locked

            return transfer_then_open()

    xcpng = _AdminXCPNG()
    progress = await _apply_account_operation(
        TransferBeforeFirstResourceLock(),  # type: ignore[arg-type]
        SimpleNamespace(xcpng=xcpng),
        "operation-transfer-race",
    )

    assert progress == {"vms": 0, "mailboxes": 0}
    assert xcpng.suspended == []
    assert xcpng.started == []
    async with admin_factory() as session:
        vm = await session.get(VMRow, "vm_transferred_after_snapshot")
        mailbox = await session.get(MailAccountRow, "mail_transferred_after_snapshot")
        assert vm is not None and vm.owner_account_id == "HNEWOWNERAAA"
        assert str(vm.status) == vm_status
        assert vm.suspension_reason == suspension_reason
        assert mailbox is not None and mailbox.owner_account_id == "HNEWOWNERAAA"
        assert mailbox.status == mail_status
        assert mailbox.suspension_reason == suspension_reason


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
                VMRow(
                    vm_id="vm_provisioning",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    status="provisioning",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                VMRow(
                    vm_id="vm_failed_disabled",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    xcpng_uuid="uuid-failed-disabled",
                    status="failed",
                    suspension_reason="account_disabled",
                ),
                MailAccountRow(
                    mailbox_id="mailbox-1",
                    address="agent@example.test",
                    owner_account_id="HBBBBBBBBBB",
                    plan="basic",
                    status="active",
                ),
                MailAccountRow(
                    mailbox_id="mailbox-expired",
                    address="expired@example.test",
                    owner_account_id="HBBBBBBBBBB",
                    plan="basic",
                    status="active",
                    expires_at=datetime.now(UTC) - timedelta(minutes=1),
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
        provisioning = await session.get(VMRow, "vm_provisioning")
        failed_disabled = await session.get(VMRow, "vm_failed_disabled")
        mailbox = await session.get(MailAccountRow, "mailbox-1")
        expired_mailbox = await session.get(MailAccountRow, "mailbox-expired")
        operation = await session.get(AdminOperationRow, "operation-suspend")
        assert active is not None and str(active.status) == "suspended"
        assert active.suspension_reason == "account_disabled"
        assert manual is not None and manual.suspension_reason == "manual_admin"
        assert provisioning is not None and str(provisioning.status) == "provisioning"
        assert provisioning.suspension_reason == "account_disabled"
        assert failed_disabled is not None and str(failed_disabled.status) == "failed"
        assert failed_disabled.suspension_reason == "account_disabled"
        assert mailbox is not None and mailbox.suspension_reason == "account_disabled"
        assert (
            expired_mailbox is not None
            and expired_mailbox.suspension_reason == "account_disabled"
        )
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
        provisioning = await session.get(VMRow, "vm_provisioning")
        failed_disabled = await session.get(VMRow, "vm_failed_disabled")
        mailbox = await session.get(MailAccountRow, "mailbox-1")
        expired_mailbox = await session.get(MailAccountRow, "mailbox-expired")
        operation = await session.get(AdminOperationRow, "operation-resume")
        assert active is not None and str(active.status) == "running"
        assert active.suspension_reason is None
        assert manual is not None and manual.suspension_reason == "manual_admin"
        assert provisioning is not None and str(provisioning.status) == "provisioning"
        assert provisioning.suspension_reason is None
        assert failed_disabled is not None and str(failed_disabled.status) == "failed"
        assert failed_disabled.suspension_reason == "account_disabled"
        assert mailbox is not None and mailbox.status == "active"
        assert expired_mailbox is not None and expired_mailbox.status == "suspended"
        assert expired_mailbox.suspension_reason == "expired"
        assert operation is not None and operation.status == "completed"

    assert xcpng.suspended == ["uuid-active"]
    assert xcpng.started == ["uuid-active"]


@pytest.mark.asyncio
async def test_provisioning_finalization_honors_account_suspension(admin_factory) -> None:
    async with admin_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_provisioning_suspended",
                owner_wallet="0xowner",
                status="provisioning",
                suspension_reason="account_disabled",
            )
        )
        await session.commit()

    await Orchestrator._simulate_provisioning(
        SimpleNamespace(db=admin_factory),
        "vm_provisioning_suspended",
    )

    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_provisioning_suspended")
        assert row is not None and str(row.status) == "suspended"
        assert row.suspension_reason == "account_disabled"


@pytest.mark.asyncio
async def test_admin_suspension_blocks_orchestrator_extension(admin_factory) -> None:
    expires_at = datetime.now(UTC) + timedelta(days=1)
    async with admin_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_admin_suspended",
                owner_wallet="0xowner",
                status="suspended",
                suspension_reason="manual_admin",
                expires_at=expires_at,
            )
        )
        await session.commit()

    result = await Orchestrator.extend_vm(
        SimpleNamespace(db=admin_factory),
        "vm_admin_suspended",
        7,
    )

    assert result is None
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_admin_suspended")
        assert row is not None and row.expires_at is not None
        stored_expiry = row.expires_at.replace(tzinfo=UTC) if row.expires_at.tzinfo is None else row.expires_at
        assert stored_expiry == expires_at


@pytest.mark.asyncio
async def test_dev_bypass_vm_billing_records_zero_charged_revenue(admin_factory) -> None:
    async with admin_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_dev_bypass_billing",
                owner_wallet="0xDEV_TEST_WALLET",
                status="provisioning",
                cost_total=Decimal("1.25"),
                retail_cost_total=Decimal("1.25"),
                billing_mode="charged",
            )
        )
        await session.commit()

    await Orchestrator.persist_payment_billing(
        SimpleNamespace(db=admin_factory),
        "vm_dev_bypass_billing",
        Decimal("1.25"),
        admin_waived=False,
        payment_tx="dev_bypass_0x0",
    )

    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_dev_bypass_billing")
    assert row is not None
    assert row.retail_cost_total == Decimal("1.25")
    assert row.cost_total == Decimal("0")
    assert row.billing_mode == "dev_bypass"


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
