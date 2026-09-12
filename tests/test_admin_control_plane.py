from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock

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
    RefundResolutionRequest,
    StepUpRequest,
    _assert_transfer_target,
    _lock_domain_transfer_bundle,
    _resume_transferred_vm,
    disable_account,
    enable_account,
    resolve_refund,
    retry_job,
    step_up,
    transfer_domain,
    transfer_vm,
    vm_action,
)
from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.db import (
    AccountRow,
    AccountWalletRow,
    AdminAuditRow,
    AdminBypassUsageRow,
    AdminOperationRow,
    Base,
    BGPJobRow,
    DomainJobRow,
    DomainOperationRow,
    DomainOrderRow,
    DomainRow,
    MailAccountRow,
    PaymentEventRow,
    RefundResolutionRow,
    SessionRow,
    VMGuestResultRow,
    VMRow,
)
from hyrule_cloud.domains.models import DomainOperationStatus, DomainOrderStatus
from hyrule_cloud.middleware.x402 import ADMIN_PAYMENT_MODE_HEADER, PaymentGate
from hyrule_cloud.models import VMStatus
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
async def test_deferred_admin_waiver_audits_before_delivery_and_restores_failed_quota(
    admin_factory,
) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    gate = _admin_gate(admin_factory, cost_limit=1)
    request = _browser_request(credentials, path="/v1/network/request")

    class FailingLedger:
        async def record(self, **kwargs) -> None:
            assert kwargs["required"] is True
            raise RuntimeError("payment_events unavailable")

    gate.ledger = FailingLedger()  # type: ignore[assignment]
    with pytest.raises(HTTPException) as exc:
        await gate.verify_only(request, Decimal("0.01"), "Network request")

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
    assert retry_verified.admin_bypass is True
    assert retry.state.payment_mode == "admin-bypass"
    async with admin_factory() as session:
        usage = (await session.scalars(select(AdminBypassUsageRow))).one()
        events = list(await session.scalars(select(PaymentEventRow)))
        assert usage.count == 1
        assert [event.event_type for event in events] == ["admin_bypass"]

    # Settlement remains deferred for real x402 payments only. An Admin
    # handle is already durably audited and must not write a duplicate event.
    assert await gate.settle_verified(retry, retry_verified) is True
    async with admin_factory() as session:
        events = list(await session.scalars(select(PaymentEventRow)))
        assert [event.event_type for event in events] == ["admin_bypass"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/vm/create", "/v1/tunnel/create", "/v1/tunnel/tun_fixture/extend"])
async def test_real_cost_waiver_requires_recent_password_step_up(admin_factory, path) -> None:
    credentials = await _admin_credentials(admin_factory)
    gate = _admin_gate(admin_factory)
    request = _browser_request(credentials, path=path)

    with pytest.raises(HTTPException) as exc:
        await gate.check_payment(request, Decimal("1.00"), "VM")

    assert exc.value.status_code == 403
    assert exc.value.detail == "admin_step_up_required"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/v1/vm/create", "/v1/tunnel/tun_fixture/extend"])
async def test_elevated_admin_can_waive_real_cost_without_settlement(admin_factory, path) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    gate = _admin_gate(admin_factory)
    server = gate.server
    request = _browser_request(credentials, path=path)

    payer = await gate.check_payment(request, Decimal("1.00"), "VM")

    assert payer == "admin:HAAAAAAAAAA"
    assert request.state.payment_tx.startswith("admin_bypass_")
    assert server.settle_payment_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("revocation", "expected_detail"),
    [
        ("demote", "Admin waiver authorization expired"),
        ("disable", "Account disabled"),
        ("session", "Admin waiver authorization expired"),
        ("csrf", "CSRF validation failed"),
        ("step_up", "admin_step_up_required"),
    ],
)
async def test_admin_waiver_revalidates_cached_security_context(
    admin_factory,
    revocation: str,
    expected_detail: str,
) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    gate = _admin_gate(admin_factory)
    request = _browser_request(credentials, path="/v1/vm/create")
    assert await gate.has_payment_credentials(request) is True

    async with admin_factory() as session:
        account = await session.get(AccountRow, "HAAAAAAAAAA")
        session_row = (
            await session.execute(
                select(SessionRow).where(SessionRow.account_id == "HAAAAAAAAAA")
            )
        ).scalar_one()
        assert account is not None
        if revocation == "demote":
            account.is_admin = False
        elif revocation == "disable":
            account.disabled_at = datetime.now(UTC)
        elif revocation == "session":
            await session.delete(session_row)
        elif revocation == "csrf":
            session_row.csrf_token_hash = "0" * 64
        else:
            session_row.admin_elevated_at = datetime.now(UTC) - timedelta(hours=1)
        await session.commit()

    with pytest.raises(HTTPException) as exc:
        await gate.check_payment(request, Decimal("1.00"), "VM")

    assert exc.value.status_code == 403
    assert exc.value.detail == expected_detail
    async with admin_factory() as session:
        assert list(await session.scalars(select(AdminBypassUsageRow))) == []
        assert list(await session.scalars(select(PaymentEventRow))) == []


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
                    network="native",
                    asset="BTC",
                    payer_wallet="intent-native-refund",
                    extra={
                        "intent_id": "intent-native-refund",
                        "native_refund_address": "bc1qexampleoperatorrefundtarget",
                        "amount_received_crypto": "0.00025000",
                        "private_provider_payload": "must-not-leak",
                    },
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
                BGPJobRow(
                    job_id="bgpj_admin_failed",
                    status="failed",
                    query={
                        "subject": {"type": "prefix", "value": "203.0.113.0/24"},
                        "record_type": "updates",
                    },
                    error="collector unavailable",
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
            assert overview.json()["operations"]["failed_jobs"] == 1

            jobs = await client.get("/v1/admin/jobs", params={"status": "failed"})
            assert jobs.status_code == 200
            assert jobs.json()["items"] == [
                {
                    "job_id": "bgpj_admin_failed",
                    "source": "bgp",
                    "kind": "bgpstream_updates",
                    "target": "203.0.113.0/24",
                    "status": "failed",
                    "last_error": "collector unavailable",
                    "claimed_by": None,
                    "heartbeat_at": None,
                    "created_at": jobs.json()["items"][0]["created_at"],
                    "completed_at": None,
                }
            ]

            refunds = await client.get("/v1/admin/refunds")
            assert refunds.status_code == 200
            open_refund = next(
                item for item in refunds.json()["items"] if item["event_id"] == "refund-open"
            )
            assert open_refund["native_refund_address"] == (
                "bc1qexampleoperatorrefundtarget"
            )
            assert Decimal(open_refund["amount_received_crypto"]) == Decimal("0.00025")
            assert open_refund["native_intent_id"] == "intent-native-refund"
            assert "private_provider_payload" not in open_refund

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
async def test_each_refund_event_can_be_resolved_for_the_same_vm(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        for event_id in ("refund-repeat-one", "refund-repeat-two"):
            session.add(
                PaymentEventRow(
                    event_id=event_id,
                    event_type="refund_owed",
                    resource_path="/v1/vm/vm_repeat_refund/extend",
                    method="POST",
                    service_group="vm",
                    amount_usd=Decimal("0.60"),
                    payer_wallet="0x1111111111111111111111111111111111111111",
                    tx_hash=f"0x{event_id}",
                    extra={"vm_id": "vm_repeat_refund"},
                )
            )
        await session.commit()

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    resolution_ids: list[str] = []
    for event_id in ("refund-repeat-one", "refund-repeat-two"):
        result = await resolve_refund(
            event_id,
            RefundResolutionRequest(
                status="resolved",
                external_reference=f"operator-{event_id}",
                reason="sent to original payer",
            ),
            _browser_request(
                credentials,
                path=f"/v1/admin/refunds/{event_id}/resolve",
            ),
            actor,
            state,
        )
        resolution_ids.append(result["resolution_id"])

    assert len(set(resolution_ids)) == 2
    async with admin_factory() as session:
        resolutions = list(await session.scalars(select(RefundResolutionRow)))
    assert len(resolutions) == 2
    assert {row.payment_event_id for row in resolutions} == {
        "refund-repeat-one",
        "refund-repeat-two",
    }
    assert {row.resource_id for row in resolutions} == {"vm_repeat_refund"}


@pytest.mark.asyncio
async def test_resolved_domain_refund_advances_customer_order(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            DomainOrderRow(
                order_id="do_refund_resolved",
                quote_id="dq_refund_resolved",
                fqdn="refund-resolved.example",
                action="register",
                owner_account_id="HAAAAAAAAAA",
                idempotency_key="refund-resolved",
                status=DomainOrderStatus.REFUND_DUE.value,
                amount_usd=Decimal("10.00"),
                domain_amount_usd=Decimal("10.00"),
                vm_amount_usd=Decimal("0"),
                payment_method="usdc",
                terms_version="2026-01",
                terms_accepted_at=datetime.now(UTC),
            )
        )
        session.add(
            PaymentEventRow(
                event_id="domain-refund-resolved",
                event_type="refund_owed",
                resource_path="/v1/domains/orders/do_refund_resolved",
                method="POST",
                service_group="domain",
                amount_usd=Decimal("10.00"),
                extra={"order_id": "do_refund_resolved"},
            )
        )
        await session.commit()

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    await resolve_refund(
        "domain-refund-resolved",
        RefundResolutionRequest(
            status="resolved",
            external_reference="operator-refund-reference",
            reason="refund sent to original payer",
        ),
        _browser_request(
            credentials,
            path="/v1/admin/refunds/domain-refund-resolved/resolve",
        ),
        actor,
        state,
    )

    async with admin_factory() as session:
        order = await session.get(DomainOrderRow, "do_refund_resolved")
        resolution = await session.scalar(
            select(RefundResolutionRow).where(
                RefundResolutionRow.payment_event_id == "domain-refund-resolved"
            )
        )
    assert order is not None and order.status == DomainOrderStatus.REFUNDED.value
    assert resolution is not None and resolution.status == "resolved"


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
        audits = list(
            await session.scalars(
                select(AdminAuditRow).order_by(AdminAuditRow.created_at)
            )
        )
    failures = [row for row in audits if row.action == "admin.step_up_failed"]
    successes = [row for row in audits if row.action == "admin.step_up"]
    assert len(failures) == 5
    assert all(row.succeeded is False for row in failures)
    assert len(successes) == 1 and successes[0].succeeded is True


@pytest.mark.asyncio
async def test_admin_step_up_rechecks_password_under_account_lock(
    admin_factory,
    monkeypatch,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        stale_actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert stale_actor is not None
        session_row = (
            await session.execute(
                select(SessionRow).where(SessionRow.account_id == "HAAAAAAAAAA")
            )
        ).scalar_one()
        token_hash = session_row.token_hash
        stale_password_hash = stale_actor.password_hash
    assert stale_password_hash is not None

    rotated_password_hash = "rotated-password-hash"
    async with admin_factory() as session:
        current_actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert current_actor is not None
        current_actor.password_hash = rotated_password_hash
        await session.commit()

    verified_hashes: list[str | None] = []

    def verify_stale_only(password_hash: str | None, _password: str) -> bool:
        verified_hashes.append(password_hash)
        return password_hash == stale_password_hash

    monkeypatch.setattr("hyrule_cloud.api.admin.verify_password", verify_stale_only)
    state = AppState(
        config=SimpleNamespace(admin_step_up_seconds=600),
        orchestrator=SimpleNamespace(),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    request = _browser_request(credentials, path="/v1/admin/step-up")
    request.state.session_token_hash = token_hash

    with pytest.raises(HTTPException) as refused:
        await step_up(
            StepUpRequest(password="old password"), request, stale_actor, state
        )

    assert refused.value.status_code == 401
    assert verified_hashes == [rotated_password_hash]
    async with admin_factory() as session:
        stored_session = await session.get(SessionRow, token_hash)
        assert stored_session is not None
        assert stored_session.admin_elevated_at is None


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
                VMRow(
                    vm_id="vm_transfer_failed",
                    owner_wallet="0x5555555555555555555555555555555555555555",
                    owner_account_id="HBBBBBBBBBB",
                    xcpng_uuid="uuid-transfer-failed",
                    status="failed",
                    suspension_reason="account_disabled",
                    suspended_by_account_id="HAAAAAAAAAA",
                ),
            ]
        )
        await session.commit()

    transfer_orchestrator = Orchestrator(HyruleConfig(), admin_factory)
    transfer_orchestrator.xcpng = xcpng
    state = AppState(
        config=SimpleNamespace(),
        orchestrator=transfer_orchestrator,
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
    await transfer_vm(
        "vm_transfer_failed",
        body,
        _browser_request(credentials, path="/v1/admin/vms/vm_transfer_failed/transfer"),
        actor,
        state,
    )

    target_wallet = "0x1111111111111111111111111111111111111111"
    async with admin_factory() as session:
        for vm_id in (
            "vm_transfer_direct",
            "vm_transfer_attached",
            "vm_transfer_manual",
            "vm_transfer_failed",
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
        failed = await session.get(VMRow, "vm_transfer_failed")
        assert direct is not None and str(direct.status) == "running"
        assert direct.suspension_reason is None
        assert not (direct.metadata_ or {}).get("transfer_resume_pending")
        assert attached is not None and str(attached.status) == "running"
        assert attached.suspension_reason is None
        assert not (attached.metadata_ or {}).get("transfer_resume_pending")
        assert manual is not None and str(manual.status) == "suspended"
        assert manual.suspension_reason == "manual_admin"
        assert failed is not None and str(failed.status) == "failed"
        assert failed.suspension_reason is None
        assert failed.suspended_by_account_id is None

        stored_actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert stored_actor is not None
        await session.delete(stored_actor)
        await session.commit()
        audits = list(await session.scalars(select(AdminAuditRow)))
        retained_manual = await session.get(VMRow, "vm_transfer_manual")

    assert not AdminAuditRow.__table__.c.actor_account_id.foreign_keys
    assert not VMRow.__table__.c.suspended_by_account_id.foreign_keys
    assert not MailAccountRow.__table__.c.suspended_by_account_id.foreign_keys
    assert {row.actor_account_id for row in audits} == {"HAAAAAAAAAA"}
    assert retained_manual is not None
    assert retained_manual.suspended_by_account_id == "HAAAAAAAAAA"
    assert xcpng.started == ["uuid-transfer-direct", "uuid-transfer-attached"]


@pytest.mark.asyncio
async def test_transfers_wait_for_extension_resume_handoff(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add_all(
            [
                AccountRow(account_id="HBBBBBBBBBB", password_hash="unused"),
                AccountRow(account_id="HCCCCCCCCCC", password_hash="unused"),
                VMRow(
                    vm_id="vm_extension_transfer",
                    owner_wallet="source",
                    owner_account_id="HBBBBBBBBBB",
                    xcpng_uuid="extension-guest",
                    status="suspended",
                    metadata_={
                        "extension_resume_pending": {
                            "owner_account_id": "HBBBBBBBBBB",
                            "xcpng_uuid": "extension-guest",
                        }
                    },
                ),
                DomainRow(
                    name="extension-transfer",
                    extension="example",
                    fqdn="extension-transfer.example",
                    vm_id="vm_extension_transfer",
                    owner_wallet="source",
                    owner_account_id="HBBBBBBBBBB",
                    status="active",
                ),
            ]
        )
        await session.commit()

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=Orchestrator(HyruleConfig(), admin_factory),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    body = OwnershipTransferRequest(
        target_account_id="HCCCCCCCCCC",
        reason="wait for extension recovery",
    )
    with pytest.raises(HTTPException) as vm_refused:
        await transfer_vm(
            "vm_extension_transfer",
            body,
            _browser_request(credentials, path="/v1/admin/vms/vm_extension_transfer/transfer"),
            actor,
            state,
        )
    with pytest.raises(HTTPException) as domain_refused:
        await transfer_domain(
            "extension-transfer.example",
            body,
            _browser_request(credentials, path="/v1/admin/domains/extension-transfer.example/transfer"),
            actor,
            state,
        )

    assert vm_refused.value.status_code == 409
    assert domain_refused.value.status_code == 409
    async with admin_factory() as session:
        vm = await session.get(VMRow, "vm_extension_transfer")
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "extension-transfer.example")
            )
        ).scalar_one()
        assert vm is not None and vm.owner_account_id == "HBBBBBBBBBB"
        assert domain.owner_account_id == "HBBBBBBBBBB"
        assert list(await session.scalars(select(AdminAuditRow))) == []


@pytest.mark.asyncio
async def test_transfer_resume_handoff_survives_provider_failure(admin_factory) -> None:
    async with admin_factory.begin() as session:
        session.add(AccountRow(account_id="HCCCCCCCCCC", password_hash="unused"))
        session.add(VMRow(
            vm_id="vm_transfer_retry", owner_wallet="fixture",
            owner_account_id="HCCCCCCCCCC", xcpng_uuid="transfer-guest",
            status=VMStatus.SUSPENDED, suspension_reason="account_disabled",
            expires_at=datetime.now(UTC) + timedelta(days=1),
            metadata_={"transfer_resume_pending": {
                "owner_account_id": "HCCCCCCCCCC", "xcpng_uuid": "transfer-guest",
            }},
        ))
    orch = Orchestrator(HyruleConfig(), admin_factory)
    orch.xcpng.get_vm_power_state = AsyncMock(
        side_effect=[RuntimeError("provider unavailable"), "Halted"]
    )
    orch.xcpng.start_vm = AsyncMock()
    assert not await orch.reconcile_transfer_resume("vm_transfer_retry")
    async with admin_factory() as session:
        failed = await session.get(VMRow, "vm_transfer_retry")
        assert (failed.metadata_ or {}).get("transfer_resume_pending")
    assert await orch.reconcile_transfer_resumes() == 1
    async with admin_factory() as session:
        recovered = await session.get(VMRow, "vm_transfer_retry")
        assert recovered.status == VMStatus.RUNNING
        assert recovered.suspension_reason is None
        assert not (recovered.metadata_ or {}).get("transfer_resume_pending")
    orch.xcpng.start_vm.assert_awaited_once_with("transfer-guest")


@pytest.mark.asyncio
async def test_transferred_vm_revalidates_disabled_recipient_before_resume(
    admin_factory,
) -> None:
    async with admin_factory() as session:
        session.add(
            AccountRow(
                account_id="HBBBBBBBBBB",
                password_hash="unused",
                disabled_at=datetime.now(UTC),
            )
        )
        session.add(
            VMRow(
                vm_id="vm_transfer_disabled_recipient",
                owner_wallet="0xowner",
                owner_account_id="HBBBBBBBBBB",
                xcpng_uuid="uuid-transfer-disabled-recipient",
                status="suspended",
                suspension_reason="account_disabled",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        await session.commit()

    xcpng = _AdminXCPNG()
    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(
            xcpng=xcpng,
            start_provisioning=AsyncMock(),
        ),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )

    await _resume_transferred_vm(state, "vm_transfer_disabled_recipient")

    assert xcpng.started == []
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_transfer_disabled_recipient")
    assert row is not None and str(row.status) == "suspended"
    assert row.suspension_reason == "account_disabled"


@pytest.mark.asyncio
async def test_transferred_vm_does_not_resume_after_deletion_claim(admin_factory) -> None:
    async with admin_factory.begin() as session:
        session.add(AccountRow(account_id="HBBBBBBBBBB", password_hash="unused"))
        session.add(
            VMRow(
                vm_id="vm_transfer_deletion_claim",
                owner_wallet="0xowner",
                owner_account_id="HBBBBBBBBBB",
                xcpng_uuid="uuid-transfer-deletion-claim",
                status="suspended",
                suspension_reason="account_disabled",
                deletion_started_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )

    xcpng = _AdminXCPNG()
    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(xcpng=xcpng),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    await _resume_transferred_vm(state, "vm_transfer_deletion_claim")
    assert xcpng.started == []
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_transfer_deletion_claim")
        assert row.suspension_reason == "account_disabled"


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
async def test_transfers_preserve_provisioning_vm_payer(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    original_wallet = "0x2222222222222222222222222222222222222222"
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add_all(
            [
                AccountRow(account_id="HBBBBBBBBBB", password_hash="unused"),
                AccountRow(account_id="HCCCCCCCCCC", password_hash="unused"),
                VMRow(
                    vm_id="vm_provisioning_transfer",
                    owner_wallet=original_wallet,
                    owner_account_id="HBBBBBBBBBB",
                    status="provisioning",
                ),
                DomainRow(
                    name="provisioning-transfer",
                    extension="example",
                    fqdn="provisioning-transfer.example",
                    vm_id="vm_provisioning_transfer",
                    owner_wallet=original_wallet,
                    owner_account_id="HBBBBBBBBBB",
                    status="active",
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
            "vm_provisioning_transfer",
            body,
            _browser_request(
                credentials,
                path="/v1/admin/vms/vm_provisioning_transfer/transfer",
            ),
            actor,
            state,
        )
    assert vm_error.value.status_code == 409

    with pytest.raises(HTTPException) as domain_error:
        await transfer_domain(
            "provisioning-transfer.example",
            body,
            _browser_request(
                credentials,
                path="/v1/admin/domains/provisioning-transfer.example/transfer",
            ),
            actor,
            state,
        )
    assert domain_error.value.status_code == 409

    async with admin_factory() as session:
        vm = await session.get(VMRow, "vm_provisioning_transfer")
        domain = (
            await session.execute(
                select(DomainRow).where(
                    DomainRow.fqdn == "provisioning-transfer.example"
                )
            )
        ).scalar_one()
        audits = list(await session.scalars(select(AdminAuditRow)))
    assert vm is not None and vm.owner_account_id == "HBBBBBBBBBB"
    assert vm.owner_wallet == original_wallet
    assert domain.owner_account_id == "HBBBBBBBBBB"
    assert domain.owner_wallet == original_wallet
    assert audits == []


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

    class FailingXCPNG:
        async def reboot_vm(self, _vm_uuid: str) -> None:
            async with admin_factory() as session:
                persisted = list(
                    await session.scalars(
                        select(AdminAuditRow).where(
                            AdminAuditRow.action == "vm.reboot.requested",
                            AdminAuditRow.target_id == "vm_audit_dispatch",
                        )
                    )
                )
            assert len(persisted) == 1
            raise RuntimeError("provider unavailable")

    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(xcpng=FailingXCPNG()),
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
        bind = None  # This unit test checks the row lock; PostgreSQL covers the lifecycle guard.
        async def execute(self, statement):
            assert statement._for_update_arg is not None
            return Result()

    assert await _assert_transfer_target(Session(), target.account_id) is target


@pytest.mark.asyncio
async def test_domain_transfer_bundle_locks_vm_before_domain() -> None:
    vm = VMRow(
        vm_id="vm_lock_order",
        owner_wallet="0xowner",
        status="running",
    )
    domain = DomainRow(
        name="lock-order",
        extension="example",
        fqdn="lock-order.example",
        vm_id=vm.vm_id,
        owner_wallet="0xowner",
        status="active",
    )

    class Result:
        def __init__(self, value, *, scalar: bool = False) -> None:
            self.value = value
            self.scalar = scalar

        def one_or_none(self):
            assert not self.scalar
            return self.value

        def scalar_one_or_none(self):
            assert self.scalar
            return self.value

    class Session:
        def __init__(self) -> None:
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) == 1:
                return Result((vm.vm_id,))
            if len(self.statements) == 2:
                return Result(vm, scalar=True)
            return Result(domain, scalar=True)

    session = Session()
    locked_domain, locked_vm = await _lock_domain_transfer_bundle(
        session, domain.fqdn
    )

    locked_entities = [
        statement.column_descriptions[0]["entity"]
        for statement in session.statements
        if statement._for_update_arg is not None
    ]
    assert locked_entities == [VMRow, DomainRow]
    assert locked_domain is domain
    assert locked_vm is vm


@pytest.mark.asyncio
async def test_admin_retry_rejects_terminal_fulfillment_job(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add_all(
            [
                DomainOrderRow(
                    order_id="do_terminal_refund",
                    quote_id="dq_terminal_refund",
                    fqdn="terminal-refund.example",
                    action="register",
                    owner_account_id="HAAAAAAAAAA",
                    idempotency_key="terminal-refund-retry",
                    status="refund_due",
                    amount_usd=Decimal("10.00"),
                    domain_amount_usd=Decimal("10.00"),
                    vm_amount_usd=Decimal("0"),
                    payment_method="usdc",
                    terms_version="2026-01",
                    terms_accepted_at=datetime.now(UTC),
                ),
                DomainJobRow(
                    job_id="djob_terminal_refund",
                    kind="fulfill_order",
                    resource_id="do_terminal_refund",
                    dedupe_key="fulfill:do_terminal_refund",
                    status="failed",
                    attempts=10,
                    last_error="registrar failed",
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
    with pytest.raises(HTTPException) as exc:
        await retry_job(
            "djob_terminal_refund",
            ReasonRequest(reason="operator retry"),
            _browser_request(
                credentials,
                path="/v1/admin/jobs/djob_terminal_refund/retry",
            ),
            actor,
            state,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "Terminal fulfillment jobs cannot be retried"
    async with admin_factory() as session:
        job = await session.get(DomainJobRow, "djob_terminal_refund")
        order = await session.get(DomainOrderRow, "do_terminal_refund")
        assert job is not None and job.status == "failed"
        assert order is not None and order.status == "refund_due"
        assert list(await session.scalars(select(AdminAuditRow))) == []


@pytest.mark.asyncio
async def test_admin_retry_reopens_domain_operation_and_blocks_owner_transfer(
    admin_factory,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add_all(
            [
                AccountRow(account_id="HBBBBBBBBBB", password_hash="unused"),
                AccountRow(account_id="HCCCCCCCCCC", password_hash="unused"),
                DomainRow(
                    name="retry-owner",
                    extension="example",
                    fqdn="retry-owner.example",
                    owner_wallet="0xowner",
                    owner_account_id="HBBBBBBBBBB",
                    status="active",
                ),
                DomainOperationRow(
                    operation_id="dop_retry_owner",
                    fqdn="retry-owner.example",
                    owner_account_id="HBBBBBBBBBB",
                    kind="nameservers",
                    status=DomainOperationStatus.FAILED.value,
                    request_payload={"mode": "managed"},
                    error_code="provider_error",
                    error_detail="temporary failure",
                    result_payload={"stale": True},
                ),
                DomainJobRow(
                    job_id="djob_retry_owner",
                    kind="nameservers",
                    resource_id="dop_retry_owner",
                    dedupe_key="nameservers:dop_retry_owner",
                    status="failed",
                    last_error="temporary failure",
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
    await retry_job(
        "djob_retry_owner",
        ReasonRequest(reason="provider recovered"),
        _browser_request(credentials, path="/v1/admin/jobs/djob_retry_owner/retry"),
        actor,
        state,
    )

    async with admin_factory() as session:
        operation = await session.get(DomainOperationRow, "dop_retry_owner")
        job = await session.get(DomainJobRow, "djob_retry_owner")
        assert operation is not None and operation.status == DomainOperationStatus.QUEUED.value
        assert operation.error_code is None
        assert operation.error_detail is None
        assert operation.result_payload is None
        assert job is not None and job.status == "queued"

    with pytest.raises(HTTPException) as exc:
        await transfer_domain(
            "retry-owner.example",
            OwnershipTransferRequest(
                target_account_id="HCCCCCCCCCC",
                reason="customer-approved transfer",
            ),
            _browser_request(
                credentials,
                path="/v1/admin/domains/retry-owner.example/transfer",
            ),
            actor,
            state,
        )
    assert exc.value.status_code == 409


class _AdminXCPNG:
    def __init__(self) -> None:
        self.suspended: list[str] = []
        self.started: list[str] = []
        self.shut_down: list[str] = []
        self.rebooted: list[str] = []
        self.power: dict[str, str] = {}

    async def suspend_vm(self, vm_uuid: str) -> None:
        self.suspended.append(vm_uuid)
        self.power[vm_uuid] = "Halted"

    async def start_vm(self, vm_uuid: str) -> None:
        self.started.append(vm_uuid)
        self.power[vm_uuid] = "Running"

    async def get_vm_power_state(self, vm_uuid: str) -> str:
        return self.power.get(vm_uuid, "Halted")

    async def shutdown_vm(self, vm_uuid: str) -> None:
        self.shut_down.append(vm_uuid)

    async def reboot_vm(self, vm_uuid: str) -> None:
        self.rebooted.append(vm_uuid)


@pytest.mark.asyncio
async def test_account_suspend_reconciles_already_halted_guest(admin_factory) -> None:
    xcpng = _AdminXCPNG()
    xcpng.power["uuid-halted-before-commit"] = "Halted"
    async with admin_factory.begin() as session:
        session.add(
            AccountRow(
                account_id="HALREADYOFF",
                password_hash="unused",
                disabled_at=datetime.now(UTC),
            )
        )
        session.add(
            VMRow(
                vm_id="vm_halted_before_commit",
                owner_wallet="0xowner",
                owner_account_id="HALREADYOFF",
                xcpng_uuid="uuid-halted-before-commit",
                status="running",
            )
        )
        session.add(
            AdminOperationRow(
                operation_id="operation-replay-suspend",
                kind="suspend_account_resources",
                account_id="HALREADYOFF",
                status="queued",
            )
        )

    assert await process_admin_operations(
        admin_factory, SimpleNamespace(xcpng=xcpng)
    ) == 1
    assert xcpng.suspended == []
    async with admin_factory() as session:
        vm = await session.get(VMRow, "vm_halted_before_commit")
        operation = await session.get(AdminOperationRow, "operation-replay-suspend")
        assert vm is not None and str(vm.status) == "suspended"
        assert vm.suspension_reason == "account_disabled"
        assert operation is not None and operation.status == "completed"


@pytest.mark.asyncio
async def test_admin_start_updates_vm_while_owner_fence_is_held(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id="vm_admin_start",
                owner_wallet="0xowner",
                owner_account_id="HAAAAAAAAAA",
                xcpng_uuid="uuid-admin-start",
                status="suspended",
                suspension_reason="manual_admin",
                suspended_by_account_id="HAAAAAAAAAA",
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
    result = await vm_action(
        "vm_admin_start",
        "start",
        ReasonRequest(reason="customer confirmed recovery"),
        _browser_request(
            credentials,
            path="/v1/admin/vms/vm_admin_start/actions/start",
        ),
        actor,
        state,
    )

    assert result["status"] == "accepted"
    assert xcpng.started == ["uuid-admin-start"]
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_admin_start")
        audit = (
            await session.execute(
                select(AdminAuditRow).where(
                    AdminAuditRow.action == "vm.start.requested"
                )
            )
        ).scalar_one()
    assert row is not None and str(row.status) == "running"
    assert row.suspension_reason is None
    assert row.suspended_by_account_id is None
    assert audit.succeeded is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "database_status", "provider_power"),
    [
        ("start", "suspended", "Running"),
        ("shutdown", "running", "Halted"),
        ("suspend", "running", "Halted"),
    ],
)
async def test_admin_power_action_reconciles_completed_provider_dispatch(
    admin_factory,
    action,
    database_status,
    provider_power,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    vm_uuid = f"uuid-admin-replay-{action}"
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id=f"vm_admin_replay_{action}",
                owner_wallet="0xowner",
                owner_account_id="HAAAAAAAAAA",
                xcpng_uuid=vm_uuid,
                status=database_status,
                suspension_reason="manual_admin" if action == "start" else None,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        await session.commit()

    xcpng = _AdminXCPNG()
    xcpng.power[vm_uuid] = provider_power
    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(xcpng=xcpng),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    await vm_action(
        f"vm_admin_replay_{action}",
        action,
        ReasonRequest(reason="reconcile completed provider dispatch"),
        _browser_request(
            credentials,
            path=f"/v1/admin/vms/vm_admin_replay_{action}/actions/{action}",
        ),
        actor,
        state,
    )

    assert xcpng.started == []
    assert xcpng.shut_down == []
    assert xcpng.suspended == []
    async with admin_factory() as session:
        row = await session.get(VMRow, f"vm_admin_replay_{action}")
    assert row is not None
    assert str(row.status) == ("running" if action == "start" else "suspended")


@pytest.mark.asyncio
async def test_admin_reboot_preserves_running_vm_suspension_provenance(
    admin_factory,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id="vm_admin_reboot",
                owner_wallet="0xowner",
                owner_account_id="HAAAAAAAAAA",
                xcpng_uuid="uuid-admin-reboot",
                status="running",
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
    result = await vm_action(
        "vm_admin_reboot",
        "reboot",
        ReasonRequest(reason="apply security updates"),
        _browser_request(
            credentials,
            path="/v1/admin/vms/vm_admin_reboot/actions/reboot",
        ),
        actor,
        state,
    )

    assert result["status"] == "accepted"
    assert xcpng.rebooted == ["uuid-admin-reboot"]
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_admin_reboot")
    assert row is not None and str(row.status) == "running"
    assert row.suspension_reason is None
    assert row.suspended_by_account_id is None


@pytest.mark.asyncio
async def test_admin_shutdown_persists_under_the_vm_action_fence(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id="vm_admin_shutdown",
                owner_wallet="0xowner",
                owner_account_id="HAAAAAAAAAA",
                xcpng_uuid="uuid-admin-shutdown",
                status="running",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        await session.commit()

    xcpng = _AdminXCPNG()
    xcpng.power["uuid-admin-shutdown"] = "Running"
    state = AppState(
        config=SimpleNamespace(),
        orchestrator=SimpleNamespace(xcpng=xcpng),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    result = await vm_action(
        "vm_admin_shutdown",
        "shutdown",
        ReasonRequest(reason="customer requested shutdown"),
        _browser_request(
            credentials,
            path="/v1/admin/vms/vm_admin_shutdown/actions/shutdown",
        ),
        actor,
        state,
    )

    assert result["status"] == "accepted"
    assert xcpng.shut_down == ["uuid-admin-shutdown"]
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_admin_shutdown")
        audit = (
            await session.execute(
                select(AdminAuditRow).where(
                    AdminAuditRow.action == "vm.shutdown.requested"
                )
            )
        ).scalar_one()
    assert row is not None and str(row.status) == "suspended"
    assert row.suspension_reason == "manual_admin"
    assert row.suspended_by_account_id == "HAAAAAAAAAA"
    assert audit.succeeded is True


@pytest.mark.asyncio
async def test_admin_reboot_rejects_disabled_owner_before_worker_marker(
    admin_factory,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            AccountRow(
                account_id="HBBBBBBBBBB",
                password_hash="unused",
                disabled_at=datetime.now(UTC),
            )
        )
        session.add(
            VMRow(
                vm_id="vm_admin_reboot_disabled",
                owner_wallet="0xowner",
                owner_account_id="HBBBBBBBBBB",
                xcpng_uuid="uuid-admin-reboot-disabled",
                status="running",
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
            "vm_admin_reboot_disabled",
            "reboot",
            ReasonRequest(reason="manual recovery"),
            _browser_request(
                credentials,
                path="/v1/admin/vms/vm_admin_reboot_disabled/actions/reboot",
            ),
            actor,
            state,
        )

    assert exc.value.status_code == 409
    assert xcpng.rebooted == []
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_admin_reboot_disabled")
        audits = list(await session.scalars(select(AdminAuditRow)))
    assert row is not None and str(row.status) == "running"
    assert row.suspension_reason is None
    assert audits == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["failed", "destroyed", "provisioning", "suspended"])
@pytest.mark.parametrize("action", ["start", "reboot"])
async def test_admin_start_rejects_non_startable_vm_states(
    admin_factory,
    status: str,
    action: str,
) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            VMRow(
                vm_id=f"vm_admin_start_{status}",
                owner_wallet="0xowner",
                owner_account_id="HAAAAAAAAAA",
                xcpng_uuid=f"uuid-admin-start-{status}",
                status=status,
                deletion_started_at=datetime.now(UTC) if status == "suspended" else None,
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
            f"vm_admin_start_{status}",
            action,
            ReasonRequest(reason="manual recovery"),
            _browser_request(
                credentials,
                path=f"/v1/admin/vms/vm_admin_start_{status}/actions/start",
            ),
            actor,
            state,
        )

    assert exc.value.status_code == 409
    assert xcpng.started == []
    assert xcpng.rebooted == []
    async with admin_factory() as session:
        row = await session.get(VMRow, f"vm_admin_start_{status}")
        audits = list(await session.scalars(select(AdminAuditRow)))
    assert row is not None and str(row.status) == status
    assert audits == []


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
async def test_admin_start_fences_on_disabled_owner_without_vm_marker(admin_factory) -> None:
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        assert actor is not None
        session.add(
            AccountRow(
                account_id="HBBBBBBBBBB",
                password_hash="unused",
                disabled_at=datetime.now(UTC),
            )
        )
        session.add(
            VMRow(
                vm_id="vm_disabled_owner",
                owner_wallet="0xowner",
                owner_account_id="HBBBBBBBBBB",
                xcpng_uuid="uuid-disabled-owner",
                status="suspended",
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
            "vm_disabled_owner",
            "start",
            ReasonRequest(reason="manual override"),
            _browser_request(
                credentials,
                path="/v1/admin/vms/vm_disabled_owner/actions/start",
            ),
            actor,
            state,
        )

    assert exc.value.status_code == 409
    assert xcpng.started == []
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_disabled_owner")
        assert row is not None and str(row.status) == "suspended"
        assert row.suspension_reason is None
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
                AccountRow(
                    account_id="HOLDOWNERAA",
                    password_hash="unused",
                    disabled_at=(
                        datetime.now(UTC)
                        if kind == "suspend_account_resources"
                        else None
                    ),
                ),
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
async def test_stale_resume_operation_does_not_revive_disabled_account(admin_factory) -> None:
    xcpng = _AdminXCPNG()
    disabled_at = datetime.now(UTC)
    async with admin_factory() as session:
        session.add_all(
            [
                AccountRow(
                    account_id="HSTALESTATE",
                    password_hash="unused",
                    disabled_at=disabled_at,
                ),
                VMRow(
                    vm_id="vm_stale_resume",
                    owner_wallet="0xowner",
                    owner_account_id="HSTALESTATE",
                    xcpng_uuid="uuid-stale-resume",
                    status="suspended",
                    suspension_reason="account_disabled",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                AdminOperationRow(
                    operation_id="operation-stale-resume",
                    kind="resume_account_resources",
                    account_id="HSTALESTATE",
                    status="running",
                    started_at=datetime.now(UTC) - timedelta(minutes=20),
                    reason="superseded enable",
                ),
            ]
        )
        await session.commit()

    progress = await _apply_account_operation(
        admin_factory,
        SimpleNamespace(xcpng=xcpng),
        "operation-stale-resume",
    )

    assert progress == {"vms": 0, "mailboxes": 0}
    assert xcpng.started == []
    async with admin_factory() as session:
        account = await session.get(AccountRow, "HSTALESTATE")
        vm = await session.get(VMRow, "vm_stale_resume")
        operation = await session.get(AdminOperationRow, "operation-stale-resume")
        assert account is not None and account.disabled_at is not None
        assert vm is not None and str(vm.status) == "suspended"
        assert vm.suspension_reason == "account_disabled"
        assert operation is not None and operation.status == "completed"
        assert operation.progress == {"vms": 0, "mailboxes": 0}


@pytest.mark.asyncio
async def test_admin_resource_operations_are_resumable_and_preserve_provenance(
    admin_factory,
) -> None:
    xcpng = _AdminXCPNG()
    xcpng.power.update(
        {
            "uuid-active": "Running",
            "uuid-provisioning": "Running",
            "uuid-failed-disabled": "Running",
        }
    )
    orchestrator = Orchestrator(HyruleConfig(), admin_factory)
    orchestrator.xcpng = xcpng
    old_report_deadline = datetime.now(UTC) - timedelta(minutes=1)
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
                    disabled_at=datetime.now(UTC),
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
                    xcpng_uuid="uuid-provisioning",
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
                VMGuestResultRow(
                    vm_id="vm_provisioning",
                    generation="a" * 32,
                    token_hash="b" * 64,
                    deadline=old_report_deadline,
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
        account = await session.get(AccountRow, "HBBBBBBBBBB")
        assert account is not None
        account.disabled_at = None
        account.disabled_reason = None
        account.disabled_by_account_id = None
        # Model a worker that started this guest before crashing ahead of its
        # database commit. Resume must reconcile rather than replay start.
        xcpng.power["uuid-active"] = "Running"
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
        receipt = await session.get(VMGuestResultRow, "vm_provisioning")
        assert active is not None and str(active.status) == "running"
        assert active.suspension_reason is None
        assert manual is not None and manual.suspension_reason == "manual_admin"
        assert provisioning is not None and str(provisioning.status) == "provisioning"
        assert provisioning.suspension_reason is None
        assert failed_disabled is not None and str(failed_disabled.status) == "failed"
        assert failed_disabled.suspension_reason is None
        assert failed_disabled.suspended_by_account_id is None
        assert mailbox is not None and mailbox.status == "active"
        assert expired_mailbox is not None and expired_mailbox.status == "suspended"
        assert expired_mailbox.suspension_reason == "expired"
        assert operation is not None and operation.status == "completed"
        assert receipt is not None
        receipt_deadline = (
            receipt.deadline.replace(tzinfo=UTC)
            if receipt.deadline.tzinfo is None
            else receipt.deadline
        )
        assert receipt_deadline > old_report_deadline

    assert xcpng.suspended == ["uuid-active", "uuid-provisioning", "uuid-failed-disabled"]
    assert xcpng.started == ["uuid-provisioning"]


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

    orchestrator = Orchestrator(HyruleConfig(), admin_factory)
    try:
        await orchestrator._simulate_provisioning("vm_provisioning_suspended")
    finally:
        await orchestrator.shutdown()

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

    orchestrator = Orchestrator(HyruleConfig(), admin_factory)
    try:
        result = await orchestrator.extend_vm("vm_admin_suspended", 7)
    finally:
        await orchestrator.shutdown()

    assert result is None
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_admin_suspended")
        assert row is not None and row.expires_at is not None
        stored_expiry = row.expires_at.replace(tzinfo=UTC) if row.expires_at.tzinfo is None else row.expires_at
        assert stored_expiry == expires_at


@pytest.mark.asyncio
async def test_disabled_owner_blocks_extension_without_vm_marker(admin_factory) -> None:
    expires_at = datetime.now(UTC) + timedelta(days=1)
    async with admin_factory() as session:
        session.add(
            AccountRow(
                account_id="HBBBBBBBBBB",
                password_hash="unused",
                disabled_at=datetime.now(UTC),
            )
        )
        session.add(
            VMRow(
                vm_id="vm_disabled_owner_extension",
                owner_wallet="0xowner",
                owner_account_id="HBBBBBBBBBB",
                status="running",
                expires_at=expires_at,
            )
        )
        await session.commit()

    orchestrator = Orchestrator(HyruleConfig(), admin_factory)
    try:
        result = await orchestrator.extend_vm("vm_disabled_owner_extension", 7)
    finally:
        await orchestrator.shutdown()

    assert result is None
    async with admin_factory() as session:
        row = await session.get(VMRow, "vm_disabled_owner_extension")
        assert row is not None and row.expires_at is not None
        stored_expiry = (
            row.expires_at.replace(tzinfo=UTC)
            if row.expires_at.tzinfo is None
            else row.expires_at
        )
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


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["disable", "enable"])
async def test_account_transition_supersedes_only_failed_inverse_operation(
    admin_factory, transition,
) -> None:
    credentials = await _admin_credentials(admin_factory, elevated=True)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, "HAAAAAAAAAA")
        target = AccountRow(
            account_id="HBBBBBBBBBB",
            password_hash="fixture",
            disabled_at=(datetime.now(UTC) if transition == "enable" else None),
        )
        session.add(target)
        inverse_kind = (
            "resume_account_resources"
            if transition == "disable"
            else "suspend_account_resources"
        )
        same_kind = (
            "suspend_account_resources"
            if transition == "disable"
            else "resume_account_resources"
        )
        session.add_all(
            [
                AdminOperationRow(
                    operation_id="failed-inverse",
                    kind=inverse_kind,
                    account_id=target.account_id,
                    status="failed",
                    error="provider unavailable",
                ),
                AdminOperationRow(
                    operation_id="failed-same-direction",
                    kind=same_kind,
                    account_id=target.account_id,
                    status="failed",
                    error="retry me",
                ),
            ]
        )
    state = AppState(
        config=HyruleConfig(),
        orchestrator=SimpleNamespace(xcpng=_AdminXCPNG()),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    operation = disable_account if transition == "disable" else enable_account
    result = await operation(
        "HBBBBBBBBBB",
        ReasonRequest(reason=f"fixture {transition}"),
        _browser_request(credentials, path=f"/v1/admin/accounts/HBBBBBBBBBB/{transition}"),
        actor,
        state,
    )
    async with admin_factory() as session:
        inverse = await session.get(AdminOperationRow, "failed-inverse")
        same = await session.get(AdminOperationRow, "failed-same-direction")
        replacement = await session.get(AdminOperationRow, result["operation_id"])
        assert inverse.status == "completed" and inverse.completed_at is not None
        assert inverse.error == "provider unavailable"
        assert inverse.progress["superseded"]["by_operation_id"] == replacement.operation_id
        assert inverse.progress["superseded"]["by_kind"] == replacement.kind
        assert same.status == "failed" and same.completed_at is None
        assert replacement.status == "queued"


@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['expired', 'running', 'claimed', 'failed', 'destroyed', 'provisioning', 'no_expiry', 'audit_failure'])
async def test_admin_expiry_extension_requires_step_up_and_atomic_audit(admin_factory, monkeypatch, case):
    from unittest.mock import AsyncMock

    now = datetime.now(UTC)
    monkeypatch.setattr('hyrule_cloud.api.admin._now', lambda: now)
    credentials = await _admin_credentials(admin_factory)
    status = 'suspended' if case in ('expired', 'claimed', 'no_expiry', 'audit_failure') else case
    expiry = now - timedelta(days=1) if case != 'running' else now + timedelta(days=2)
    async with admin_factory.begin() as session:
        session.add(VMRow(vm_id='vm_admin_expiry', owner_wallet='fixture', status=status,
                          expires_at=None if case == 'no_expiry' else expiry,
                          suspension_reason='expired' if status == 'suspended' else None,
                          deletion_started_at=now if case == 'claimed' else None))
    orch = Orchestrator(HyruleConfig(), admin_factory)
    orch.xcpng.start_vm = AsyncMock(side_effect=AssertionError('expiry grant must not change power'))
    state = AppState(config=HyruleConfig(), orchestrator=orch, payment_gate=_admin_gate(admin_factory),
                     network_provider=None, session_factory=admin_factory)
    previous = getattr(app.state, '_typed_state', None)
    app.state._typed_state = state
    path = '/v1/admin/vms/vm_admin_expiry/actions/extend'
    body = {'days': 7, 'reason': 'Operator recovery window'}
    try:
        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url='http://localhost') as client:
            assert (await client.post(path, json=body)).status_code == 401
            client.cookies.set('hyr_sess', credentials.token)
            client.cookies.set('hyr_csrf', credentials.csrf_token)
            assert (await client.post(path, json=body)).status_code == 403
            headers = {'X-CSRF-Token': credentials.csrf_token}
            assert (await client.post(path, json=body, headers=headers)).status_code == 403
            async with admin_factory.begin() as session:
                login = await session.scalar(select(SessionRow).where(SessionRow.account_id == 'HAAAAAAAAAA'))
                login.admin_elevated_at = now
            for days in (0, 366, True):
                response = await client.post(path, json={**body, 'days': days}, headers=headers)
                assert response.status_code == 422
            if case == 'audit_failure':
                from hyrule_cloud.api import admin
                real_audit = admin._audit

                def invalid_audit(*args, **kwargs):
                    audit = real_audit(*args, **kwargs)
                    audit.action = None  # Force a real NOT NULL failure at commit.
                    return audit

                monkeypatch.setattr(admin, '_audit', invalid_audit)
            response = await client.post(path, json=body, headers=headers)
            expected_status = 200 if case in ('expired', 'running') else 500 if case == 'audit_failure' else 409
            assert response.status_code == expected_status
            async with admin_factory() as session:
                vm = await session.get(VMRow, 'vm_admin_expiry')
                audits = list(await session.scalars(select(AdminAuditRow).where(AdminAuditRow.action == 'vm.extend')))
                if response.status_code == 200:
                    expected = max(expiry, now) + timedelta(days=7)
                    assert vm.expires_at.replace(tzinfo=UTC) == expected
                    assert response.json()['power_changed'] is False
                    assert len(audits) == 1 and audits[0].actor_account_id == 'HAAAAAAAAAA'
                    assert audits[0].reason == body['reason']
                    assert audits[0].details['previous_expiry'] == expiry.isoformat()
                    assert audits[0].details['new_expiry'] == expected.isoformat()
                else:
                    assert not audits
                    assert vm.expires_at is None if case == 'no_expiry' else vm.expires_at.replace(tzinfo=UTC) == expiry
                assert str(vm.status) == status
                assert vm.suspension_reason == ('expired' if status == 'suspended' else None)
            orch.xcpng.start_vm.assert_not_awaited()
    finally:
        app.state._typed_state = previous
        await orch.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['none', 'provider', 'request_audit', 'completion_audit',
                                   'request_ack', 'completion_ack', 'authorization_audit', 'authorization_ack'])
async def test_retained_restore_is_audited_replayable_and_keeps_cycle_history(admin_factory, monkeypatch, failure):
    from uuid import uuid4

    from sqlalchemy.ext.asyncio import AsyncSession

    from hyrule_cloud.db import VMRestoreRow, VMRetentionRow
    from hyrule_cloud.providers.xcpng import VMProtectionManifest
    from hyrule_cloud.services.vm_retention import prepare_retention

    credentials = await _admin_credentials(admin_factory)
    now = datetime.now(UTC)
    manifest = VMProtectionManifest('guest-retained', ('disk',), (), True, 'restart', ())
    async with admin_factory.begin() as session:
        session.add(VMRow(vm_id='vm_retained_restore', owner_wallet='fixture',
                          xcpng_uuid='guest-retained', status='suspended', suspension_reason='expired',
                          expires_at=now - timedelta(days=3), deletion_started_at=now,
                          ipv6_prefix_index=8, ipv6_prefix='2a0c:b641:b51:8::/64'))
    async with admin_factory.begin() as session:
        retained = await prepare_retention(session, 'vm_retained_restore', manifest, now + timedelta(days=30))
        retained.state = 'retained'
        retained.retained_at = now
    orch = Orchestrator(HyruleConfig(), admin_factory)
    seen = []

    async def restore(received):
        assert received == manifest
        async with admin_factory() as session:
            retained = await session.get(VMRetentionRow, 'vm_retained_restore')
            operation = await session.get(VMRestoreRow, retained.restore_operation_id)
            assert retained.state == 'restoring' and operation.state == 'authorized'
            vm = await session.get(VMRow, retained.vm_id)
            assert vm.expires_at == operation.new_expiry
            assert vm.expires_at.replace(tzinfo=UTC) > datetime.now(UTC)
            assert vm.deletion_started_at is not None
            assert await session.scalar(select(AdminAuditRow).where(
                AdminAuditRow.action == 'vm.restore_authorized')) is not None
            assert await session.scalar(select(AdminAuditRow).where(
                AdminAuditRow.action == 'vm.restore_requested')) is not None
        seen.append(True)
        if failure == 'provider' and len(seen) == 1:
            raise ConnectionError('lost provider acknowledgement')

    original_commit = AsyncSession.commit
    injected = False

    async def interrupted_commit(session):
        nonlocal injected
        target = ('vm.restore_requested' if failure.startswith('request_') else
                  'vm.restore_authorized' if failure.startswith('authorization_') else 'vm.restore_completed')
        audits = [row for row in session.new if isinstance(row, AdminAuditRow) and row.action == target]
        inject = failure not in {'none', 'provider'} and not injected and bool(audits)
        if inject:
            injected = True
            if failure.endswith('_audit'):
                audits[0].action = None  # Real NOT NULL failure rolls back the transaction.
        await original_commit(session)
        if inject and failure.endswith('_ack'):
            raise ConnectionError('commit succeeded but acknowledgement was lost')

    monkeypatch.setattr(AsyncSession, 'commit', interrupted_commit)
    orch.xcpng.restore_retained_vm = AsyncMock(side_effect=restore)
    orch.xcpng.start_vm = AsyncMock(side_effect=AssertionError('recovery must not start VM'))
    state = AppState(config=HyruleConfig(), orchestrator=orch, payment_gate=_admin_gate(admin_factory),
                     network_provider=None, session_factory=admin_factory)
    previous = getattr(app.state, '_typed_state', None)
    app.state._typed_state = state
    path = '/v1/admin/vms/vm_retained_restore/actions/restore'
    body = {'days': 7, 'reason': 'Recover retained customer data', 'operation_id': str(uuid4())}
    headers = {'X-CSRF-Token': credentials.csrf_token}
    try:
        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url='https://test') as client:
            client.cookies.set('hyr_sess', credentials.token)
            client.cookies.set('hyr_csrf', credentials.csrf_token)
            response = await client.post(path, json=body, headers=headers)
            assert response.status_code == 403
            async with admin_factory.begin() as session:
                login = await session.scalar(select(SessionRow).where(SessionRow.account_id == 'HAAAAAAAAAA'))
                login.admin_elevated_at = now
            response = await client.post(path, json=body, headers=headers)
            if failure != 'none':
                assert response.status_code == (503 if failure == 'provider' else 500)
                async with admin_factory() as session:
                    vm = await session.get(VMRow, 'vm_retained_restore')
                    assert (vm.deletion_started_at is None) == (failure == 'completion_ack')
                    operation = await session.get(VMRestoreRow, body['operation_id'])
                    if failure == 'request_audit':
                        assert operation is None and seen == []
                    else:
                        expected_state = ('completed' if failure == 'completion_ack' else
                                          'pending' if failure in {'request_ack', 'authorization_audit'} else 'authorized')
                        assert operation.state == expected_state
                        expected_expiry = (now - timedelta(days=3) if expected_state == 'pending' else operation.new_expiry)
                        assert vm.expires_at.replace(tzinfo=UTC) == expected_expiry.replace(tzinfo=UTC)
                    if failure in {'request_ack', 'authorization_audit', 'authorization_ack'}:
                        assert seen == []
                response = await client.post(path, json=body, headers=headers)
            assert response.status_code == 200, response.text
            replay = await client.post(path, json=body, headers=headers)
            assert replay.status_code == 200 and replay.json() == response.json()
            conflict = await client.post(path, json={**body, 'days': 8}, headers=headers)
            assert conflict.status_code == 409
        async with admin_factory.begin() as session:
            vm = await session.get(VMRow, 'vm_retained_restore')
            assert vm.status == 'suspended' and vm.ipv6_prefix_index == 8
            assert vm.deletion_started_at is None
            assert await session.get(VMRetentionRow, vm.vm_id) is None
            operation = await session.get(VMRestoreRow, body['operation_id'])
            assert operation.state == 'completed'
            assert operation.retention_snapshot['manifest']['disk_ids'] == ['disk']
            assert operation.retention_snapshot['previous_expiry'] == (now - timedelta(days=3)).isoformat()
            audits = list(await session.scalars(select(AdminAuditRow).where(
                AdminAuditRow.action.in_(['vm.restore_requested', 'vm.restore_authorized', 'vm.restore_completed']))))
            assert len(audits) == 3
            # A later retention cycle gets fresh evidence without overwriting recovery history.
            next_manifest = VMProtectionManifest('guest-retained', ('disk',), (), False, '', ())
            next_retained = await prepare_retention(session, vm.vm_id, next_manifest, now + timedelta(days=60))
            assert next_retained.manifest['auto_poweron'] is False
            assert operation.retention_snapshot['manifest']['auto_poweron'] is True
        assert len(seen) == (2 if failure in {'provider', 'completion_audit'} else 1)
        assert injected == (failure not in {'none', 'provider'})
    finally:
        app.state._typed_state = previous
        await orch.xcpng.close()


@pytest.mark.asyncio
async def test_retention_status_exposes_pending_retry_without_sensitive_manifest(admin_factory):
    from hyrule_cloud.db import VMRestoreRow, VMRetentionRow

    credentials = await _admin_credentials(admin_factory)
    now = datetime.now(UTC)
    async with admin_factory.begin() as session:
        session.add(VMRow(vm_id='vm_recovery_status', owner_wallet='fixture', status='suspended'))
        session.add(VMRetentionRow(vm_id='vm_recovery_status', source_vm_uuid='private-provider-id',
                                  owner_wallet='fixture', state='restoring',
                                  manifest={'secret_fixture': 'must-not-return-manifest'},
                                  restore_config={'ssh_pubkey': 'must-not-return-config'},
                                  retain_until=now + timedelta(days=30), restore_operation_id='pending-old'))
        for operation_id, age, status in [('pending-old', 3, 'pending'), ('newer', 1, 'completed')]:
            session.add(VMRestoreRow(operation_id=operation_id, vm_id='vm_recovery_status',
                                    actor_account_id='HAAAAAAAAAA', days=7, reason='Operator recovery',
                                    state=status, retention_snapshot={'hidden': 'must-not-return-history'},
                                    new_expiry=now + timedelta(days=7), created_at=now - timedelta(days=age)))
    previous = getattr(app.state, '_typed_state', None)
    app.state._typed_state = AppState(config=HyruleConfig(), orchestrator=SimpleNamespace(db=admin_factory), payment_gate=None,
                                     network_provider=None, session_factory=admin_factory)
    path = '/v1/admin/vms/vm_recovery_status/retention?limit=1'
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url='https://test') as client:
            assert (await client.get(path)).status_code == 401
            client.cookies.set('hyr_sess', credentials.token)
            response = await client.get(path)
            assert response.status_code == 200
            payload = response.json()
            assert payload['active_recovery']['operation_id'] == 'pending-old'
            assert payload['active_recovery']['days'] == 7
            assert payload['active_recovery']['reason'] == 'Operator recovery'
            assert payload['history'][0]['operation_id'] == 'newer'
            assert payload['has_more_history'] is True
            assert payload['next_offset'] == 1
            older = (await client.get(path + '&offset=1')).json()
            assert older['history'][0]['operation_id'] == 'pending-old'
            assert older['next_offset'] is None
            assert 'must-not-return' not in response.text and 'private-provider-id' not in response.text
            assert (await client.get('/v1/admin/vms/missing/retention')).status_code == 404
            # Historical evidence remains inspectable after resource removal.
            async with admin_factory.begin() as session:
                await session.delete(await session.get(VMRetentionRow, 'vm_recovery_status'))
                await session.delete(await session.get(VMRow, 'vm_recovery_status'))
            archived = (await client.get(path)).json()
            assert archived['vm_status'] is None and archived['retention'] is None
            assert archived['history'][0]['operation_id'] == 'newer'
            for offset in (2, 100):
                empty_page = await client.get(path + f'&offset={offset}')
                assert empty_page.status_code == 200
                assert empty_page.json()['history'] == []
                assert empty_page.json()['has_more_history'] is False
                assert empty_page.json()['next_offset'] is None
            assert (await client.get('/v1/admin/vms/missing/retention?offset=100')).status_code == 404
    finally:
        app.state._typed_state = previous


@pytest.mark.asyncio
@pytest.mark.parametrize('status,claimed', [('suspended', True), ('destroyed', False)])
async def test_domain_transfer_rejects_attached_vm_deletion(admin_factory, status, claimed):
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add_all([AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture'),
                         AccountRow(account_id='HCCCCCCCCCC', password_hash='fixture')])
        session.add(VMRow(vm_id='vm_claimed_domain', owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                          status=status, xcpng_uuid='fixture-guest', suspension_reason='account_disabled',
                          deletion_started_at=datetime.now(UTC) if claimed else None,
                          expires_at=datetime.now(UTC) + timedelta(days=1)))
        session.add(DomainRow(name='claimed', extension='example', fqdn='claimed.example',
                              vm_id='vm_claimed_domain', owner_wallet='fixture',
                              owner_account_id='HBBBBBBBBBB', status='active'))
    xcpng = _AdminXCPNG()
    state = AppState(config=SimpleNamespace(), orchestrator=SimpleNamespace(xcpng=xcpng),
                     payment_gate=None, network_provider=None, session_factory=admin_factory)
    with pytest.raises(HTTPException) as exc:
        await transfer_domain('claimed.example', OwnershipTransferRequest(
            target_account_id='HCCCCCCCCCC', reason='Fixture transfer'),
            _browser_request(credentials, path='/fixture'), actor, state)
    assert exc.value.status_code == 409
    assert xcpng.started == []
    async with admin_factory() as session:
        vm = await session.get(VMRow, 'vm_claimed_domain')
        domain = await session.scalar(select(DomainRow).where(DomainRow.fqdn == 'claimed.example'))
        assert vm.owner_account_id == domain.owner_account_id == 'HBBBBBBBBBB'
        assert list(await session.scalars(select(AdminAuditRow).where(AdminAuditRow.action == 'domain.transfer'))) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['check_payment', 'verify_only'])
async def test_marketplace_registration_uses_normal_payment_without_admin_waiver(admin_factory, method):
    credentials = await _admin_credentials(admin_factory, elevated=True)
    gate = _admin_gate(admin_factory)
    request = _browser_request(credentials, path='/v1/domains/registrations')
    result = await getattr(gate, method)(request, Decimal('12.00'), 'Domain registration')
    assert isinstance(result, Response) and result.status_code == 402
    assert getattr(request.state, 'payment_mode', None) != 'admin-bypass'
    async with admin_factory() as session:
        assert list(await session.scalars(select(AdminBypassUsageRow))) == []
        events = list(await session.scalars(select(PaymentEventRow)))
        assert all(event.event_type != 'admin_bypass' for event in events)


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['account_enable', 'ownership_transfer'])
async def test_legacy_restart_receipt_survives_commit_before_scheduling_crash(admin_factory, monkeypatch, source):
    import asyncio
    from unittest.mock import AsyncMock

    from hyrule_cloud.db import VMGuestResultRow

    monkeypatch.setattr('hyrule_cloud.services.launch_proof._LAUNCH_PROOF_REAL', True)
    config = HyruleConfig()
    original = Orchestrator(config, admin_factory)
    recovered = Orchestrator(config, admin_factory)
    async with admin_factory.begin() as session:
        session.add(AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture'))
        session.add(VMRow(vm_id='vm_legacy_restart', owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                          status='suspended', suspension_reason='account_disabled',
                          expires_at=datetime.now(UTC) + timedelta(days=1),
                          metadata_={"transfer_resume_pending": {
                              "owner_account_id": "HBBBBBBBBBB", "xcpng_uuid": None,
                          }} if source == 'ownership_transfer' else None))
        session.add(AdminOperationRow(operation_id='legacy-restart', kind='resume_account_resources',
                                      account_id='HBBBBBBBBBB', status='running'))
    generations = []

    async def crash_after_commit(vm_id):
        async with admin_factory() as session:
            vm = await session.get(VMRow, vm_id)
            receipt = await session.get(VMGuestResultRow, vm_id)
            assert vm.status == 'provisioning' and vm.suspension_reason is None
            assert receipt is not None
            generations.append(receipt.generation)
        raise asyncio.CancelledError('fixture process exit before in-memory scheduling')

    original.start_provisioning = AsyncMock(side_effect=crash_after_commit)
    recovered._provision_vm_owned = AsyncMock()
    try:
        with pytest.raises(asyncio.CancelledError):
            if source == 'account_enable':
                await _apply_account_operation(admin_factory, original, 'legacy-restart')
            else:
                state = AppState(config=config, orchestrator=original, payment_gate=None,
                                 network_provider=None, session_factory=admin_factory)
                await _resume_transferred_vm(state, 'vm_legacy_restart')
        assert await recovered.recover_tracked_provisioning() == 1
        await asyncio.gather(*list(recovered._tasks))
        recovered._provision_vm_owned.assert_awaited_once_with('vm_legacy_restart')
        async with admin_factory() as session:
            receipt = await session.get(VMGuestResultRow, 'vm_legacy_restart')
            assert receipt.generation == generations[0]
    finally:
        await original.shutdown()
        await recovered.shutdown()


@pytest.mark.asyncio
async def test_restore_after_account_enable_stays_stopped_when_queued_enable_runs(admin_factory):
    from uuid import uuid4

    from hyrule_cloud.db import VMRetentionRow
    from hyrule_cloud.providers.xcpng import VMProtectionManifest
    from hyrule_cloud.services.vm_retention import prepare_retention

    credentials = await _admin_credentials(admin_factory, elevated=True)
    now = datetime.now(UTC)
    async with admin_factory.begin() as session:
        session.add(AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture', disabled_at=now))
        session.add(VMRow(vm_id='vm_disabled_retained', owner_account_id='HBBBBBBBBBB',
                          owner_wallet='fixture', xcpng_uuid='disabled-retained-guest',
                          status='suspended', suspension_reason='account_disabled',
                          expires_at=now - timedelta(days=3), deletion_started_at=now))
    async with admin_factory.begin() as session:
        retained = await prepare_retention(
            session, 'vm_disabled_retained',
            VMProtectionManifest('disabled-retained-guest', ('disk',), (), False, '', ()),
            now + timedelta(days=30),
        )
        retained.state = 'retained'
        retained.retained_at = now
    orch = Orchestrator(HyruleConfig(), admin_factory)
    orch.xcpng.restore_retained_vm = AsyncMock()
    orch.xcpng.start_vm = AsyncMock(side_effect=AssertionError('recovery must remain stopped'))
    previous = getattr(app.state, '_typed_state', None)
    app.state._typed_state = AppState(config=HyruleConfig(), orchestrator=orch,
                                     payment_gate=_admin_gate(admin_factory),
                                     network_provider=None, session_factory=admin_factory)
    body = {'operation_id': str(uuid4()), 'days': 7, 'reason': 'Recover retained data after enabling owner'}
    path = '/v1/admin/vms/vm_disabled_retained/actions/restore'
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url='https://test') as client:
            client.cookies.set('hyr_sess', credentials.token)
            client.cookies.set('hyr_csrf', credentials.csrf_token)
            headers = {'X-CSRF-Token': credentials.csrf_token}
            assert (await client.post(path, json=body, headers=headers)).status_code == 409
            orch.xcpng.restore_retained_vm.assert_not_awaited()
            async with admin_factory.begin() as session:
                owner = await session.get(AccountRow, 'HBBBBBBBBBB')
                owner.disabled_at = None
                session.add(AdminOperationRow(operation_id='delayed-enable', kind='resume_account_resources',
                                              account_id=owner.account_id, status='running'))
            response = await client.post(path, json=body, headers=headers)
            assert response.status_code == 200, response.text
            assert response.json()['power_changed'] is False
        # Run the real queued operation after recovery has committed its new term.
        await _apply_account_operation(admin_factory, orch, 'delayed-enable')
        async with admin_factory() as session:
            vm = await session.get(VMRow, 'vm_disabled_retained')
            assert vm.status == 'suspended' and vm.deletion_started_at is None
            assert vm.suspension_reason == 'manual_admin'
            assert vm.suspended_by_account_id == 'HAAAAAAAAAA'
            assert vm.expires_at.replace(tzinfo=UTC) > now
            assert await session.get(VMRetentionRow, vm.vm_id) is None
        orch.xcpng.restore_retained_vm.assert_awaited_once()
        orch.xcpng.start_vm.assert_not_awaited()
    finally:
        app.state._typed_state = previous
        await orch.xcpng.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('revocation', ['disable', 'demote'])
@pytest.mark.parametrize('action', ['start', 'reboot', 'shutdown', 'suspend', 'extend'])
async def test_vm_dispatch_rechecks_previously_authenticated_admin(admin_factory, revocation, action):
    from unittest.mock import AsyncMock

    from hyrule_cloud.api.admin import ExpiryExtensionRequest, extend_vm_expiry

    credentials = await _admin_credentials(admin_factory, elevated=True)
    expiry = datetime.now(UTC) + timedelta(days=1)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(VMRow(vm_id='vm_revoked_dispatch', owner_wallet='fixture', status='suspended',
                          xcpng_uuid='revocation-fixture-guest', expires_at=expiry))
    # Keep the previously authenticated object while another transaction commits
    # revocation, matching an in-flight request paused after its dependency.
    async with admin_factory.begin() as session:
        current = await session.get(AccountRow, actor.account_id)
        if revocation == 'disable':
            current.disabled_at = datetime.now(UTC)
        else:
            current.is_admin = False
    assert actor.is_admin and actor.disabled_at is None
    provider = SimpleNamespace(**{name: AsyncMock() for name in ('start_vm', 'reboot_vm', 'suspend_vm', 'shutdown_vm')})
    state = AppState(config=HyruleConfig(), orchestrator=SimpleNamespace(xcpng=provider),
                     payment_gate=None, network_provider=None, session_factory=admin_factory)
    request = _browser_request(credentials, path=f'/v1/admin/vms/vm_revoked_dispatch/actions/{action}')
    with pytest.raises(HTTPException) as refused:
        if action == 'extend':
            await extend_vm_expiry('vm_revoked_dispatch', ExpiryExtensionRequest(days=7, reason='fixture recovery'),
                                   request, actor, state)
        else:
            await vm_action('vm_revoked_dispatch', action, ReasonRequest(reason='fixture power action'),
                            request, actor, state)
    assert refused.value.status_code == 403
    for method in vars(provider).values():
        method.assert_not_awaited()
    async with admin_factory() as session:
        row = await session.get(VMRow, 'vm_revoked_dispatch')
        assert row.status == 'suspended' and row.expires_at.replace(tzinfo=UTC) == expiry
        assert list(await session.scalars(select(AdminAuditRow).where(
            AdminAuditRow.target_id == 'vm_revoked_dispatch'))) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('revocation', ['none', 'disable', 'demote'])
@pytest.mark.parametrize('action', ['destroy', 'nameservers', 'dnssec', 'dns'])
async def test_privileged_service_acceptance_rechecks_actor(admin_factory, revocation, action):
    from unittest.mock import AsyncMock

    from hyrule_cloud.api.admin import (
        DNSAdminRequest,
        DNSSECAdminRequest,
        NameserverAdminRequest,
        admin_dns,
        admin_dnssec,
        admin_nameservers,
    )
    from hyrule_cloud.db import DomainOperationRow
    from hyrule_cloud.domains.service import DomainService

    credentials = await _admin_credentials(admin_factory, elevated=True)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(VMRow(vm_id='vm_acceptance', owner_wallet='fixture', xcpng_uuid='acceptance-guest',
                          status='suspended', expires_at=datetime.now(UTC) + timedelta(days=1)))
        session.add(DomainRow(name='acceptance', extension='dev', fqdn='acceptance.dev',
                              owner_account_id=actor.account_id, owner_wallet='fixture',
                              status='active', nameserver_mode='managed', dnssec_mode='managed',
                              dnssec_status='active', zone_revision=1))
    if revocation != 'none':
        async with admin_factory.begin() as session:
            current = await session.get(AccountRow, actor.account_id)
            if revocation == 'disable':
                current.disabled_at = datetime.now(UTC)
            else:
                current.is_admin = False
    config = HyruleConfig()
    orch = Orchestrator(config, admin_factory)
    orch.xcpng.destroy_vm = AsyncMock()
    domains = object.__new__(DomainService)
    domains.db = admin_factory
    domains.domain_config = config.domain
    domains.dns = SimpleNamespace(apply_zone=AsyncMock())
    state = AppState(config=config, orchestrator=orch, payment_gate=None, network_provider=None,
                     session_factory=admin_factory, domains=domains)
    request = _browser_request(credentials, path=f'/v1/admin/fixture/{action}')

    async def dispatch():
        if action == 'destroy':
            return await vm_action('vm_acceptance', action, ReasonRequest(reason='fixture deletion'), request, actor, state)
        if action == 'nameservers':
            return await admin_nameservers('acceptance.dev', NameserverAdminRequest(
                reason='fixture nameservers', request={'mode': 'managed'}), request, actor, state)
        if action == 'dnssec':
            return await admin_dnssec('acceptance.dev', DNSSECAdminRequest(
                reason='fixture dnssec', request={'mode': 'managed'}), request, actor, state)
        return await admin_dns('acceptance.dev', DNSAdminRequest(
            reason='fixture dns update', expected_revision=1,
            request={'changes': [{'action': 'upsert', 'rrset': {
                'name': 'www', 'type': 'AAAA', 'ttl': 300, 'values': ['2001:db8::1'],
            }}]}), request, actor, state)

    try:
        if revocation == 'none':
            await dispatch()
        else:
            with pytest.raises(HTTPException) as refused:
                await dispatch()
            assert refused.value.status_code == 403
        async with admin_factory() as session:
            vm = await session.get(VMRow, 'vm_acceptance')
            operations = list(await session.scalars(select(DomainOperationRow)))
            audits = list(await session.scalars(select(AdminAuditRow)))
            domain = await session.scalar(select(DomainRow).where(DomainRow.fqdn == 'acceptance.dev'))
            accepted = revocation == 'none'
            assert (vm.deletion_started_at is not None) == (accepted and action == 'destroy')
            assert len(operations) == int(accepted and action in {'nameservers', 'dnssec'})
            assert len(audits) == int(accepted)
            assert domain.zone_revision == (2 if accepted and action == 'dns' else 1)
        assert orch.xcpng.destroy_vm.await_count == int(accepted and action == 'destroy')
        assert domains.dns.apply_zone.await_count == int(accepted and action == 'dns')
    finally:
        await orch.xcpng.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('revocation', ['disable', 'demote'])
@pytest.mark.parametrize('resource', ['vm', 'domain'])
async def test_revoked_admin_cannot_transfer_attached_resources(admin_factory, revocation, resource):
    from hyrule_cloud.api.admin import OwnershipTransferRequest, transfer_domain, transfer_vm

    credentials = await _admin_credentials(admin_factory)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture'))
        session.add(AccountRow(account_id='HCCCCCCCCCC', password_hash='fixture'))
        session.add(VMRow(vm_id='vm_revoked_transfer', owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                          status='suspended', anon_management_token_hash='keep-vm-token'))
        session.add(DomainRow(name='transfer', extension='dev', fqdn='transfer.dev',
                              owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                              vm_id='vm_revoked_transfer', status='active',
                              anon_management_token_hash='keep-domain-token'))
    async with admin_factory.begin() as session:
        current = await session.get(AccountRow, actor.account_id)
        if revocation == 'disable':
            current.disabled_at = datetime.now(UTC)
        else:
            current.is_admin = False
    state = AppState(config=HyruleConfig(), orchestrator=None, payment_gate=None,
                     network_provider=None, session_factory=admin_factory)
    body = OwnershipTransferRequest(target_account_id='HCCCCCCCCCC', reason='fixture transfer')
    with pytest.raises(HTTPException) as refused:
        if resource == 'vm':
            await transfer_vm('vm_revoked_transfer', body, _browser_request(credentials, path='/fixture'), actor, state)
        else:
            await transfer_domain('transfer.dev', body, _browser_request(credentials, path='/fixture'), actor, state)
    assert refused.value.status_code == 403
    async with admin_factory() as session:
        vm = await session.get(VMRow, 'vm_revoked_transfer')
        domain = await session.scalar(select(DomainRow).where(DomainRow.fqdn == 'transfer.dev'))
        assert vm.owner_account_id == domain.owner_account_id == 'HBBBBBBBBBB'
        assert vm.anon_management_token_hash == 'keep-vm-token'
        assert domain.anon_management_token_hash == 'keep-domain-token'
        assert list(await session.scalars(select(AdminAuditRow))) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['start', 'reboot', 'shutdown', 'suspend'])
async def test_admin_power_rejects_committed_deletion_claim(admin_factory, action):
    from unittest.mock import AsyncMock

    credentials = await _admin_credentials(admin_factory)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(VMRow(vm_id='vm_power_claim', owner_wallet='fixture', status='suspended',
                          xcpng_uuid='claim-guest', expires_at=datetime.now(UTC) + timedelta(days=1),
                          deletion_started_at=datetime.now(UTC)))
    provider = SimpleNamespace(**{name: AsyncMock() for name in ('start_vm', 'reboot_vm', 'shutdown_vm', 'suspend_vm')})
    state = AppState(config=HyruleConfig(), orchestrator=SimpleNamespace(xcpng=provider), payment_gate=None,
                     network_provider=None, session_factory=admin_factory)
    with pytest.raises(HTTPException) as refused:
        await vm_action('vm_power_claim', action, ReasonRequest(reason='fixture claimed guest'),
                        _browser_request(credentials, path='/fixture'), actor, state)
    assert refused.value.status_code == 409
    for method in vars(provider).values():
        method.assert_not_awaited()
    async with admin_factory() as session:
        assert list(await session.scalars(select(AdminAuditRow))) == []
        assert (await session.get(VMRow, 'vm_power_claim')).status == 'suspended'


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['shutdown', 'suspend'])
async def test_admin_power_off_rejects_provisioning_guest(admin_factory, action):
    from unittest.mock import AsyncMock

    credentials = await _admin_credentials(admin_factory)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(VMRow(
            vm_id='vm_power_provisioning', owner_wallet='fixture',
            status='provisioning', xcpng_uuid='provisioning-guest',
            expires_at=datetime.now(UTC) + timedelta(days=1),
        ))
    provider = SimpleNamespace(**{
        name: AsyncMock()
        for name in ('start_vm', 'reboot_vm', 'shutdown_vm', 'suspend_vm')
    })
    state = AppState(
        config=HyruleConfig(),
        orchestrator=SimpleNamespace(xcpng=provider),
        payment_gate=None,
        network_provider=None,
        session_factory=admin_factory,
    )
    with pytest.raises(HTTPException) as refused:
        await vm_action(
            'vm_power_provisioning', action,
            ReasonRequest(reason='fixture power off'),
            _browser_request(credentials, path='/fixture'), actor, state,
        )
    assert refused.value.status_code == 409
    provider.shutdown_vm.assert_not_awaited()
    provider.suspend_vm.assert_not_awaited()
    async with admin_factory() as session:
        vm = await session.get(VMRow, 'vm_power_provisioning')
        assert vm.status == 'provisioning' and vm.suspension_reason is None
        assert list(await session.scalars(select(AdminAuditRow))) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['shutdown', 'suspend'])
async def test_power_off_keeps_failed_guest_terminal_across_account_enable(admin_factory, action):
    credentials = await _admin_credentials(admin_factory)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture'))
        session.add(VMRow(vm_id='vm_terminal_off', owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                          status='failed', suspension_reason='account_disabled', xcpng_uuid='failed-guest',
                          expires_at=datetime.now(UTC) + timedelta(days=1)))
        session.add(AdminOperationRow(operation_id='enable-failed', kind='resume_account_resources',
                                      account_id='HBBBBBBBBBB', status='running'))
    provider = _AdminXCPNG()
    provider.power["failed-guest"] = "Running"
    orch = SimpleNamespace(xcpng=provider)
    state = AppState(config=HyruleConfig(), orchestrator=orch, payment_gate=None,
                     network_provider=None, session_factory=admin_factory)
    await vm_action('vm_terminal_off', action, ReasonRequest(reason='stop failed guest'),
                    _browser_request(credentials, path='/fixture'), actor, state)
    await _apply_account_operation(admin_factory, orch, 'enable-failed')
    async with admin_factory() as session:
        vm = await session.get(VMRow, 'vm_terminal_off')
        assert vm.status == 'failed' and vm.suspension_reason is None
        assert vm.suspended_by_account_id is None
    assert provider.started == []
    assert (provider.shut_down if action == 'shutdown' else provider.suspended) == ['failed-guest']


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["provisioning", "suspended"])
@pytest.mark.parametrize("power", ["Running", "Halted", "Unknown"])
@pytest.mark.parametrize("reason", [None, "manual_admin", "expired"])
async def test_account_disable_reconciles_provider_guest(admin_factory, status, power, reason):
    async with admin_factory.begin() as session:
        session.add(AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture', disabled_at=datetime.now(UTC)))
        session.add(VMRow(vm_id='vm_initializing_disable', owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                          status=status, suspension_reason=reason, xcpng_uuid='initializing-guest'))
        session.add(AdminOperationRow(operation_id='disable-initializing', kind='suspend_account_resources',
                                      account_id='HBBBBBBBBBB', status='running'))
    provider = _AdminXCPNG()
    provider.power["initializing-guest"] = power
    if power == "Unknown":
        with pytest.raises(RuntimeError, match="unexpected VM power state"):
            await _apply_account_operation(admin_factory, SimpleNamespace(xcpng=provider), 'disable-initializing')
    else:
        await _apply_account_operation(admin_factory, SimpleNamespace(xcpng=provider), 'disable-initializing')
    assert provider.suspended == (['initializing-guest'] if power == "Running" else [])
    async with admin_factory() as session:
        vm = await session.get(VMRow, 'vm_initializing_disable')
        assert vm.status == status
        preserve_reason = power == 'Unknown' or (status == 'suspended' and reason is not None)
        assert vm.suspension_reason == (reason if preserve_reason else 'account_disabled')


@pytest.mark.asyncio
async def test_transfer_handoff_waits_for_recipient_reenable(admin_factory):
    async with admin_factory.begin() as session:
        session.add(AccountRow(account_id='HBBBBBBBBBB', password_hash='fixture', disabled_at=datetime.now(UTC)))
        session.add(VMRow(vm_id='vm_disabled_handoff', owner_wallet='fixture', owner_account_id='HBBBBBBBBBB',
                          status='suspended', xcpng_uuid='handoff-guest', suspension_reason='account_disabled',
                          expires_at=datetime.now(UTC) + timedelta(days=1),
                          metadata_={'transfer_resume_pending': {'owner_account_id': 'HBBBBBBBBBB'}}))
    provider = _AdminXCPNG()
    orch = Orchestrator(HyruleConfig(), admin_factory)
    orch.xcpng = provider
    assert not await orch.reconcile_transfer_resume('vm_disabled_handoff')
    assert provider.started == []
    async with admin_factory.begin() as session:
        row = await session.get(VMRow, 'vm_disabled_handoff')
        assert row.metadata_['transfer_resume_pending']
        owner = await session.get(AccountRow, 'HBBBBBBBBBB')
        owner.disabled_at = None
    assert await orch.reconcile_transfer_resume('vm_disabled_handoff')
    assert provider.started == ['handoff-guest']
    async with admin_factory() as session:
        row = await session.get(VMRow, 'vm_disabled_handoff')
        assert row.status == 'running'
        assert not (row.metadata_ or {}).get('transfer_resume_pending')


@pytest.mark.asyncio
@pytest.mark.parametrize('revoke_after', [1, 2])
async def test_recovery_rechecks_admin_after_committed_request(admin_factory, monkeypatch, revoke_after):
    from contextlib import asynccontextmanager
    from uuid import uuid4

    from hyrule_cloud.api import admin as admin_api
    from hyrule_cloud.db import VMRestoreRow, VMRetentionRow
    from hyrule_cloud.providers.xcpng import VMProtectionManifest
    from hyrule_cloud.services.vm_retention import prepare_retention

    credentials = await _admin_credentials(admin_factory)
    now = datetime.now(UTC)
    async with admin_factory.begin() as session:
        actor = await session.get(AccountRow, 'HAAAAAAAAAA')
        session.add(VMRow(vm_id='vm_revoked_recovery', owner_wallet='fixture', status='suspended',
                          xcpng_uuid='revoked-recovery-guest', expires_at=now - timedelta(days=3),
                          deletion_started_at=now))
    async with admin_factory.begin() as session:
        retained = await prepare_retention(session, 'vm_revoked_recovery',
                                          VMProtectionManifest('revoked-recovery-guest', ('disk',), (), False, '', ()),
                                          now + timedelta(days=30))
        retained.state = 'retained'
    original_lock = admin_api._locked_admin_vm
    calls = 0

    @asynccontextmanager
    async def revoke_after_acceptance(*args):
        nonlocal calls
        calls += 1
        async with original_lock(*args) as pair:
            yield pair
        if calls == revoke_after:
            async with admin_factory.begin() as session:
                current = await session.get(AccountRow, actor.account_id)
                current.is_admin = False

    monkeypatch.setattr(admin_api, '_locked_admin_vm', revoke_after_acceptance)
    provider = SimpleNamespace(restore_retained_vm=AsyncMock())
    state = AppState(config=HyruleConfig(), orchestrator=SimpleNamespace(xcpng=provider),
                     payment_gate=None, network_provider=None, session_factory=admin_factory)
    body = admin_api.RetainedRestoreRequest(operation_id=uuid4(), days=7, reason='fixture recovery')
    with pytest.raises(HTTPException) as refused:
        await admin_api.restore_retained_vm('vm_revoked_recovery', body,
                                           _browser_request(credentials, path='/fixture'), actor, state)
    assert refused.value.status_code == 403
    provider.restore_retained_vm.assert_not_awaited()
    async with admin_factory() as session:
        assert (await session.get(VMRestoreRow, str(body.operation_id))).state == ('pending' if revoke_after == 1 else 'authorized')
        assert (await session.get(VMRetentionRow, 'vm_revoked_recovery')).state == 'restoring'
        vm = await session.get(VMRow, 'vm_revoked_recovery')
        assert vm.deletion_started_at is not None
        assert (vm.expires_at.replace(tzinfo=UTC) < now) == (revoke_after == 1)
        audits = list(await session.scalars(select(AdminAuditRow).where(AdminAuditRow.target_id == vm.vm_id)))
        assert [audit.action for audit in audits] == (['vm.restore_requested'] if revoke_after == 1 else
                                                     ['vm.restore_requested', 'vm.restore_authorized'])
