from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import ValidationError
from sqlalchemy import select

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    Base,
    CryptoIntentRow,
    DomainDNSRecordRow,
    DomainJobRow,
    DomainOperationRow,
    DomainOrderRow,
    DomainQuoteRow,
    DomainRow,
    DomainTLDRow,
    PaymentEventRow,
    VMQuoteRow,
    VMRow,
    create_db_engine,
    create_session_factory,
)
from hyrule_cloud.domains.api import (
    _settle_x402_order,
)
from hyrule_cloud.domains.api import (
    get_operation as get_operation_route,
)
from hyrule_cloud.domains.catalog import parse_iana_root_db
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import (
    DNSChange,
    DNSChangeAction,
    DNSChangesetRequest,
    DNSRRSet,
    DNSSECMode,
    DNSSECUpdateRequest,
    DomainAction,
    DomainFailurePolicy,
    DomainOrderRequest,
    DomainOrderStatus,
    DomainPaymentMethod,
    LegacyDomainClaimRequest,
    ManagedRecordType,
    NameserverMode,
    NameserverUpdateRequest,
)
from hyrule_cloud.domains.pricing import price_domain
from hyrule_cloud.domains.service import DomainService
from hyrule_cloud.domains.validation import normalize_registrable_domain
from hyrule_cloud.domains.wallet_auth import (
    WalletAction,
    WalletAuthService,
    WalletChallengeRequest,
    WalletVerifyRequest,
)
from hyrule_cloud.models import (
    CryptoIntentStatus,
    DomainMode,
    QuoteStatus,
    VMCreateRequest,
    VMSize,
    VMStatus,
)
from hyrule_cloud.providers.openprovider import (
    OpenproviderClient,
    OpenproviderUnavailableError,
    _extract_product_price,
)
from hyrule_cloud.services.passwords import hash_password
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.services.refunds import RefundService

BTC_REFUND_ADDRESS = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
XMR_REFUND_ADDRESS = (
    "42Lxp5b63YJ8mVZTzcioVnCk9WQCPAMk4RH7e7ygPTkzEZhMuRMBPjF8u5PXzAzC"
    "PDViDAyJnBL5u5mc5QVGBZXF9ySeCtM"
)


class _Provider:
    def __init__(self) -> None:
        self.registration_nameservers: list[str] | None = None
        self.registrations: list[str] = []
        self.renewals: list[tuple[int, str, str, int]] = []

    async def check_domain(self, name, extension):
        return {
            "status": "free",
            "price_amount": Decimal("10"),
            "price_currency": "USD",
            "is_premium": False,
        }

    async def search_domain(self, name, extension):
        return None

    async def register_domain(self, name, extension, period=1, *, nameservers=None):
        self.registration_nameservers = nameservers
        self.registrations.append(f"{name}.{extension}")
        return {
            "id": 1234,
            "status": "ACT",
            "expiration_date": "2027-07-15T00:00:00Z",
        }

    async def update_nameservers(self, domain_id, nameservers):
        return {}

    async def set_dnssec_keys(self, domain_id, keys):
        return {}

    async def get_tld(self, extension):
        return {
            "name": extension,
            "prices": {
                "renew": {"price": "10", "currency": "USD"},
            },
        }

    async def get_domain(self, domain_id):
        return {
            "id": domain_id,
            "status": "ACT",
            "expiration_date": (datetime.now(UTC) + timedelta(days=20)).isoformat(),
        }

    async def renew_domain(self, domain_id, *, name, extension, period=1):
        self.renewals.append((domain_id, name, extension, period))
        return {
            "id": domain_id,
            "status": "ACT",
            "expiration_date": (datetime.now(UTC) + timedelta(days=385)).isoformat(),
        }


class _AmbiguousRegistrationProvider(_Provider):
    def __init__(self) -> None:
        super().__init__()
        self.visible_domain: dict | None = None

    async def search_domain(self, name, extension):
        return self.visible_domain

    async def register_domain(self, name, extension, period=1, *, nameservers=None):
        self.registration_nameservers = nameservers
        self.registrations.append(f"{name}.{extension}")
        raise OpenproviderUnavailableError(
            "registrar_timeout",
            "The registrar accepted the request but its response timed out.",
            retryable=True,
        )


class _Rates:
    async def get_usd_per_fiat(self, currency):
        assert currency == "USD"
        return Decimal("1")


class _DNS:
    configured = True

    def __init__(self) -> None:
        self.zones: dict[str, dict] = {}

    async def apply_zone(self, zone, *, revision, records):
        self.zones[zone] = {"revision": revision, "records": records}
        return {}

    async def dnssec_keys(self, zone):
        return [{"flags": 257, "protocol": 3, "alg": 13, "pub_key": "AA=="}]

    async def close(self):
        return None


class _Orchestrator:
    def __init__(self, sessions) -> None:
        self.refunds = RefundService(PaymentLedger(sessions))
        self.started_vms: list[str] = []

    def start_provisioning(self, vm_id: str) -> None:
        self.started_vms.append(vm_id)


def _bundle_spec(fqdn: str) -> VMCreateRequest:
    return VMCreateRequest(
        duration_days=30,
        size=VMSize.XS,
        os="debian-13",
        ssh_pubkey="ssh-ed25519 AAAA domain-bundle-test",
        domain_mode=DomainMode.CUSTOM,
        domain=fqdn,
        open_ports=[80, 443],
    )


@pytest_asyncio.fixture
async def domain_service(tmp_path):
    engine = create_db_engine(f"sqlite+aiosqlite:///{tmp_path / 'domains.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = create_session_factory(engine)
    config = HyruleConfig(database_url=f"sqlite+aiosqlite:///{tmp_path / 'domains.db'}")
    config.domain.purchases_enabled = True
    config.domain.agent_purchases_enabled = True
    config.domain.legal_approved = True
    config.domain.tax_approved = True
    config.domain.agent_order_fernet_key = Fernet.generate_key().decode()
    config.openprovider.username = "user"
    config.openprovider.password = "password"
    config.openprovider.owner_handle = "owner"
    config.openprovider.admin_handle = "admin"
    config.openprovider.tech_handle = "tech"
    config.openprovider.billing_handle = "billing"
    provider = _Provider()
    service = DomainService(
        config,
        sessions,
        provider,
        _Rates(),
        SimpleNamespace(),
        _Orchestrator(sessions),
    )
    await service.dns.close()
    service.dns = _DNS()
    async with sessions() as session:
        session.add(
            AccountRow(
                account_id="H1234567890",
                password_hash=hash_password("a sufficiently long test password"),
            )
        )
        session.add(
            DomainTLDRow(
                tld="dev",
                iana_type="generic",
                provider_status="ACT",
                eligible=True,
                registration_cost=Decimal("10"),
                renewal_cost=Decimal("10"),
                currency="USD",
                metadata_={},
                refreshed_at=datetime.now(UTC),
            )
        )
        await session.commit()
    yield service, provider, sessions
    await service.close()
    await engine.dispose()


def test_ascii_second_level_validation_and_pricing():
    assert normalize_registrable_domain("Example.DEV.") == ("example", "dev", "example.dev")
    with pytest.raises(DomainProblem) as nested:
        normalize_registrable_domain("www.example.dev")
    assert nested.value.code == "invalid_domain"
    with pytest.raises(DomainProblem) as idn:
        normalize_registrable_domain("münchen.dev")
    assert idn.value.code == "idn_not_supported"

    config = HyruleConfig().domain
    assert price_domain(Decimal("4"), Decimal("1"), config)[3] == Decimal("7.00")
    assert price_domain(Decimal("20"), Decimal("1"), config)[3] == Decimal("25.00")


def test_domain_api_persists_settlement_state_around_the_facilitator_call() -> None:
    source = inspect.getsource(_settle_x402_order)
    settlement = source.index("settle_verified")
    durable = source.index("record_x402_settlement", settlement)
    handoff = source.index("mark_x402_paid", durable)
    assert source.index("begin_x402_settlement") < settlement
    assert settlement < durable < handoff


def test_native_refund_addresses_are_validated_for_the_selected_asset() -> None:
    btc = DomainOrderRequest(
        quote_id="dq_refund_validation",
        payment_method=DomainPaymentMethod.BTC,
        refund_address=f"  {BTC_REFUND_ADDRESS}  ",
        terms_version="v1",
    )
    assert btc.refund_address == BTC_REFUND_ADDRESS
    xmr = DomainOrderRequest(
        quote_id="dq_refund_validation",
        payment_method=DomainPaymentMethod.XMR,
        refund_address=XMR_REFUND_ADDRESS,
        terms_version="v1",
    )
    assert xmr.refund_address == XMR_REFUND_ADDRESS

    with pytest.raises(ValidationError, match="valid BTC mainnet address"):
        DomainOrderRequest(
            quote_id="dq_refund_validation",
            payment_method=DomainPaymentMethod.BTC,
            refund_address="not-a-real-address",
            terms_version="v1",
        )
    with pytest.raises(ValidationError, match="valid XMR mainnet address"):
        DomainOrderRequest(
            quote_id="dq_refund_validation",
            payment_method=DomainPaymentMethod.XMR,
            refund_address=BTC_REFUND_ADDRESS,
            terms_version="v1",
        )


def test_iana_parser_preserves_exact_tld_type():
    parsed = parse_iana_root_db(
        "<table><tr><td>.dev</td><td>generic</td></tr>"
        "<tr><td>.uk</td><td>country-code</td></tr></table>"
    )
    assert parsed == {"dev": "generic", "uk": "country-code"}


@pytest.mark.asyncio
async def test_domain_purchase_launch_requires_every_approval(domain_service):
    service, _provider, _sessions = domain_service
    service.domain_config.purchases_enabled = False
    with pytest.raises(DomainProblem) as purchases:
        service.require_purchase_launch("H1234567890")
    assert purchases.value.code == "purchases_disabled"

    service.domain_config.purchases_enabled = True
    service.domain_config.legal_approved = False
    with pytest.raises(DomainProblem) as legal:
        service.require_purchase_launch("H1234567890")
    assert legal.value.code == "launch_approval_pending"

    service.domain_config.legal_approved = True
    service.domain_config.tax_approved = False
    with pytest.raises(DomainProblem) as tax:
        service.require_purchase_launch("H1234567890")
    assert tax.value.code == "launch_approval_pending"


@pytest.mark.asyncio
async def test_wallet_native_agent_can_buy_and_poll_domain_without_account(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("autonomous-agent.dev", DomainAction.REGISTER, None)
    order, token, created = await service.create_agent_order(
        quote_id=quote.quote_id,
        terms_version=service.domain_config.terms_version,
        idempotency_key="autonomous-agent-domain-idempotency-0001",
    )
    replay, replay_token, replay_created = await service.create_agent_order(
        quote_id=quote.quote_id,
        terms_version=service.domain_config.terms_version,
        idempotency_key="autonomous-agent-domain-idempotency-0001",
    )
    assert created is True
    assert replay_created is False
    assert replay.order_id == order.order_id
    assert replay_token == token
    assert token.startswith("hyr_dom_")
    assert order.owner_account_id is None
    with pytest.raises(DomainProblem) as hidden:
        await service.get_agent_order(order.order_id, "hyr_dom_" + "x" * 43)
    assert hidden.value.code == "order_not_found"

    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "5" * 40,
        tx_hash="0xagent-domain",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    assert await service.process_jobs(worker_id="agent-domain-test") == 1
    polled = await service.get_agent_order(order.order_id, token)
    assert polled.status.value == "active"
    assert polled.management_token is None
    async with sessions() as session:
        domain = await session.scalar(
            select(DomainRow).where(DomainRow.fqdn == "autonomous-agent.dev")
        )
    assert domain is not None
    assert domain.owner_account_id is None
    assert domain.anon_management_token_hash


def test_combined_identity_token_can_claim_its_purchased_domain() -> None:
    token = "hyr_identity_" + "x" * 43
    assert LegacyDomainClaimRequest(token=token).token == token


@pytest.mark.asyncio
async def test_combined_payment_recovers_domain_expired_during_handoff_grace(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("late-combined.dev", DomainAction.REGISTER, None)
    order, _token, _created = await service.create_agent_order(
        quote_id=quote.quote_id,
        terms_version=service.domain_config.terms_version,
        idempotency_key="late-combined-domain-idempotency-0001",
        additional_amount_usd=Decimal("1.00"),
        management_token="hyr_identity_" + "y" * 43,
    )
    async with sessions() as session:
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
        stored_order = await session.get(DomainOrderRow, order.order_id)
        stored_quote.status = "expired"
        stored_quote.expires_at = datetime.now(UTC) - timedelta(minutes=30)
        stored_order.status = DomainOrderStatus.EXPIRED.value
        stored_order.error_code = "quote_expired"
        await session.commit()

    recovered = await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "7" * 40,
        tx_hash="0xlate-combined",
        payment_network="eip155:8453",
        payment_asset="USDC",
        payment_handoff_grace=timedelta(hours=1),
    )

    assert recovered.status == DomainOrderStatus.QUEUED.value
    async with sessions() as session:
        consumed_quote = await session.get(DomainQuoteRow, quote.quote_id)
        refund = await session.scalar(
            select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
        )
        assert consumed_quote.status == "consumed"
        assert refund is None


@pytest.mark.asyncio
async def test_combined_payment_after_handoff_grace_records_full_refund(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("late-refund.dev", DomainAction.REGISTER, None)
    order, _token, _created = await service.create_agent_order(
        quote_id=quote.quote_id,
        terms_version=service.domain_config.terms_version,
        idempotency_key="late-combined-domain-refund-idempotency-0001",
        additional_amount_usd=Decimal("1.00"),
        management_token="hyr_identity_" + "z" * 43,
    )
    async with sessions() as session:
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
        stored_order = await session.get(DomainOrderRow, order.order_id)
        stored_quote.status = "expired"
        stored_quote.expires_at = datetime.now(UTC) - timedelta(hours=2)
        stored_order.status = DomainOrderStatus.EXPIRED.value
        stored_order.error_code = "quote_expired"
        await session.commit()

    terminal = await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "8" * 40,
        tx_hash="0xlate-combined-refund",
        payment_network="eip155:8453",
        payment_asset="USDC",
        payment_handoff_grace=timedelta(hours=1),
    )

    assert terminal.status == DomainOrderStatus.REFUND_DUE.value
    async with sessions() as session:
        refund = await session.scalar(
            select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
        )
        assert refund is not None
        assert Decimal(refund.amount_usd) == Decimal(order.amount_usd)
        assert refund.tx_hash == "0xlate-combined-refund"


@pytest.mark.asyncio
async def test_paid_order_is_idempotent_and_fulfills_through_outbox(domain_service):
    service, provider, sessions = domain_service
    quote = await service.create_quote("example.dev", DomainAction.REGISTER, "H1234567890")
    assert quote.price.total_usd == "13.00"
    request = DomainOrderRequest(
        quote_id=quote.quote_id,
        payment_method=DomainPaymentMethod.USDC,
        terms_version=service.domain_config.terms_version,
    )
    order, created = await service.create_order(
        request,
        owner_account_id="H1234567890",
        idempotency_key="checkout-1",
    )
    replay, replay_created = await service.create_order(
        request,
        owner_account_id="H1234567890",
        idempotency_key="checkout-1",
    )
    assert created is True
    assert replay_created is False
    assert replay.order_id == order.order_id
    with pytest.raises(DomainProblem) as rebound:
        await service.create_order(
            request.model_copy(update={"on_domain_failure": DomainFailurePolicy.CANCEL_BUNDLE}),
            owner_account_id="H1234567890",
            idempotency_key="checkout-1",
        )
    assert rebound.value.code == "idempotency_conflict"

    await service.mark_x402_paid(order.order_id, payer="0x" + "1" * 40, tx_hash="0xtx")
    async with sessions() as session:
        jobs = list(await session.scalars(select(DomainJobRow)))
        assert len(jobs) == 1
    assert await service.process_jobs(worker_id="test") == 1

    async with sessions() as session:
        stored_order = await session.get(DomainOrderRow, order.order_id)
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "example.dev"))
        ).scalar_one()
    assert stored_order.status == "active"
    assert str(domain.status) == "active"
    assert domain.nameservers == ["ns1.hyrule.host", "ns2.hyrule.host"]
    assert domain.dnssec_status == "active"
    assert provider.registration_nameservers == ["ns1.hyrule.host", "ns2.hyrule.host"]


@pytest.mark.asyncio
async def test_pending_registration_schedules_prompt_reconciliation(domain_service):
    service, provider, sessions = domain_service
    provider.register_domain = AsyncMock(
        return_value={
            "id": 1234,
            "status": "PEN",
            "expiration_date": "2027-07-15T00:00:00Z",
        }
    )
    provider.get_domain = AsyncMock(
        side_effect=[
            {
                "id": 1234,
                "status": "PEN",
                "expiration_date": "2027-07-15T00:00:00Z",
            },
            {
                "id": 1234,
                "status": "ACT",
                "expiration_date": "2027-07-15T00:00:00Z",
            },
        ]
    )
    quote = await service.create_quote(
        "pending-registration.dev", DomainAction.REGISTER, "H1234567890"
    )
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="pending-registration",
    )
    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "1" * 40,
        tx_hash="0xpending-registration",
    )

    assert await service.process_jobs(worker_id="test") == 1
    async with sessions() as session:
        pending_order = await session.get(DomainOrderRow, order.order_id)
        reconcile = (
            await session.execute(
                select(DomainJobRow).where(
                    DomainJobRow.dedupe_key == f"provider-pending:{order.order_id}"
                )
            )
        ).scalar_one()
    assert pending_order is not None and pending_order.status == "provider_pending"
    assert reconcile.status == "queued"
    assert reconcile.available_at.replace(tzinfo=UTC) > datetime.now(UTC)

    async with sessions() as session:
        reconcile = await session.get(DomainJobRow, reconcile.job_id)
        assert reconcile is not None
        reconcile.available_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        retry = await session.get(DomainJobRow, reconcile.job_id)
    assert retry is not None and retry.status == "queued" and retry.attempts == 1

    async with sessions() as session:
        retry = await session.get(DomainJobRow, reconcile.job_id)
        assert retry is not None
        retry.available_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        active_order = await session.get(DomainOrderRow, order.order_id)
        active_domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "pending-registration.dev")
            )
        ).scalar_one()
    assert active_order is not None and active_order.status == "active"
    assert str(active_domain.status) == "active"


@pytest.mark.asyncio
async def test_terminal_pending_registration_creates_refund_obligation(domain_service):
    service, provider, sessions = domain_service
    provider.register_domain = AsyncMock(
        return_value={
            "id": 1234,
            "status": "PEN",
            "expiration_date": "2027-07-15T00:00:00Z",
        }
    )
    provider.get_domain = AsyncMock(
        return_value={
            "id": 1234,
            "status": "EXP",
            "expiration_date": "2026-07-15T00:00:00Z",
        }
    )
    quote = await service.create_quote(
        "terminal-registration.dev", DomainAction.REGISTER, "H1234567890"
    )
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="terminal-registration",
    )
    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "1" * 40,
        tx_hash="0xterminal-registration",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )

    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        reconcile = (
            await session.execute(
                select(DomainJobRow).where(
                    DomainJobRow.dedupe_key == f"provider-pending:{order.order_id}"
                )
            )
        ).scalar_one()
        reconcile.available_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        failed_order = await session.get(DomainOrderRow, order.order_id)
        assert failed_order is not None
        operation = await session.get(DomainOperationRow, failed_order.operation_id)
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "terminal-registration.dev")
            )
        ).scalar_one()
        refunds = list(
            await session.scalars(
                select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
            )
        )
    assert failed_order.status == "refund_due"
    assert failed_order.error_code == "registrar_terminal_status"
    assert failed_order.provider_status == "EXP"
    assert operation is not None and operation.status == "failed"
    assert str(domain.status) == "expired"
    assert domain.can_renew is False
    assert len(refunds) == 1
    assert refunds[0].amount_usd == order.amount_usd
    assert refunds[0].extra["order_id"] == order.order_id
    assert await service.reconcile_pending() == 0


@pytest.mark.asyncio
async def test_domain_quote_is_reserved_before_payment(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("single-order.dev", DomainAction.REGISTER, "H1234567890")
    request = DomainOrderRequest(
        quote_id=quote.quote_id,
        payment_method=DomainPaymentMethod.USDC,
        terms_version=service.domain_config.terms_version,
    )
    order, _ = await service.create_order(
        request,
        owner_account_id="H1234567890",
        idempotency_key="single-order-first",
    )

    with pytest.raises(DomainProblem) as second:
        await service.create_order(
            request,
            owner_account_id="H1234567890",
            idempotency_key="single-order-second",
        )
    assert second.value.code == "quote_unavailable"
    async with sessions() as session:
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
    assert stored_quote is not None and stored_quote.status == "reserved"

    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "1" * 40,
        tx_hash="0xsingle",
    )
    async with sessions() as session:
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
    assert stored_quote is not None and stored_quote.status == "consumed"


@pytest.mark.asyncio
async def test_native_domain_intent_expires_with_its_quote(domain_service):
    service, _provider, sessions = domain_service

    async def usd_per(asset: str) -> Decimal:
        assert asset == "BTC"
        return Decimal("60000")

    service.rates.get_usd_per = usd_per
    service.native_crypto.derive_btc_address = lambda _index: BTC_REFUND_ADDRESS
    quote = await service.create_quote("native-window.dev", DomainAction.REGISTER, "H1234567890")
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.BTC,
            refund_address=BTC_REFUND_ADDRESS,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="native-window",
    )

    async with sessions() as session:
        intent = await session.get(CryptoIntentRow, order.native_intent_id)
    assert intent is not None
    assert intent.expires_at.replace(tzinfo=UTC) == quote.expires_at


@pytest.mark.asyncio
async def test_renewal_order_rejects_vm_bundle(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("renew-no-bundle.dev", DomainAction.REGISTER, "H1234567890")
    async with sessions() as session:
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
        assert stored_quote is not None
        stored_quote.action = DomainAction.RENEW.value
        await session.commit()

    with pytest.raises(DomainProblem) as rejected:
        await service.create_order(
            DomainOrderRequest(
                quote_id=quote.quote_id,
                payment_method=DomainPaymentMethod.USDC,
                terms_version=service.domain_config.terms_version,
                vm_quote_id="vmq_not_allowed",
            ),
            owner_account_id="H1234567890",
            idempotency_key="renew-no-bundle",
        )
    assert rejected.value.code == "bundle_not_supported"


@pytest.mark.asyncio
async def test_openprovider_renew_payload_includes_domain_identity() -> None:
    client = OpenproviderClient(HyruleConfig().openprovider)
    request = AsyncMock(return_value={"status": "ACT"})
    client._request = request
    try:
        await client.renew_domain(
            123456,
            name="renew-me",
            extension="dev",
            period=2,
        )
    finally:
        await client.close()

    request.assert_awaited_once_with(
        "POST",
        "/domains/123456/renew",
        json={
            "domain": {"name": "renew-me", "extension": "dev"},
            "period": 2,
        },
    )


@pytest.mark.asyncio
async def test_renewal_service_passes_domain_identity_to_registrar(domain_service):
    service, provider, sessions = domain_service
    now = datetime.now(UTC)
    old_expiry = now + timedelta(days=20)
    renewed_expiry = now + timedelta(days=385)
    provider.get_domain = AsyncMock(
        side_effect=[
            {"id": 123456, "status": "ACT", "expiration_date": old_expiry.isoformat()},
            {"id": 123456, "status": "PEN", "expiration_date": old_expiry.isoformat()},
            {
                "id": 123456,
                "status": "ACT",
                "expiration_date": renewed_expiry.isoformat(),
            },
        ]
    )
    provider.renew_domain = AsyncMock(
        return_value={
            "id": 123456,
            "status": "PEN",
            "expiration_date": old_expiry.isoformat(),
        }
    )
    async with sessions() as session:
        session.add_all(
            [
                DomainQuoteRow(
                    quote_id="dq_renew_payload",
                    fqdn="renew-payload.dev",
                    action="renew",
                    owner_account_id="H1234567890",
                    status="consumed",
                    provider_cost=Decimal("10"),
                    provider_currency="USD",
                    fx_rate=Decimal("1"),
                    provider_cost_usd=Decimal("10"),
                    hyrule_fee_usd=Decimal("3"),
                    tax_usd=Decimal("0"),
                    total_usd=Decimal("13"),
                    available=True,
                    premium=False,
                    terms_version=service.domain_config.terms_version,
                    expires_at=now + timedelta(minutes=15),
                ),
                DomainRow(
                    name="renew-payload",
                    extension="dev",
                    fqdn="renew-payload.dev",
                    owner_wallet="0x" + "1" * 40,
                    owner_account_id="H1234567890",
                    status="renewal_due",
                    openprovider_id=123456,
                    nameserver_mode="managed",
                    nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                    dnssec_mode="managed",
                    dnssec_status="active",
                    expires_at=old_expiry,
                    can_renew=True,
                ),
                DomainOrderRow(
                    order_id="do_renew_payload",
                    quote_id="dq_renew_payload",
                    fqdn="renew-payload.dev",
                    action="renew",
                    owner_account_id="H1234567890",
                    idempotency_key="renew-payload",
                    status="queued",
                    amount_usd=Decimal("13"),
                    domain_amount_usd=Decimal("13"),
                    vm_amount_usd=Decimal("0"),
                    payment_method="usdc",
                    on_domain_failure="keep_vm",
                    terms_version=service.domain_config.terms_version,
                    terms_accepted_at=now,
                ),
            ]
        )
        await session.commit()

    await service._fulfill_renewal("do_renew_payload")

    provider.renew_domain.assert_awaited_once_with(
        123456,
        name="renew-payload",
        extension="dev",
        period=1,
    )
    async with sessions() as session:
        pending_order = await session.get(DomainOrderRow, "do_renew_payload")
        reconcile = (
            await session.execute(
                select(DomainJobRow).where(
                    DomainJobRow.dedupe_key == "provider-pending:do_renew_payload"
                )
            )
        ).scalar_one()
    assert pending_order is not None and pending_order.status == "provider_pending"
    assert reconcile.status == "queued"
    assert reconcile.available_at.replace(tzinfo=UTC) > datetime.now(UTC)

    async with sessions() as session:
        reconcile = await session.get(DomainJobRow, reconcile.job_id)
        assert reconcile is not None
        reconcile.available_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        retry = await session.get(DomainJobRow, reconcile.job_id)
        order_after_pending_poll = await session.get(DomainOrderRow, "do_renew_payload")
    assert retry is not None and retry.status == "queued" and retry.attempts == 1
    assert order_after_pending_poll is not None
    assert order_after_pending_poll.provider_response is not None
    assert "_hyrule_renewal_baseline" in order_after_pending_poll.provider_response

    async with sessions() as session:
        retry = await session.get(DomainJobRow, reconcile.job_id)
        assert retry is not None
        retry.available_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        active_order = await session.get(DomainOrderRow, "do_renew_payload")
        renewed_domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "renew-payload.dev"))
        ).scalar_one()
    assert active_order is not None and active_order.status == "active"
    assert renewed_domain.expires_at.replace(tzinfo=UTC) == renewed_expiry


@pytest.mark.asyncio
async def test_terminal_pending_renewal_creates_refund_obligation(domain_service):
    service, provider, sessions = domain_service
    old_expiry = datetime.now(UTC) + timedelta(days=20)
    provider.get_domain = AsyncMock(
        side_effect=[
            {"id": 7654, "status": "ACT", "expiration_date": old_expiry.isoformat()},
            {"id": 7654, "status": "EXP", "expiration_date": old_expiry.isoformat()},
        ]
    )
    provider.renew_domain = AsyncMock(
        return_value={
            "id": 7654,
            "status": "PEN",
            "expiration_date": old_expiry.isoformat(),
        }
    )
    async with sessions() as session:
        session.add(
            DomainRow(
                name="terminal-renewal",
                extension="dev",
                fqdn="terminal-renewal.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="renewal_due",
                openprovider_id=7654,
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
                expires_at=old_expiry,
                can_renew=True,
            )
        )
        await session.commit()
    quote = await service.create_quote("terminal-renewal.dev", DomainAction.RENEW, "H1234567890")
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="terminal-renewal",
    )
    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "1" * 40,
        tx_hash="0xterminal-renewal",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )

    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        reconcile = (
            await session.execute(
                select(DomainJobRow).where(
                    DomainJobRow.dedupe_key == f"provider-pending:{order.order_id}"
                )
            )
        ).scalar_one()
        reconcile.available_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        failed_order = await session.get(DomainOrderRow, order.order_id)
        assert failed_order is not None
        operation = await session.get(DomainOperationRow, failed_order.operation_id)
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "terminal-renewal.dev"))
        ).scalar_one()
        refunds = list(
            await session.scalars(
                select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
            )
        )
    assert failed_order.status == "refund_due"
    assert failed_order.error_code == "registrar_terminal_status"
    assert failed_order.provider_status == "EXP"
    assert operation is not None and operation.status == "failed"
    assert str(domain.status) == "expired"
    assert domain.can_renew is False
    assert len(refunds) == 1
    assert refunds[0].amount_usd == order.amount_usd
    assert refunds[0].extra["order_id"] == order.order_id


@pytest.mark.asyncio
async def test_ambiguous_registration_is_reconciled_without_refund(domain_service):
    service, _provider, sessions = domain_service
    provider = _AmbiguousRegistrationProvider()
    service.provider = provider
    service.catalog.provider = provider
    quote = await service.create_quote(
        "eventually-visible.dev", DomainAction.REGISTER, "H1234567890"
    )
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="ambiguous-registration",
    )
    await service.mark_x402_paid(order.order_id, payer="0x" + "1" * 40, tx_hash="0xlate")
    async with sessions() as session:
        job = (await session.scalars(select(DomainJobRow))).one()
        job.attempts = 9
        await session.commit()

    assert await service.process_jobs(worker_id="test") == 1
    async with sessions() as session:
        pending_order = await session.get(DomainOrderRow, order.order_id)
        pending_domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "eventually-visible.dev")
            )
        ).scalar_one()
    assert pending_order.status == "provider_pending"
    assert pending_order.error_code == "registration_reconciliation_required"
    assert str(pending_domain.status) == "provider_pending"
    assert pending_domain.openprovider_id is None
    assert pending_domain.provider_operation_id == f"register:{order.order_id}"

    assert await service.reconcile_pending() == 1
    assert await service.reconcile_pending() == 0
    provider.visible_domain = {
        "id": 4321,
        "status": "ACT",
        "expiration_date": "2027-07-15T00:00:00Z",
    }
    assert await service.process_jobs(worker_id="test") == 1

    async with sessions() as session:
        active_order = await session.get(DomainOrderRow, order.order_id)
        active_domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "eventually-visible.dev")
            )
        ).scalar_one()
    assert active_order.status == "active"
    assert str(active_domain.status) == "active"
    assert active_domain.openprovider_id == 4321


@pytest.mark.asyncio
async def test_failed_unregistered_domain_row_is_rebound_to_later_order(domain_service):
    service, provider, sessions = domain_service
    first_quote = await service.create_quote(
        "retry-registration.dev",
        DomainAction.REGISTER,
        "H1234567890",
    )
    first_order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=first_quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="retry-registration-first",
    )
    await service.mark_x402_paid(
        first_order.order_id,
        payer="0x" + "1" * 40,
        tx_hash="0xretry-first",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    async with sessions() as session:
        stored_order = await session.get(DomainOrderRow, first_order.order_id)
        stored_quote = await session.get(DomainQuoteRow, first_quote.quote_id)
    assert stored_order is not None and stored_quote is not None
    reserved = await service._reserve_registration_domain(
        stored_order,
        stored_quote,
        "retry-registration",
        "dev",
    )
    assert reserved is not None
    await service._fail_paid_order(
        first_order.order_id,
        "price_increased",
        "The registrar price increased after payment.",
    )

    second_quote = await service.create_quote(
        "retry-registration.dev",
        DomainAction.REGISTER,
        "H1234567890",
    )
    second_order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=second_quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="retry-registration-second",
    )
    await service.mark_x402_paid(
        second_order.order_id,
        payer="0x" + "2" * 40,
        tx_hash="0xretry-second",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )

    await service._fulfill_registration(second_order.order_id)

    async with sessions() as session:
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "retry-registration.dev")
            )
        ).scalar_one()
        first = await session.get(DomainOrderRow, first_order.order_id)
        second = await session.get(DomainOrderRow, second_order.order_id)
    assert domain.client_order_id == second_order.order_id
    assert domain.openprovider_id == 1234
    assert str(domain.status) == "active"
    assert first is not None and first.status == "refund_due"
    assert second is not None and second.status == "active"
    assert provider.registrations == ["retry-registration.dev"]


@pytest.mark.asyncio
async def test_terminal_fulfillment_failure_updates_order_operation(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("renew-failure.dev", DomainAction.REGISTER, "H1234567890")
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="renew-failure",
    )
    await service.mark_x402_paid(order.order_id, payer="0x" + "1" * 40, tx_hash="0xrenew")
    async with sessions() as session:
        current = await session.get(DomainOrderRow, order.order_id)
        assert current is not None and current.operation_id is not None
        current.action = DomainAction.RENEW.value
        session.add(
            DomainRow(
                name="renew-failure",
                extension="dev",
                fqdn="renew-failure.dev",
                owner_wallet=current.payer or current.order_id,
                owner_account_id="H1234567890",
                status="active",
                openprovider_id=777,
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        job = (
            await session.execute(
                select(DomainJobRow).where(DomainJobRow.resource_id == order.order_id)
            )
        ).scalar_one()
        job.attempts = 10
        operation_id = current.operation_id
        await session.commit()

    await service._retry_or_fail_job(
        job.job_id,
        DomainProblem(422, "renewal_rejected", "Registrar rejected renewal."),
    )

    async with sessions() as session:
        operation = await session.get(DomainOperationRow, operation_id)
        current = await session.get(DomainOrderRow, order.order_id)
    assert operation is not None and operation.status == "failed"
    assert current is not None and current.status == "provider_pending"


@pytest.mark.asyncio
async def test_dns_changeset_uses_optimistic_revision(domain_service):
    service, _provider, sessions = domain_service
    async with sessions() as session:
        session.add(
            DomainRow(
                name="zone",
                extension="dev",
                fqdn="zone.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        await session.commit()
    changes = DNSChangesetRequest(
        changes=[
            DNSChange(
                action=DNSChangeAction.UPSERT,
                rrset=DNSRRSet(
                    name="www",
                    type=ManagedRecordType.AAAA,
                    ttl=300,
                    values=["2001:db8::1"],
                ),
            )
        ]
    )
    result = await service.apply_changeset(
        "H1234567890",
        "zone.dev",
        1,
        changes,
        idempotency_key="dns-change-1",
    )
    assert result.revision == 2
    assert result.records[0].values == ["2001:db8::1"]
    replay = await service.apply_changeset(
        "H1234567890",
        "zone.dev",
        1,
        changes,
        idempotency_key="dns-change-1",
    )
    assert replay == result
    with pytest.raises(DomainProblem) as stale:
        await service.apply_changeset(
            "H1234567890",
            "zone.dev",
            1,
            changes,
            idempotency_key="dns-change-2",
        )
    assert stale.value.status == 412


@pytest.mark.asyncio
async def test_dns_changeset_cannot_modify_service_owned_rrsets(domain_service):
    service, _provider, sessions = domain_service
    async with sessions() as session:
        session.add(
            DomainRow(
                name="service-owned",
                extension="dev",
                fqdn="service-owned.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        session.add(
            DomainDNSRecordRow(
                fqdn="service-owned.dev",
                name="mail",
                type="A",
                ttl=300,
                values=["192.0.2.10"],
                managed_by="agent_mail",
            )
        )
        await session.commit()

    for index, action in enumerate((DNSChangeAction.DELETE, DNSChangeAction.UPSERT), start=1):
        with pytest.raises(DomainProblem) as managed:
            await service.apply_changeset(
                "H1234567890",
                "service-owned.dev",
                1,
                DNSChangesetRequest(
                    changes=[
                        DNSChange(
                            action=action,
                            rrset=DNSRRSet(
                                name="mail",
                                type=ManagedRecordType.A,
                                ttl=300,
                                values=["192.0.2.20"],
                            ),
                        )
                    ]
                ),
                idempotency_key=f"service-owned-change-{index}",
            )
        assert managed.value.status == 409
        assert managed.value.code == "service_dns_record_managed"

    async with sessions() as session:
        record = await session.scalar(
            select(DomainDNSRecordRow).where(
                DomainDNSRecordRow.fqdn == "service-owned.dev",
                DomainDNSRecordRow.name == "mail",
                DomainDNSRecordRow.type == "A",
            )
        )
        assert record.values == ["192.0.2.10"]
        assert record.managed_by == "agent_mail"
    assert service.dns.zones == {}


def test_domain_order_payment_asset_accepts_evm_token_addresses():
    assert DomainOrderRow.__table__.c.payment_asset.type.length == 66


@pytest.mark.asyncio
async def test_dns_changeset_rejects_cname_owner_conflicts(domain_service):
    service, _provider, sessions = domain_service
    async with sessions() as session:
        session.add(
            DomainRow(
                name="cname-conflict",
                extension="dev",
                fqdn="cname-conflict.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        session.add(
            DomainDNSRecordRow(
                fqdn="cname-conflict.dev",
                name="www",
                type="A",
                ttl=300,
                values=["192.0.2.1"],
            )
        )
        await session.commit()

    conflicts = [
        DNSChangesetRequest(
            changes=[
                DNSChange(
                    action=DNSChangeAction.UPSERT,
                    rrset=DNSRRSet(
                        name="www.cname-conflict.dev",
                        type=ManagedRecordType.CNAME,
                        ttl=300,
                        values=["target.cname-conflict.dev."],
                    ),
                )
            ]
        ),
        DNSChangesetRequest(
            changes=[
                DNSChange(
                    action=DNSChangeAction.UPSERT,
                    rrset=DNSRRSet(
                        name="api",
                        type=ManagedRecordType.CNAME,
                        ttl=300,
                        values=["target.cname-conflict.dev."],
                    ),
                ),
                DNSChange(
                    action=DNSChangeAction.UPSERT,
                    rrset=DNSRRSet(
                        name="api",
                        type=ManagedRecordType.AAAA,
                        ttl=300,
                        values=["2001:db8::1"],
                    ),
                ),
            ]
        ),
    ]
    for index, changes in enumerate(conflicts, start=1):
        with pytest.raises(DomainProblem) as conflict:
            await service.apply_changeset(
                "H1234567890",
                "cname-conflict.dev",
                1,
                changes,
                idempotency_key=f"cname-conflict-{index}",
            )
        assert conflict.value.status == 422
        assert conflict.value.code == "cname_conflict"
    assert service.dns.zones == {}

    replacement = await service.apply_changeset(
        "H1234567890",
        "cname-conflict.dev",
        1,
        DNSChangesetRequest(
            changes=[
                DNSChange(
                    action=DNSChangeAction.DELETE,
                    rrset=DNSRRSet(
                        name="www",
                        type=ManagedRecordType.A,
                        ttl=300,
                        values=["192.0.2.1"],
                    ),
                ),
                DNSChange(
                    action=DNSChangeAction.UPSERT,
                    rrset=DNSRRSet(
                        name="www",
                        type=ManagedRecordType.CNAME,
                        ttl=300,
                        values=["target.cname-conflict.dev."],
                    ),
                ),
            ]
        ),
        idempotency_key="cname-valid-replacement",
    )
    assert replacement.revision == 2
    assert [(record.name, record.type) for record in replacement.records] == [
        ("www", ManagedRecordType.CNAME)
    ]


@pytest.mark.asyncio
async def test_vm_attachment_claim_is_atomic_and_detach_preserves_customer_edit(
    domain_service,
):
    service, _provider, sessions = domain_service
    async with sessions() as session:
        session.add(
            DomainRow(
                name="attached",
                extension="dev",
                fqdn="attached.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        await session.commit()

    await service.claim_vm_attachment("H1234567890", "attached.dev", "vm_claim_one")
    with pytest.raises(DomainProblem) as conflict:
        await service.claim_vm_attachment("H1234567890", "attached.dev", "vm_claim_two")
    assert conflict.value.code == "domain_already_attached"

    await service.attach_vm("H1234567890", "attached.dev", "vm_claim_one", "2001:db8::20")
    protected_changes = [
        DNSChange(
            action=DNSChangeAction.UPSERT,
            rrset=DNSRRSet(
                name="@",
                type=ManagedRecordType.AAAA,
                ttl=300,
                values=["2001:db8::99"],
            ),
        ),
        DNSChange(
            action=DNSChangeAction.DELETE,
            rrset=DNSRRSet(
                name="@",
                type=ManagedRecordType.AAAA,
                ttl=300,
                values=["2001:db8::20"],
            ),
        ),
    ]
    for index, change in enumerate(protected_changes, start=1):
        with pytest.raises(DomainProblem) as protected:
            await service.apply_changeset(
                "H1234567890",
                "attached.dev",
                2,
                DNSChangesetRequest(changes=[change]),
                idempotency_key=f"protected-vm-apex-{index}",
            )
        assert protected.value.status == 409
        assert protected.value.code == "vm_apex_record_managed"

    async with sessions() as session:
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "attached.dev"))
        ).scalar_one()
        record = (
            await session.execute(
                select(DomainDNSRecordRow).where(
                    DomainDNSRecordRow.fqdn == "attached.dev",
                    DomainDNSRecordRow.name == "@",
                    DomainDNSRecordRow.type == "AAAA",
                )
            )
        ).scalar_one()
        assert domain.vm_ipv6 == "2001:db8::20"
        assert domain.zone_revision == 2
        assert record.ttl == 300
        assert record.values == ["2001:db8::20"]
        # A customer edit changes ownership of this RRset. Detach must unlink
        # the VM without deleting the customer's new value.
        record.ttl = 600
        record.values = ["2001:db8::99"]
        await session.commit()

    await service.detach_vm("H1234567890", "attached.dev", "vm_claim_one")
    async with sessions() as session:
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "attached.dev"))
        ).scalar_one()
        record = (
            await session.execute(
                select(DomainDNSRecordRow).where(
                    DomainDNSRecordRow.fqdn == "attached.dev",
                    DomainDNSRecordRow.name == "@",
                    DomainDNSRecordRow.type == "AAAA",
                )
            )
        ).scalar_one()
    assert domain.vm_id is None
    assert domain.vm_ipv6 is None
    assert record.values == ["2001:db8::99"]


@pytest.mark.asyncio
async def test_expired_native_intent_is_not_rendered_as_payable(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("expired-native.dev", DomainAction.REGISTER, "H1234567890")
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="expired-native",
    )
    intent = CryptoIntentRow(
        intent_id="intent-expired-domain",
        asset="BTC",
        amount_crypto=Decimal("0.001"),
        amount_usd=Decimal("13"),
        address="bc1qexpired",
        status=CryptoIntentStatus.EXPIRED,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
        resource_type="domain_order",
        resource_id=order.order_id,
    )
    async with sessions() as session:
        current = await session.get(DomainOrderRow, order.order_id)
        assert current is not None
        current.payment_method = DomainPaymentMethod.BTC.value
        current.native_intent_id = intent.intent_id
        session.add(intent)
        await session.commit()

    response = await service.get_order("H1234567890", order.order_id)

    assert response.status.value == "expired"
    assert response.payment is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resource_path",
    ["/v1/domains/orders", "/v1/domains/agent/orders"],
)
async def test_settlement_ledger_recovers_lost_x402_order_handoff(domain_service, resource_path):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("recover-payment.dev", DomainAction.REGISTER, "H1234567890")
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="recover-payment",
    )
    ledger = PaymentLedger(sessions)
    event = ledger.build_event(
        event_type="settled",
        resource_path=resource_path,
        method="POST",
        amount=Decimal("13"),
        network="eip155:8453",
        asset="USDC",
        payer="0x" + "2" * 40,
        tx_hash="0xrecover",
        extra={"order_id": order.order_id, "domain": "recover-payment.dev"},
    )
    now = datetime.now(UTC)
    event.created_at = now - timedelta(minutes=10)
    newer_events = []
    for index in range(3):
        newer = ledger.build_event(
            event_type="settled",
            resource_path=resource_path,
            method="POST",
            amount=Decimal("13"),
            network="eip155:8453",
            asset="USDC",
            payer="0x" + "3" * 40,
            tx_hash=f"0xalready-recovered-{index}",
            extra={"order_id": f"do_already_recovered_{index}"},
        )
        newer.created_at = now + timedelta(seconds=index)
        newer_events.append(newer)
    async with sessions() as session:
        session.add_all([event, *newer_events])
        await session.commit()

    # The recoverable event sits beyond the first page of already-processed
    # ledger entries, so a single fixed LIMIT would strand it forever.
    assert await service.recover_x402_handoffs(limit=2) == 1
    assert await service.recover_x402_handoffs(limit=2) == 0
    async with sessions() as session:
        current = await session.get(DomainOrderRow, order.order_id)
        jobs = list(
            await session.scalars(
                select(DomainJobRow).where(DomainJobRow.resource_id == order.order_id)
            )
        )
    assert current is not None and current.status == "queued"
    assert current.payment_tx == "0xrecover"
    assert len(jobs) == 1


@pytest.mark.asyncio
async def test_order_local_settlement_recovers_without_metrics_ledger(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote(
        "durable-domain-settlement.dev",
        DomainAction.REGISTER,
        "H1234567890",
    )
    order, _created = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="durable-domain-settlement",
    )
    await service.begin_x402_settlement(
        order.order_id,
        payer="0x" + "4" * 40,
        payment_network="eip155:8453",
        payment_asset="0x" + "5" * 40,
    )
    async with sessions() as session:
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
        stored_quote.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await session.commit()

    assert await service.expire_quotes() == 0
    await service.record_x402_settlement(
        order.order_id,
        payer="0x" + "4" * 40,
        tx_hash="0xdurable-domain-settlement",
        payment_network="eip155:8453",
        payment_asset="0x" + "5" * 40,
    )
    assert await service.recover_x402_handoffs() == 1

    async with sessions() as session:
        recovered = await session.get(DomainOrderRow, order.order_id)
        stored_quote = await session.get(DomainQuoteRow, quote.quote_id)
        events = list(await session.scalars(select(PaymentEventRow)))
    assert recovered.status == DomainOrderStatus.QUEUED.value
    assert recovered.payment_tx == "0xdurable-domain-settlement"
    assert recovered.payment_settlement_pending_at is None
    assert stored_quote.status == "consumed"
    assert events == []


@pytest.mark.asyncio
async def test_dnssec_validation_rejects_empty_ds_before_resolver(domain_service):
    service, _provider, _sessions = domain_service
    with pytest.raises(DomainProblem) as problem:
        await service._resolve_matching_dnskeys("example.dev", [])
    assert problem.value.code == "dnssec_records_required"


def test_openprovider_sell_price_prefers_reseller_component() -> None:
    amount, currency = _extract_product_price(
        {
            "price": {
                "product": {"price": "5.00", "currency": "EUR"},
                "reseller": {"price": "7.25", "currency": "USD"},
            }
        }
    )
    assert amount == Decimal("7.25")
    assert currency == "USD"


@pytest.mark.asyncio
async def test_two_paid_orders_cannot_reassign_the_same_registrar_domain(domain_service):
    service, provider, sessions = domain_service
    first_quote = await service.create_quote("contended.dev", DomainAction.REGISTER, "H1234567890")
    second_quote = await service.create_quote("contended.dev", DomainAction.REGISTER, "H1234567890")
    first, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=first_quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="contended-1",
    )
    second, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=second_quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="contended-2",
    )
    await service.mark_x402_paid(first.order_id, payer="0x" + "1" * 40, tx_hash="0x1")
    await service.mark_x402_paid(second.order_id, payer="0x" + "1" * 40, tx_hash="0x2")

    assert await service.process_jobs(worker_id="test", limit=10) == 2

    async with sessions() as session:
        first_stored = await session.get(DomainOrderRow, first.order_id)
        second_stored = await session.get(DomainOrderRow, second.order_id)
        managed = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "contended.dev"))
        ).scalar_one()
        refunds = list(
            await session.scalars(
                select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
            )
        )
    assert first_stored.status == "active"
    assert second_stored.status == "refund_due"
    assert managed.client_order_id == first.order_id
    assert provider.registrations == ["contended.dev"]
    assert [event.extra["order_id"] for event in refunds] == [second.order_id]


@pytest.mark.asyncio
async def test_operation_idempotency_cannot_be_rebound_to_another_domain(domain_service):
    service, _provider, sessions = domain_service
    async with sessions() as session:
        for name in ("first", "second"):
            session.add(
                DomainRow(
                    name=name,
                    extension="dev",
                    fqdn=f"{name}.dev",
                    owner_wallet="0x" + "1" * 40,
                    owner_account_id="H1234567890",
                    status="active",
                    nameserver_mode="managed",
                    nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                    dnssec_mode="managed",
                    dnssec_status="active",
                )
            )
        await session.commit()
    body = NameserverUpdateRequest(mode=NameserverMode.MANAGED)
    await service.enqueue_nameserver_update("H1234567890", "first.dev", body, "same-operation-key")
    with pytest.raises(DomainProblem) as conflict:
        await service.enqueue_nameserver_update(
            "H1234567890", "second.dev", body, "same-operation-key"
        )
    assert conflict.value.code == "idempotency_conflict"


@pytest.mark.asyncio
async def test_external_nameservers_are_blocked_for_vm_attachment_and_worker_race(
    domain_service,
):
    service, provider, sessions = domain_service
    provider.update_nameservers = AsyncMock(return_value={})
    provider.set_dnssec_keys = AsyncMock(return_value={})
    async with sessions() as session:
        session.add(
            DomainRow(
                name="attached-delegation",
                extension="dev",
                fqdn="attached-delegation.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                openprovider_id=8123,
                vm_id="vm_attached_delegation",
                vm_ipv6="2001:db8::81",
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        await session.commit()
    body = NameserverUpdateRequest(
        mode=NameserverMode.EXTERNAL,
        nameservers=["ns1.example.net", "ns2.example.net"],
    )

    with pytest.raises(DomainProblem) as attached:
        await service.enqueue_nameserver_update(
            "H1234567890",
            "attached-delegation.dev",
            body,
            "attached-delegation-blocked",
        )
    assert attached.value.status == 409
    assert attached.value.code == "domain_attached_to_vm"

    async with sessions() as session:
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "attached-delegation.dev")
            )
        ).scalar_one()
        domain.vm_id = None
        domain.vm_ipv6 = None
        await session.commit()
    operation = await service.enqueue_nameserver_update(
        "H1234567890",
        "attached-delegation.dev",
        body,
        "attached-delegation-race",
    )
    async with sessions() as session:
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "attached-delegation.dev")
            )
        ).scalar_one()
        domain.vm_id = "vm_attached_delegation"
        domain.vm_ipv6 = "2001:db8::81"
        await session.commit()
    replay = await service.enqueue_nameserver_update(
        "H1234567890",
        "attached-delegation.dev",
        body,
        "attached-delegation-race",
    )
    assert replay.operation_id == operation.operation_id

    assert await service.process_jobs(worker_id="test", limit=1) == 1
    async with sessions() as session:
        failed_operation = await session.get(DomainOperationRow, operation.operation_id)
        domain = (
            await session.execute(
                select(DomainRow).where(DomainRow.fqdn == "attached-delegation.dev")
            )
        ).scalar_one()
    assert failed_operation is not None and failed_operation.status == "failed"
    assert failed_operation.error_code == "domain_attached_to_vm"
    assert domain.nameserver_mode == "managed"
    assert domain.vm_id == "vm_attached_delegation"
    provider.update_nameservers.assert_not_awaited()
    provider.set_dnssec_keys.assert_not_awaited()


@pytest.mark.asyncio
async def test_external_dnssec_is_cleared_before_switching_to_managed_nameservers(
    domain_service,
):
    service, provider, sessions = domain_service
    provider_calls: list[tuple[str, int, list]] = []

    async def set_dnssec_keys(domain_id, keys):
        provider_calls.append(("dnssec", domain_id, keys))
        return {}

    async def update_nameservers(domain_id, nameservers):
        provider_calls.append(("nameservers", domain_id, nameservers))
        return {}

    provider.set_dnssec_keys = AsyncMock(side_effect=set_dnssec_keys)
    provider.update_nameservers = AsyncMock(side_effect=update_nameservers)
    async with sessions() as session:
        session.add(
            DomainRow(
                name="external-dnssec",
                extension="dev",
                fqdn="external-dnssec.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                openprovider_id=8345,
                nameserver_mode="external",
                nameservers=["ns1.example.net", "ns2.example.net"],
                dnssec_mode="external",
                dnssec_status="active",
                ds_records=[
                    {
                        "key_tag": 12345,
                        "algorithm": 13,
                        "digest_type": 2,
                        "digest": "A" * 64,
                    }
                ],
            )
        )
        await session.commit()

    operation = await service.enqueue_nameserver_update(
        "H1234567890",
        "external-dnssec.dev",
        NameserverUpdateRequest(mode=NameserverMode.MANAGED),
        "external-dnssec-to-managed",
    )
    assert await service.process_jobs(worker_id="test", limit=1) == 1

    async with sessions() as session:
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "external-dnssec.dev"))
        ).scalar_one()
        completed = await session.get(DomainOperationRow, operation.operation_id)
    assert completed is not None and completed.status == "succeeded"
    assert domain.nameserver_mode == "managed"
    assert domain.nameservers == ["ns1.hyrule.host", "ns2.hyrule.host"]
    assert domain.dnssec_mode == "off"
    assert domain.dnssec_status == "off"
    assert domain.ds_records == []
    assert provider_calls == [
        ("dnssec", 8345, []),
        ("nameservers", 8345, ["ns1.hyrule.host", "ns2.hyrule.host"]),
    ]


@pytest.mark.asyncio
async def test_reconciliation_preserves_dnssec_off_and_managed_enable_installs_keys(
    domain_service,
):
    service, provider, sessions = domain_service
    provider.update_nameservers = AsyncMock(return_value={})
    provider.set_dnssec_keys = AsyncMock(return_value={})
    service.dns.dnssec_keys = AsyncMock(return_value=[])
    async with sessions() as session:
        session.add(
            DomainRow(
                name="dnssec-off",
                extension="dev",
                fqdn="dnssec-off.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id="H1234567890",
                status="active",
                openprovider_id=8456,
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="off",
                dnssec_status="off",
            )
        )
        await session.commit()

    await service._reconcile_domain("dnssec-off.dev")

    async with sessions() as session:
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "dnssec-off.dev"))
        ).scalar_one()
    assert domain.dnssec_mode == "off"
    assert domain.dnssec_status == "off"
    assert service.dns.zones["dnssec-off.dev"]["revision"] == 1
    service.dns.dnssec_keys.assert_not_awaited()
    provider.set_dnssec_keys.assert_not_awaited()
    provider.update_nameservers.assert_awaited_once_with(
        8456, ["ns1.hyrule.host", "ns2.hyrule.host"]
    )

    keys = [{"flags": 257, "protocol": 3, "alg": 13, "pub_key": "AA=="}]
    service.dns.dnssec_keys.return_value = keys
    operation = await service.enqueue_dnssec_update(
        "H1234567890",
        "dnssec-off.dev",
        DNSSECUpdateRequest(mode=DNSSECMode.MANAGED),
        "enable-managed-dnssec",
    )
    assert await service.process_jobs(worker_id="test", limit=1) == 1

    async with sessions() as session:
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "dnssec-off.dev"))
        ).scalar_one()
        completed = await session.get(DomainOperationRow, operation.operation_id)
    assert domain.dnssec_mode == "managed"
    assert domain.dnssec_status == "active"
    assert completed is not None and completed.status == "succeeded"
    service.dns.dnssec_keys.assert_awaited_once_with("dnssec-off.dev")
    provider.set_dnssec_keys.assert_awaited_once_with(8456, keys)


@pytest.mark.asyncio
async def test_renewal_window_and_stale_job_recovery(domain_service):
    service, _provider, sessions = domain_service
    now = datetime.now(UTC)
    async with sessions() as session:
        session.add_all(
            [
                DomainRow(
                    name="due",
                    extension="dev",
                    fqdn="due.dev",
                    owner_wallet="0x" + "1" * 40,
                    owner_account_id="H1234567890",
                    status="active",
                    nameserver_mode="managed",
                    nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                    dnssec_mode="managed",
                    dnssec_status="active",
                    expires_at=now + timedelta(days=20),
                ),
                DomainRow(
                    name="later",
                    extension="dev",
                    fqdn="later.dev",
                    owner_wallet="0x" + "1" * 40,
                    owner_account_id="H1234567890",
                    status="active",
                    nameserver_mode="managed",
                    nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                    dnssec_mode="managed",
                    dnssec_status="active",
                    expires_at=now + timedelta(days=100),
                ),
                DomainJobRow(
                    job_id="djob_stale",
                    kind="reconcile_domain",
                    resource_id="missing.dev",
                    dedupe_key="stale-job",
                    payload={},
                    status="running",
                    attempts=1,
                    available_at=now - timedelta(hours=1),
                    locked_at=now - timedelta(hours=1),
                    locked_by="dead-worker",
                ),
            ]
        )
        await session.commit()

    assert await service.refresh_renewal_states() == 1
    claimed = await service._claim_job("replacement-worker")
    assert claimed is not None
    assert claimed.job_id == "djob_stale"
    assert claimed.attempts == 2
    async with sessions() as session:
        due = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "due.dev"))
        ).scalar_one()
        later = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == "later.dev"))
        ).scalar_one()
    assert str(due.status) == "renewal_due"
    assert due.can_renew is True
    assert str(later.status) == "active"
    assert later.can_renew is False


@pytest.mark.asyncio
async def test_worker_recovers_only_domain_bundle_vm_provisioning(domain_service):
    service, _provider, sessions = domain_service
    quote = await service.create_quote("bundle-recovery.dev", DomainAction.REGISTER, "H1234567890")
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
        ),
        owner_account_id="H1234567890",
        idempotency_key="bundle-recovery",
    )
    async with sessions() as session:
        stored_order = await session.get(DomainOrderRow, order.order_id)
        stored_order.vm_id = "vm_bundle_recovery"
        session.add_all(
            [
                VMRow(
                    vm_id="vm_bundle_recovery",
                    owner_wallet="0x" + "1" * 40,
                    owner_account_id="H1234567890",
                    status=VMStatus.PROVISIONING,
                    size=VMSize.XS,
                    os="debian-13",
                    ssh_pubkey="ssh-ed25519 AAAA test",
                    open_ports=[22],
                    cost_total=Decimal("0.05"),
                ),
                VMRow(
                    vm_id="vm_unrelated_provisioning",
                    owner_wallet="0x" + "2" * 40,
                    owner_account_id="H1234567890",
                    status=VMStatus.PROVISIONING,
                    size=VMSize.XS,
                    os="debian-13",
                    ssh_pubkey="ssh-ed25519 AAAA test",
                    open_ports=[22],
                    cost_total=Decimal("0.05"),
                ),
            ]
        )
        await session.commit()

    assert await service.recover_bundle_provisioning() == 1
    assert service.orchestrator.started_vms == ["vm_bundle_recovery"]


@pytest.mark.asyncio
async def test_bundle_claims_domain_before_reserving_vm(domain_service):
    service, _provider, sessions = domain_service
    fqdn = "claimed-bundle.dev"
    quote = await service.create_quote(fqdn, DomainAction.REGISTER, "H1234567890")
    vm_quote_id = "vmq_claimed_bundle"
    async with sessions() as session:
        session.add(
            VMQuoteRow(
                quote_id=vm_quote_id,
                order_payload=_bundle_spec(fqdn).model_dump(mode="json", exclude={"quote_id"}),
                amount_usd=Decimal("5"),
                status=QuoteStatus.CREATED,
                owner_account_id="H1234567890",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        await session.commit()
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
            vm_quote_id=vm_quote_id,
        ),
        owner_account_id="H1234567890",
        idempotency_key="claimed-bundle",
    )
    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "4" * 40,
        tx_hash="0xbundle-claim",
    )
    async with sessions() as session:
        session.add(
            DomainRow(
                name="claimed-bundle",
                extension="dev",
                fqdn=fqdn,
                owner_wallet="0x" + "4" * 40,
                owner_account_id="H1234567890",
                status="active",
                openprovider_id=7001,
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
            )
        )
        await session.commit()

    observed_claim: list[str] = []

    async def reserve_vm_with_capacity(_spec, **kwargs):
        async with sessions() as session:
            domain = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
            ).scalar_one()
        assert domain.vm_id == kwargs["vm_id"]
        observed_claim.append(domain.vm_id)
        return SimpleNamespace(vm_id=kwargs["vm_id"]), "token"

    async def activate_vm_reservation(vm_id, **_kwargs):
        return SimpleNamespace(vm_id=vm_id, status=VMStatus.READY.value)

    async def release_vm_reservation(_vm_id):
        return None

    async def persist_charged_amount(_vm_id: str, _amount: Decimal) -> None:
        return None

    service.orchestrator.reserve_vm_with_capacity = reserve_vm_with_capacity
    service.orchestrator.activate_vm_reservation = activate_vm_reservation
    service.orchestrator.release_vm_reservation = release_vm_reservation
    service.orchestrator.persist_charged_amount = persist_charged_amount
    await service._provision_bundle(order.order_id)

    assert len(observed_claim) == 1
    async with sessions() as session:
        domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
        ).scalar_one()
    assert domain.vm_id == observed_claim[0]


@pytest.mark.asyncio
async def test_bundle_vm_quote_is_claimed_by_only_one_domain_order(domain_service):
    service, _provider, sessions = domain_service
    fqdn = "contended-bundle.dev"
    domain_quotes = [
        await service.create_quote(fqdn, DomainAction.REGISTER, "H1234567890") for _ in range(2)
    ]
    vm_quote_id = "vmq_contended_bundle"
    async with sessions() as session:
        session.add(
            VMQuoteRow(
                quote_id=vm_quote_id,
                order_payload=_bundle_spec(fqdn).model_dump(mode="json", exclude={"quote_id"}),
                amount_usd=Decimal("5"),
                status=QuoteStatus.CREATED,
                owner_account_id="H1234567890",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        await session.commit()

    async def create_bundle_order(index: int):
        return await service.create_order(
            DomainOrderRequest(
                quote_id=domain_quotes[index].quote_id,
                payment_method=DomainPaymentMethod.USDC,
                terms_version=service.domain_config.terms_version,
                vm_quote_id=vm_quote_id,
            ),
            owner_account_id="H1234567890",
            idempotency_key=f"contended-bundle-{index}",
        )

    results = await asyncio.gather(
        create_bundle_order(0),
        create_bundle_order(1),
        return_exceptions=True,
    )
    successes = [result for result in results if isinstance(result, tuple)]
    failures = [result for result in results if isinstance(result, DomainProblem)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].code == "vm_quote_expired"
    winning_order, created = successes[0]
    assert created is True

    queued = await service.mark_x402_paid(
        winning_order.order_id,
        payer="0x" + "6" * 40,
        tx_hash="0xcontended-bundle",
    )
    assert queued.status == "queued"
    async with sessions() as session:
        vm_quote = await session.get(VMQuoteRow, vm_quote_id)
        orders = list(await session.scalars(select(DomainOrderRow)))
        stored_domain_quotes = list(
            await session.scalars(
                select(DomainQuoteRow).where(
                    DomainQuoteRow.quote_id.in_(
                        [domain_quote.quote_id for domain_quote in domain_quotes]
                    )
                )
            )
        )
    assert vm_quote is not None and vm_quote.status == QuoteStatus.CONSUMED
    assert [order.order_id for order in orders] == [winning_order.order_id]
    assert sorted(quote.status for quote in stored_domain_quotes) == ["active", "consumed"]


@pytest.mark.asyncio
async def test_expiring_unpaid_bundle_order_releases_unlinked_vm_quote(domain_service):
    service, _provider, sessions = domain_service
    fqdn = "abandoned-bundle.dev"
    domain_quote = await service.create_quote(fqdn, DomainAction.REGISTER, "H1234567890")
    vm_quote_id = "vmq_abandoned_bundle"
    async with sessions() as session:
        session.add(
            VMQuoteRow(
                quote_id=vm_quote_id,
                order_payload=_bundle_spec(fqdn).model_dump(mode="json", exclude={"quote_id"}),
                amount_usd=Decimal("5"),
                status=QuoteStatus.CREATED,
                owner_account_id="H1234567890",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        await session.commit()
    abandoned_order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=domain_quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
            vm_quote_id=vm_quote_id,
        ),
        owner_account_id="H1234567890",
        idempotency_key="abandoned-bundle",
    )
    async with sessions() as session:
        expired_quote = await session.get(DomainQuoteRow, domain_quote.quote_id)
        assert expired_quote is not None
        expired_quote.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    assert await service.expire_quotes() == 1
    async with sessions() as session:
        stored_order = await session.get(DomainOrderRow, abandoned_order.order_id)
        stored_domain_quote = await session.get(DomainQuoteRow, domain_quote.quote_id)
        released_vm_quote = await session.get(VMQuoteRow, vm_quote_id)
    assert stored_order is not None and stored_order.status == "expired"
    assert stored_order.error_code == "quote_expired"
    assert stored_domain_quote is not None and stored_domain_quote.status == "expired"
    assert released_vm_quote is not None
    assert released_vm_quote.status == QuoteStatus.CREATED
    assert released_vm_quote.vm_id is None

    replacement_quote = await service.create_quote(fqdn, DomainAction.REGISTER, "H1234567890")
    replacement_order, created = await service.create_order(
        DomainOrderRequest(
            quote_id=replacement_quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
            vm_quote_id=vm_quote_id,
        ),
        owner_account_id="H1234567890",
        idempotency_key="replacement-bundle",
    )
    assert created is True
    assert replacement_order.order_id != abandoned_order.order_id
    async with sessions() as session:
        reclaimed_vm_quote = await session.get(VMQuoteRow, vm_quote_id)
    assert reclaimed_vm_quote is not None
    assert reclaimed_vm_quote.status == QuoteStatus.CONSUMED


@pytest.mark.asyncio
async def test_partial_bundle_refund_commits_atomically_with_terminal_job(
    domain_service,
    monkeypatch,
):
    service, _provider, sessions = domain_service
    fqdn = "partial-refund.dev"
    quote = await service.create_quote(fqdn, DomainAction.REGISTER, "H1234567890")
    vm_quote_id = "vmq_partial_refund"
    async with sessions() as session:
        session.add(
            VMQuoteRow(
                quote_id=vm_quote_id,
                order_payload=_bundle_spec(fqdn).model_dump(mode="json", exclude={"quote_id"}),
                amount_usd=Decimal("5"),
                status=QuoteStatus.CREATED,
                owner_account_id="H1234567890",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        await session.commit()
    order, _ = await service.create_order(
        DomainOrderRequest(
            quote_id=quote.quote_id,
            payment_method=DomainPaymentMethod.USDC,
            terms_version=service.domain_config.terms_version,
            vm_quote_id=vm_quote_id,
        ),
        owner_account_id="H1234567890",
        idempotency_key="partial-refund",
    )
    await service.mark_x402_paid(
        order.order_id,
        payer="0x" + "5" * 40,
        tx_hash="0xpartial",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    async with sessions() as session:
        stored_order = await session.get(DomainOrderRow, order.order_id)
        assert stored_order is not None
        stored_order.vm_id = "vm_orphaned_bundle_claim"
        session.add(
            DomainRow(
                name="partial-refund",
                extension="dev",
                fqdn=fqdn,
                owner_wallet="0x" + "5" * 40,
                owner_account_id="H1234567890",
                status="active",
                openprovider_id=7002,
                nameserver_mode="managed",
                nameservers=["ns1.hyrule.host", "ns2.hyrule.host"],
                dnssec_mode="managed",
                dnssec_status="active",
                vm_id="vm_orphaned_bundle_claim",
            )
        )
        job = (
            await session.execute(
                select(DomainJobRow).where(DomainJobRow.resource_id == order.order_id)
            )
        ).scalar_one()
        job.status = "running"
        job.attempts = 10
        job_id = job.job_id
        await session.commit()

    refunds = service.orchestrator.refunds
    original_builder = refunds.build_owed_event

    def ledger_failure(**_kwargs):
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr(refunds, "build_owed_event", ledger_failure)
    with pytest.raises(RuntimeError, match="ledger unavailable"):
        await service._retry_or_fail_job(job_id, RuntimeError("bundle VM failed"))

    async with sessions() as session:
        rolled_back_job = await session.get(DomainJobRow, job_id)
        rolled_back_order = await session.get(DomainOrderRow, order.order_id)
        rolled_back_domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
        ).scalar_one()
        refund_events = list(
            await session.scalars(
                select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
            )
        )
    assert rolled_back_job is not None and rolled_back_job.status == "running"
    assert rolled_back_order is not None and rolled_back_order.status == "queued"
    assert rolled_back_domain.vm_id == "vm_orphaned_bundle_claim"
    assert refund_events == []

    monkeypatch.setattr(refunds, "build_owed_event", original_builder)
    await service._retry_or_fail_job(job_id, RuntimeError("bundle VM failed"))
    async with sessions() as session:
        failed_job = await session.get(DomainJobRow, job_id)
        active_order = await session.get(DomainOrderRow, order.order_id)
        active_domain = (
            await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
        ).scalar_one()
        refund_event = (
            await session.execute(
                select(PaymentEventRow).where(PaymentEventRow.event_type == "refund_owed")
            )
        ).scalar_one()
    assert failed_job is not None and failed_job.status == "failed"
    assert active_order is not None and active_order.status == "active"
    assert active_domain.vm_id is None
    assert refund_event.amount_usd == Decimal("5")
    assert refund_event.extra["order_id"] == order.order_id


@pytest.mark.asyncio
async def test_read_only_operation_poll_does_not_consume_transfer_secret(domain_service):
    service, _provider, sessions = domain_service
    key = Fernet.generate_key()
    service.domain_config.authcode_fernet_key = key.decode()
    operation_id = "dop_transfer_secret_test"
    async with sessions() as session:
        session.add(
            DomainOperationRow(
                operation_id=operation_id,
                fqdn="transfer-secret.dev",
                owner_account_id="H1234567890",
                kind="transfer_out",
                status="succeeded",
                secret_ciphertext=Fernet(key).encrypt(b"AUTH-CODE-123").decode(),
                secret_expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
        )
        await session.commit()

    read_only = await service.get_operation(
        "H1234567890",
        operation_id,
        reveal_secret=False,
    )
    assert read_only.secret is None
    async with sessions() as session:
        stored = await session.get(DomainOperationRow, operation_id)
    assert stored is not None and stored.secret_ciphertext is not None
    assert stored.secret_revealed_at is None

    authorized = await service.get_operation(
        "H1234567890",
        operation_id,
        reveal_secret=True,
    )
    assert authorized.secret == "AUTH-CODE-123"
    async with sessions() as session:
        stored = await session.get(DomainOperationRow, operation_id)
    assert stored is not None and stored.secret_ciphertext is None
    assert stored.secret_revealed_at is not None


@pytest.mark.asyncio
async def test_operation_route_only_reveals_secret_to_transfer_authority() -> None:
    reveal_values: list[bool] = []

    class Service:
        async def get_operation(self, _account_id, _operation_id, *, reveal_secret):
            reveal_values.append(reveal_secret)
            return SimpleNamespace()

    account = SimpleNamespace(account_id="H1234567890")
    for is_api_key, scopes in (
        (True, {"domain:read"}),
        (True, {"domain:read", "domain:transfer"}),
        (False, set()),
    ):
        request = SimpleNamespace(
            state=SimpleNamespace(is_api_key=is_api_key, api_key_scopes=scopes)
        )
        await get_operation_route(
            "dop_scope_test",
            request,
            account=account,
            service=Service(),
        )

    assert reveal_values == [False, True, True]


@pytest.mark.asyncio
async def test_wallet_login_and_two_signature_rotation(tmp_path):
    engine = create_db_engine(f"sqlite+aiosqlite:///{tmp_path / 'wallet.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = create_session_factory(engine)
    service = WalletAuthService(HyruleConfig(), sessions)
    current = Account.create()
    challenge = await service.create_challenge(
        WalletChallengeRequest(
            action=WalletAction.LOGIN,
            address=current.address,
            chain_id=8453,
        ),
        account=None,
    )
    signature = Account.sign_message(
        encode_defunct(text=challenge.message), current.key
    ).signature.hex()
    request = SimpleNamespace(headers={}, client=None)
    account, wallet, action, created, _token = await service.verify_login_or_account_action(
        WalletVerifyRequest(nonce=challenge.nonce, signature=signature),
        account=None,
        request=request,
    )
    assert action is WalletAction.LOGIN
    assert created is True
    assert wallet.address.lower() == current.address.lower()

    replacement = Account.create()
    rotate = await service.create_challenge(
        WalletChallengeRequest(
            action=WalletAction.ROTATE,
            address=replacement.address,
            chain_id=8453,
        ),
        account=account,
    )
    old_signature = Account.sign_message(
        encode_defunct(text=rotate.message), current.key
    ).signature.hex()
    new_signature = Account.sign_message(
        encode_defunct(text=rotate.message), replacement.key
    ).signature.hex()
    _account, rotated, action, _created, _token = await service.verify_login_or_account_action(
        WalletVerifyRequest(
            nonce=rotate.nonce,
            signature=old_signature,
            secondary_signature=new_signature,
        ),
        account=account,
        request=request,
    )
    assert action is WalletAction.ROTATE
    assert rotated.address.lower() == replacement.address.lower()
    await engine.dispose()
