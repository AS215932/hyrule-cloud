from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
import pytest_asyncio
from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import select

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    Base,
    DomainJobRow,
    DomainOrderRow,
    DomainRow,
    DomainTLDRow,
    VMRow,
    create_db_engine,
    create_session_factory,
)
from hyrule_cloud.domains.catalog import parse_iana_root_db
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import (
    DNSChange,
    DNSChangeAction,
    DNSChangesetRequest,
    DNSRRSet,
    DomainAction,
    DomainFailurePolicy,
    DomainOrderRequest,
    DomainPaymentMethod,
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
from hyrule_cloud.models import VMSize, VMStatus
from hyrule_cloud.providers.openprovider import OpenproviderUnavailableError
from hyrule_cloud.services.passwords import hash_password


class _Provider:
    def __init__(self) -> None:
        self.registration_nameservers: list[str] | None = None
        self.registrations: list[str] = []

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


class _Refunds:
    async def record_owed(self, **kwargs):
        return True


class _Orchestrator:
    refunds = _Refunds()

    def __init__(self) -> None:
        self.started_vms: list[str] = []

    def start_provisioning(self, vm_id: str) -> None:
        self.started_vms.append(vm_id)


@pytest_asyncio.fixture
async def domain_service(tmp_path):
    engine = create_db_engine(f"sqlite+aiosqlite:///{tmp_path / 'domains.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = create_session_factory(engine)
    config = HyruleConfig(database_url=f"sqlite+aiosqlite:///{tmp_path / 'domains.db'}")
    config.domain.purchases_enabled = True
    config.domain.legal_approved = True
    config.domain.tax_approved = True
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
        _Orchestrator(),
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
    assert first_stored.status == "active"
    assert second_stored.status == "refund_due"
    assert managed.client_order_id == first.order_id
    assert provider.registrations == ["contended.dev"]


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
