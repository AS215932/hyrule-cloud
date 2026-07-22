from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import Text, func, select
from starlette.requests import Request
from starlette.responses import Response

from hyrule_cloud.api.mail import (
    _mail_payment_authorization_fingerprint,
    create_account,
    ingest_events,
    internal_router,
)
from hyrule_cloud.api.mail import (
    send_message as send_message_route,
)
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    Base,
    DomainOrderRow,
    DomainRow,
    MailAccountRow,
    MailEventRow,
    MailMessageIndexRow,
    MailPaymentAuthorizationRow,
    MailQuoteRow,
    MailRecipientRow,
    MailSendRow,
    MailWebhookDeliveryRow,
    MailWebhookRow,
    PaymentEventRow,
    create_db_engine,
    create_session_factory,
)
from hyrule_cloud.domains.models import DomainOrderStatus, NameserverMode
from hyrule_cloud.mail.backend import (
    MailAttachmentTooLargeError,
    MailBackendError,
    MailDNSIncompleteError,
    StalwartClient,
)
from hyrule_cloud.mail.models import (
    MailAccountCreateRequest,
    MailAccountQuoteRequest,
    MailboxMode,
    MailboxStatus,
    MailSendQuoteRequest,
    MailSendRequest,
    MailWebhookCreateRequest,
    StalwartEventEnvelope,
    generate_mail_id,
)
from hyrule_cloud.mail.security import hash_token
from hyrule_cloud.mail.service import MailProblem, MailService
from hyrule_cloud.middleware.x402 import (
    PaymentGate,
    PaymentReconciliation,
    RecoveredPayment,
)
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.services.refunds import RefundService


class _Backend:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.deleted: list[str] = []
        self.deleted_messages: list[dict] = []
        self.accounts: list[dict] = []
        self.retention_sweeps: list[dict] = []
        self.retention_delete_count = 0
        self.messages_by_send_id: dict[str, str] = {}
        self.authoritative_messages: list[dict] = []

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None

    async def ensure_domain(self, domain: str):
        return f"domain:{domain}", []

    async def ensure_account(self, **kwargs):
        self.accounts.append(kwargs)
        return f"account:{kwargs['address']}"

    async def delete_account(self, account_id: str) -> None:
        self.deleted.append(account_id)

    async def delete_message(self, **kwargs) -> None:
        self.deleted_messages.append(kwargs)

    async def delete_messages_before(self, **kwargs) -> int:
        self.retention_sweeps.append(kwargs)
        return self.retention_delete_count

    async def send_message(self, **kwargs):
        self.sent.append(kwargs)
        message_id = f"message-{len(self.sent)}"
        self.messages_by_send_id[kwargs["send_id"]] = message_id
        return message_id

    async def find_message_by_send_id(self, **kwargs):
        return self.messages_by_send_id.get(kwargs["send_id"])

    async def get_message(self, **kwargs):
        stored = next(
            (
                item
                for item in self.authoritative_messages
                if item.get("id") == kwargs["message_id"]
            ),
            None,
        )
        if stored is not None:
            return dict(stored)
        return {
            "id": kwargs["message_id"],
            "messageId": [f"<{kwargs['message_id']}@example.test>"],
            "from": [{"email": "sender@example.net"}],
            "to": [{"email": kwargs["address"]}],
            "subject": "Message",
            "receivedAt": datetime.now(UTC).isoformat(),
            "textBody": [{"partId": "text"}],
            "bodyValues": {"text": {"value": "hello"}},
            "attachments": [],
        }

    async def list_messages(self, **kwargs):
        return [dict(item) for item in self.authoritative_messages[: kwargs["limit"]]]


class _Domains:
    def __init__(self) -> None:
        self.agent_orders: list[dict] = []
        self.paid_orders: list[dict] = []
        self.removed_service_records: list[dict] = []
        self.dns = SimpleNamespace(configured=True)

    async def create_quote(self, domain, action, owner):
        assert action.value == "register"
        assert owner is None
        return SimpleNamespace(
            quote_id="dq_atomic_123456",
            price=SimpleNamespace(total_usd="12.00"),
        )

    async def create_agent_order(self, **kwargs):
        self.agent_orders.append(kwargs)
        return SimpleNamespace(order_id="do_atomic_123456"), kwargs["management_token"], True

    async def mark_x402_paid(self, *args, **kwargs):
        self.paid_orders.append({"args": args, **kwargs})
        return SimpleNamespace(status="queued")

    async def replace_service_records(self, *args, **kwargs):
        return None

    async def remove_service_records(self, *args, **kwargs):
        self.removed_service_records.append({"args": args, **kwargs})
        return None


@pytest_asyncio.fixture
async def mail_service(tmp_path):
    database = tmp_path / "mail.db"
    engine = create_db_engine(f"sqlite+aiosqlite:///{database}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = create_session_factory(engine)
    config = HyruleConfig(database_url=f"sqlite+aiosqlite:///{database}")
    config.mail.enabled = True
    config.mail.legal_approved = True
    config.mail.abuse_approved = True
    config.mail.backend_url = "https://mail.internal"
    config.mail.backend_token = "test-management-token"
    config.mail.credential_fernet_key = Fernet.generate_key().decode()
    config.mail.internal_webhook_secret = "test-event-secret-at-least-32-bytes"
    config.mail.mailbox_send_limit_per_day = 1
    config.domain.agent_purchases_enabled = True
    backend = _Backend()
    domains = _Domains()
    refunds = RefundService(PaymentLedger(sessions))
    service = MailService(config, sessions, domains, refunds, backend=backend)
    yield service, sessions, backend, domains, refunds
    await service.close()
    await engine.dispose()


async def _active_hosted(
    service: MailService,
    *,
    local_part: str = "journey-agent",
    idempotency_key: str = "hosted-activation-idempotency-0001",
):
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part=local_part,
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, token, created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key=idempotency_key,
    )
    assert created is True
    replay, replay_token, replay_created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key=idempotency_key,
    )
    assert replay.mailbox_id == account.mailbox_id
    assert replay_token == token
    assert replay_created is False
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x1234567890abcdef",
        tx_hash="0xpaid",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    assert await service.provision_pending() == 1
    current = await service.get_account(account.mailbox_id, token)
    assert current.status is MailboxStatus.ACTIVE
    assert current.management_token is None
    return account.mailbox_id, token


def test_generated_mail_ids_fit_postgres_columns():
    for prefix in ("mbx", "mailq", "send", "wh", "whd"):
        generated = generate_mail_id(prefix)
        assert generated.startswith(f"{prefix}_")
        assert len(generated) <= 36


def test_agent_mail_review_safety_schema_contracts():
    assert MailAccountRow.__table__.c.capacity_reserved_at.index is True
    assert MailAccountRow.__table__.c.provision_claimed_at.index is True
    assert MailAccountRow.__table__.c.provision_next_attempt_at.index is True
    assert MailAccountRow.__table__.c.provision_retry_count.server_default is not None
    fingerprint = MailPaymentAuthorizationRow.__table__.c.fingerprint
    assert fingerprint.primary_key is True
    assert fingerprint.type.length == 64
    authorization_quote_constraints = [
        constraint
        for constraint in MailPaymentAuthorizationRow.__table__.constraints
        if constraint.name == "uq_mail_payment_authorization_quote"
    ]
    assert len(authorization_quote_constraints) == 1
    assert [column.name for column in authorization_quote_constraints[0].columns] == ["quote_id"]
    assert MailAccountRow.__table__.c.dns_cleanup_pending.index is True
    assert MailAccountRow.__table__.c.payment_settled_at.index is True
    assert MailAccountRow.__table__.c.payment_authorization_header.type.length is None
    assert MailSendRow.__table__.c.payment_settled_at.index is True
    assert MailSendRow.__table__.c.payment_authorization_header.type.length is None
    assert MailSendRow.__table__.c.payment_settlement_pending_at.nullable is True
    assert isinstance(MailSendRow.__table__.c.in_reply_to.type, Text)
    assert MailAccountRow.__table__.c.domain_authority_hash.type.length == 64
    assert [column.name for column in MailMessageIndexRow.__table__.primary_key.columns] == [
        "mailbox_id",
        "message_id",
    ]


def test_send_reservation_serializes_the_global_capacity_check():
    source = inspect.getsource(MailService._reserve_send_intent)
    lock = "pg_advisory_xact_lock(_MAIL_SEND_CAPACITY_LOCK_ID)"

    assert lock in source
    assert source.index(lock) < source.index("global_count =")


def test_payment_fingerprint_uses_canonical_signed_payload_fields():
    accepted = {
        "scheme": "exact",
        "network": "eip155:8453",
        "asset": "0x" + "1" * 40,
        "amount": "10000",
        "payTo": "0x" + "2" * 40,
        "maxTimeoutSeconds": 300,
        "extra": {},
    }
    signed = {
        "authorization": {
            "from": "0x" + "3" * 40,
            "to": accepted["payTo"],
            "value": accepted["amount"],
            "validAfter": "0",
            "validBefore": "9999999999",
            "nonce": "0x" + "4" * 64,
        },
        "signature": "0x" + "5" * 130,
    }
    first = {"x402Version": 2, "accepted": accepted, "payload": signed}
    second = {
        "payload": {**signed, "ignoredTransportHint": "not a signed field"},
        "accepted": accepted,
        "x402Version": 2,
    }

    def fingerprint(payload: dict, *, compact: bool) -> str | None:
        raw = json.dumps(
            payload, separators=(",", ":") if compact else None, indent=None if compact else 2
        )
        encoded = base64.b64encode(raw.encode()).decode()
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/mail/messages/send",
                "headers": [(b"payment-signature", encoded.encode())],
            }
        )
        return _mail_payment_authorization_fingerprint(request)

    assert fingerprint(first, compact=True) == fingerprint(second, compact=False)
    signature_variant = json.loads(json.dumps(first))
    signature_variant["payload"]["signature"] = "0x" + "6" * 130
    assert fingerprint(first, compact=True) == fingerprint(signature_variant, compact=True)
    changed_authorization = json.loads(json.dumps(first))
    changed_authorization["payload"]["authorization"]["nonce"] = "0x" + "7" * 64
    assert fingerprint(first, compact=True) != fingerprint(changed_authorization, compact=True)


@pytest.mark.asyncio
async def test_send_quote_honors_configured_body_limit_above_100k(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="large-body",
        idempotency_key="large-body-idempotency-0001",
    )
    body = MailSendQuoteRequest(
        mailbox_id=mailbox_id,
        to="recipient@example.net",
        subject="Configured body limit",
        text="x" * 100_001,
    )

    service.mail_config.max_text_chars = 150_000
    quote = await service.create_send_quote(body, token)
    assert quote.kind == "send"

    service.mail_config.max_text_chars = 100_000
    with pytest.raises(MailProblem) as too_large:
        await service.create_send_quote(body, token)
    assert too_large.value.code == "message_too_large"


@pytest.mark.asyncio
async def test_launch_switch_blocks_send_quotes_and_previously_quoted_delivery(mail_service):
    service, _sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="launch-switch",
        idempotency_key="launch-switch-idempotency-0001",
    )
    request = MailSendQuoteRequest(
        mailbox_id=mailbox_id,
        to="recipient@example.net",
        subject="Launch switch",
        text="Do not send after shutdown.",
    )
    quote = await service.create_send_quote(request, token)
    service.mail_config.enabled = False

    with pytest.raises(MailProblem) as new_quote:
        await service.create_send_quote(request, token)
    assert new_quote.value.code == "mail_not_launched"
    with pytest.raises(MailProblem) as delivery:
        await service.deliver_send(quote.quote_id, token)
    assert delivery.value.code == "mail_not_launched"
    assert backend.sent == []


@pytest.mark.asyncio
async def test_custom_domain_quote_requires_managed_dns(mail_service):
    service, _sessions, _backend, domains, _refunds = mail_service
    domains.dns.configured = False

    with pytest.raises(MailProblem) as unavailable:
        await service.create_account_quote(
            MailAccountQuoteRequest(
                local_part="managed-dns-required",
                mode=MailboxMode.CUSTOM,
                domain="managed-dns-required.dev",
                domain_management_token="hyr_identity_" + "x" * 43,
                terms_version=service.mail_config.terms_version,
            )
        )

    assert unavailable.value.code == "managed_dns_not_ready"


@pytest.mark.asyncio
async def test_pricing_and_activation_quote_use_configured_term_and_storage(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    service.mail_config.active_days = 45
    service.mail_config.storage_quota_bytes = 1_610_612_736

    pricing = service.pricing()
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="configured-terms",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )

    assert pricing.active_days == 45
    assert pricing.storage_gb == 1.5
    assert pricing.storage_bytes == 1_610_612_736
    assert "45 days" in quote.constraints
    assert "1.5 GiB (1610612736 bytes)" in quote.constraints


def test_custom_mail_catalog_does_not_depend_on_domain_sales(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    service.config.domain.agent_purchases_enabled = False

    products = {product.id: product for product in service.products().products}

    assert products["agent-mail-custom"].available is True
    assert products["agent-mail-domain-bundle"].available is False


def test_domain_bundle_catalog_requires_complete_agent_checkout(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service

    incomplete = {product.id: product for product in service.products().products}
    assert incomplete["agent-mail-domain-bundle"].available is False

    service.config.domain.legal_approved = True
    service.config.domain.tax_approved = True
    service.config.domain.dns_control_url = "https://dns.internal"
    service.config.domain.dns_control_secret = "dns-control-secret"
    service.config.domain.agent_order_fernet_key = Fernet.generate_key().decode()
    service.config.openprovider.username = "operator"
    service.config.openprovider.password = "password"
    service.config.openprovider.owner_handle = "owner"
    service.config.openprovider.admin_handle = "admin"
    service.config.openprovider.tech_handle = "tech"
    service.config.openprovider.billing_handle = "billing"

    ready = {product.id: product for product in service.products().products}
    assert ready["agent-mail-domain-bundle"].available is True


@pytest.mark.asyncio
async def test_custom_domain_delegation_is_revalidated_before_payment(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    token = "hyr_identity_" + "a" * 43
    async with sessions() as session:
        session.add(
            DomainRow(
                name="authority",
                extension="dev",
                fqdn="authority.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id=None,
                anon_management_token_hash=hash_token(token),
                status="active",
            )
        )
        await session.commit()
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="agent",
            mode=MailboxMode.CUSTOM,
            domain="authority.dev",
            domain_management_token=token,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _management_token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="custom-authority-idempotency-0001",
    )
    async with sessions() as session:
        domain = await session.scalar(select(DomainRow).where(DomainRow.fqdn == "authority.dev"))
        assert domain is not None
        domain.nameserver_mode = NameserverMode.EXTERNAL.value
        await session.commit()

    with pytest.raises(MailProblem) as changed:
        await service.reserve_activation_capacity(
            account.mailbox_id,
            quote_id=quote.quote_id,
        )
    assert changed.value.code == "managed_domain_authority_changed"


@pytest.mark.asyncio
async def test_stalwart_domain_payload_uses_v016_management_variants(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    calls: list[list[list]] = []

    async def manage(method_calls):
        calls.append(method_calls)
        call_id = method_calls[0][2]
        if call_id == "query-domain":
            return {"methodResponses": [["x:Domain/query", {"ids": []}, call_id]]}
        if call_id == "create-domain":
            return {
                "methodResponses": [
                    ["x:Domain/set", {"created": {"domain": {"id": "domain-1"}}}, call_id]
                ]
            }
        zone = """example.test. 3600 MX 10 mx1.example.test.
example.test. 3600 TXT \"v=spf1 mx -all\"
selector._domainkey.example.test. 3600 TXT \"v=DKIM1; p=public-key\"
"""
        return {"methodResponses": [["x:Domain/get", {"list": [{"dnsZoneFile": zone}]}, call_id]]}

    monkeypatch.setattr(client, "_manage", manage)
    try:
        domain_id, records = await client.ensure_domain("example.test")
        assert domain_id == "domain-1"
        assert {record["type"] for record in records} == {"MX", "TXT"}
    finally:
        await client.close()

    created = calls[1][0][1]["create"]["domain"]
    assert created == {
        "name": "example.test",
        "aliases": [],
        "certificateManagement": {"@type": "Manual"},
        "dkimManagement": {"@type": "Automatic"},
        "dnsManagement": {"@type": "Manual"},
        "subAddressing": {"@type": "Disabled"},
    }


@pytest.mark.asyncio
async def test_stalwart_domain_rejects_incomplete_generated_dns(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)

    async def manage(method_calls):
        call_id = method_calls[0][2]
        if call_id == "query-domain":
            return {"methodResponses": [["x:Domain/query", {"ids": ["domain-1"]}, call_id]]}
        return {
            "methodResponses": [
                [
                    "x:Domain/get",
                    {"list": [{"dnsZoneFile": "example.test. 3600 MX 10 mx.test."}]},
                    call_id,
                ]
            ]
        }

    monkeypatch.setattr(client, "_manage", manage)
    try:
        with pytest.raises(MailDNSIncompleteError, match="MX, SPF, and DKIM"):
            await client.ensure_domain("example.test")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stalwart_account_payload_uses_local_part_and_v016_schema(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    calls: list[list[list]] = []

    async def manage(method_calls):
        calls.append(method_calls)
        call_id = method_calls[0][2]
        if call_id == "query-account":
            return {"methodResponses": [["x:Account/query", {"ids": []}, call_id]]}
        return {
            "methodResponses": [
                ["x:Account/set", {"created": {"account": {"id": "account-1"}}}, call_id]
            ]
        }

    monkeypatch.setattr(client, "_manage", manage)
    try:
        account_id = await client.ensure_account(
            address="journey@example.test",
            domain_id="domain-1",
            password="generated-secret",
            quota_bytes=1_073_741_824,
        )
    finally:
        await client.close()

    assert account_id == "account-1"
    assert calls[0][0][1]["filter"] == {"name": "journey", "domainId": "domain-1"}
    created = calls[1][0][1]["create"]["account"]
    assert created == {
        "@type": "User",
        "name": "journey",
        "domainId": "domain-1",
        "credentials": [{"@type": "Password", "secret": "generated-secret"}],
        "memberGroupIds": [],
        "roles": {"@type": "User"},
        "permissions": {"@type": "Inherit"},
        "quotas": {"maxDiskQuota": 1_073_741_824},
        "aliases": [],
        "encryptionAtRest": {"@type": "Disabled"},
    }

    with pytest.raises(MailBackendError, match="address is invalid"):
        await client.create_account(
            address="not-an-address",
            domain_id="domain-1",
            password="generated-secret",
            quota_bytes=1_073_741_824,
        )


@pytest.mark.asyncio
async def test_stalwart_account_deletion_rejects_per_account_failures(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    failure = {
        "type": "serverFail",
        "description": "Account data could not be removed",
    }

    async def manage(_method_calls):
        return {
            "methodResponses": [
                [
                    "x:Account/set",
                    {"notDestroyed": {"account-1": failure}},
                    "delete-account",
                ]
            ]
        }

    monkeypatch.setattr(client, "_manage", manage)
    try:
        with pytest.raises(MailBackendError, match="Account data could not be removed"):
            await client.delete_account("account-1")
        failure = {"type": "notFound"}
        await client.delete_account("account-1")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stalwart_rejects_standard_jmap_method_errors(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            json={
                "methodResponses": [
                    [
                        "error",
                        {"type": "serverFail", "description": "backend refused mutation"},
                        "destructive-call",
                    ]
                ]
            },
        )

    await client._http.aclose()
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def session(_address, _password):
        return {"apiUrl": "https://mail.internal/jmap"}, None

    monkeypatch.setattr(client, "_session", session)
    try:
        with pytest.raises(MailBackendError, match="backend refused mutation"):
            await client._manage(
                [["x:Account/set", {"destroy": ["account-1"]}, "destructive-call"]]
            )
        with pytest.raises(MailBackendError, match="backend refused mutation"):
            await client._jmap(
                "journey@example.test",
                "generated-secret",
                [["Email/set", {"destroy": ["message-1"]}, "destructive-call"]],
                ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stalwart_readiness_requires_an_authenticated_management_query(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.example.test"
    config.backend_token = "management-token-long-enough"
    client = StalwartClient(config)
    calls: list[list[list[object]]] = []

    async def manage(method_calls):
        calls.append(method_calls)
        return {"methodResponses": [["x:Domain/query", {"ids": []}, "readiness-domain-query"]]}

    monkeypatch.setattr(client, "_manage", manage)
    try:
        assert await client.ready() is True
    finally:
        await client.close()
    assert calls == [[["x:Domain/query", {"limit": 1}, "readiness-domain-query"]]]


@pytest.mark.asyncio
async def test_stalwart_message_deletion_uses_jmap_email_destroy(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    calls: list[tuple[list[list], list[str]]] = []

    async def session(_address, _password):
        return (
            {
                "primaryAccounts": {
                    "urn:ietf:params:jmap:mail": "account-1",
                }
            },
            None,
        )

    async def jmap(_address, _password, method_calls, using):
        calls.append((method_calls, using))
        return {
            "response": {
                "methodResponses": [
                    [
                        "Email/set",
                        {"destroyed": ["message-old"]},
                        "delete-email",
                    ]
                ]
            }
        }

    monkeypatch.setattr(client, "_session", session)
    monkeypatch.setattr(client, "_jmap", jmap)
    try:
        await client.delete_message(
            address="journey@example.test",
            password="generated-secret",
            message_id="message-old",
        )
    finally:
        await client.close()

    assert calls == [
        (
            [
                [
                    "Email/set",
                    {"accountId": "account-1", "destroy": ["message-old"]},
                    "delete-email",
                ]
            ],
            ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        )
    ]


@pytest.mark.asyncio
async def test_stalwart_listing_prefers_inbox_for_multi_mailbox_messages(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)

    async def session(_address, _password):
        return (
            {"primaryAccounts": {"urn:ietf:params:jmap:mail": "account-1"}},
            None,
        )

    async def jmap(_address, _password, method_calls, _using):
        if method_calls[0][0] == "Email/query":
            return {
                "response": {
                    "methodResponses": [["Email/query", {"ids": ["message-1"]}, "list-email-query"]]
                }
            }
        mailbox_call_id = method_calls[0][2]
        email_call_id = method_calls[1][2]
        return {
            "response": {
                "methodResponses": [
                    [
                        "Mailbox/get",
                        {
                            "list": [
                                {"id": "archive-id", "role": "archive"},
                                {"id": "inbox-id", "role": "inbox"},
                            ]
                        },
                        mailbox_call_id,
                    ],
                    [
                        "Email/get",
                        {
                            "list": [
                                {
                                    "id": "message-1",
                                    "messageId": ["<message-1@example.test>"],
                                    "mailboxIds": {"archive-id": True, "inbox-id": True},
                                    "receivedAt": datetime.now(UTC).isoformat(),
                                    "from": [{"email": "sender@example.net"}],
                                    "to": [{"email": "journey@example.test"}],
                                    "subject": "Stored twice",
                                    "attachments": [],
                                }
                            ]
                        },
                        email_call_id,
                    ],
                ]
            }
        }

    monkeypatch.setattr(client, "_session", session)
    monkeypatch.setattr(client, "_jmap", jmap)
    try:
        messages = await client.list_messages(
            address="journey@example.test",
            password="generated-secret",
            limit=50,
        )
        detail = await client.get_message(
            address="journey@example.test",
            password="generated-secret",
            message_id="message-1",
        )
    finally:
        await client.close()

    assert messages[0]["folder"] == "inbox"
    assert messages[0]["messageId"] == ["<message-1@example.test>"]
    assert detail["folder"] == "inbox"


@pytest.mark.asyncio
async def test_stalwart_attachment_download_is_bounded_before_buffering():
    config = HyruleConfig().mail
    config.backend_url = "https://mail.example.test"
    config.backend_token = "management-token-long-enough"
    config.max_attachment_bytes = 5

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jmap":
            return httpx.Response(
                200,
                json={
                    "primaryAccounts": {"urn:ietf:params:jmap:mail": "account-1"},
                    "downloadUrl": (
                        "https://mail.example.test/download/{accountId}/{blobId}/{name}?type={type}"
                    ),
                },
            )
        return httpx.Response(200, content=b"123456")

    client = StalwartClient(config)
    await client._http.aclose()
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(MailAttachmentTooLargeError):
            await client.download_blob(
                address="journey@example.test",
                password="mailbox-secret",
                blob_id="blob-1",
                name="proof.txt",
                media_type="text/plain",
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stalwart_send_requires_submission_acceptance(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    submitted_calls: list[list[list]] = []

    async def session(_address, _password):
        return (
            {"primaryAccounts": {"urn:ietf:params:jmap:mail": "account-1"}},
            None,
        )

    async def jmap(_address, _password, method_calls, _using):
        if method_calls[0][0] == "Mailbox/query":
            return {
                "response": {
                    "methodResponses": [
                        ["Mailbox/query", {"ids": ["drafts"]}, "drafts"],
                        ["Identity/get", {"list": [{"id": "identity-1"}]}, "identities"],
                    ]
                }
            }
        submitted_calls.append(method_calls)
        return {
            "response": {
                "methodResponses": [
                    [
                        "Email/set",
                        {"created": {"draft": {"id": "message-1"}}},
                        "email",
                    ],
                    [
                        "EmailSubmission/set",
                        {
                            "notCreated": {
                                "submission": {
                                    "type": "forbiddenFrom",
                                    "description": "policy rejected submission",
                                }
                            }
                        },
                        "submit",
                    ],
                ]
            }
        }

    monkeypatch.setattr(client, "_session", session)
    monkeypatch.setattr(client, "_jmap", jmap)
    try:
        with pytest.raises(MailBackendError, match="policy rejected submission"):
            await client.send_message(
                address="journey@example.test",
                password="generated-secret",
                recipient="proof@example.net",
                subject="Proof",
                text="hello",
                html=None,
                in_reply_to=None,
                send_id="send_submission_acceptance",
            )
    finally:
        await client.close()
    created_email = submitted_calls[0][0][1]["create"]["draft"]
    assert created_email["header:X-Hyrule-Send-ID:asText"] == "send_submission_acceptance"


@pytest.mark.asyncio
async def test_stalwart_send_reconciliation_queries_the_stable_header(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    calls: list[list[list]] = []

    async def session(_address, _password):
        return (
            {
                "primaryAccounts": {
                    "urn:ietf:params:jmap:mail": "account-1",
                    "urn:ietf:params:jmap:submission": "submission-account-1",
                }
            },
            None,
        )

    async def jmap(_address, _password, method_calls, _using):
        calls.append(method_calls)
        method = method_calls[0][0]
        if method == "Email/query":
            response = ["Email/query", {"ids": ["message-recovered"]}, "send-intent-query"]
        elif method == "EmailSubmission/query":
            response = [
                "EmailSubmission/query",
                {"ids": ["submission-recovered"]},
                "send-submission-query",
            ]
        else:
            response = [
                "EmailSubmission/get",
                {"list": [{"id": "submission-recovered", "emailId": "message-recovered"}]},
                "send-submission-get",
            ]
        return {"response": {"methodResponses": [response]}}

    monkeypatch.setattr(client, "_session", session)
    monkeypatch.setattr(client, "_jmap", jmap)
    try:
        assert (
            await client.find_message_by_send_id(
                address="journey@example.test",
                password="generated-secret",
                send_id="send_recovery_123",
            )
            == "message-recovered"
        )
    finally:
        await client.close()
    assert calls[0][0][1]["filter"] == {"header": ["X-Hyrule-Send-ID", "send_recovery_123"]}
    assert calls[1][0][0] == "EmailSubmission/query"
    assert calls[1][0][1]["filter"] == {"emailIds": ["message-recovered"]}
    assert calls[2][0][0] == "EmailSubmission/get"


@pytest.mark.asyncio
async def test_stalwart_send_reconciliation_ignores_matching_drafts(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)

    async def session(_address, _password):
        return (
            {"primaryAccounts": {"urn:ietf:params:jmap:mail": "account-1"}},
            None,
        )

    async def jmap(_address, _password, method_calls, _using):
        if method_calls[0][0] == "Email/query":
            response = ["Email/query", {"ids": ["draft-only"]}, "send-intent-query"]
        else:
            response = ["EmailSubmission/query", {"ids": []}, "send-submission-query"]
        return {"response": {"methodResponses": [response]}}

    monkeypatch.setattr(client, "_session", session)
    monkeypatch.setattr(client, "_jmap", jmap)
    try:
        assert (
            await client.find_message_by_send_id(
                address="journey@example.test",
                password="generated-secret",
                send_id="send_draft_only",
            )
            is None
        )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stalwart_retention_scans_mailbox_not_local_index(monkeypatch):
    config = HyruleConfig().mail
    config.backend_url = "https://mail.internal"
    config.backend_token = "token"
    client = StalwartClient(config)
    calls: list[list[list]] = []
    query_count = 0

    async def session(_address, _password):
        return (
            {"primaryAccounts": {"urn:ietf:params:jmap:mail": "account-1"}},
            None,
        )

    async def jmap(_address, _password, method_calls, _using):
        nonlocal query_count
        calls.append(method_calls)
        call_id = method_calls[0][2]
        if call_id == "retention-query":
            query_count += 1
            ids = ["old-1", "old-2"] if query_count == 1 else []
            return {"response": {"methodResponses": [["Email/query", {"ids": ids}, call_id]]}}
        return {
            "response": {
                "methodResponses": [["Email/set", {"destroyed": ["old-1", "old-2"]}, call_id]]
            }
        }

    monkeypatch.setattr(client, "_session", session)
    monkeypatch.setattr(client, "_jmap", jmap)
    try:
        deleted = await client.delete_messages_before(
            address="journey@example.test",
            password="generated-secret",
            cutoff=datetime(2026, 6, 19, tzinfo=UTC),
        )
    finally:
        await client.close()

    assert deleted == 2
    assert calls[0][0][1]["filter"] == {"before": "2026-06-19T00:00:00Z"}
    assert calls[1] == [
        [
            "Email/set",
            {"accountId": "account-1", "destroy": ["old-1", "old-2"]},
            "retention-delete",
        ]
    ]


@pytest.mark.asyncio
async def test_hosted_activation_is_idempotent_and_never_exposes_mail_protocols(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    products = service.products()
    assert products.available is True
    assert "agent-mail-domain-bundle" in {product.id for product in products.products}
    capabilities = service.capabilities()
    assert capabilities.public_smtp_submission is False
    assert capabilities.public_imap is False
    assert capabilities.webmail is False
    assert capabilities.outbound_attachments is False
    assert capabilities.inbound_attachment_max_bytes == 26_214_400
    await _active_hosted(service)


@pytest.mark.asyncio
async def test_activation_capacity_is_rechecked_when_the_quote_is_reserved(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    service.mail_config.max_active_mailboxes = 1
    first = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="capacity-first",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    second = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="capacity-second",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    first_account, _first_token, _ = await service.prepare_activation(
        first.quote_id,
        idempotency_key="capacity-first-idempotency-0001",
    )
    second_account, _second_token, _ = await service.prepare_activation(
        second.quote_id,
        idempotency_key="capacity-second-idempotency-0001",
    )
    await service.reserve_activation_capacity(first_account.mailbox_id)
    with pytest.raises(MailProblem) as full:
        await service.reserve_activation_capacity(second_account.mailbox_id)
    assert full.value.code == "mail_capacity_reached"
    async with sessions() as session:
        stored = await session.get(MailQuoteRow, second.quote_id)
        pending = await session.get(MailAccountRow, second_account.mailbox_id)
        assert stored.status == "reserved"
        assert pending.status == MailboxStatus.AWAITING_PAYMENT.value
        assert pending.capacity_reserved_at is None


@pytest.mark.asyncio
async def test_deleted_mailbox_address_is_recycled_for_reactivation(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    first = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="reactivate-me",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    original, original_token, _ = await service.prepare_activation(
        first.quote_id,
        idempotency_key="reactivation-original-idempotency-0001",
    )
    async with sessions() as session:
        tombstone = await session.get(MailAccountRow, original.mailbox_id)
        tombstone.status = MailboxStatus.DELETED.value
        tombstone.management_token_ciphertext = None
        tombstone.deleted_at = datetime.now(UTC)
        await session.commit()

    second = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="reactivate-me",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    reactivated, new_token, created = await service.prepare_activation(
        second.quote_id,
        idempotency_key="reactivation-new-idempotency-0002",
    )

    assert created is True
    assert reactivated.mailbox_id == original.mailbox_id
    assert new_token != original_token
    assert reactivated.status == MailboxStatus.AWAITING_PAYMENT.value
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(MailAccountRow)
                .where(MailAccountRow.address == reactivated.address)
            )
            == 1
        )


@pytest.mark.asyncio
async def test_incomplete_mail_dns_keeps_provisioning_retryable(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="dns-retry",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="dns-retry-idempotency-0001",
    )
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "d" * 40,
        tx_hash="0xdns-retry",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    original_ensure_domain = backend.ensure_domain

    async def incomplete_domain(_domain):
        raise MailDNSIncompleteError("generated zone is incomplete")

    backend.ensure_domain = incomplete_domain
    assert await service.provision_pending() == 0
    async with sessions() as session:
        pending = await session.get(MailAccountRow, account.mailbox_id)
        refunds = await session.scalar(
            select(func.count())
            .select_from(PaymentEventRow)
            .where(PaymentEventRow.event_type == "refund_owed")
        )
        assert pending.status == MailboxStatus.PROVISIONING.value
        assert pending.provision_retry_count == 1
        assert pending.provision_next_attempt_at is not None
        assert "1/15 attempts" in pending.provision_error
        assert refunds == 0
        pending.provision_next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    backend.ensure_domain = original_ensure_domain
    assert await service.provision_pending() == 1


@pytest.mark.asyncio
async def test_unready_domain_orders_do_not_starve_ready_mailboxes(mail_service):
    service, sessions, _backend, domains, _refunds = mail_service

    async def awaiting_provision(local_part: str, key: str):
        quote = await service.create_account_quote(
            MailAccountQuoteRequest(
                local_part=local_part,
                mode=MailboxMode.HOSTED,
                terms_version=service.mail_config.terms_version,
            )
        )
        account, _token, _created = await service.prepare_activation(
            quote.quote_id,
            idempotency_key=key,
        )
        return await service.mark_activation_paid(
            account.mailbox_id,
            quote.quote_id,
            payer="0x" + "8" * 40,
            tx_hash=f"0x{local_part}",
            payment_network="eip155:8453",
            payment_asset="USDC",
        )

    blocked = await awaiting_provision(
        "blocked-domain-order",
        "blocked-domain-order-idempotency-0001",
    )
    ready = await awaiting_provision(
        "ready-hosted-mailbox",
        "ready-hosted-mailbox-idempotency-0001",
    )
    active_domain = await awaiting_provision(
        "ready-domain-order",
        "ready-domain-order-idempotency-0001",
    )
    now = datetime.now(UTC)
    async with sessions() as session:
        blocked_row = await session.get(MailAccountRow, blocked.mailbox_id)
        ready_row = await session.get(MailAccountRow, ready.mailbox_id)
        active_domain_row = await session.get(MailAccountRow, active_domain.mailbox_id)
        blocked_row.status = MailboxStatus.PENDING_DOMAIN.value
        blocked_row.plan = MailboxMode.DOMAIN_AND_MAILBOX.value
        blocked_row.domain = "blocked-domain-order.dev"
        blocked_row.domain_order_id = "do_blocked_domain_order"
        blocked_row.created_at = now - timedelta(hours=3)
        ready_row.created_at = now - timedelta(hours=2)
        active_domain_row.status = MailboxStatus.PENDING_DOMAIN.value
        active_domain_row.domain_order_id = "do_ready_domain_order"
        active_domain_row.created_at = now - timedelta(hours=1)
        session.add_all(
            [
                DomainOrderRow(
                    order_id="do_blocked_domain_order",
                    quote_id="dq_blocked_domain_order",
                    fqdn="blocked-domain-order.dev",
                    action="register",
                    owner_account_id=None,
                    idempotency_key="blocked-domain-order",
                    status=DomainOrderStatus.PROVIDER_PENDING.value,
                    amount_usd=Decimal("1"),
                    domain_amount_usd=Decimal("1"),
                    vm_amount_usd=Decimal("0"),
                    service_amount_usd=Decimal("0"),
                    payment_method="usdc",
                    on_domain_failure="keep_vm",
                    terms_version=service.config.domain.terms_version,
                    terms_accepted_at=now,
                ),
                DomainOrderRow(
                    order_id="do_ready_domain_order",
                    quote_id="dq_ready_domain_order",
                    fqdn="ready-domain-order.dev",
                    action="register",
                    owner_account_id=None,
                    idempotency_key="ready-domain-order",
                    status=DomainOrderStatus.ACTIVE.value,
                    amount_usd=Decimal("1"),
                    domain_amount_usd=Decimal("1"),
                    vm_amount_usd=Decimal("0"),
                    service_amount_usd=Decimal("0"),
                    payment_method="usdc",
                    on_domain_failure="keep_vm",
                    terms_version=service.config.domain.terms_version,
                    terms_accepted_at=now,
                ),
            ]
        )
        await session.commit()

    assert await service.provision_pending(limit=1) == 1
    async with sessions() as session:
        still_blocked = await session.get(MailAccountRow, blocked.mailbox_id)
        provisioned = await session.get(MailAccountRow, ready.mailbox_id)
        promoted = await session.get(MailAccountRow, active_domain.mailbox_id)
    assert still_blocked.status == MailboxStatus.PENDING_DOMAIN.value
    assert provisioned.status == MailboxStatus.ACTIVE.value
    assert promoted.status == MailboxStatus.PROVISIONING.value

    assert await service.provision_pending(limit=1) == 1
    async with sessions() as session:
        active_domain_provisioned = await session.get(
            MailAccountRow,
            active_domain.mailbox_id,
        )
    assert active_domain_provisioned.status == MailboxStatus.ACTIVE.value

    async with sessions() as session:
        blocked_order = await session.get(DomainOrderRow, "do_blocked_domain_order")
        blocked_order.status = DomainOrderStatus.REFUNDED.value
        await session.commit()
    assert await service.provision_pending(limit=1) == 1
    async with sessions() as session:
        terminal = await session.get(MailAccountRow, blocked.mailbox_id)
    assert terminal.status == MailboxStatus.FAILED.value
    assert terminal.provision_error == "domain_registration_failed"
    assert terminal.dns_cleanup_pending is False
    assert domains.removed_service_records == []


@pytest.mark.asyncio
async def test_incomplete_mail_dns_eventually_fails_and_refunds(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    service.mail_config.provision_dns_max_attempts = 2
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="dns-exhausted",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="dns-exhausted-idempotency-0001",
    )
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "e" * 40,
        tx_hash="0xdns-exhausted",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )

    async def incomplete_domain(_domain):
        raise MailDNSIncompleteError("generated zone is incomplete")

    backend.ensure_domain = incomplete_domain
    assert await service.provision_pending() == 0
    async with sessions() as session:
        pending = await session.get(MailAccountRow, account.mailbox_id)
        pending.provision_next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    assert await service.provision_pending() == 1
    async with sessions() as session:
        failed = await session.get(MailAccountRow, account.mailbox_id)
        refund = await session.scalar(
            select(PaymentEventRow).where(
                PaymentEventRow.event_type == "refund_owed",
                PaymentEventRow.extra["mailbox_id"].as_string() == account.mailbox_id,
            )
        )
        assert failed.status == MailboxStatus.REFUND_DUE.value
        assert failed.provision_retry_count == 2
        assert failed.provision_error == "mailbox_dns_incomplete_after_2_attempts"
        assert refund is not None
    with pytest.raises(MailProblem) as closed:
        await service.get_account(account.mailbox_id, token)
    assert closed.value.code == "mailbox_activation_failed"


@pytest.mark.asyncio
async def test_paid_reservation_enforces_one_mailbox_per_custom_domain(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    requests = [
        MailAccountQuoteRequest(
            local_part=local_part,
            mode=MailboxMode.DOMAIN_AND_MAILBOX,
            domain="exclusive-mail.dev",
            terms_version=service.mail_config.terms_version,
            domain_terms_version=service.config.domain.terms_version,
        )
        for local_part in ("first", "second")
    ]
    first_quote = await service.create_account_quote(requests[0])
    second_quote = await service.create_account_quote(requests[1])
    first, _first_token, _ = await service.prepare_activation(
        first_quote.quote_id,
        idempotency_key="exclusive-domain-first-idempotency-0001",
    )
    second, _second_token, _ = await service.prepare_activation(
        second_quote.quote_id,
        idempotency_key="exclusive-domain-second-idempotency-0002",
    )

    await service.reserve_activation_capacity(first.mailbox_id)
    with pytest.raises(MailProblem) as conflict:
        await service.reserve_activation_capacity(second.mailbox_id)
    assert conflict.value.code == "domain_mailbox_exists"


@pytest.mark.asyncio
async def test_provisioning_reuses_password_after_process_interruption(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="crash-safe",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="crash-safe-activation-idempotency-0001",
    )
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x1234567890abcdef",
        tx_hash="0xpaid-crash-safe",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    first_passwords: list[str] = []
    original_ensure = backend.ensure_account

    async def interrupted_ensure(**kwargs):
        first_passwords.append(kwargs["password"])
        raise KeyboardInterrupt

    backend.ensure_account = interrupted_ensure
    with pytest.raises(KeyboardInterrupt):
        await service._provision_one(account.mailbox_id)
    async with sessions() as session:
        interrupted = await session.get(MailAccountRow, account.mailbox_id)
        assert interrupted.backend_credential_ciphertext
        assert interrupted.status == MailboxStatus.PROVISIONING.value
        interrupted.provision_claimed_at = datetime.now(UTC) - timedelta(
            seconds=service.mail_config.provision_lease_seconds + 1
        )
        await session.commit()

    backend.ensure_account = original_ensure
    await service._provision_one(account.mailbox_id)
    assert backend.accounts[-1]["password"] == first_passwords[0]
    current = await service.get_account(account.mailbox_id, _token)
    assert current.status is MailboxStatus.ACTIVE


@pytest.mark.asyncio
async def test_provisioning_lease_prevents_concurrent_backend_cleanup(mail_service):
    service, _sessions, backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="leased-provisioning",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="leased-provisioning-idempotency-0001",
    )
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "7" * 40,
        tx_hash="0xleased-provisioning",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    original_ensure = backend.ensure_account

    async def slow_ensure(**kwargs):
        entered.set()
        await release.wait()
        return await original_ensure(**kwargs)

    backend.ensure_account = slow_ensure
    first = asyncio.create_task(service._provision_one(account.mailbox_id))
    await entered.wait()
    assert await service._provision_one(account.mailbox_id) is False
    release.set()
    assert await first is True

    current = await service.get_account(account.mailbox_id, token)
    assert current.status is MailboxStatus.ACTIVE
    assert len(backend.accounts) == 1
    assert backend.deleted == []


@pytest.mark.asyncio
async def test_expired_provisioning_lease_never_deletes_the_winners_account(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="expired-lease",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="expired-lease-idempotency-0001",
    )
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "8" * 40,
        tx_hash="0xexpired-lease",
        payment_network="eip155:8453",
        payment_asset="USDC",
    )
    first_entered = asyncio.Event()
    release_first = asyncio.Event()
    original_ensure = backend.ensure_account
    calls = 0

    async def stale_first_ensure(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            first_entered.set()
            await release_first.wait()
        return await original_ensure(**kwargs)

    backend.ensure_account = stale_first_ensure
    stale_worker = asyncio.create_task(service._provision_one(account.mailbox_id))
    await first_entered.wait()
    async with sessions() as session:
        claimed = await session.get(MailAccountRow, account.mailbox_id)
        claimed.provision_claimed_at = datetime.now(UTC) - timedelta(
            seconds=service.mail_config.provision_lease_seconds + 1
        )
        await session.commit()

    assert await service._provision_one(account.mailbox_id) is True
    release_first.set()
    assert await stale_worker is False

    current = await service.get_account(account.mailbox_id, token)
    assert current.status is MailboxStatus.ACTIVE
    assert len(backend.accounts) == 2
    assert backend.deleted == []


@pytest.mark.asyncio
async def test_settlement_ledger_recovers_lost_mail_activation_handoff(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="recover-payment",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="recover-mail-payment-idempotency-0001",
    )
    ledger = PaymentLedger(sessions)
    event = ledger.build_event(
        event_type="settled",
        resource_path="/v1/mail/accounts",
        method="POST",
        amount=service.config.payment.price_mail_activation,
        network="eip155:8453",
        asset="USDC",
        payer="0x" + "4" * 40,
        tx_hash="0xmail-recover",
        extra={
            "mailbox_id": account.mailbox_id,
            "quote_id": quote.quote_id,
            "address": account.address,
        },
    )
    irrelevant_events = [
        ledger.build_event(
            event_type="settled",
            resource_path="/v1/mail/accounts",
            method="POST",
            amount=service.config.payment.price_mail_activation,
            network="eip155:8453",
            asset="USDC",
            payer="0x" + "5" * 40,
            tx_hash=f"0xirrelevant-mail-{index}",
            extra={
                "mailbox_id": f"mbx_irrelevant_{index}",
                "quote_id": f"mailq_irrelevant_{index}",
            },
        )
        for index in range(3)
    ]
    async with sessions() as session:
        stored_quote = await session.get(MailQuoteRow, quote.quote_id)
        stored_quote.expires_at = datetime.now(UTC) - timedelta(hours=2)
        session.add_all([event, *irrelevant_events])
        await session.commit()

    assert await service.expire_quotes() == 0
    async with sessions() as session:
        preserved = await session.get(MailAccountRow, account.mailbox_id)
        assert preserved.status == MailboxStatus.AWAITING_PAYMENT.value
        assert preserved.management_token_ciphertext
    assert await service.recover_x402_handoffs(limit=1) == 1
    assert await service.recover_x402_handoffs(limit=1) == 0
    async with sessions() as session:
        recovered = await session.get(MailAccountRow, account.mailbox_id)
        assert recovered.status == MailboxStatus.PROVISIONING.value
        assert recovered.payment_tx == "0xmail-recover"


@pytest.mark.asyncio
async def test_durable_activation_settlement_recovers_without_metrics_ledger(
    mail_service, monkeypatch
):
    service, sessions, _backend, _domains, _refunds = mail_service
    service.config.payment.dev_bypass_secret = "mail-dev-bypass"
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="durable-settlement",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("cloud.hyrule.host", 443),
            "path": "/v1/mail/accounts",
            "query_string": b"",
            "headers": [(b"x-dev-bypass", b"mail-dev-bypass")],
        }
    )
    original_mark_paid = service.mark_activation_paid

    async def interrupted_handoff(*_args, **_kwargs):
        raise RuntimeError("API process lost the provisioning handoff")

    monkeypatch.setattr(service, "mark_activation_paid", interrupted_handoff)
    with pytest.raises(MailProblem) as pending:
        await create_account(
            MailAccountCreateRequest(quote_id=quote.quote_id),
            request,
            Response(),
            idempotency_key="durable-settlement-idempotency-0001",
            service=service,
            gate=PaymentGate(service.config.payment),
        )
    assert pending.value.code == "mail_payment_handoff_pending"
    async with sessions() as session:
        account = await session.scalar(
            select(MailAccountRow).where(MailAccountRow.quote_id == quote.quote_id)
        )
        assert account.status == MailboxStatus.AWAITING_PAYMENT.value
        assert account.payment_settled_at is not None
        assert account.payment_settlement_pending_at is None
        assert account.payment_tx == "dev_bypass_0x0"
        assert await session.scalar(select(func.count()).select_from(PaymentEventRow)) == 0

    monkeypatch.setattr(service, "mark_activation_paid", original_mark_paid)
    assert await service.recover_x402_handoffs() == 1
    async with sessions() as session:
        recovered = await session.get(MailAccountRow, account.mailbox_id)
        assert recovered.status == MailboxStatus.PROVISIONING.value


@pytest.mark.asyncio
async def test_stored_authorization_recovers_mail_payment_without_metrics_ledger(
    mail_service,
):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="authorization-recovery",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="authorization-recovery-idempotency-0001",
    )
    await service.reserve_activation_capacity(
        account.mailbox_id,
        quote_id=quote.quote_id,
    )
    await service.begin_activation_settlement(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "4" * 40,
        payment_network="eip155:8453",
        payment_asset="0x" + "5" * 40,
        payment_authorization="stored-eip3009-authorization",
    )

    class _RecoveryGate:
        async def reconcile_settlement(self, header, amount, *, pending_since, resource_key):
            assert header == "stored-eip3009-authorization"
            assert amount == Decimal(quote.amount_usd)
            assert pending_since is not None
            assert resource_key == f"mail_activation:{quote.quote_id}"
            return PaymentReconciliation(
                payment=RecoveredPayment(
                    payer="0x" + "4" * 40,
                    tx_hash="0xauthorization-recovered",
                    network="eip155:8453",
                    asset="0x" + "5" * 40,
                )
            )

    assert await service.recover_x402_handoffs(gate=_RecoveryGate()) == 1
    async with sessions() as session:
        recovered = await session.get(MailAccountRow, account.mailbox_id)
        events = list(await session.scalars(select(PaymentEventRow)))
    assert recovered is not None
    assert recovered.status == MailboxStatus.PROVISIONING.value
    assert recovered.payment_tx == "0xauthorization-recovered"
    assert recovered.payment_authorization_header is None
    assert events == []


@pytest.mark.asyncio
async def test_unpaid_activation_reports_zero_charged_amount(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="uncharged-activation",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="uncharged-activation-idempotency-0001",
    )

    pending = await service.activation_response(account, management_token=token)

    assert pending.status is MailboxStatus.AWAITING_PAYMENT
    assert pending.charged_amount_usd == "0.00"


@pytest.mark.asyncio
async def test_terminal_authorization_releases_mail_capacity(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="terminal-authorization",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="terminal-authorization-idempotency-0001",
    )
    await service.reserve_activation_capacity(account.mailbox_id, quote_id=quote.quote_id)
    await service.begin_activation_settlement(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "4" * 40,
        payment_network="eip155:8453",
        payment_asset="0x" + "5" * 40,
        payment_authorization="expired-authorization",
    )

    class _ExpiredGate:
        async def reconcile_settlement(self, header, amount, *, pending_since, resource_key):
            assert header == "expired-authorization"
            assert amount == Decimal(quote.amount_usd)
            assert pending_since is not None
            assert resource_key == f"mail_activation:{quote.quote_id}"
            return PaymentReconciliation(
                terminal_unsettled=True,
                reason="expired",
            )

    assert await service.recover_x402_handoffs(gate=_ExpiredGate()) == 0
    async with sessions() as session:
        closed = await session.get(MailAccountRow, account.mailbox_id)
        closed_quote = await session.get(MailQuoteRow, quote.quote_id)
    assert closed is not None
    assert closed.status == MailboxStatus.DELETED.value
    assert closed.capacity_reserved_at is None
    assert closed.payment_settlement_pending_at is None
    assert closed.payment_authorization_header is None
    assert closed.provision_error == "payment_authorization_expired"
    assert closed_quote is not None
    assert closed_quote.status == "expired"
    assert closed_quote.request_payload == {
        "redacted": True,
        "mode": MailboxMode.HOSTED.value,
        "activation_amount_usd": quote.activation_amount_usd,
    }
    rendered = await service.get_quote(quote.quote_id)
    assert rendered.mode is MailboxMode.HOSTED
    assert rendered.activation_amount_usd == quote.activation_amount_usd
    assert rendered.amount_usd == quote.amount_usd


@pytest.mark.asyncio
async def test_unpaid_activation_expiry_releases_address_after_handoff_grace(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="released-after-expiry",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="released-after-expiry-first-0001",
    )
    async with sessions() as session:
        stored_quote = await session.get(MailQuoteRow, quote.quote_id)
        stored_quote.expires_at = datetime.now(UTC) - timedelta(hours=2)
        await session.commit()

    assert await service.expire_quotes() == 1
    async with sessions() as session:
        expired = await session.get(MailAccountRow, account.mailbox_id)
        assert expired.status == MailboxStatus.DELETED.value
        assert expired.management_token_ciphertext is None
        assert expired.deleted_at is not None

    replacement_quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="released-after-expiry",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    replacement, _replacement_token, replacement_created = await service.prepare_activation(
        replacement_quote.quote_id,
        idempotency_key="released-after-expiry-second-0002",
    )
    assert replacement_created is True
    assert replacement.mailbox_id == account.mailbox_id


@pytest.mark.asyncio
async def test_historical_payment_cannot_recover_a_reactivated_address(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    first_quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="historical-payment",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    first, _first_token, _ = await service.prepare_activation(
        first_quote.quote_id,
        idempotency_key="historical-payment-first-0001",
    )
    historical = PaymentLedger(sessions).build_event(
        event_type="settled",
        resource_path="/v1/mail/accounts",
        method="POST",
        amount=Decimal(first_quote.amount_usd),
        network="eip155:8453",
        asset="USDC",
        payer="0x" + "6" * 40,
        tx_hash="0xhistorical-payment",
        extra={
            "mailbox_id": first.mailbox_id,
            "quote_id": first_quote.quote_id,
            "address": first.address,
        },
    )
    async with sessions() as session:
        tombstone = await session.get(MailAccountRow, first.mailbox_id)
        tombstone.status = MailboxStatus.DELETED.value
        tombstone.management_token_ciphertext = None
        tombstone.deleted_at = datetime.now(UTC)
        session.add(historical)
        await session.commit()

    second_quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="historical-payment",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    second, _second_token, _ = await service.prepare_activation(
        second_quote.quote_id,
        idempotency_key="historical-payment-second-0002",
    )
    assert second.mailbox_id == first.mailbox_id

    assert await service.recover_x402_handoffs() == 0
    async with sessions() as session:
        awaiting = await session.get(MailAccountRow, second.mailbox_id)
        assert awaiting.quote_id == second_quote.quote_id
        assert awaiting.status == MailboxStatus.AWAITING_PAYMENT.value
        assert awaiting.payment_tx is None


@pytest.mark.asyncio
async def test_paid_activation_failure_commits_refund_obligation_with_terminal_state(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="refund-atomic",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="refund-atomic-idempotency-0001",
    )
    await service.mark_activation_paid(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "5" * 40,
        tx_hash="0xrefund-source",
        payment_network="eip155:8453",
        payment_asset="0x" + "a" * 40,
    )
    await service._fail_activation(account.mailbox_id, "backend failed", refund=True)

    async with sessions() as session:
        failed = await session.get(MailAccountRow, account.mailbox_id)
        obligation = await session.scalar(
            select(PaymentEventRow).where(
                PaymentEventRow.event_type == "refund_owed",
                PaymentEventRow.extra["mailbox_id"].as_string() == account.mailbox_id,
            )
        )
        assert failed.status == MailboxStatus.REFUND_DUE.value
        assert obligation is not None
        assert obligation.asset == "0x" + "a" * 40
        assert obligation.tx_hash == "0xrefund-source"


@pytest.mark.asyncio
async def test_failed_activation_retries_backend_cleanup_and_closes_reads(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="cleanup-retry",
        idempotency_key="cleanup-retry-idempotency-0001",
    )
    async with sessions() as session:
        active = await session.get(MailAccountRow, mailbox_id)
        backend_id = active.backend_id
    original_delete = backend.delete_account

    async def unavailable_delete(_backend_id):
        raise MailBackendError("backend temporarily unavailable")

    backend.delete_account = unavailable_delete
    await service._fail_activation(mailbox_id, "post-create failure", refund=True)

    with pytest.raises(MailProblem) as closed:
        await service.get_account(mailbox_id, token)
    assert closed.value.code == "mailbox_activation_failed"
    async with sessions() as session:
        failed = await session.get(MailAccountRow, mailbox_id)
        assert failed.status == MailboxStatus.REFUND_DUE.value
        assert failed.backend_id == backend_id
        assert failed.backend_credential_ciphertext

    backend.delete_account = original_delete
    assert await service.retry_failed_backend_cleanup() == 1
    async with sessions() as session:
        cleaned = await session.get(MailAccountRow, mailbox_id)
        assert cleaned.backend_id is None
        assert cleaned.backend_credential_ciphertext is None
    assert backend.deleted == [backend_id]


@pytest.mark.asyncio
async def test_failed_activation_persists_and_retries_dns_cleanup(mail_service, monkeypatch):
    service, sessions, _backend, domains, _refunds = mail_service
    mailbox_id, _token = await _active_hosted(
        service,
        local_part="dns-cleanup-retry",
        idempotency_key="dns-cleanup-retry-idempotency-0001",
    )
    async with sessions() as session:
        account = await session.get(MailAccountRow, mailbox_id)
        account.plan = MailboxMode.CUSTOM.value
        account.domain = "dns-cleanup-retry.dev"
        await session.commit()

    attempts = 0

    async def remove_service_records(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            async with sessions() as session:
                terminal = await session.get(MailAccountRow, mailbox_id)
                assert terminal.status == MailboxStatus.REFUND_DUE.value
                assert terminal.dns_cleanup_pending is True
            raise RuntimeError("DNS control plane unavailable")

    monkeypatch.setattr(domains, "remove_service_records", remove_service_records)
    assert await service._fail_activation(mailbox_id, "post-DNS provisioning failure", refund=True)
    async with sessions() as session:
        failed = await session.get(MailAccountRow, mailbox_id)
        assert failed.status == MailboxStatus.REFUND_DUE.value
        assert failed.provision_error == "post-DNS provisioning failure"
        assert failed.dns_cleanup_pending is True

    replacement_quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="dns-cleanup-replacement",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    replacement, _replacement_token, _created = await service.prepare_activation(
        replacement_quote.quote_id,
        idempotency_key="dns-cleanup-replacement-idempotency-0001",
    )
    async with sessions() as session:
        replacement_row = await session.get(MailAccountRow, replacement.mailbox_id)
        replacement_row.plan = MailboxMode.CUSTOM.value
        replacement_row.domain = "dns-cleanup-retry.dev"
        replacement_row.domain_authority_hash = hash_token("replacement-domain-authority")
        session.add(
            DomainRow(
                name="dns-cleanup-retry",
                extension="dev",
                fqdn="dns-cleanup-retry.dev",
                owner_wallet="0x" + "1" * 40,
                owner_account_id=None,
                anon_management_token_hash=hash_token("replacement-domain-authority"),
                status="active",
            )
        )
        await session.commit()
    with pytest.raises(MailProblem) as still_reserved:
        await service.reserve_activation_capacity(
            replacement.mailbox_id,
            quote_id=replacement_quote.quote_id,
        )
    assert still_reserved.value.code == "domain_mailbox_exists"

    assert await service.process_lifecycle() == 1
    await service.reserve_activation_capacity(
        replacement.mailbox_id,
        quote_id=replacement_quote.quote_id,
    )
    async with sessions() as session:
        cleaned = await session.get(MailAccountRow, mailbox_id)
        replacement_row = await session.get(MailAccountRow, replacement.mailbox_id)
        assert cleaned.provision_error == "post-DNS provisioning failure"
        assert cleaned.dns_cleanup_pending is False
        assert replacement_row.capacity_reserved_at is not None
    assert attempts == 2


@pytest.mark.asyncio
async def test_paid_activation_never_writes_capability_to_payment_ledger(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    service.config.payment.dev_bypass_secret = "mail-dev-bypass"
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="ledger-safe",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("cloud.hyrule.host", 443),
            "path": "/v1/mail/accounts",
            "query_string": b"",
            "headers": [(b"x-dev-bypass", b"mail-dev-bypass")],
        }
    )
    route_response = Response()
    result = await create_account(
        MailAccountCreateRequest(quote_id=quote.quote_id),
        request,
        route_response,
        idempotency_key="ledger-safe-activation-idempotency-0001",
        service=service,
        gate=PaymentGate(service.config.payment, ledger=PaymentLedger(sessions)),
    )
    assert not isinstance(result, Response)
    assert result.management_token
    assert route_response.headers["cache-control"] == "no-store"
    async with sessions() as session:
        event = await session.scalar(
            select(PaymentEventRow).where(PaymentEventRow.event_type == "dev_bypass")
        )
    assert event is not None
    assert event.extra["mailbox_id"] == result.mailbox_id
    assert event.extra["quote_id"] == quote.quote_id
    assert "management_token" not in event.extra
    assert result.management_token not in json.dumps(event.extra)


@pytest.mark.asyncio
async def test_combined_domain_and_mailbox_quote_is_one_atomic_amount(mail_service):
    service, sessions, _backend, domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="agent",
            mode=MailboxMode.DOMAIN_AND_MAILBOX,
            domain="prompttoproof.dev",
            terms_version=service.mail_config.terms_version,
            domain_terms_version=service.config.domain.terms_version,
        )
    )
    assert quote.domain_amount_usd == "12.00"
    assert quote.activation_amount_usd == "1.00"
    assert quote.amount_usd == "13.00"
    service.config.payment.price_mail_activation = Decimal("9.99")
    unchanged = await service.get_quote(quote.quote_id)
    assert unchanged.domain_amount_usd == "12.00"
    assert unchanged.activation_amount_usd == "1.00"
    assert unchanged.amount_usd == "13.00"
    account, token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="atomic-domain-mail-idempotency-0001",
    )
    assert account.domain_order_id == "do_atomic_123456"
    assert domains.agent_orders[0]["additional_amount_usd"] == Decimal("1.00")
    assert domains.agent_orders[0]["management_token"] == token
    async with sessions() as session:
        stored = await session.get(MailAccountRow, account.mailbox_id)
        assert stored.activation_amount_usd == Decimal("1.00")
        assert stored.total_amount_usd == Decimal("13.00")


@pytest.mark.asyncio
async def test_combined_activation_hashes_maximum_length_domain_idempotency_key(mail_service):
    service, _sessions, _backend, domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="long-idempotency",
            mode=MailboxMode.DOMAIN_AND_MAILBOX,
            domain="long-idempotency.dev",
            terms_version=service.mail_config.terms_version,
            domain_terms_version=service.config.domain.terms_version,
        )
    )
    key = "k" * 128

    await service.prepare_activation(quote.quote_id, idempotency_key=key)

    derived = domains.agent_orders[-1]["idempotency_key"]
    assert derived == f"mail:{hashlib.sha256(key.encode()).hexdigest()}"
    assert len(derived) <= 128


@pytest.mark.asyncio
async def test_combined_activation_reuses_committed_domain_capability_on_retry(
    mail_service, monkeypatch
):
    service, sessions, _backend, domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="domain-token-replay",
            mode=MailboxMode.DOMAIN_AND_MAILBOX,
            domain="domain-token-replay.dev",
            terms_version=service.mail_config.terms_version,
            domain_terms_version=service.config.domain.terms_version,
        )
    )
    committed_token: str | None = None

    async def create_committed_order(**kwargs):
        nonlocal committed_token
        created = committed_token is None
        committed_token = committed_token or kwargs["management_token"]
        if created:
            service.mail_config.max_active_mailboxes = 0
        return SimpleNamespace(order_id="do_committed_123"), committed_token, created

    monkeypatch.setattr(domains, "create_agent_order", create_committed_order)
    key = "domain-token-retry-idempotency-0001"
    with pytest.raises(MailProblem) as capacity:
        await service.prepare_activation(quote.quote_id, idempotency_key=key)
    assert capacity.value.code == "mail_capacity_reached"
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(MailAccountRow)) == 0

    service.mail_config.max_active_mailboxes = 20
    account, replayed_token, created = await service.prepare_activation(
        quote.quote_id, idempotency_key=key
    )

    assert created is True
    assert committed_token is not None
    assert replayed_token == committed_token
    async with sessions() as session:
        stored = await session.get(MailAccountRow, account.mailbox_id)
        assert service._token_matches(stored, committed_token)


@pytest.mark.asyncio
async def test_activation_quote_is_rejected_after_mail_terms_change(mail_service):
    service, sessions, _backend, domains, _refunds = mail_service
    accepted_terms = service.mail_config.terms_version
    prepared_quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="terms-snapshot",
            mode=MailboxMode.HOSTED,
            terms_version=accepted_terms,
        )
    )
    unprepared_quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="terms-snapshot-unprepared",
            mode=MailboxMode.HOSTED,
            terms_version=accepted_terms,
        )
    )
    prepared, _token, _ = await service.prepare_activation(
        prepared_quote.quote_id,
        idempotency_key="terms-snapshot-idempotency-0001",
    )
    service.mail_config.terms_version = "2026-08-05"

    with pytest.raises(MailProblem) as changed_before_prepare:
        await service.prepare_activation(
            unprepared_quote.quote_id,
            idempotency_key="terms-snapshot-unprepared-idempotency-0002",
        )
    with pytest.raises(MailProblem) as changed_after_prepare:
        await service.prepare_activation(
            prepared_quote.quote_id,
            idempotency_key="terms-snapshot-idempotency-0001",
        )

    assert changed_before_prepare.value.code == "terms_changed"
    assert changed_after_prepare.value.code == "terms_changed"
    assert domains.agent_orders == []
    async with sessions() as session:
        stored = await session.get(MailAccountRow, prepared.mailbox_id)
        assert stored.terms_version == accepted_terms
        assert await session.scalar(select(func.count()).select_from(MailAccountRow)) == 1


@pytest.mark.asyncio
async def test_send_payload_is_locked_sanitized_and_rate_limited(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Canary",
            text="Plain canary",
            html='<p>Hello</p><script>alert(1)</script><a href="javascript:bad">bad</a>',
        ),
        token,
    )
    async with sessions() as session:
        stored = await session.get(MailQuoteRow, quote.quote_id)
        assert "<script" not in stored.request_payload["html"]
        assert "javascript:" not in stored.request_payload["html"]
    sent = await service.deliver_send(quote.quote_id, token)
    assert sent.status == "accepted"
    assert len(backend.sent) == 1
    async with sessions() as session:
        consumed = await session.get(MailQuoteRow, quote.quote_id)
        assert consumed.request_payload == {"redacted": True}

    second = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="second@example.net",
            subject="Second",
            text="Should be blocked before submission",
        ),
        token,
    )
    with pytest.raises(MailProblem) as limited:
        await service.deliver_send(second.quote_id, token)
    assert limited.value.code == "mailbox_send_limit"
    assert len(backend.sent) == 1


@pytest.mark.asyncio
async def test_new_recipient_limit_excludes_known_and_duplicate_pending_addresses(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    service.mail_config.mailbox_send_limit_per_day = 10
    service.mail_config.mailbox_new_recipient_limit_per_day = 2
    mailbox_id, token = await _active_hosted(
        service,
        local_part="recipient-union",
        idempotency_key="recipient-union-idempotency-0001",
    )
    now = datetime.now(UTC)
    async with sessions() as session:
        session.add_all(
            [
                MailRecipientRow(
                    mailbox_id=mailbox_id,
                    recipient="known@example.net",
                    first_sent_at=now - timedelta(days=2),
                    last_sent_at=now,
                ),
                MailRecipientRow(
                    mailbox_id=mailbox_id,
                    recipient="today@example.net",
                    first_sent_at=now,
                    last_sent_at=now,
                ),
                MailSendRow(
                    send_id="send_pending_known",
                    mailbox_id=mailbox_id,
                    quote_id="mailq_pending_known",
                    recipient="known@example.net",
                    status="pending",
                    created_at=now,
                ),
                MailSendRow(
                    send_id="send_pending_today",
                    mailbox_id=mailbox_id,
                    quote_id="mailq_pending_today",
                    recipient="today@example.net",
                    status="submitting",
                    created_at=now,
                ),
            ]
        )
        await session.commit()
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="genuinely-new@example.net",
            subject="Union count",
            text="Only the distinct genuinely new recipients count.",
        ),
        token,
    )

    sent = await service.deliver_send(quote.quote_id, token)

    assert sent.status == "accepted"
    assert sent.recipient == "genuinely-new@example.net"


@pytest.mark.asyncio
async def test_send_intent_reconciles_after_acceptance_without_duplicate_submission(
    mail_service, monkeypatch
):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Crash-safe",
            text="Send exactly once",
        ),
        token,
    )
    original_finalize = service._finalize_send

    async def interrupted_finalize(_send_id, _message_id):
        raise KeyboardInterrupt

    monkeypatch.setattr(service, "_finalize_send", interrupted_finalize)
    with pytest.raises(KeyboardInterrupt):
        await service.deliver_send(quote.quote_id, token)
    assert len(backend.sent) == 1
    async with sessions() as session:
        intent = await session.scalar(
            select(MailSendRow).where(MailSendRow.quote_id == quote.quote_id)
        )
        assert intent.status == "submitting"
        assert intent.submission_started_at is not None
        assert intent.amount_usd == Decimal(quote.amount_usd)
        intent.submission_started_at = datetime.now(UTC) - timedelta(minutes=6)
        await session.commit()

    monkeypatch.setattr(service, "_finalize_send", original_finalize)
    assert await service.reconcile_send_intents() == 1
    replay = await service.deliver_send(quote.quote_id, token)
    assert replay.status == "accepted"
    assert replay.charged_amount_usd == "0.00"
    assert len(backend.sent) == 1


@pytest.mark.asyncio
async def test_send_reconciliation_advances_past_stale_missing_submission(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    service.mail_config.mailbox_send_limit_per_day = 10
    service.mail_config.global_send_limit_per_day = 10
    mailbox_id, token = await _active_hosted(
        service,
        local_part="send-reconciliation-pagination",
        idempotency_key="send-reconciliation-pagination-idempotency-0001",
    )
    first_quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="missing@example.net",
            subject="Missing submission",
            text="This stale intent should become retryable.",
        ),
        token,
    )
    second_quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="recovered@example.net",
            subject="Recovered submission",
            text="This later intent must not starve.",
        ),
        token,
    )
    first = await service._reserve_send_intent(first_quote.quote_id)
    second = await service._reserve_send_intent(second_quote.quote_id)
    stale = datetime.now(UTC) - timedelta(minutes=6)
    async with sessions() as session:
        first_row = await session.get(MailSendRow, first.send_id)
        second_row = await session.get(MailSendRow, second.send_id)
        first_row.status = "submitting"
        first_row.submission_started_at = stale
        first_row.created_at = stale - timedelta(minutes=1)
        second_row.status = "submitting"
        second_row.submission_started_at = stale
        second_row.created_at = stale
        await session.commit()
    backend.messages_by_send_id[second.send_id] = "message-recovered-after-stale"

    assert await service.reconcile_send_intents(limit=1) == 1
    async with sessions() as session:
        retryable = await session.get(MailSendRow, first.send_id)
        waiting = await session.get(MailSendRow, second.send_id)
    assert retryable.status == "pending"
    assert retryable.error == "submission_not_found_after_lease"
    assert waiting.status == "submitting"

    assert await service.reconcile_send_intents(limit=1) == 1
    async with sessions() as session:
        recovered = await session.get(MailSendRow, second.send_id)
    assert recovered.status == "accepted"
    assert recovered.message_id == "message-recovered-after-stale"


@pytest.mark.asyncio
async def test_send_route_verifies_and_reports_the_immutable_quote_amount(mail_service):
    service, _sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Locked price",
            text="Use the quote price",
        ),
        token,
    )
    service.config.payment.price_mail_send = Decimal("9.99")

    class Gate:
        amount: Decimal | None = None

        async def verify_only(self, _request, *, amount, **_kwargs):
            self.amount = amount
            return SimpleNamespace(
                payer="0x" + "7" * 40,
                matching_requirements=SimpleNamespace(
                    network="eip155:8453",
                    asset="USDC",
                ),
            )

        async def settle_verified(self, request, _verified, **_kwargs):
            request.state.payment_tx = "0xsend-settled"
            request.state.payment_network = "eip155:8453"
            request.state.payment_asset = "USDC"
            request.state.payment_payer = "0x" + "7" * 40
            return True

    gate = Gate()
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("cloud.hyrule.host", 443),
            "path": "/v1/mail/messages/send",
            "query_string": b"",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }
    )
    result = await send_message_route(
        MailSendRequest(quote_id=quote.quote_id),
        request,
        service=service,
        gate=gate,
    )
    assert not isinstance(result, Response)
    assert gate.amount == Decimal(quote.amount_usd)
    assert result.charged_amount_usd == quote.amount_usd


@pytest.mark.asyncio
async def test_send_route_persists_settlement_intent_before_backend_submission(
    mail_service, monkeypatch
):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Durable settlement intent",
            text="Persist authorization before the external write.",
        ),
        token,
    )
    observed: dict[str, object] = {}

    async def fail_after_observing_intent(**_kwargs):
        async with sessions() as session:
            stored = await session.scalar(
                select(MailSendRow).where(MailSendRow.quote_id == quote.quote_id)
            )
        observed["status"] = stored.status
        observed["authorization"] = stored.payment_authorization_header
        observed["pending_at"] = stored.payment_settlement_pending_at
        raise MailBackendError("submission outcome unavailable")

    monkeypatch.setattr(backend, "send_message", fail_after_observing_intent)
    monkeypatch.setattr(
        "hyrule_cloud.api.mail._mail_payment_authorization_fingerprint",
        lambda _request: "a" * 64,
    )

    class Gate:
        settle_calls = 0

        async def verify_only(self, _request, **_kwargs):
            return SimpleNamespace(
                payer="0x" + "7" * 40,
                matching_requirements=SimpleNamespace(
                    network="eip155:8453",
                    asset="USDC",
                ),
            )

        async def settle_verified(self, *_args, **_kwargs):
            self.settle_calls += 1
            raise AssertionError("payment cannot settle before message acceptance")

    gate = Gate()
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("cloud.hyrule.host", 443),
            "path": "/v1/mail/messages/send",
            "query_string": b"",
            "headers": [
                (b"authorization", f"Bearer {token}".encode()),
                (b"payment-signature", b"stored-authorization"),
            ],
        }
    )

    with pytest.raises(MailProblem) as failed:
        await send_message_route(
            MailSendRequest(quote_id=quote.quote_id),
            request,
            service=service,
            gate=gate,
        )
    assert failed.value.code == "mail_submission_failed"
    assert observed["status"] == "submitting"
    assert observed["authorization"] == "stored-authorization"
    assert observed["pending_at"] is not None
    assert gate.settle_calls == 0
    async with sessions() as session:
        stored = await session.scalar(
            select(MailSendRow).where(MailSendRow.quote_id == quote.quote_id)
        )
    assert stored.payment_authorization_header == "stored-authorization"
    assert stored.payment_settlement_pending_at is not None


@pytest.mark.asyncio
async def test_send_route_replays_ledger_settlement_without_a_second_payment(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Paid once",
            text="Do not settle a second authorization",
        ),
        token,
    )
    sent = await service.deliver_send(quote.quote_id, token)
    settlement = PaymentLedger(sessions).build_event(
        event_type="settled",
        resource_path="/v1/mail/messages/send",
        method="POST",
        amount=Decimal(quote.amount_usd),
        network="eip155:8453",
        asset="USDC",
        payer="0x" + "7" * 40,
        tx_hash="0xsettled-before-attribution",
        extra={"quote_id": quote.quote_id, "one_recipient": True},
    )
    async with sessions() as session:
        stored_send = await session.get(MailSendRow, sent.send_id)
        assert stored_send.payment_tx is None
        session.add(settlement)
        await session.commit()

    class Gate:
        async def verify_only(self, *_args, **_kwargs):
            raise AssertionError("an already-paid quote must not be verified again")

        async def settle_verified(self, *_args, **_kwargs):
            raise AssertionError("an already-paid quote must not be settled again")

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("cloud.hyrule.host", 443),
            "path": "/v1/mail/messages/send",
            "query_string": b"",
            "headers": [
                (b"authorization", f"Bearer {token}".encode()),
                (b"payment-signature", b"a-new-signed-authorization"),
            ],
        }
    )

    replay = await send_message_route(
        MailSendRequest(quote_id=quote.quote_id),
        request,
        service=service,
        gate=Gate(),
    )
    assert not isinstance(replay, Response)
    assert replay.send_id == sent.send_id
    assert replay.charged_amount_usd == quote.amount_usd
    async with sessions() as session:
        attributed = await session.get(MailSendRow, sent.send_id)
    assert attributed.payment_settled_at is not None
    assert attributed.payment_tx == "0xsettled-before-attribution"


@pytest.mark.asyncio
async def test_stored_authorization_recovers_send_payment_without_metrics_ledger(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="send-payment-recovery",
        idempotency_key="send-payment-recovery-idempotency-0001",
    )
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Recover settlement",
            text="The accepted message remains attributable.",
        ),
        token,
    )
    sent = await service.deliver_send(quote.quote_id, token)
    await service.begin_send_settlement(
        sent.send_id,
        quote.quote_id,
        payer="0x" + "4" * 40,
        payment_network="eip155:8453",
        payment_asset="0x" + "5" * 40,
        payment_authorization="stored-send-authorization",
    )

    with pytest.raises(MailProblem) as pending:
        await service.settled_send_response(quote.quote_id, token)
    assert pending.value.code == "mail_payment_settlement_pending"

    class _RecoveryGate:
        async def reconcile_settlement(self, header, amount, *, pending_since, resource_key):
            assert header == "stored-send-authorization"
            assert amount == Decimal(quote.amount_usd)
            assert pending_since is not None
            assert resource_key == f"mail_send:{quote.quote_id}"
            return PaymentReconciliation(
                payment=RecoveredPayment(
                    payer="0x" + "4" * 40,
                    tx_hash="0xsend-authorization-recovered",
                    network="eip155:8453",
                    asset="0x" + "5" * 40,
                )
            )

    assert await service.recover_x402_handoffs(gate=_RecoveryGate()) == 1
    replay = await service.settled_send_response(quote.quote_id, token)
    assert replay is not None
    assert replay.charged_amount_usd == quote.amount_usd
    async with sessions() as session:
        recovered = await session.get(MailSendRow, sent.send_id)
    assert recovered.payment_tx == "0xsend-authorization-recovered"
    assert recovered.payment_authorization_header is None
    assert recovered.payment_settlement_pending_at is None
    assert recovered.payment_settled_at is not None


@pytest.mark.asyncio
async def test_terminal_send_authorization_can_be_replaced(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="send-payment-terminal",
        idempotency_key="send-payment-terminal-idempotency-0001",
    )
    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="proof@example.net",
            subject="Replace authorization",
            text="Retry payment without resending the accepted message.",
        ),
        token,
    )
    sent = await service.deliver_send(quote.quote_id, token)
    first = hashlib.sha256(b"terminal-send-authorization").hexdigest()
    replacement = hashlib.sha256(b"replacement-send-authorization").hexdigest()
    await service.bind_payment_authorization(first, quote.quote_id)
    await service.begin_send_settlement(
        sent.send_id,
        quote.quote_id,
        payer="0x" + "4" * 40,
        payment_network="eip155:8453",
        payment_asset="USDC",
        payment_authorization="terminal-send-authorization",
    )

    class _TerminalGate:
        async def reconcile_settlement(self, header, amount, *, pending_since, resource_key):
            assert header == "terminal-send-authorization"
            assert amount == Decimal(quote.amount_usd)
            assert pending_since is not None
            assert resource_key == f"mail_send:{quote.quote_id}"
            return PaymentReconciliation(terminal_unsettled=True, reason="expired")

    assert await service.recover_x402_handoffs(gate=_TerminalGate()) == 0
    assert await service.settled_send_response(quote.quote_id, token) is None
    await service.bind_payment_authorization(replacement, quote.quote_id)

    async with sessions() as session:
        unpaid = await session.get(MailSendRow, sent.send_id)
        bindings = list(await session.scalars(select(MailPaymentAuthorizationRow)))
    assert unpaid.status == "accepted"
    assert unpaid.payment_settlement_pending_at is None
    assert unpaid.payment_authorization_header is None
    assert unpaid.error == "payment_authorization_expired_retryable"
    assert [(row.fingerprint, row.quote_id) for row in bindings] == [(replacement, quote.quote_id)]


@pytest.mark.asyncio
async def test_payment_authorization_is_durably_bound_to_one_send_quote(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    fingerprint = hashlib.sha256(b"one-valid-payment-authorization").hexdigest()

    await service.bind_payment_authorization(fingerprint, "mailq_first_send")
    await service.bind_payment_authorization(fingerprint, "mailq_first_send")
    with pytest.raises(MailProblem) as reused:
        await service.bind_payment_authorization(fingerprint, "mailq_second_send")
    with pytest.raises(MailProblem) as quote_rebound:
        await service.bind_payment_authorization(
            hashlib.sha256(b"a-distinct-valid-payment-authorization").hexdigest(),
            "mailq_first_send",
        )

    assert reused.value.code == "payment_authorization_reused"
    assert quote_rebound.value.code == "mail_quote_payment_bound"
    async with sessions() as session:
        bindings = list(await session.scalars(select(MailPaymentAuthorizationRow)))
    assert [(row.fingerprint, row.quote_id) for row in bindings] == [
        (fingerprint, "mailq_first_send")
    ]


@pytest.mark.asyncio
async def test_definitive_activation_failure_releases_quote_authorization(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="replacement-authorization",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    account, _token, _created = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="replacement-authorization-idempotency-0001",
    )
    first = hashlib.sha256(b"definitively-failed-authorization").hexdigest()
    replacement = hashlib.sha256(b"replacement-authorization").hexdigest()
    await service.bind_payment_authorization(first, quote.quote_id)
    await service.begin_activation_settlement(
        account.mailbox_id,
        quote.quote_id,
        payer="0x" + "1" * 40,
        payment_network="eip155:8453",
        payment_asset="USDC",
        payment_authorization="failed-authorization-header",
    )

    await service.clear_activation_settlement(account.mailbox_id, quote.quote_id)
    await service.bind_payment_authorization(replacement, quote.quote_id)

    async with sessions() as session:
        bindings = list(await session.scalars(select(MailPaymentAuthorizationRow)))
    assert [(row.fingerprint, row.quote_id) for row in bindings] == [(replacement, quote.quote_id)]


@pytest.mark.asyncio
async def test_reply_quote_translates_jmap_id_to_rfc_message_id(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    async with sessions() as session:
        account = await session.get(MailAccountRow, mailbox_id)
        session.add(
            MailMessageIndexRow(
                message_id="jmap-inbound-1",
                mailbox_id=mailbox_id,
                folder="inbox",
                sender="correspondent@example.net",
                recipients=[account.address],
                subject="Original",
                flags=[],
                has_attachments=False,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()
    long_message_id = f"<{'r' * 300}@example.net>"
    backend.authoritative_messages = [
        {
            "id": "jmap-inbound-1",
            "messageId": [long_message_id],
            "folder": "inbox",
            "from": [{"email": "correspondent@example.net"}],
            "to": [{"email": account.address}],
            "subject": "Original",
            "receivedAt": datetime.now(UTC).isoformat(),
            "textBody": [{"partId": "text"}],
            "bodyValues": {"text": {"value": "hello"}},
            "attachments": [],
        }
    ]

    quote = await service.create_send_quote(
        MailSendQuoteRequest(
            mailbox_id=mailbox_id,
            to="correspondent@example.net",
            subject="Re: Original",
            text="Reply",
            in_reply_to="jmap-inbound-1",
        ),
        token,
    )
    async with sessions() as session:
        stored = await session.get(MailQuoteRow, quote.quote_id)
        assert stored.request_payload["in_reply_to"] == long_message_id
    sent = await service.deliver_send(quote.quote_id, token)
    assert backend.sent[-1]["in_reply_to"] == long_message_id
    async with sessions() as session:
        stored_send = await session.get(MailSendRow, sent.send_id)
    assert stored_send.in_reply_to == long_message_id


@pytest.mark.asyncio
async def test_message_listing_and_detail_reconcile_from_authoritative_jmap(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    async with sessions() as session:
        account = await session.get(MailAccountRow, mailbox_id)
    backend.authoritative_messages = [
        {
            "id": "jmap-only-message",
            "messageId": ["<jmap-only@example.net>"],
            "folder": "inbox",
            "mailboxIds": {"inbox-id": True},
            "keywords": {"$seen": True},
            "from": [{"email": "sender@example.net"}],
            "to": [{"email": account.address}],
            "subject": "Webhook was delayed",
            "receivedAt": datetime.now(UTC).isoformat(),
            "textBody": [{"partId": "text"}],
            "bodyValues": {"text": {"value": "authoritative body"}},
            "attachments": [],
        }
    ]

    listed = await service.list_messages(mailbox_id, token)
    assert [message.message_id for message in listed.messages] == ["jmap-only-message"]
    async with sessions() as session:
        indexed = await session.get(
            MailMessageIndexRow,
            (mailbox_id, "jmap-only-message"),
        )
        assert indexed is not None
        await session.delete(indexed)
        await session.commit()

    detail = await service.get_message(mailbox_id, "jmap-only-message", token)
    assert detail.text == "authoritative body"
    async with sessions() as session:
        assert (
            await session.get(
                MailMessageIndexRow,
                (mailbox_id, "jmap-only-message"),
            )
            is not None
        )


@pytest.mark.asyncio
async def test_jmap_message_ids_are_scoped_to_each_mailbox(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    first_id, first_token = await _active_hosted(
        service,
        local_part="message-scope-first",
        idempotency_key="message-scope-first-idempotency-0001",
    )
    second_id, second_token = await _active_hosted(
        service,
        local_part="message-scope-second",
        idempotency_key="message-scope-second-idempotency-0001",
    )
    backend.authoritative_messages = [
        {
            "id": "account-scoped-jmap-id",
            "messageId": ["<shared-object-id@example.net>"],
            "folder": "inbox",
            "from": [{"email": "sender@example.net"}],
            "to": [{"email": "recipient@example.test"}],
            "subject": "Same object id in two accounts",
            "receivedAt": datetime.now(UTC).isoformat(),
            "textBody": [{"partId": "text"}],
            "bodyValues": {"text": {"value": "mailbox-local message"}},
            "attachments": [],
        }
    ]

    assert len((await service.list_messages(first_id, first_token)).messages) == 1
    assert len((await service.list_messages(second_id, second_token)).messages) == 1
    assert (
        await service.get_message(second_id, "account-scoped-jmap-id", second_token)
    ).text == "mailbox-local message"

    async with sessions() as session:
        first = await session.get(
            MailMessageIndexRow,
            (first_id, "account-scoped-jmap-id"),
        )
        second = await session.get(
            MailMessageIndexRow,
            (second_id, "account-scoped-jmap-id"),
        )
    assert first is not None
    assert second is not None


@pytest.mark.asyncio
async def test_webhooks_require_active_mailbox_and_enforce_cap(mail_service, monkeypatch):
    service, sessions, _backend, _domains, _refunds = mail_service
    quote = await service.create_account_quote(
        MailAccountQuoteRequest(
            local_part="webhook-gated",
            mode=MailboxMode.HOSTED,
            terms_version=service.mail_config.terms_version,
        )
    )
    pending, pending_token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="webhook-pending-idempotency-0001",
    )
    body = MailWebhookCreateRequest(
        url="https://hooks.example.net/mail",
        events=["message.received"],
    )
    with pytest.raises(MailProblem) as inactive:
        await service.create_webhook(pending.mailbox_id, pending_token, body)
    assert inactive.value.code == "mailbox_not_active"

    mailbox_id, token = await _active_hosted(
        service,
        local_part="webhook-active",
        idempotency_key="webhook-active-idempotency-0002",
    )

    async def safe_url(url):
        return url, ["203.0.113.10"]

    monkeypatch.setattr("hyrule_cloud.mail.service.validate_webhook_url", safe_url)
    service.mail_config.max_webhooks_per_mailbox = 1
    created = await service.create_webhook(mailbox_id, token, body)
    assert created.signing_secret
    with pytest.raises(MailProblem) as capped:
        await service.create_webhook(mailbox_id, token, body)
    assert capped.value.code == "mail_webhook_limit"
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(MailWebhookRow)
                .where(MailWebhookRow.mailbox_id == mailbox_id)
            )
            == 1
        )


@pytest.mark.asyncio
async def test_webhook_delivery_tries_every_validated_address(mail_service, monkeypatch):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="webhook-address-failover",
        idempotency_key="webhook-address-failover-idempotency-0001",
    )
    addresses = ["2001:db8::10", "203.0.113.10"]

    async def safe_url(url):
        return url, addresses

    monkeypatch.setattr("hyrule_cloud.mail.service.validate_webhook_url", safe_url)
    await service.create_webhook(
        mailbox_id,
        token,
        MailWebhookCreateRequest(
            url="https://hooks.example.net/mail",
            events=["message.received"],
        ),
    )
    async with sessions() as session:
        account = await session.get(MailAccountRow, mailbox_id)
    assert account is not None
    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "webhook-address-failover-event",
                    "type": "store.ingest",
                    "data": {
                        "from": "sender@example.net",
                        "to": [account.address],
                        "messageId": "webhook-address-failover-message",
                        "subject": "Address failover",
                    },
                }
            ]
        )
        == 1
    )
    attempted: list[str] = []

    async def post_pinned(url, address, body, signature, event_id):
        attempted.append(address)
        assert url == "https://hooks.example.net/mail"
        assert body and signature
        assert event_id == "webhook-address-failover-event"
        if address == addresses[0]:
            raise RuntimeError("IPv6 route unavailable")

    monkeypatch.setattr(service, "_post_pinned", post_pinned)

    assert await service.deliver_webhooks() == 1
    assert attempted == addresses
    async with sessions() as session:
        delivery = await session.scalar(
            select(MailWebhookDeliveryRow).where(
                MailWebhookDeliveryRow.event_id == "webhook-address-failover-event"
            )
        )
    assert delivery is not None
    assert delivery.status == "delivered"
    assert delivery.attempt_count == 1


@pytest.mark.asyncio
async def test_webhook_delivery_isolates_undecryptable_signing_secrets(mail_service, monkeypatch):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(
        service,
        local_part="webhook-secret-isolation",
        idempotency_key="webhook-secret-isolation-idempotency-0001",
    )

    async def safe_url(url):
        return url, ["203.0.113.10"]

    monkeypatch.setattr("hyrule_cloud.mail.service.validate_webhook_url", safe_url)
    service.mail_config.max_webhooks_per_mailbox = 2
    broken = await service.create_webhook(
        mailbox_id,
        token,
        MailWebhookCreateRequest(
            url="https://broken-hooks.example.net/mail",
            events=["message.received"],
        ),
    )
    healthy = await service.create_webhook(
        mailbox_id,
        token,
        MailWebhookCreateRequest(
            url="https://healthy-hooks.example.net/mail",
            events=["message.received"],
        ),
    )
    async with sessions() as session:
        broken_row = await session.get(MailWebhookRow, broken.webhook_id)
        broken_row.secret_ciphertext = "not-a-fernet-token"
        account = await session.get(MailAccountRow, mailbox_id)
        await session.commit()
    assert account is not None
    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "webhook-secret-isolation-event",
                    "type": "store.ingest",
                    "data": {
                        "from": "sender@example.net",
                        "to": [account.address],
                        "messageId": "webhook-secret-isolation-message",
                        "subject": "Secret isolation",
                    },
                }
            ]
        )
        == 1
    )
    delivered_to: list[str] = []

    async def post_pinned(url, *_args):
        delivered_to.append(url)

    monkeypatch.setattr(service, "_post_pinned", post_pinned)

    assert await service.deliver_webhooks() == 1
    assert delivered_to == ["https://healthy-hooks.example.net/mail"]
    async with sessions() as session:
        broken_delivery = await session.scalar(
            select(MailWebhookDeliveryRow).where(
                MailWebhookDeliveryRow.webhook_id == broken.webhook_id
            )
        )
        healthy_delivery = await session.scalar(
            select(MailWebhookDeliveryRow).where(
                MailWebhookDeliveryRow.webhook_id == healthy.webhook_id
            )
        )
    assert broken_delivery.status == "pending"
    assert broken_delivery.attempt_count == 1
    assert healthy_delivery.status == "delivered"


@pytest.mark.asyncio
async def test_lifecycle_preserves_fixed_grace_deadline_after_worker_outage(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, _token = await _active_hosted(
        service,
        local_part="fixed-grace",
        idempotency_key="fixed-grace-idempotency-0001",
    )
    now = datetime.now(UTC)
    async with sessions() as session:
        row = await session.get(MailAccountRow, mailbox_id)
        backend_id = row.backend_id
        row.expires_at = now - timedelta(days=10)
        row.grace_ends_at = now - timedelta(days=3)
        await session.commit()

    await service.process_lifecycle()

    async with sessions() as session:
        deleted = await session.get(MailAccountRow, mailbox_id)
        assert deleted.status == MailboxStatus.DELETED.value
        assert deleted.grace_ends_at.replace(tzinfo=UTC) == now - timedelta(days=3)
    assert backend.deleted == [backend_id]


@pytest.mark.asyncio
async def test_complaint_suspends_outbound_then_expires_and_purges_mailbox_data(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    async with sessions() as session:
        row = await session.get(MailAccountRow, mailbox_id)
        backend_id = row.backend_id
    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "event-complaint-1",
                    "type": "delivery.complaint",
                    "data": {"accountId": backend_id, "reason": "recipient complaint"},
                }
            ]
        )
        == 1
    )
    account = await service.get_account(mailbox_id, token)
    assert account.status is MailboxStatus.SUSPENDED

    async with sessions() as session:
        row = await session.get(MailAccountRow, mailbox_id)
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(
            MailWebhookDeliveryRow(
                delivery_id="whd_expiry_cleanup",
                webhook_id="wh_expiry_cleanup",
                event_id="event-complaint-1",
                status="pending",
                attempt_count=0,
                next_attempt_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        )
        session.add(
            MailSendRow(
                send_id="send_expiry_cleanup",
                mailbox_id=mailbox_id,
                quote_id="mailq_expiry_cleanup",
                recipient="proof@example.net",
                status="accepted",
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()
    await service.process_lifecycle()
    account = await service.get_account(mailbox_id, token)
    assert account.status is MailboxStatus.GRACE
    async with sessions() as session:
        row = await session.get(MailAccountRow, mailbox_id)
        row.grace_ends_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    await service.process_lifecycle()
    async with sessions() as session:
        deleted = await session.scalar(
            select(MailAccountRow).where(MailAccountRow.mailbox_id == mailbox_id)
        )
        assert deleted.status == MailboxStatus.DELETED.value
        assert deleted.management_token_ciphertext is None
        assert deleted.backend_credential_ciphertext is None
        assert (
            await session.scalar(
                select(func.count())
                .select_from(MailEventRow)
                .where(MailEventRow.mailbox_id == mailbox_id)
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(MailWebhookDeliveryRow)
                .where(MailWebhookDeliveryRow.event_id == "event-complaint-1")
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(MailSendRow)
                .where(MailSendRow.mailbox_id == mailbox_id)
            )
            == 0
        )
    assert backend.deleted == [backend_id]
    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "delayed-event-after-deletion",
                    "type": "delivery.completed",
                    "data": {"to": ["journey-agent@agentmail.hyrule.host"]},
                }
            ]
        )
        == 0
    )
    async with sessions() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(MailEventRow)
                .where(MailEventRow.mailbox_id == mailbox_id)
            )
            == 0
        )


@pytest.mark.asyncio
async def test_retention_deletes_backend_message_before_its_index(mail_service):
    service, sessions, backend, _domains, _refunds = mail_service
    mailbox_id, _token = await _active_hosted(service)
    backend.retention_delete_count = 1
    async with sessions() as session:
        session.add(
            MailMessageIndexRow(
                message_id="retention-message-old",
                mailbox_id=mailbox_id,
                folder="inbox",
                sender="sender@example.net",
                recipients=["journey-agent@agentmail.hyrule.host"],
                subject="Old message",
                flags=[],
                has_attachments=False,
                created_at=datetime.now(UTC)
                - timedelta(days=service.mail_config.retention_days + 1),
            )
        )
        await session.commit()

    assert await service.sweep_retention() == 1
    assert len(backend.retention_sweeps) == 1
    assert backend.retention_sweeps[0]["address"] == "journey-agent@agentmail.hyrule.host"
    async with sessions() as session:
        assert (
            await session.get(
                MailMessageIndexRow,
                (mailbox_id, "retention-message-old"),
            )
            is None
        )


@pytest.mark.asyncio
async def test_official_stalwart_signature_and_abuse_event_suspend_mailbox(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, token = await _active_hosted(service)
    async with sessions() as session:
        row = await session.get(MailAccountRow, mailbox_id)
        backend_id = row.backend_id

    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "official-stalwart-delivery-event-with-an-id-longer-than-the-db-column",
                    "createdAt": "2026-07-19T11:59:00Z",
                    "type": "delivery.delivered",
                    "data": {
                        "from": "Journey Agent <journey-agent@agentmail.hyrule.host>",
                        "to": ["proof@example.net"],
                        "messageId": "queue-message-1",
                    },
                }
            ]
        )
        == 1
    )

    event = {
        "id": "official-stalwart-abuse-1",
        "createdAt": "2026-07-19T12:00:00Z",
        "type": "incoming-report.abuse-report",
        "data": {"accountId": backend_id},
    }
    raw = json.dumps({"events": [event]}, separators=(",", ":")).encode()
    signature = base64.b64encode(
        hmac.new(
            service.mail_config.internal_webhook_secret.encode(),
            raw,
            hashlib.sha256,
        ).digest()
    ).decode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    request = Request({"type": "http", "method": "POST", "path": "/"}, receive)
    result = await ingest_events(
        body=StalwartEventEnvelope(events=[event]),
        request=request,
        signature=signature,
        legacy_signature=None,
        state=SimpleNamespace(config=service.config),
        service=service,
    )
    assert result == {"accepted": 1}
    account = await service.get_account(mailbox_id, token)
    assert account.status is MailboxStatus.SUSPENDED
    listed_events = await service.list_events(mailbox_id, token)
    assert all(len(item.event_id) <= 36 for item in listed_events.events)
    async with sessions() as session:
        row = await session.get(MailAccountRow, mailbox_id)
        assert row.suspended_reason == "recipient_complaint"

    route = next(route for route in internal_router.routes if route.path.endswith("/events"))
    aliases = {parameter.alias for parameter in route.dependant.header_params}
    assert "X-Signature" in aliases


@pytest.mark.asyncio
async def test_receive_event_survives_an_existing_message_index(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    mailbox_id, _token = await _active_hosted(
        service,
        local_part="receive-upsert",
        idempotency_key="receive-upsert-idempotency-0001",
    )
    async with sessions() as session:
        account = await session.get(MailAccountRow, mailbox_id)
        session.add(
            MailMessageIndexRow(
                message_id="already-polled-message",
                mailbox_id=mailbox_id,
                folder="inbox",
                sender="sender@example.net",
                recipients=[account.address],
                subject="Authoritative poll",
                flags=[],
                has_attachments=False,
                created_at=datetime.now(UTC),
            )
        )
        session.add(
            MailWebhookRow(
                webhook_id="wh_receive_upsert",
                mailbox_id=mailbox_id,
                url="https://hooks.example.net/mail",
                events=["message.received"],
                status="active",
                failure_count=0,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()

    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "receive-after-authoritative-poll",
                    "type": "store.ingest",
                    "data": {
                        "from": "sender@example.net",
                        "to": [account.address],
                        "messageId": "already-polled-message",
                        "subject": "Delayed event",
                    },
                }
            ]
        )
        == 1
    )
    async with sessions() as session:
        event = await session.get(MailEventRow, "receive-after-authoritative-poll")
        index = await session.get(
            MailMessageIndexRow,
            (mailbox_id, "already-polled-message"),
        )
        delivery = await session.scalar(
            select(MailWebhookDeliveryRow).where(
                MailWebhookDeliveryRow.event_id == "receive-after-authoritative-poll"
            )
        )
        assert event is not None
        assert delivery is not None
        assert index.subject == "Authoritative poll"


@pytest.mark.asyncio
async def test_stalwart_events_use_directional_mailbox_ownership(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    sender_id, _sender_token = await _active_hosted(
        service,
        local_part="event-sender",
        idempotency_key="event-sender-idempotency-0001",
    )
    recipient_id, _recipient_token = await _active_hosted(
        service,
        local_part="event-recipient",
        idempotency_key="event-recipient-idempotency-0001",
    )
    async with sessions() as session:
        sender = await session.get(MailAccountRow, sender_id)
        recipient = await session.get(MailAccountRow, recipient_id)

    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "directional-inbound",
                    "type": "store.ingest",
                    "data": {
                        "from": sender.address,
                        "to": [recipient.address],
                        "messageId": "directional-inbound-message",
                    },
                },
                {
                    "id": "directional-delivery",
                    "type": "delivery.delivered",
                    "data": {
                        "from": sender.address,
                        "to": [recipient.address],
                        "messageId": "directional-delivery-message",
                    },
                },
                {
                    "id": "directional-append",
                    "type": "message-ingest.jmap-append",
                    "data": {
                        "accountId": sender.backend_id,
                        "messageId": "directional-append-message",
                    },
                },
            ]
        )
        == 3
    )
    assert (
        await service.ingest_stalwart_events(
            [
                {
                    "id": "ambiguous-append",
                    "type": "message-ingest.imap-append",
                    "data": {"from": sender.address, "to": [recipient.address]},
                }
            ]
        )
        == 0
    )
    async with sessions() as session:
        inbound = await session.get(MailEventRow, "directional-inbound")
        delivery = await session.get(MailEventRow, "directional-delivery")
        append = await session.get(MailEventRow, "directional-append")
        assert inbound.mailbox_id == recipient_id
        assert inbound.type == "message.received"
        assert delivery.mailbox_id == sender_id
        assert delivery.type == "message.delivery"
        assert append.mailbox_id == sender_id
        assert append.type == "mail.system"
        assert (
            await session.get(
                MailMessageIndexRow,
                (sender_id, "directional-append-message"),
            )
            is None
        )
