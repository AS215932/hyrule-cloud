from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import func, select
from starlette.requests import Request
from starlette.responses import Response

from hyrule_cloud.api.mail import (
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
    MailAccountRow,
    MailEventRow,
    MailMessageIndexRow,
    MailPaymentAuthorizationRow,
    MailQuoteRow,
    MailSendRow,
    MailWebhookDeliveryRow,
    MailWebhookRow,
    PaymentEventRow,
    create_db_engine,
    create_session_factory,
)
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
from hyrule_cloud.mail.service import MailProblem, MailService
from hyrule_cloud.middleware.x402 import PaymentGate
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
    fingerprint = MailPaymentAuthorizationRow.__table__.c.fingerprint
    assert fingerprint.primary_key is True
    assert fingerprint.type.length == 64


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
        return {
            "methodResponses": [
                ["x:Domain/get", {"list": [{"dnsZoneFile": zone}]}, call_id]
            ]
        }

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
                    "methodResponses": [
                        ["Email/query", {"ids": ["message-1"]}, "list-email-query"]
                    ]
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
            {"primaryAccounts": {"urn:ietf:params:jmap:mail": "account-1"}},
            None,
        )

    async def jmap(_address, _password, method_calls, _using):
        calls.append(method_calls)
        return {
            "response": {
                "methodResponses": [
                    ["Email/query", {"ids": ["message-recovered"]}, "send-intent-query"]
                ]
            }
        }

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
        assert refunds == 0

    backend.ensure_domain = original_ensure_domain
    assert await service.provision_pending() == 1


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

    backend.ensure_account = original_ensure
    await service._provision_one(account.mailbox_id)
    assert backend.accounts[-1]["password"] == first_passwords[0]
    current = await service.get_account(account.mailbox_id, _token)
    assert current.status is MailboxStatus.ACTIVE


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
    event = PaymentLedger(sessions).build_event(
        event_type="settled",
        resource_path="/v1/mail/accounts",
        method="POST",
        amount=service.config.payment.price_mail_activation,
        network="eip155:8453",
        asset="USDC",
        payer="0x" + "4" * 40,
        tx_hash="0xmail-recover",
        extra={"mailbox_id": account.mailbox_id, "address": account.address},
    )
    async with sessions() as session:
        stored_quote = await session.get(MailQuoteRow, quote.quote_id)
        stored_quote.expires_at = datetime.now(UTC) - timedelta(hours=2)
        session.add(event)
        await session.commit()

    assert await service.expire_quotes() == 0
    async with sessions() as session:
        preserved = await session.get(MailAccountRow, account.mailbox_id)
        assert preserved.status == MailboxStatus.AWAITING_PAYMENT.value
        assert preserved.management_token_ciphertext
    assert await service.recover_x402_handoffs() == 1
    assert await service.recover_x402_handoffs() == 0
    async with sessions() as session:
        recovered = await session.get(MailAccountRow, account.mailbox_id)
        assert recovered.status == MailboxStatus.PROVISIONING.value
        assert recovered.payment_tx == "0xmail-recover"


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
    assert "management_token" not in event.extra
    assert result.management_token not in json.dumps(event.extra)


@pytest.mark.asyncio
async def test_combined_domain_and_mailbox_quote_is_one_atomic_amount(mail_service):
    service, _sessions, _backend, domains, _refunds = mail_service
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
    account, token, _ = await service.prepare_activation(
        quote.quote_id,
        idempotency_key="atomic-domain-mail-idempotency-0001",
    )
    assert account.domain_order_id == "do_atomic_123456"
    assert (
        domains.agent_orders[0]["additional_amount_usd"]
        == service.config.payment.price_mail_activation
    )
    assert domains.agent_orders[0]["management_token"] == token


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

    monkeypatch.setattr(service, "_finalize_send", original_finalize)
    assert await service.reconcile_send_intents() == 1
    replay = await service.deliver_send(quote.quote_id, token)
    assert replay.status == "accepted"
    assert replay.charged_amount_usd == quote.amount_usd
    assert len(backend.sent) == 1


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
            return object()

        async def settle_verified(self, _request, _verified, **_kwargs):
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
async def test_payment_authorization_is_durably_bound_to_one_send_quote(mail_service):
    service, sessions, _backend, _domains, _refunds = mail_service
    fingerprint = hashlib.sha256(b"one-valid-payment-authorization").hexdigest()

    await service.bind_send_payment_authorization(fingerprint, "mailq_first_send")
    await service.bind_send_payment_authorization(fingerprint, "mailq_first_send")
    with pytest.raises(MailProblem) as reused:
        await service.bind_send_payment_authorization(fingerprint, "mailq_second_send")

    assert reused.value.code == "payment_authorization_reused"
    async with sessions() as session:
        bindings = list(await session.scalars(select(MailPaymentAuthorizationRow)))
    assert [(row.fingerprint, row.quote_id) for row in bindings] == [
        (fingerprint, "mailq_first_send")
    ]


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
    backend.authoritative_messages = [
        {
            "id": "jmap-inbound-1",
            "messageId": ["<original-rfc-id@example.net>"],
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
        assert stored.request_payload["in_reply_to"] == "<original-rfc-id@example.net>"
    await service.deliver_send(quote.quote_id, token)
    assert backend.sent[-1]["in_reply_to"] == "<original-rfc-id@example.net>"


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
        indexed = await session.get(MailMessageIndexRow, "jmap-only-message")
        assert indexed is not None
        await session.delete(indexed)
        await session.commit()

    detail = await service.get_message(mailbox_id, "jmap-only-message", token)
    assert detail.text == "authoritative body"
    async with sessions() as session:
        assert await session.get(MailMessageIndexRow, "jmap-only-message") is not None


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
        assert await session.get(MailMessageIndexRow, "retention-message-old") is None


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
        assert await session.get(MailMessageIndexRow, "directional-append-message") is None
