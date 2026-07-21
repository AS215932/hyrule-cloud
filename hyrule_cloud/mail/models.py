from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

_LOCAL_PART_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$"
)


def generate_mail_id(prefix: str) -> str:
    # Every existing mail identifier column is at most 36 characters. Keep the
    # readable prefix without relying on SQLite's non-enforcement of VARCHAR
    # lengths (PostgreSQL correctly rejects oversized values).
    suffix_length = min(32, 35 - len(prefix))
    if suffix_length < 16:
        raise ValueError("mail id prefix is too long")
    return f"{prefix}_{uuid.uuid4().hex[:suffix_length]}"


def normalize_local_part(value: str) -> str:
    result = value.strip().lower()
    if not _LOCAL_PART_RE.fullmatch(result) or ".." in result:
        raise ValueError(
            "local_part must be 1-64 lowercase letters, numbers, dots, underscores, or hyphens"
        )
    return result


def normalize_domain(value: str) -> str:
    result = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(result):
        raise ValueError("domain must be a valid ASCII DNS name")
    return result


def normalize_address(value: str) -> str:
    raw = value.strip().lower()
    if raw.count("@") != 1:
        raise ValueError("recipient must be a single email address")
    local_part, domain = raw.rsplit("@", 1)
    return f"{normalize_local_part(local_part)}@{normalize_domain(domain)}"


class MailboxMode(enum.StrEnum):
    HOSTED = "hosted"
    CUSTOM = "custom"
    DOMAIN_AND_MAILBOX = "domain_and_mailbox"


class MailboxStatus(enum.StrEnum):
    AWAITING_PAYMENT = "awaiting_payment"
    PENDING_DOMAIN = "pending_domain"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    GRACE = "grace"
    FAILED = "failed"
    REFUND_DUE = "refund_due"
    DELETED = "deleted"


class MailQuoteStatus(enum.StrEnum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class MailProduct(BaseModel):
    id: str
    title: str
    price_usd: str
    billing: str
    available: bool
    constraints: list[str]


class MailProductsResponse(BaseModel):
    available: bool
    products: list[MailProduct]
    terms_version: str
    backend: str = "dedicated Stalwart"


class MailPricingResponse(BaseModel):
    activation_usd: str
    outbound_message_usd: str
    inbound_usd: str = "0.00"
    storage_gb: int = 1
    active_days: int = 30
    grace_days: int = 7
    auto_renew: bool = False


class MailCapabilitiesResponse(BaseModel):
    submission: str = "API only"
    retrieval: str = "API and signed webhooks"
    public_smtp_submission: bool = False
    public_imap: bool = False
    webmail: bool = False
    outbound_attachments: bool = False
    inbound_attachments: bool = True
    inbound_attachment_max_bytes: int
    recipients_per_message: int = 1
    outbound_per_day: int
    new_recipients_per_day: int


class MailAccountQuoteRequest(BaseModel):
    local_part: str
    mode: MailboxMode = MailboxMode.HOSTED
    domain: str | None = None
    domain_management_token: str | None = Field(default=None, min_length=32, max_length=256)
    terms_version: str
    domain_terms_version: str | None = Field(default=None, min_length=1, max_length=64)

    _local_part = field_validator("local_part")(normalize_local_part)

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str | None) -> str | None:
        return normalize_domain(value) if value else None

    @model_validator(mode="after")
    def validate_mode(self) -> MailAccountQuoteRequest:
        if self.mode is MailboxMode.HOSTED and self.domain is not None:
            raise ValueError("hosted mailboxes use agentmail.hyrule.host; omit domain")
        if self.mode is MailboxMode.CUSTOM and (
            self.domain is None or not self.domain_management_token
        ):
            raise ValueError("custom mailboxes require domain and domain_management_token")
        if self.mode is MailboxMode.DOMAIN_AND_MAILBOX and self.domain is None:
            raise ValueError("domain_and_mailbox requires domain")
        if self.mode is MailboxMode.DOMAIN_AND_MAILBOX and not self.domain_terms_version:
            raise ValueError("domain_and_mailbox requires domain_terms_version")
        return self


class MailQuoteResponse(BaseModel):
    quote_id: str
    kind: str
    address: str
    mode: MailboxMode | None = None
    amount_usd: str
    domain_amount_usd: str = "0.00"
    activation_amount_usd: str = "0.00"
    outbound_amount_usd: str = "0.00"
    terms_version: str
    expires_at: datetime
    payable_path: str
    constraints: list[str] = Field(default_factory=list)


class MailAccountCreateRequest(BaseModel):
    quote_id: str = Field(min_length=8, max_length=64)


class MailAccountResponse(BaseModel):
    mailbox_id: str
    address: str
    mode: MailboxMode
    status: MailboxStatus
    management_token: str | None = None
    status_url: str
    messages_url: str
    send_quote_url: str
    domain_order_id: str | None = None
    domain_status_url: str | None = None
    active_until: datetime | None = None
    grace_ends_at: datetime | None = None
    charged_amount_usd: str
    auto_renew: bool = False
    error: str | None = None


class MailSendQuoteRequest(BaseModel):
    mailbox_id: str = Field(min_length=8, max_length=64)
    to: str
    subject: str = Field(min_length=1, max_length=998)
    # Request parsing accepts the full configuration range. MailService applies
    # the operator's lower runtime limits before a quote is persisted.
    text: str = Field(default="", max_length=1_000_000)
    html: str | None = Field(default=None, max_length=1_000_000)
    in_reply_to: str | None = Field(default=None, max_length=128)

    _to = field_validator("to")(normalize_address)

    @model_validator(mode="after")
    def body_required(self) -> MailSendQuoteRequest:
        if not self.text and not self.html:
            raise ValueError("text or html body is required")
        return self


class MailSendRequest(BaseModel):
    quote_id: str = Field(min_length=8, max_length=64)


class MailSendResponse(BaseModel):
    send_id: str
    mailbox_id: str
    message_id: str | None = None
    status: str
    recipient: str
    accepted_at: datetime | None = None
    charged_amount_usd: str
    delivery_is_final: bool = False


class MailMessageSummary(BaseModel):
    message_id: str
    folder: str
    sender: str | None = None
    recipients: list[str] = Field(default_factory=list)
    subject: str | None = None
    flags: list[str] = Field(default_factory=list)
    has_attachments: bool = False
    created_at: datetime


class MailAttachment(BaseModel):
    blob_id: str
    name: str | None = None
    type: str | None = None
    size: int | None = None
    download_url: str


class MailMessageDetail(MailMessageSummary):
    text: str = ""
    html: str | None = None
    attachments: list[MailAttachment] = Field(default_factory=list)


class MailMessagesResponse(BaseModel):
    mailbox_id: str
    messages: list[MailMessageSummary]


class MailEventResponse(BaseModel):
    event_id: str
    type: str
    message_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class MailEventsResponse(BaseModel):
    mailbox_id: str
    events: list[MailEventResponse]


class MailWebhookCreateRequest(BaseModel):
    url: str = Field(min_length=12, max_length=2048)
    events: list[str] = Field(default_factory=lambda: ["message.received", "message.delivery"])


class MailWebhookResponse(BaseModel):
    webhook_id: str
    url: str
    events: list[str]
    status: str
    signing_secret: str | None = None
    created_at: datetime


class MailWebhookListResponse(BaseModel):
    webhooks: list[MailWebhookResponse]


class StalwartEventEnvelope(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=100)


def amount(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01')):.2f}"
