"""Contract-first paid Agent Mail API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from hyrule_cloud.api._contract import not_implemented, payment_price
from hyrule_cloud.models import (
    CapabilityEndpoint,
    GenericActionResponse,
    MailAccountCreateRequest,
    MailAccountExtendRequest,
    MailAccountResponse,
    MailAccountUpdateRequest,
    MailAliasRequest,
    MailAliasResponse,
    MailAPIKeyCreateRequest,
    MailAPIKeyResponse,
    MailDomainCreateRequest,
    MailDomainResponse,
    MailEventResponse,
    MailIdentityRequest,
    MailIdentityResponse,
    MailMessageActionRequest,
    MailMessageListResponse,
    MailMessageResponse,
    MailPricingResponse,
    MailProductsResponse,
    MailSearchRequest,
    MailSendRequest,
    MailWebhookRequest,
    MailWebhookResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)

router = APIRouter(prefix="/v1/mail", tags=["Agent Mail"])


@router.get("/products", response_model=MailProductsResponse)
async def get_mail_products(request: Request) -> MailProductsResponse:
    basic = str(payment_price(request, "price_mail_agent_basic_day", "0.05"))
    return MailProductsResponse(
        products=[
            {
                "plan": "agent-basic",
                "name": "Agent Basic Mailbox",
                "price_usd_day": basic,
                "storage_mb": 1024,
                "outbound_messages_per_day": 100,
                "inbound_messages_per_day": 1000,
                "features": ["smtp", "imap", "api", "webhooks", "aliases", "identities"],
            }
        ]
    )


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_mail_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="mail",
        purpose="Email accounts for AI agents with SMTP/IMAP plus first-class API send, fetch, search, webhooks, logs, aliases, identities, and quarantine. Not yet purchasable: the mail backend is under construction.",
        separation_of_concerns="/v1/mail operates mailboxes; /v1/mx diagnoses mail deliverability; /v1/domains owns registration and authoritative DNS.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/mail/products", method="GET", description="Agent mailbox product catalog"),
            CapabilityEndpoint(path="/v1/mail/pricing", method="GET", description="Mail product pricing"),
        ],
        paid_endpoints=[],
    )


@router.get("/pricing", response_model=MailPricingResponse)
async def get_mail_pricing(request: Request) -> MailPricingResponse:
    return MailPricingResponse(
        agent_basic_usd_day=str(payment_price(request, "price_mail_agent_basic_day", "0.05")),
        storage_extra_usd_gb_day=str(payment_price(request, "price_mail_storage_gb_day", "0.01")),
        outbound_overage_usd_message=str(payment_price(request, "price_mail_outbound_message", "0.001")),
    )


@router.post("/accounts/quote", response_model=PaidEndpointQuote)
async def quote_mail_account(request: Request, body: MailAccountCreateRequest) -> JSONResponse:
    # The paid endpoint this quotes is 501 while the mail backend is unbuilt;
    # a payable-looking quote for it would send agents into a dead end.
    return not_implemented("mail.accounts.quote")


@router.post("/accounts", response_model=MailAccountResponse)
async def create_mail_account(request: Request, body: MailAccountCreateRequest) -> JSONResponse | Response:
    # Not implemented yet: refuse before charging so no payment is taken for a 501.
    return not_implemented("mail.accounts.create")


@router.get("/accounts", response_model=list[MailAccountResponse])
async def list_mail_accounts() -> JSONResponse:
    return not_implemented("mail.accounts.list")


@router.get("/accounts/{mailbox_id}", response_model=MailAccountResponse)
async def get_mail_account(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.accounts.get")


@router.patch("/accounts/{mailbox_id}", response_model=MailAccountResponse)
async def update_mail_account(mailbox_id: str, body: MailAccountUpdateRequest) -> JSONResponse:
    return not_implemented("mail.accounts.update")


@router.delete("/accounts/{mailbox_id}", response_model=GenericActionResponse)
async def delete_mail_account(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.accounts.delete")


@router.post("/accounts/{mailbox_id}/extend", response_model=MailAccountResponse)
async def extend_mail_account(mailbox_id: str, body: MailAccountExtendRequest) -> JSONResponse:
    return not_implemented("mail.accounts.extend")


@router.post("/accounts/{mailbox_id}/suspend", response_model=GenericActionResponse)
async def suspend_mail_account(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.accounts.suspend")


@router.post("/accounts/{mailbox_id}/resume", response_model=GenericActionResponse)
async def resume_mail_account(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.accounts.resume")


@router.post("/domains", response_model=MailDomainResponse)
async def create_mail_domain(body: MailDomainCreateRequest) -> JSONResponse:
    return not_implemented("mail.domains.create")


@router.get("/domains/{domain_id}", response_model=MailDomainResponse)
async def get_mail_domain(domain_id: str) -> JSONResponse:
    return not_implemented("mail.domains.get")


@router.post("/domains/{domain_id}/verify", response_model=MailDomainResponse)
async def verify_mail_domain(domain_id: str) -> JSONResponse:
    return not_implemented("mail.domains.verify")


@router.get("/domains/{domain_id}/dns-instructions", response_model=MailDomainResponse)
async def get_mail_domain_dns_instructions(domain_id: str) -> JSONResponse:
    return not_implemented("mail.domains.dns_instructions")


@router.delete("/domains/{domain_id}", response_model=GenericActionResponse)
async def delete_mail_domain(domain_id: str) -> JSONResponse:
    return not_implemented("mail.domains.delete")


@router.get("/accounts/{mailbox_id}/aliases", response_model=list[MailAliasResponse])
async def list_mail_aliases(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.aliases.list")


@router.post("/accounts/{mailbox_id}/aliases", response_model=MailAliasResponse)
async def create_mail_alias(mailbox_id: str, body: MailAliasRequest) -> JSONResponse:
    return not_implemented("mail.aliases.create")


@router.delete("/accounts/{mailbox_id}/aliases/{alias_id}", response_model=GenericActionResponse)
async def delete_mail_alias(mailbox_id: str, alias_id: str) -> JSONResponse:
    return not_implemented("mail.aliases.delete")


@router.get("/accounts/{mailbox_id}/identities", response_model=list[MailIdentityResponse])
async def list_mail_identities(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.identities.list")


@router.post("/accounts/{mailbox_id}/identities", response_model=MailIdentityResponse)
async def create_mail_identity(mailbox_id: str, body: MailIdentityRequest) -> JSONResponse:
    return not_implemented("mail.identities.create")


@router.patch("/accounts/{mailbox_id}/identities/{identity_id}", response_model=MailIdentityResponse)
async def update_mail_identity(mailbox_id: str, identity_id: str, body: MailIdentityRequest) -> JSONResponse:
    return not_implemented("mail.identities.update")


@router.delete("/accounts/{mailbox_id}/identities/{identity_id}", response_model=GenericActionResponse)
async def delete_mail_identity(mailbox_id: str, identity_id: str) -> JSONResponse:
    return not_implemented("mail.identities.delete")


@router.post("/accounts/{mailbox_id}/api-keys", response_model=MailAPIKeyResponse)
async def create_mail_api_key(mailbox_id: str, body: MailAPIKeyCreateRequest) -> JSONResponse:
    return not_implemented("mail.api_keys.create")


@router.delete("/accounts/{mailbox_id}/api-keys/{key_id}", response_model=GenericActionResponse)
async def delete_mail_api_key(mailbox_id: str, key_id: str) -> JSONResponse:
    return not_implemented("mail.api_keys.delete")


@router.post("/accounts/{mailbox_id}/rotate-password", response_model=GenericActionResponse)
async def rotate_mail_password(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.password.rotate")


@router.get("/messages", response_model=MailMessageListResponse)
async def list_mail_messages(mailbox_id: str | None = None, folder: str | None = None, limit: int = 50, cursor: str | None = None) -> JSONResponse:
    return not_implemented("mail.messages.list")


@router.post("/search", response_model=MailMessageListResponse)
async def search_mail_messages(body: MailSearchRequest) -> JSONResponse:
    return not_implemented("mail.messages.search")


@router.post("/messages/send", response_model=MailMessageResponse)
async def send_mail_message(request: Request, body: MailSendRequest) -> JSONResponse | Response:
    # Not implemented yet: refuse before charging so no payment is taken for a 501.
    return not_implemented("mail.messages.send")


@router.get("/messages/{message_id}/raw", response_model=None)
async def get_mail_message_raw(message_id: str) -> Response:
    return not_implemented("mail.messages.raw")


@router.get("/messages/{message_id}/attachments/{attachment_id}", response_model=None)
async def get_mail_attachment(message_id: str, attachment_id: str) -> Response:
    return not_implemented("mail.messages.attachment")


@router.get("/messages/{message_id}", response_model=MailMessageResponse)
async def get_mail_message(message_id: str) -> JSONResponse:
    return not_implemented("mail.messages.get")


@router.post("/messages/{message_id}/reply", response_model=MailMessageResponse)
async def reply_mail_message(message_id: str, body: MailMessageActionRequest) -> JSONResponse:
    return not_implemented("mail.messages.reply")


@router.post("/messages/{message_id}/forward", response_model=MailMessageResponse)
async def forward_mail_message(message_id: str, body: MailMessageActionRequest) -> JSONResponse:
    return not_implemented("mail.messages.forward")


@router.patch("/messages/{message_id}", response_model=MailMessageResponse)
async def update_mail_message(message_id: str, flags: list[str] | None = None, folder: str | None = None) -> JSONResponse:
    return not_implemented("mail.messages.update")


@router.delete("/messages/{message_id}", response_model=GenericActionResponse)
async def delete_mail_message(message_id: str) -> JSONResponse:
    return not_implemented("mail.messages.delete")


@router.get("/accounts/{mailbox_id}/folders", response_model=None)
async def list_mail_folders(mailbox_id: str) -> Response:
    return not_implemented("mail.folders.list")


@router.post("/accounts/{mailbox_id}/folders", response_model=None)
async def create_mail_folder(mailbox_id: str, name: str) -> Response:
    return not_implemented("mail.folders.create")


@router.get("/accounts/{mailbox_id}/rules", response_model=None)
async def list_mail_rules(mailbox_id: str) -> Response:
    return not_implemented("mail.rules.list")


@router.post("/accounts/{mailbox_id}/rules", response_model=None)
async def create_mail_rule(mailbox_id: str, rule: dict[str, object]) -> Response:
    return not_implemented("mail.rules.create")


@router.get("/accounts/{mailbox_id}/events", response_model=list[MailEventResponse])
async def list_mail_events(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.events.list")


@router.get("/accounts/{mailbox_id}/delivery-log", response_model=None)
async def list_mail_delivery_log(mailbox_id: str) -> Response:
    return not_implemented("mail.delivery_log.list")


@router.get("/accounts/{mailbox_id}/webhooks", response_model=list[MailWebhookResponse])
async def list_mail_webhooks(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.webhooks.list")


@router.post("/accounts/{mailbox_id}/webhooks", response_model=MailWebhookResponse)
async def create_mail_webhook(mailbox_id: str, body: MailWebhookRequest) -> JSONResponse:
    return not_implemented("mail.webhooks.create")


@router.delete("/accounts/{mailbox_id}/webhooks/{webhook_id}", response_model=GenericActionResponse)
async def delete_mail_webhook(mailbox_id: str, webhook_id: str) -> JSONResponse:
    return not_implemented("mail.webhooks.delete")


@router.get("/accounts/{mailbox_id}/quarantine", response_model=MailMessageListResponse)
async def list_mail_quarantine(mailbox_id: str) -> JSONResponse:
    return not_implemented("mail.quarantine.list")


@router.post("/accounts/{mailbox_id}/quarantine/{message_id}/release", response_model=GenericActionResponse)
async def release_mail_quarantine(mailbox_id: str, message_id: str) -> JSONResponse:
    return not_implemented("mail.quarantine.release")


@router.post("/accounts/{mailbox_id}/quarantine/{message_id}/delete", response_model=GenericActionResponse)
async def delete_mail_quarantine(mailbox_id: str, message_id: str) -> JSONResponse:
    return not_implemented("mail.quarantine.delete")


@router.post("/accounts/{mailbox_id}/report-spam", response_model=GenericActionResponse)
async def report_mail_spam(mailbox_id: str, message_id: str) -> JSONResponse:
    return not_implemented("mail.spam.report")


@router.post("/accounts/{mailbox_id}/report-not-spam", response_model=GenericActionResponse)
async def report_mail_not_spam(mailbox_id: str, message_id: str) -> JSONResponse:
    return not_implemented("mail.not_spam.report")
