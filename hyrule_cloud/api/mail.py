"""Public Agent Mail facade. SMTP/IMAP and Stalwart credentials stay private."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from base64 import b64encode
from decimal import Decimal
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Header, Query, Request, Response

from hyrule_cloud.mail.models import (
    MailAccountCreateRequest,
    MailAccountQuoteRequest,
    MailAccountResponse,
    MailCapabilitiesResponse,
    MailEventsResponse,
    MailMessageDetail,
    MailMessagesResponse,
    MailPricingResponse,
    MailProductsResponse,
    MailQuoteResponse,
    MailSendQuoteRequest,
    MailSendRequest,
    MailSendResponse,
    MailWebhookCreateRequest,
    MailWebhookListResponse,
    MailWebhookResponse,
    StalwartEventEnvelope,
)
from hyrule_cloud.mail.service import MailProblem, MailService
from hyrule_cloud.middleware.x402 import PaymentGate, canonical_payment_authorization
from hyrule_cloud.state import AppState, get_app_state

router = APIRouter(prefix="/v1/mail", tags=["agent-mail"])
internal_router = APIRouter(prefix="/v1/internal/mail", tags=["internal"], include_in_schema=False)
log = structlog.get_logger().bind(component="agent_mail_api")


def _mail_payment_authorization(request: Request) -> str | None:
    return request.headers.get("payment-signature") or request.headers.get("x-payment")


def _mail_payment_authorization_fingerprint(request: Request) -> str | None:
    supplied = _mail_payment_authorization(request)
    if not supplied:
        return None
    try:
        return canonical_payment_authorization(supplied).fingerprint
    except (TypeError, ValueError) as exc:
        raise MailProblem(
            400,
            "payment_authorization_invalid",
            "The payment authorization could not be decoded.",
        ) from exc


async def get_mail(state: AppState = Depends(get_app_state)) -> MailService:
    if state.mail is None:
        raise MailProblem(503, "mail_service_unavailable", "Agent Mail is unavailable.")
    return state.mail


async def get_gate(state: AppState = Depends(get_app_state)) -> PaymentGate:
    return state.payment_gate


def _token(request: Request) -> str:
    scheme, _, value = (request.headers.get("authorization") or "").strip().partition(" ")
    if scheme.lower() != "bearer" or not value.startswith("hyr_identity_"):
        raise MailProblem(
            401, "management_token_required", "A mailbox management token is required."
        )
    return value


def _idempotency(value: str | None) -> str:
    if not value:
        raise MailProblem(400, "idempotency_key_required", "An Idempotency-Key is required.")
    return value


@router.get("/products", response_model=MailProductsResponse)
async def products(service: MailService = Depends(get_mail)) -> MailProductsResponse:
    return service.products()


@router.get("/pricing", response_model=MailPricingResponse)
async def pricing(service: MailService = Depends(get_mail)) -> MailPricingResponse:
    return service.pricing()


@router.get("/capabilities", response_model=MailCapabilitiesResponse)
async def capabilities(service: MailService = Depends(get_mail)) -> MailCapabilitiesResponse:
    return service.capabilities()


@router.post("/accounts/quote", response_model=MailQuoteResponse, status_code=201)
async def create_account_quote(
    body: MailAccountQuoteRequest,
    service: MailService = Depends(get_mail),
) -> MailQuoteResponse:
    return await service.create_account_quote(body)


@router.get("/quotes/{quote_id}", response_model=MailQuoteResponse)
async def get_quote(
    quote_id: str,
    service: MailService = Depends(get_mail),
) -> MailQuoteResponse:
    return await service.get_quote(quote_id)


@router.post("/accounts", response_model=MailAccountResponse)
async def create_account(
    body: MailAccountCreateRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    service: MailService = Depends(get_mail),
    gate: PaymentGate = Depends(get_gate),
) -> MailAccountResponse | Response:
    response.headers["Cache-Control"] = "no-store"
    account, token, _created = await service.prepare_activation(
        body.quote_id,
        idempotency_key=_idempotency(idempotency_key),
    )
    if account.status == "awaiting_payment" and account.payment_settled_at is not None:
        account = await service.mark_activation_paid(
            account.mailbox_id,
            body.quote_id,
            payer=account.owner_wallet or "unknown",
            tx_hash=account.payment_tx,
            payment_network=account.payment_network,
            payment_asset=account.payment_asset,
        )
    if account.status == "awaiting_payment":
        activation_amount = account.total_amount_usd
        if activation_amount is None:
            raise MailProblem(
                500,
                "mail_activation_amount_missing",
                "The activation price is unavailable; no payment was attempted.",
            )
        payment_metadata = {
            "mailbox_id": account.mailbox_id,
            "quote_id": body.quote_id,
            "address": account.address,
            "status_url": f"/v1/mail/accounts/{account.mailbox_id}",
            "domain_order_id": account.domain_order_id,
        }
        challenge_metadata = dict(payment_metadata)
        # The first 402 must hand the caller its capability. A paid request
        # omits it from extra_body because settled extra_body is persisted in
        # the payment ledger for recovery and must never contain secrets.
        if not isinstance(gate, PaymentGate) or not gate.has_payment_credentials(request):
            challenge_metadata["management_token"] = token
        verification_metadata = (
            payment_metadata if gate.has_payment_credentials(request) else challenge_metadata
        )
        verified = await gate.verify_only(
            request,
            amount=activation_amount,
            description=f"Activate Agent Mail for {account.address}",
            extra_body=verification_metadata,
        )
        if isinstance(verified, Response):
            verified.headers["Cache-Control"] = "no-store"
            return verified
        fingerprint = _mail_payment_authorization_fingerprint(request)
        if fingerprint is not None:
            await service.bind_payment_authorization(fingerprint, body.quote_id)
        await service.reserve_activation_capacity(account.mailbox_id, quote_id=body.quote_id)
        await service.begin_activation_settlement(
            account.mailbox_id,
            body.quote_id,
            payer=verified.payer or "unknown",
            payment_network=getattr(verified.matching_requirements, "network", None),
            payment_asset=getattr(verified.matching_requirements, "asset", None),
            payment_authorization=_mail_payment_authorization(request),
        )
        if not await gate.settle_verified(request, verified, extra_body=payment_metadata):
            if getattr(request.state, "payment_settlement_indeterminate", False):
                raise MailProblem(
                    503,
                    "mail_payment_settlement_pending",
                    "Payment outcome is being reconciled; retry this activation later.",
                )
            await service.clear_activation_settlement(account.mailbox_id, body.quote_id)
            await service.release_activation_capacity(account.mailbox_id)
            raise MailProblem(
                402,
                "mail_payment_settlement_failed",
                "Payment did not settle; no mailbox capacity was consumed.",
            )
        payer = getattr(request.state, "payment_payer", None) or verified.payer or "unknown"
        durable_error: Exception | None = None
        for attempt in range(3):
            try:
                account = await service.record_activation_settlement(
                    account.mailbox_id,
                    body.quote_id,
                    payer=payer,
                    tx_hash=getattr(request.state, "payment_tx", None),
                    payment_network=getattr(request.state, "payment_network", None),
                    payment_asset=getattr(request.state, "payment_asset", None),
                )
                durable_error = None
                break
            except Exception as exc:
                durable_error = exc
                log.warning(
                    "mail_payment_settlement_record_failed",
                    mailbox_id=account.mailbox_id,
                    attempt=attempt + 1,
                    exc_info=True,
                )
                if attempt < 2:
                    await asyncio.sleep(0.1 * (attempt + 1))
        if durable_error is not None:
            raise MailProblem(
                503,
                "mail_payment_handoff_pending",
                "Payment settled, but activation is pending durable recovery.",
            ) from durable_error
        handoff_error: Exception | None = None
        for attempt in range(3):
            try:
                account = await service.mark_activation_paid(
                    account.mailbox_id,
                    body.quote_id,
                    payer=payer,
                    tx_hash=getattr(request.state, "payment_tx", None),
                    payment_network=getattr(request.state, "payment_network", None),
                    payment_asset=getattr(request.state, "payment_asset", None),
                )
                handoff_error = None
                break
            except Exception as exc:
                handoff_error = exc
                log.warning(
                    "mail_payment_handoff_attempt_failed",
                    mailbox_id=account.mailbox_id,
                    attempt=attempt + 1,
                    exc_info=True,
                )
                if attempt < 2:
                    await asyncio.sleep(0.1 * (attempt + 1))
        if handoff_error is not None:
            raise MailProblem(
                503,
                "mail_payment_handoff_pending",
                "Payment settled, but activation is pending durable recovery.",
            ) from handoff_error
        response.status_code = 202
    else:
        response.status_code = 200
    return await service.activation_response(account, management_token=token)


@router.get("/accounts/{mailbox_id}", response_model=MailAccountResponse)
async def get_account(
    mailbox_id: str,
    request: Request,
    service: MailService = Depends(get_mail),
) -> MailAccountResponse:
    return await service.get_account(mailbox_id, _token(request))


@router.post("/messages/send/quote", response_model=MailQuoteResponse, status_code=201)
async def create_send_quote(
    body: MailSendQuoteRequest,
    request: Request,
    service: MailService = Depends(get_mail),
) -> MailQuoteResponse:
    return await service.create_send_quote(body, _token(request))


@router.post("/messages/send", response_model=MailSendResponse)
async def send_message(
    body: MailSendRequest,
    request: Request,
    service: MailService = Depends(get_mail),
    gate: PaymentGate = Depends(get_gate),
) -> MailSendResponse | Response:
    service.require_launch()
    quote = await service.get_quote(body.quote_id)
    if quote.kind != "send":
        raise MailProblem(422, "wrong_quote_kind", "A send quote is required.")
    token = _token(request)
    settled = await service.settled_send_response(body.quote_id, token)
    if settled is not None:
        return settled
    payment_metadata = {"quote_id": body.quote_id, "one_recipient": True}
    verified = await gate.verify_only(
        request,
        amount=Decimal(quote.amount_usd),
        description="Send one Agent Mail message",
        extra_body=payment_metadata,
    )
    if isinstance(verified, Response):
        return verified
    fingerprint = _mail_payment_authorization_fingerprint(request)
    if fingerprint is not None:
        await service.bind_payment_authorization(fingerprint, body.quote_id)
    result = await service.deliver_send(body.quote_id, token)
    await service.begin_send_settlement(
        result.send_id,
        body.quote_id,
        payer=verified.payer or "unknown",
        payment_network=getattr(verified.matching_requirements, "network", None),
        payment_asset=getattr(verified.matching_requirements, "asset", None),
        payment_authorization=_mail_payment_authorization(request),
    )
    settlement_metadata = {**payment_metadata, "send_id": result.send_id}
    if not await gate.settle_verified(request, verified, extra_body=settlement_metadata):
        if getattr(request.state, "payment_settlement_indeterminate", False):
            raise MailProblem(
                503,
                "mail_payment_settlement_pending",
                "The message was accepted and its payment outcome is being reconciled.",
            )
        await service.clear_send_settlement(result.send_id, body.quote_id)
        raise MailProblem(
            402,
            "mail_payment_settlement_failed",
            "The message was accepted, but payment did not settle; retry this same quote.",
        )
    payer = getattr(request.state, "payment_payer", None) or verified.payer or "unknown"
    durable_error: Exception | None = None
    for attempt in range(3):
        try:
            send = await service.record_send_settlement(
                result.send_id,
                body.quote_id,
                payer=payer,
                tx_hash=getattr(request.state, "payment_tx", None),
                payment_network=getattr(request.state, "payment_network", None),
                payment_asset=getattr(request.state, "payment_asset", None),
            )
            durable_error = None
            break
        except Exception as exc:
            durable_error = exc
            log.warning(
                "mail_send_payment_settlement_record_failed",
                send_id=result.send_id,
                attempt=attempt + 1,
                exc_info=True,
            )
            if attempt < 2:
                await asyncio.sleep(0.1 * (attempt + 1))
    if durable_error is not None:
        raise MailProblem(
            503,
            "mail_payment_handoff_pending",
            "Payment settled, but send attribution is pending durable recovery.",
        ) from durable_error
    return send


@router.get("/accounts/{mailbox_id}/messages", response_model=MailMessagesResponse)
async def list_messages(
    mailbox_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    service: MailService = Depends(get_mail),
) -> MailMessagesResponse:
    return await service.list_messages(mailbox_id, _token(request), limit=limit)


@router.get("/accounts/{mailbox_id}/messages/{message_id}", response_model=MailMessageDetail)
async def get_message(
    mailbox_id: str,
    message_id: str,
    request: Request,
    service: MailService = Depends(get_mail),
) -> MailMessageDetail:
    return await service.get_message(mailbox_id, message_id, _token(request))


@router.get("/accounts/{mailbox_id}/attachments/{blob_id}")
async def download_attachment(
    mailbox_id: str,
    blob_id: str,
    request: Request,
    name: str = Query(default="attachment", min_length=1, max_length=255),
    type: str = Query(default="application/octet-stream", min_length=3, max_length=255),
    service: MailService = Depends(get_mail),
) -> Response:
    body, media_type = await service.download_attachment(
        mailbox_id,
        blob_id,
        _token(request),
        name=name,
        media_type=type,
    )
    return Response(content=body, media_type=media_type)


@router.get("/accounts/{mailbox_id}/events", response_model=MailEventsResponse)
async def list_events(
    mailbox_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=200),
    service: MailService = Depends(get_mail),
) -> MailEventsResponse:
    return await service.list_events(mailbox_id, _token(request), limit=limit)


@router.post(
    "/accounts/{mailbox_id}/webhooks",
    response_model=MailWebhookResponse,
    status_code=201,
)
async def create_webhook(
    mailbox_id: str,
    body: MailWebhookCreateRequest,
    request: Request,
    service: MailService = Depends(get_mail),
) -> MailWebhookResponse:
    return await service.create_webhook(mailbox_id, _token(request), body)


@router.get(
    "/accounts/{mailbox_id}/webhooks",
    response_model=MailWebhookListResponse,
)
async def list_webhooks(
    mailbox_id: str,
    request: Request,
    service: MailService = Depends(get_mail),
) -> MailWebhookListResponse:
    return await service.list_webhooks(mailbox_id, _token(request))


@router.delete("/accounts/{mailbox_id}/webhooks/{webhook_id}", status_code=204)
async def delete_webhook(
    mailbox_id: str,
    webhook_id: str,
    request: Request,
    service: MailService = Depends(get_mail),
) -> Response:
    await service.delete_webhook(mailbox_id, webhook_id, _token(request))
    return Response(status_code=204)


@internal_router.post("/events", status_code=202)
async def ingest_events(
    body: StalwartEventEnvelope,
    request: Request,
    signature: Annotated[str | None, Header(alias="X-Signature")] = None,
    legacy_signature: Annotated[str | None, Header(alias="X-Stalwart-Signature")] = None,
    state: AppState = Depends(get_app_state),
    service: MailService = Depends(get_mail),
) -> dict[str, int]:
    secret = state.config.mail.internal_webhook_secret
    if not secret:
        raise MailProblem(404, "not_found", "Not found.")
    raw = await request.body()
    expected_hex = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    expected_b64 = b64encode(hmac.new(secret.encode(), raw, hashlib.sha256).digest()).decode()
    supplied = (signature or legacy_signature or "").removeprefix("sha256=")
    if not (
        hmac.compare_digest(expected_hex, supplied) or hmac.compare_digest(expected_b64, supplied)
    ):
        raise MailProblem(401, "invalid_event_signature", "The event signature is invalid.")
    # Re-parse raw bytes so the authenticated representation is the one used.
    try:
        payload = StalwartEventEnvelope.model_validate(json.loads(raw))
    except (ValueError, TypeError) as exc:
        raise MailProblem(400, "invalid_event_payload", "The event payload is invalid.") from exc
    return {"accepted": await service.ingest_stalwart_events(payload.events)}
