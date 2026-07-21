"""Public and account-scoped managed-domain HTTP API."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from hyrule_cloud.db import AccountRow, DomainOrderRow, DomainQuoteRow
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import (
    AgentDomainOrderRequest,
    AgentDomainOrderResponse,
    DNSChangesetRequest,
    DNSSECUpdateRequest,
    DNSZoneResponse,
    DomainCheckResponse,
    DomainDetailResponse,
    DomainListResponse,
    DomainOperationResponse,
    DomainOrderRequest,
    DomainOrderResponse,
    DomainQuoteRequest,
    DomainQuoteResponse,
    DomainTLDListResponse,
    DomainTransferOutRequest,
    LegacyDomainClaimRequest,
    NameserverUpdateRequest,
)
from hyrule_cloud.domains.service import DomainService
from hyrule_cloud.domains.validation import normalize_registrable_domain
from hyrule_cloud.domains.wallet_auth import (
    WalletAction,
    WalletAuthService,
    WalletChallengeRequest,
    WalletChallengeResponse,
)
from hyrule_cloud.middleware.auth import current_account, require_account, require_scope
from hyrule_cloud.middleware.x402 import PaymentGate, canonical_payment_authorization
from hyrule_cloud.state import AppState, get_app_state

router = APIRouter(prefix="/v1/domains", tags=["domains"])
log = structlog.get_logger()


async def get_domains(state: AppState = Depends(get_app_state)) -> DomainService:
    service = state.domains
    if service is None:
        raise DomainProblem(503, "domain_service_unavailable", "The domain service is unavailable.")
    return service


async def get_wallet_auth(state: AppState = Depends(get_app_state)) -> WalletAuthService:
    service = state.wallet_auth
    if service is None:
        raise DomainProblem(503, "wallet_auth_unavailable", "Wallet authentication is unavailable.")
    return service


async def get_gate(state: AppState = Depends(get_app_state)) -> PaymentGate:
    return state.payment_gate


def _idempotency(value: str | None) -> str:
    if not value or len(value) > 128:
        raise DomainProblem(
            400, "idempotency_key_required", "A valid Idempotency-Key header is required."
        )
    return value


async def _settle_x402_order(
    *,
    service: DomainService,
    gate: PaymentGate,
    request: Request,
    order: DomainOrderRow,
    description: str,
    payment_metadata: dict[str, Any],
    pending_code: str,
) -> DomainOrderRow | Response:
    """Settle only after a recoverable order-local intent is committed."""

    if order.status == "awaiting_payment" and order.paid_at is not None:
        return await service.mark_x402_paid(
            order.order_id,
            payer=order.payer or "unknown",
            tx_hash=order.payment_tx,
            payment_network=order.payment_network,
            payment_asset=order.payment_asset,
        )
    await service.assert_x402_payable(order.order_id)
    verified = await gate.verify_only(
        request,
        amount=order.amount_usd,
        description=description,
        extra_body=payment_metadata,
    )
    if isinstance(verified, Response):
        return verified
    requirements = verified.matching_requirements
    payment_authorization = request.headers.get("payment-signature") or request.headers.get(
        "x-payment"
    )
    payment_authorization_fingerprint: str | None = None
    if payment_authorization is not None:
        try:
            payment_authorization_fingerprint = canonical_payment_authorization(
                payment_authorization
            ).fingerprint
        except (TypeError, ValueError) as exc:
            raise DomainProblem(
                400,
                "payment_authorization_invalid",
                "The payment authorization could not be decoded.",
            ) from exc
    await service.begin_x402_settlement(
        order.order_id,
        payer=verified.payer or "unknown",
        payment_network=getattr(requirements, "network", None),
        payment_asset=getattr(requirements, "asset", None),
        payment_authorization_fingerprint=payment_authorization_fingerprint,
        payment_authorization=payment_authorization,
    )
    if not await gate.settle_verified(
        request,
        verified,
        extra_body=payment_metadata,
    ):
        if getattr(request.state, "payment_settlement_indeterminate", False):
            raise DomainProblem(
                503,
                pending_code,
                "Payment outcome is being reconciled; retry this domain order later.",
            )
        await service.clear_x402_settlement(order.order_id)
        raise DomainProblem(
            402,
            "payment_settlement_failed",
            "Payment did not settle; the domain order remains unpaid.",
        )

    payer = getattr(request.state, "payment_payer", None) or verified.payer or "unknown"
    durable_error: Exception | None = None
    for attempt in range(3):
        try:
            order = await service.record_x402_settlement(
                order.order_id,
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
                "domain_payment_settlement_record_failed",
                order_id=order.order_id,
                attempt=attempt + 1,
                exc_info=True,
            )
            if attempt < 2:
                await asyncio.sleep(0.1 * (attempt + 1))
    if durable_error is not None:
        raise DomainProblem(
            503,
            pending_code,
            "Payment settled, but the domain order is pending durable recovery.",
        ) from durable_error

    handoff_error: Exception | None = None
    for attempt in range(3):
        try:
            order = await service.mark_x402_paid(
                order.order_id,
                payer=payer,
                tx_hash=order.payment_tx,
                payment_network=order.payment_network,
                payment_asset=order.payment_asset,
            )
            handoff_error = None
            break
        except Exception as exc:
            handoff_error = exc
            log.warning(
                "domain_payment_handoff_attempt_failed",
                order_id=order.order_id,
                attempt=attempt + 1,
                exc_info=True,
            )
            if attempt < 2:
                await asyncio.sleep(0.1 * (attempt + 1))
    if handoff_error is not None:
        raise DomainProblem(
            503,
            pending_code,
            "Payment settled, but the domain order is pending durable recovery.",
        ) from handoff_error
    return order


@router.get("/tlds", response_model=DomainTLDListResponse)
async def list_tlds(service: DomainService = Depends(get_domains)) -> DomainTLDListResponse:
    return await service.list_tlds()


@router.get("/openapi.json", include_in_schema=False)
async def domain_openapi(request: Request) -> dict[str, Any]:
    routes = [
        route
        for route in request.app.routes
        if isinstance(route, APIRoute)
        and (route.path.startswith("/v1/domains") or route.path.startswith("/v1/auth/wallet"))
        and route.include_in_schema
    ]
    return get_openapi(
        title="Hyrule Domains API",
        version=request.app.version,
        description=(
            "Account-owned domain registration, renewal, nameservers, DNSSEC, "
            "managed DNS, wallet authentication, and transfer-out."
        ),
        routes=routes,
    )


@router.get("/docs", include_in_schema=False)
async def domain_docs() -> HTMLResponse:
    return get_swagger_ui_html(
        openapi_url="/v1/domains/openapi.json",
        title="Hyrule Domains API",
    )


@router.get("/check", response_model=DomainCheckResponse)
async def check_domain(
    domain: str = Query(min_length=3, max_length=253),
    service: DomainService = Depends(get_domains),
) -> DomainCheckResponse:
    return await service.check(domain)


@router.post("/quotes", response_model=DomainQuoteResponse, status_code=201)
async def create_quote(
    body: DomainQuoteRequest,
    request: Request,
    account: AccountRow | None = Depends(current_account),
    service: DomainService = Depends(get_domains),
) -> DomainQuoteResponse:
    if (
        body.action.value == "renew"
        and getattr(request.state, "is_api_key", False)
        and "domain:renew" not in getattr(request.state, "api_key_scopes", set())
    ):
        raise DomainProblem(403, "missing_scope", "API key missing required scope: domain:renew.")
    return await service.create_quote(
        body.domain,
        body.action,
        account.account_id if account else None,
    )


@router.get("/quotes/{quote_id}", response_model=DomainQuoteResponse)
async def get_quote(
    quote_id: str,
    service: DomainService = Depends(get_domains),
) -> DomainQuoteResponse:
    return await service.get_quote(quote_id)


@router.post("/orders", response_model=DomainOrderResponse)
async def create_order(
    body: DomainOrderRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    account: AccountRow = Depends(require_account),
    service: DomainService = Depends(get_domains),
    gate: PaymentGate = Depends(get_gate),
) -> DomainOrderResponse | Response:
    if getattr(request.state, "is_api_key", False):
        held: set[str] = getattr(request.state, "api_key_scopes", set())
        async with service.db() as session:
            quote = await session.get(DomainQuoteRow, body.quote_id)
        needed = (
            "domain:renew" if quote is not None and quote.action == "renew" else "domain:purchase"
        )
        if needed not in held:
            raise DomainProblem(403, "missing_scope", f"API key missing required scope: {needed}.")
    order, created = await service.create_order(
        body,
        owner_account_id=account.account_id,
        idempotency_key=_idempotency(idempotency_key),
    )
    if body.payment_method.value in {"btc", "xmr"}:
        response.status_code = 201 if created else 200
        return await service.order_response(order)
    if order.status == "awaiting_payment":
        settled = await _settle_x402_order(
            service=service,
            gate=gate,
            request=request,
            order=order,
            description=f"Hyrule domain order for {order.fqdn}",
            payment_metadata={
                "order_id": order.order_id,
                "domain": order.fqdn,
                "amount_usd": f"{order.amount_usd:.2f}",
                "quote_id": order.quote_id,
            },
            pending_code="payment_handoff_pending",
        )
        if isinstance(settled, Response):
            return settled
        order = settled
        response.status_code = 202
    else:
        response.status_code = 200
    return await service.order_response(order)


def _agent_token(request: Request) -> str:
    scheme, _, token = (request.headers.get("authorization") or "").strip().partition(" ")
    if scheme.lower() != "bearer" or not token.startswith(("hyr_dom_", "hyr_identity_")):
        raise DomainProblem(
            401, "management_token_required", "A domain management token is required."
        )
    return token


@router.post("/agent/orders", response_model=AgentDomainOrderResponse)
async def create_agent_order(
    body: AgentDomainOrderRequest,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    service: DomainService = Depends(get_domains),
    gate: PaymentGate = Depends(get_gate),
) -> AgentDomainOrderResponse | Response:
    response.headers["Cache-Control"] = "no-store"
    order, token, created = await service.create_agent_order(
        quote_id=body.quote_id,
        terms_version=body.terms_version,
        idempotency_key=_idempotency(idempotency_key),
    )
    if order.status == "awaiting_payment":
        payment_metadata = {
            "order_id": order.order_id,
            "domain": order.fqdn,
            "status_url": f"/v1/domains/agent/orders/{order.order_id}",
        }
        challenge_metadata = dict(payment_metadata)
        if not isinstance(gate, PaymentGate) or not gate.has_payment_credentials(request):
            challenge_metadata["management_token"] = token
        settled = await _settle_x402_order(
            service=service,
            gate=gate,
            request=request,
            order=order,
            description=f"Hyrule wallet-native domain order for {order.fqdn}",
            payment_metadata=challenge_metadata,
            pending_code="agent_domain_payment_handoff_pending",
        )
        if isinstance(settled, Response):
            settled.headers["Cache-Control"] = "no-store"
            return settled
        order = settled
        response.status_code = 202
    else:
        response.status_code = 201 if created else 200
    return await service.agent_order_response(order, management_token=token)


@router.get("/agent/orders/{order_id}", response_model=AgentDomainOrderResponse)
async def get_agent_order(
    order_id: str,
    request: Request,
    service: DomainService = Depends(get_domains),
) -> AgentDomainOrderResponse:
    return await service.get_agent_order(order_id, _agent_token(request))


@router.get("/orders/{order_id}", response_model=DomainOrderResponse)
async def get_order(
    order_id: str,
    account: AccountRow = Depends(require_scope("domain:read")),
    service: DomainService = Depends(get_domains),
) -> DomainOrderResponse:
    return await service.get_order(account.account_id, order_id)


@router.get("", response_model=DomainListResponse)
async def list_domains(
    account: AccountRow = Depends(require_scope("domain:read")),
    service: DomainService = Depends(get_domains),
) -> DomainListResponse:
    return await service.list_domains(account.account_id)


@router.get("/{domain}", response_model=DomainDetailResponse)
async def get_domain(
    domain: str,
    account: AccountRow = Depends(require_scope("domain:read")),
    service: DomainService = Depends(get_domains),
) -> DomainDetailResponse:
    return await service.get_domain(account.account_id, domain)


@router.put("/{domain}/nameservers", response_model=DomainOperationResponse, status_code=202)
async def update_nameservers(
    domain: str,
    body: NameserverUpdateRequest,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    account: AccountRow = Depends(require_scope("domain:nameservers")),
    service: DomainService = Depends(get_domains),
) -> DomainOperationResponse:
    return await service.enqueue_nameserver_update(
        account.account_id, domain, body, _idempotency(idempotency_key)
    )


@router.get("/{domain}/dns", response_model=DNSZoneResponse)
async def get_dns_zone(
    domain: str,
    account: AccountRow = Depends(require_scope("domain:dns")),
    service: DomainService = Depends(get_domains),
) -> DNSZoneResponse:
    return await service.get_zone(account.account_id, domain)


@router.post("/{domain}/dns/changesets", response_model=DNSZoneResponse)
async def apply_dns_changeset(
    domain: str,
    body: DNSChangesetRequest,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    account: AccountRow = Depends(require_scope("domain:dns")),
    service: DomainService = Depends(get_domains),
) -> DNSZoneResponse:
    idempotency_key = _idempotency(idempotency_key)
    if if_match is None:
        raise DomainProblem(428, "if_match_required", "An If-Match zone revision is required.")
    match = re.fullmatch(r'(?:W/)?"?(\d+)"?', if_match.strip())
    if match is None:
        raise DomainProblem(
            400,
            "invalid_if_match",
            "If-Match must contain the numeric zone revision.",
        )
    revision = int(match.group(1))
    return await service.apply_changeset(
        account.account_id,
        domain,
        revision,
        body,
        idempotency_key=idempotency_key,
    )


@router.put("/{domain}/dnssec", response_model=DomainOperationResponse, status_code=202)
async def update_dnssec(
    domain: str,
    body: DNSSECUpdateRequest,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    account: AccountRow = Depends(require_scope("domain:dns")),
    service: DomainService = Depends(get_domains),
) -> DomainOperationResponse:
    return await service.enqueue_dnssec_update(
        account.account_id, domain, body, _idempotency(idempotency_key)
    )


class TransferChallengeBody(BaseModel):
    address: str = Field(pattern=r"^0x[0-9A-Fa-f]{40}$")
    chain_id: int = Field(gt=0)


@router.post("/{domain}/transfer-out/challenge", response_model=WalletChallengeResponse)
async def transfer_challenge(
    domain: str,
    body: TransferChallengeBody,
    account: AccountRow = Depends(require_scope("domain:transfer")),
    domains: DomainService = Depends(get_domains),
    wallet: WalletAuthService = Depends(get_wallet_auth),
) -> WalletChallengeResponse:
    _, _, fqdn = normalize_registrable_domain(domain)
    await domains.get_domain(account.account_id, fqdn)
    row = await wallet.create_challenge(
        WalletChallengeRequest(
            action=WalletAction.TRANSFER,
            address=body.address,
            chain_id=body.chain_id,
            resource=fqdn,
        ),
        account=account,
    )
    return WalletChallengeResponse(nonce=row.nonce, message=row.message, expires_at=row.expires_at)


@router.post("/{domain}/transfer-out", response_model=DomainOperationResponse, status_code=202)
async def transfer_out(
    domain: str,
    body: DomainTransferOutRequest,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    account: AccountRow = Depends(require_scope("domain:transfer")),
    domains: DomainService = Depends(get_domains),
    wallet: WalletAuthService = Depends(get_wallet_auth),
) -> DomainOperationResponse:
    _, _, fqdn = normalize_registrable_domain(domain)
    await domains.get_domain(account.account_id, fqdn)
    key = _idempotency(idempotency_key)
    existing = await domains.find_existing_operation(
        account.account_id,
        fqdn,
        "transfer_out",
        {},
        key,
    )
    if existing is not None:
        return existing
    await wallet.consume_transfer_challenge(
        nonce=body.nonce,
        signature=body.signature,
        account_id=account.account_id,
        resource=fqdn,
    )
    return await domains.enqueue_transfer_out(account.account_id, fqdn, key)


@router.get("/operations/{operation_id}", response_model=DomainOperationResponse)
async def get_operation(
    operation_id: str,
    request: Request,
    account: AccountRow = Depends(require_scope("domain:read")),
    service: DomainService = Depends(get_domains),
) -> DomainOperationResponse:
    reveal_secret = not getattr(request.state, "is_api_key", False) or (
        "domain:transfer" in getattr(request.state, "api_key_scopes", set())
    )
    return await service.get_operation(
        account.account_id,
        operation_id,
        reveal_secret=reveal_secret,
    )


@router.post("/{domain}/claim", response_model=DomainDetailResponse)
async def claim_legacy_domain(
    domain: str,
    body: LegacyDomainClaimRequest,
    account: AccountRow = Depends(require_scope("domain:purchase")),
    service: DomainService = Depends(get_domains),
) -> DomainDetailResponse:
    return await service.claim_legacy_domain(account.account_id, domain, body.token)


@router.post("/webhooks/openprovider", include_in_schema=False, status_code=202)
async def openprovider_webhook(
    request: Request,
    signature: Annotated[str | None, Header(alias="X-OpenProvider-Signature")] = None,
    state: AppState = Depends(get_app_state),
) -> dict[str, bool]:
    secret = state.config.domain.openprovider_webhook_secret
    if not secret:
        raise DomainProblem(404, "not_found", "Not found.")
    raw = await request.body()
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    provided = (signature or "").removeprefix("sha256=")
    if not hmac.compare_digest(expected, provided):
        raise DomainProblem(401, "invalid_webhook_signature", "The webhook signature is invalid.")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise DomainProblem(400, "invalid_webhook", "The webhook body is invalid.") from exc
    service = await get_domains(state)
    await service.ingest_webhook(payload, event_id=request.headers.get("X-OpenProvider-Event-Id"))
    return {"accepted": True}
