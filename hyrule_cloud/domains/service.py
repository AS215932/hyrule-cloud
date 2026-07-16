"""Managed-domain lifecycle service and durable fulfillment outbox."""

from __future__ import annotations

import hashlib
import json
import socket
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast, overload

import dns.asyncresolver
import dns.dnssec
import dns.name
import dns.rdatatype
import structlog
from cryptography.fernet import Fernet, InvalidToken
from fastapi.encoders import jsonable_encoder
from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    CryptoIntentRow,
    DomainDNSRecordRow,
    DomainIdempotencyRow,
    DomainJobRow,
    DomainOperationRow,
    DomainOrderRow,
    DomainQuoteRow,
    DomainRow,
    OpenproviderWebhookRow,
    PaymentEventRow,
    VMQuoteRow,
    VMRow,
)
from hyrule_cloud.domains.catalog import DomainCatalog, _operation_price
from hyrule_cloud.domains.dns_control import DNSControlClient, DNSControlError
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import (
    DNSChangeAction,
    DNSChangesetRequest,
    DNSRRSet,
    DNSSECMode,
    DNSSECUpdateRequest,
    DNSZoneResponse,
    DomainAction,
    DomainCheckResponse,
    DomainDetailResponse,
    DomainFailurePolicy,
    DomainListResponse,
    DomainOperationResponse,
    DomainOperationStatus,
    DomainOrderRequest,
    DomainOrderResponse,
    DomainOrderStatus,
    DomainPaymentMethod,
    DomainQuoteResponse,
    DomainSummary,
    DomainTLDListResponse,
    DomainTLDSummary,
    ManagedRecordType,
    NameserverMode,
    NameserverUpdateRequest,
    NativePaymentInstructions,
    generate_domain_job_id,
    generate_domain_operation_id,
    generate_domain_order_id,
    generate_domain_quote_id,
)
from hyrule_cloud.domains.pricing import money_breakdown, price_domain
from hyrule_cloud.domains.validation import (
    normalize_registrable_domain,
    validate_nameservers,
    validate_rrset,
)
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.models import (
    CryptoIntentStatus,
    DomainMode,
    DomainStatus,
    QuoteStatus,
    VMCreateRequest,
    VMStatus,
    generate_vm_id,
)
from hyrule_cloud.providers.native_crypto import Asset, NativeCryptoProvider
from hyrule_cloud.providers.openprovider import (
    OpenproviderClient,
    OpenproviderError,
    OpenproviderUnavailableError,
)
from hyrule_cloud.providers.rates import RateProvider
from hyrule_cloud.services.intents import IntentExistsError, create_intent
from hyrule_cloud.services.quotes import link_quote_vm

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(UTC)


@overload
def _aware(value: datetime) -> datetime: ...


@overload
def _aware(value: None) -> None: ...


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class DomainService:
    def __init__(
        self,
        config: HyruleConfig,
        session_factory: async_sessionmaker[AsyncSession],
        provider: OpenproviderClient,
        rates: RateProvider,
        native_crypto: NativeCryptoProvider,
        orchestrator: Any,
    ) -> None:
        self.config = config
        self.domain_config = config.domain
        self.db = session_factory
        self.provider = provider
        self.rates = rates
        self.native_crypto = native_crypto
        self.orchestrator = orchestrator
        self.catalog = DomainCatalog(config.domain, session_factory, provider)
        self.dns = DNSControlClient(config.domain)

    async def close(self) -> None:
        await self.dns.close()

    def require_purchase_launch(self, account_id: str) -> None:
        cfg = self.domain_config
        if not cfg.enabled or not cfg.purchases_enabled:
            raise DomainProblem(
                503,
                "purchases_disabled",
                "Domain purchases are not enabled yet.",
                headers={"Retry-After": "3600"},
            )
        if not cfg.legal_approved or not cfg.tax_approved:
            raise DomainProblem(
                503,
                "launch_approval_pending",
                "Domain checkout is awaiting legal and tax launch approval.",
                headers={"Retry-After": "3600"},
            )
        if not self.dns.configured:
            raise DomainProblem(
                503,
                "managed_dns_not_ready",
                "Domain checkout is unavailable until managed DNS is configured.",
                headers={"Retry-After": "3600"},
            )
        provider_cfg = self.config.openprovider
        if not all(
            (
                provider_cfg.username,
                provider_cfg.password,
                provider_cfg.owner_handle,
                provider_cfg.admin_handle,
                provider_cfg.tech_handle,
                provider_cfg.billing_handle,
            )
        ):
            raise DomainProblem(
                503,
                "registrar_not_ready",
                "Domain checkout is unavailable until registrar contacts are configured.",
            )
        if cfg.account_allowlist and account_id not in cfg.account_allowlist:
            raise DomainProblem(
                403, "account_not_allowlisted", "This account is not in the launch cohort."
            )

    async def list_tlds(self) -> DomainTLDListResponse:
        rows = await self.catalog.list_eligible()
        if not rows:
            raise DomainProblem(
                503,
                "catalog_unavailable",
                "Domain pricing is not available until the first catalog sync completes.",
            )
        summaries: list[DomainTLDSummary] = []
        for row in rows:
            if row.registration_cost is None or row.renewal_cost is None or not row.currency:
                continue
            fx = await self._fx(row.currency)
            reg = price_domain(Decimal(row.registration_cost), fx, self.domain_config)
            renewal = price_domain(Decimal(row.renewal_cost), fx, self.domain_config)
            summaries.append(
                DomainTLDSummary(
                    tld=row.tld,
                    registration=money_breakdown(*reg),
                    renewal=money_breakdown(*renewal),
                    refreshed_at=row.refreshed_at,
                )
            )
        refreshed = min((_aware(row.refreshed_at) for row in rows), default=None)
        return DomainTLDListResponse(tlds=summaries, refreshed_at=refreshed)

    async def check(self, value: str) -> DomainCheckResponse:
        name, tld, fqdn = normalize_registrable_domain(value)
        await self.catalog.get(tld)
        try:
            result = await self.provider.check_domain(name, tld)
        except OpenproviderError as exc:
            raise DomainProblem(
                503,
                "registrar_unavailable",
                "Live domain availability is temporarily unavailable.",
                headers={"Retry-After": "60"},
            ) from exc
        available = _is_available(result)
        premium = bool(result.get("is_premium") or result.get("premium"))
        checked_at = _now()
        if premium:
            return DomainCheckResponse(
                domain=fqdn,
                eligible=False,
                available=available,
                premium=True,
                reason="premium_not_supported",
                checked_at=checked_at,
            )
        if not available:
            return DomainCheckResponse(
                domain=fqdn,
                eligible=True,
                available=False,
                premium=False,
                reason="registered_or_unavailable",
                checked_at=checked_at,
            )
        amount = result.get("price_amount")
        currency = str(result.get("price_currency") or "").upper()
        if amount is None or not currency:
            raise DomainProblem(
                503,
                "price_unavailable",
                "The registrar did not return a firm registration price.",
            )
        registration = price_domain(
            Decimal(str(amount)), await self._fx(currency), self.domain_config
        )
        tld_row = await self.catalog.get(tld)
        if tld_row.renewal_cost is None or not tld_row.currency:
            raise DomainProblem(503, "price_unavailable", "Renewal pricing is unavailable.")
        renewal = price_domain(
            Decimal(tld_row.renewal_cost),
            await self._fx(tld_row.currency),
            self.domain_config,
        )
        return DomainCheckResponse(
            domain=fqdn,
            eligible=True,
            available=True,
            premium=False,
            registration=money_breakdown(*registration),
            renewal=money_breakdown(*renewal),
            checked_at=checked_at,
        )

    async def create_quote(
        self,
        value: str,
        action: DomainAction,
        owner_account_id: str | None,
    ) -> DomainQuoteResponse:
        _, tld, fqdn = normalize_registrable_domain(value)
        tld_row = await self.catalog.get(tld)
        snapshot: dict[str, Any]
        available = True
        premium = False
        if action is DomainAction.REGISTER:
            name, extension, _ = normalize_registrable_domain(fqdn)
            try:
                snapshot = await self.provider.check_domain(name, extension)
            except OpenproviderError as exc:
                raise DomainProblem(
                    503,
                    "registrar_unavailable",
                    "Live domain availability is temporarily unavailable.",
                ) from exc
            if not _is_available(snapshot):
                raise DomainProblem(409, "domain_unavailable", "This domain is not available.")
            provider_cost_raw = snapshot.get("price_amount")
            currency = str(snapshot.get("price_currency") or "").upper()
            premium = bool(snapshot.get("is_premium") or snapshot.get("premium"))
        else:
            if owner_account_id is None:
                raise DomainProblem(
                    401, "authentication_required", "Renewal quotes require an account."
                )
            domain = await self._owned_domain(owner_account_id, fqdn)
            if domain.status not in {DomainStatus.ACTIVE, DomainStatus.RENEWAL_DUE}:
                raise DomainProblem(
                    409,
                    "domain_not_renewable",
                    "This domain cannot be renewed in its current state.",
                )
            if not domain.can_renew:
                raise DomainProblem(
                    409, "renewal_window_closed", "The registrar renewal window is not open yet."
                )
            provider_cost_raw = tld_row.renewal_cost
            currency = str(tld_row.currency or "").upper()
            snapshot = dict(tld_row.metadata_ or {})
        if premium:
            raise DomainProblem(422, "premium_not_supported", "Premium domains are not supported.")
        if provider_cost_raw is None or not currency:
            raise DomainProblem(503, "price_unavailable", "A firm registrar price is unavailable.")
        provider_cost = Decimal(str(provider_cost_raw))
        fx = await self._fx(currency)
        priced = price_domain(provider_cost, fx, self.domain_config)
        now = _now()
        row = DomainQuoteRow(
            quote_id=generate_domain_quote_id(),
            fqdn=fqdn,
            action=action.value,
            owner_account_id=owner_account_id,
            status="active",
            provider_cost=provider_cost,
            provider_currency=currency,
            fx_rate=fx,
            provider_cost_usd=priced[0],
            hyrule_fee_usd=priced[1],
            tax_usd=priced[2],
            total_usd=priced[3],
            available=available,
            premium=premium,
            provider_snapshot=jsonable_encoder(snapshot),
            terms_version=self.domain_config.terms_version,
            created_at=now,
            expires_at=now + timedelta(seconds=self.domain_config.quote_ttl_seconds),
        )
        async with self.db() as session:
            session.add(row)
            await session.commit()
        return self._quote_response(row)

    async def get_quote(self, quote_id: str) -> DomainQuoteResponse:
        async with self.db() as session:
            row = await session.get(DomainQuoteRow, quote_id)
        if row is None:
            raise DomainProblem(404, "quote_not_found", "Domain quote not found.")
        return self._quote_response(row)

    async def create_order(
        self,
        body: DomainOrderRequest,
        *,
        owner_account_id: str,
        idempotency_key: str,
    ) -> tuple[DomainOrderRow, bool]:
        self.require_purchase_launch(owner_account_id)
        if not idempotency_key or len(idempotency_key) > 128:
            raise DomainProblem(
                400, "idempotency_key_required", "A valid Idempotency-Key header is required."
            )
        async with self.db() as session:
            existing = (
                await session.execute(
                    select(DomainOrderRow).where(
                        DomainOrderRow.owner_account_id == owner_account_id,
                        DomainOrderRow.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                self._validate_order_replay(existing, body)
                if body.payment_method in {
                    DomainPaymentMethod.BTC,
                    DomainPaymentMethod.XMR,
                }:
                    existing = await self._ensure_native_order_intent(
                        existing,
                        body,
                        owner_account_id=owner_account_id,
                        idempotency_key=idempotency_key,
                    )
                return existing, False
            quote = await session.get(DomainQuoteRow, body.quote_id)
            if quote is None:
                raise DomainProblem(404, "quote_not_found", "Domain quote not found.")
            if quote.owner_account_id and quote.owner_account_id != owner_account_id:
                raise DomainProblem(404, "quote_not_found", "Domain quote not found.")
            if _aware(quote.expires_at) < _now() or quote.status == "expired":
                raise DomainProblem(409, "quote_expired", "This domain quote has expired.")
            if quote.status != "active":
                raise DomainProblem(
                    409,
                    "quote_unavailable",
                    "This domain quote is already bound to another order.",
                )
            if (
                quote.terms_version != body.terms_version
                or body.terms_version != self.domain_config.terms_version
            ):
                raise DomainProblem(
                    409, "terms_changed", "The domain terms changed; request a new quote."
                )
            vm_amount = Decimal("0")
            if body.vm_quote_id:
                if quote.action != DomainAction.REGISTER.value:
                    raise DomainProblem(
                        422,
                        "bundle_not_supported",
                        "A VM can only be bundled with a domain registration.",
                    )
                vm_quote = await session.get(VMQuoteRow, body.vm_quote_id)
                if vm_quote is None or (
                    vm_quote.owner_account_id and vm_quote.owner_account_id != owner_account_id
                ):
                    raise DomainProblem(404, "vm_quote_not_found", "VM quote not found.")
                if vm_quote.status != QuoteStatus.CREATED or _aware(vm_quote.expires_at) < _now():
                    raise DomainProblem(
                        409, "vm_quote_expired", "The VM quote is no longer payable."
                    )
                vm_spec = VMCreateRequest.model_validate(vm_quote.order_payload)
                if vm_spec.domain_mode is not DomainMode.CUSTOM or vm_spec.domain != quote.fqdn:
                    raise DomainProblem(
                        409,
                        "bundle_mismatch",
                        "The VM quote is not bound to this managed domain.",
                    )
                vm_amount = Decimal(vm_quote.amount_usd)
            now = _now()
            # Reserve the quote in the same transaction that creates its order.
            # The conditional write is the concurrency guard: only one order can
            # become payable, even if two idempotency keys race on the same quote.
            reserved = await session.execute(
                update(DomainQuoteRow)
                .where(
                    DomainQuoteRow.quote_id == quote.quote_id,
                    DomainQuoteRow.status == "active",
                    DomainQuoteRow.expires_at > now,
                )
                .values(status="reserved")
                .execution_options(synchronize_session=False)
            )
            if int(getattr(reserved, "rowcount", 0) or 0) != 1:
                await session.rollback()
                winner = (
                    await session.execute(
                        select(DomainOrderRow).where(
                            DomainOrderRow.owner_account_id == owner_account_id,
                            DomainOrderRow.idempotency_key == idempotency_key,
                        )
                    )
                ).scalar_one_or_none()
                if winner is not None:
                    self._validate_order_replay(winner, body)
                    if body.payment_method in {
                        DomainPaymentMethod.BTC,
                        DomainPaymentMethod.XMR,
                    }:
                        winner = await self._ensure_native_order_intent(
                            winner,
                            body,
                            owner_account_id=owner_account_id,
                            idempotency_key=idempotency_key,
                        )
                    return winner, False
                raise DomainProblem(
                    409,
                    "quote_unavailable",
                    "This domain quote is already bound to another order.",
                )
            if body.vm_quote_id:
                vm_quote_claim = await session.execute(
                    update(VMQuoteRow)
                    .where(
                        VMQuoteRow.quote_id == body.vm_quote_id,
                        VMQuoteRow.status == QuoteStatus.CREATED.value,
                        VMQuoteRow.expires_at > now,
                    )
                    .values(status=QuoteStatus.CONSUMED.value)
                    .execution_options(synchronize_session=False)
                )
                if int(getattr(vm_quote_claim, "rowcount", 0) or 0) != 1:
                    await session.rollback()
                    raise DomainProblem(
                        409,
                        "vm_quote_expired",
                        "The VM quote is no longer payable.",
                    )
            order = DomainOrderRow(
                order_id=generate_domain_order_id(),
                quote_id=quote.quote_id,
                fqdn=quote.fqdn,
                action=quote.action,
                owner_account_id=owner_account_id,
                idempotency_key=idempotency_key,
                status=DomainOrderStatus.AWAITING_PAYMENT.value,
                amount_usd=Decimal(quote.total_usd) + vm_amount,
                domain_amount_usd=quote.total_usd,
                vm_amount_usd=vm_amount,
                payment_method=body.payment_method.value,
                refund_address=body.refund_address,
                vm_quote_id=body.vm_quote_id,
                on_domain_failure=body.on_domain_failure.value,
                terms_version=body.terms_version,
                terms_accepted_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(order)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                winner = (
                    await session.execute(
                        select(DomainOrderRow).where(
                            DomainOrderRow.owner_account_id == owner_account_id,
                            DomainOrderRow.idempotency_key == idempotency_key,
                        )
                    )
                ).scalar_one_or_none()
                if winner is not None:
                    self._validate_order_replay(winner, body)
                    if body.payment_method in {
                        DomainPaymentMethod.BTC,
                        DomainPaymentMethod.XMR,
                    }:
                        winner = await self._ensure_native_order_intent(
                            winner,
                            body,
                            owner_account_id=owner_account_id,
                            idempotency_key=idempotency_key,
                        )
                    return winner, False
                raise DomainProblem(409, "order_conflict", "This order already exists.") from exc
        if body.payment_method in {DomainPaymentMethod.BTC, DomainPaymentMethod.XMR}:
            order = await self._ensure_native_order_intent(
                order,
                body,
                owner_account_id=owner_account_id,
                idempotency_key=idempotency_key,
            )
        return order, True

    @staticmethod
    def _validate_order_replay(order: DomainOrderRow, body: DomainOrderRequest) -> None:
        if (
            order.quote_id != body.quote_id
            or order.payment_method != body.payment_method.value
            or order.refund_address != body.refund_address
            or order.vm_quote_id != body.vm_quote_id
            or order.on_domain_failure != body.on_domain_failure.value
            or order.terms_version != body.terms_version
        ):
            raise DomainProblem(
                409,
                "idempotency_conflict",
                "This Idempotency-Key is already bound to a different order.",
            )

    async def _ensure_native_order_intent(
        self,
        order: DomainOrderRow,
        body: DomainOrderRequest,
        *,
        owner_account_id: str,
        idempotency_key: str,
    ) -> DomainOrderRow:
        if order.native_intent_id:
            return order
        async with self.db() as session:
            quote_expires_at = await session.scalar(
                select(DomainQuoteRow.expires_at).where(
                    DomainQuoteRow.quote_id == order.quote_id
                )
            )
        if quote_expires_at is None:
            raise DomainProblem(404, "quote_not_found", "Domain quote not found.")
        client_order_id = (
            "dom_"
            + hashlib.sha256(f"{owner_account_id}:{idempotency_key}".encode()).hexdigest()[:48]
        )
        try:
            intent = await create_intent(
                session_factory=self.db,
                provider=self.native_crypto,
                rates=self.rates,
                asset=body.payment_method.value.upper(),
                order_payload={"domain_order_id": order.order_id},
                amount_usd=Decimal(order.amount_usd),
                client_order_id=client_order_id,
                owner_account_id=owner_account_id,
                expires_at=quote_expires_at,
                resource_type="domain_order",
                resource_id=order.order_id,
                refund_address=body.refund_address,
            )
        except IntentExistsError as exc:
            intent = exc.existing
        except Exception as exc:
            await self._set_order_error(
                order.order_id,
                "payment_unavailable",
                str(exc),
                paid=False,
            )
            raise DomainProblem(
                503,
                "native_payment_unavailable",
                "Native payment is unavailable.",
            ) from exc
        async with self.db() as session:
            current = await session.get(DomainOrderRow, order.order_id)
            if current is None:
                raise DomainProblem(404, "order_not_found", "Domain order not found.")
            current.native_intent_id = intent.intent_id
            if (
                current.status == DomainOrderStatus.FAILED.value
                and current.error_code == "payment_unavailable"
            ):
                current.status = DomainOrderStatus.AWAITING_PAYMENT.value
                current.error_code = None
                current.error_detail = None
            await session.commit()
            return current

    async def mark_x402_paid(
        self,
        order_id: str,
        *,
        payer: str,
        tx_hash: str | None,
        payment_network: str | None = None,
        payment_asset: str | None = None,
    ) -> DomainOrderRow:
        return await self._mark_paid(
            order_id,
            payer=payer,
            tx_hash=tx_hash,
            payment_network=payment_network,
            payment_asset=payment_asset,
        )

    async def assert_x402_payable(self, order_id: str) -> None:
        async with self.db() as session:
            order = (
                await session.execute(
                    select(DomainOrderRow)
                    .where(DomainOrderRow.order_id == order_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if order is None:
                raise DomainProblem(404, "order_not_found", "Domain order not found.")
            quote = await session.get(DomainQuoteRow, order.quote_id)
            if (
                quote is None
                or quote.status not in {"active", "reserved"}
                or (_aware(quote.expires_at) is not None and _aware(quote.expires_at) <= _now())
            ):
                now = _now()
                await self._expire_unpaid_order(session, order, now=now)
                if quote is not None and _aware(quote.expires_at) <= now:
                    quote.status = "expired"
                await session.commit()
                raise DomainProblem(
                    409, "quote_expired", "This order's payment window has expired."
                )

    async def native_order_settled(self, order_id: str, intent: CryptoIntentRow) -> DomainOrderRow:
        return await self._mark_paid(
            order_id,
            payer=intent.intent_id,
            tx_hash=intent.tx_hash,
            payment_network="native",
            payment_asset=intent.asset,
        )

    async def _mark_paid(
        self,
        order_id: str,
        *,
        payer: str,
        tx_hash: str | None,
        payment_network: str | None = None,
        payment_asset: str | None = None,
    ) -> DomainOrderRow:
        async with self.db() as session:
            order = (
                await session.execute(
                    select(DomainOrderRow)
                    .where(DomainOrderRow.order_id == order_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if order is None:
                raise DomainProblem(404, "order_not_found", "Domain order not found.")
            if order.status not in {
                DomainOrderStatus.AWAITING_PAYMENT.value,
                DomainOrderStatus.PAID.value,
                DomainOrderStatus.QUEUED.value,
            }:
                return order
            if order.status == DomainOrderStatus.AWAITING_PAYMENT.value:
                # Persist settlement attribution before any quote validation so
                # an invalidated quote still produces a usable refund record.
                order.paid_at = _now()
                order.payer = payer[:128]
                order.payment_tx = tx_hash
                order.payment_network = payment_network
                order.payment_asset = payment_asset
                quote = (
                    await session.execute(
                        select(DomainQuoteRow)
                        .where(DomainQuoteRow.quote_id == order.quote_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    quote is None
                    or quote.status not in {"active", "reserved"}
                    or _aware(quote.expires_at) <= _now()
                ):
                    if quote is not None and _aware(quote.expires_at) <= _now():
                        quote.status = "expired"
                    order.status = DomainOrderStatus.REFUND_DUE.value
                    order.error_code = "quote_already_consumed"
                    session.add(self._build_refund_event(order, "quote_already_consumed"))
                    await session.commit()
                    return order
                quote.status = "consumed"
                quote.consumed_at = _now()
                if order.vm_quote_id:
                    vm_quote = await session.get(VMQuoteRow, order.vm_quote_id)
                    if vm_quote is None or vm_quote.status != QuoteStatus.CONSUMED:
                        order.status = DomainOrderStatus.REFUND_DUE.value
                        order.error_code = "vm_quote_already_consumed"
                        session.add(
                            self._build_refund_event(order, "vm_quote_already_consumed")
                        )
                        await session.commit()
                        return order
                order.status = DomainOrderStatus.QUEUED.value
                operation = DomainOperationRow(
                    operation_id=generate_domain_operation_id(),
                    fqdn=order.fqdn,
                    owner_account_id=order.owner_account_id,
                    order_id=order.order_id,
                    kind=order.action,
                    status=DomainOperationStatus.QUEUED.value,
                    request_payload={"order_id": order.order_id},
                )
                order.operation_id = operation.operation_id
                session.add(operation)
                self._add_job(
                    session,
                    kind="fulfill_order",
                    resource_id=order.order_id,
                    dedupe_key=f"order:{order.order_id}",
                    payload={"operation_id": operation.operation_id},
                )
                await session.commit()
            return order

    async def get_order(self, owner_account_id: str, order_id: str) -> DomainOrderResponse:
        async with self.db() as session:
            row = await session.get(DomainOrderRow, order_id)
            if row is None or row.owner_account_id != owner_account_id:
                raise DomainProblem(404, "order_not_found", "Domain order not found.")
            intent = (
                await session.get(CryptoIntentRow, row.native_intent_id)
                if row.native_intent_id
                else None
            )
            if (
                intent is not None
                and str(intent.status) == CryptoIntentStatus.EXPIRED.value
                and row.status == DomainOrderStatus.AWAITING_PAYMENT.value
            ):
                await self._expire_unpaid_order(session, row, now=_now())
                await session.commit()
                await session.refresh(row)
        return self._order_response(row, intent)

    async def order_response(self, row: DomainOrderRow) -> DomainOrderResponse:
        async with self.db() as session:
            current = await session.get(DomainOrderRow, row.order_id)
            if current is None:
                raise DomainProblem(404, "order_not_found", "Domain order not found.")
            intent = (
                await session.get(CryptoIntentRow, current.native_intent_id)
                if current.native_intent_id
                else None
            )
            if (
                intent is not None
                and str(intent.status) == CryptoIntentStatus.EXPIRED.value
                and current.status == DomainOrderStatus.AWAITING_PAYMENT.value
            ):
                await self._expire_unpaid_order(session, current, now=_now())
                await session.commit()
                await session.refresh(current)
        return self._order_response(current, intent)

    async def list_domains(self, owner_account_id: str) -> DomainListResponse:
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(DomainRow)
                    .where(DomainRow.owner_account_id == owner_account_id)
                    .order_by(DomainRow.fqdn)
                )
            )
        return DomainListResponse(domains=[self._domain_summary(row) for row in rows])

    async def get_domain(self, owner_account_id: str, value: str) -> DomainDetailResponse:
        _, _, fqdn = normalize_registrable_domain(value)
        row = await self._owned_domain(owner_account_id, fqdn)
        status = str(row.status)
        return DomainDetailResponse(
            **self._domain_summary(row).model_dump(),
            registered_at=row.registered_at,
            provider_status=row.provider_status,
            can_renew=bool(row.can_renew),
            can_transfer=status in {DomainStatus.ACTIVE.value, DomainStatus.RENEWAL_DUE.value},
            linked_vm_id=row.vm_id,
        )

    async def get_zone(self, owner_account_id: str, value: str) -> DNSZoneResponse:
        _, _, fqdn = normalize_registrable_domain(value)
        domain = await self._owned_domain(owner_account_id, fqdn)
        async with self.db() as session:
            records = list(
                await session.scalars(
                    select(DomainDNSRecordRow)
                    .where(DomainDNSRecordRow.fqdn == fqdn)
                    .order_by(DomainDNSRecordRow.name, DomainDNSRecordRow.type)
                )
            )
        return DNSZoneResponse(
            domain=fqdn,
            revision=domain.zone_revision,
            records=[DNSRRSet.model_validate(self._record_payload(row)) for row in records],
            dnssec_mode=DNSSECMode(domain.dnssec_mode),
            dnssec_status=domain.dnssec_status,
        )

    async def apply_changeset(
        self,
        owner_account_id: str,
        value: str,
        expected_revision: int,
        body: DNSChangesetRequest,
        *,
        idempotency_key: str,
    ) -> DNSZoneResponse:
        _, _, fqdn = normalize_registrable_domain(value)
        if len(body.changes) > self.domain_config.max_dns_changes:
            raise DomainProblem(422, "too_many_dns_changes", "This changeset has too many entries.")
        kind = f"dns_changeset:{fqdn}"
        canonical = json.dumps(
            {
                "fqdn": fqdn,
                "expected_revision": expected_revision,
                "body": body.model_dump(mode="json"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        request_hash = hashlib.sha256(canonical).hexdigest()
        async with self.db() as session:
            existing_idempotency = (
                await session.execute(
                    select(DomainIdempotencyRow).where(
                        DomainIdempotencyRow.owner_account_id == owner_account_id,
                        DomainIdempotencyRow.kind == kind,
                        DomainIdempotencyRow.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing_idempotency is not None:
                if existing_idempotency.request_hash != request_hash:
                    raise DomainProblem(
                        409,
                        "idempotency_conflict",
                        "This Idempotency-Key is already bound to a different DNS changeset.",
                    )
                return DNSZoneResponse.model_validate(existing_idempotency.response_payload)
            domain = (
                await session.execute(
                    select(DomainRow)
                    .where(DomainRow.fqdn == fqdn, DomainRow.owner_account_id == owner_account_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if domain is None:
                raise DomainProblem(404, "domain_not_found", "Domain not found.")
            # A concurrent request with the same key may have completed while
            # this transaction waited for the zone row lock.
            existing_idempotency = (
                await session.execute(
                    select(DomainIdempotencyRow).where(
                        DomainIdempotencyRow.owner_account_id == owner_account_id,
                        DomainIdempotencyRow.kind == kind,
                        DomainIdempotencyRow.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing_idempotency is not None:
                if existing_idempotency.request_hash != request_hash:
                    raise DomainProblem(
                        409,
                        "idempotency_conflict",
                        "This Idempotency-Key is already bound to a different DNS changeset.",
                    )
                return DNSZoneResponse.model_validate(existing_idempotency.response_payload)
            if domain.nameserver_mode != NameserverMode.MANAGED.value:
                raise DomainProblem(
                    409, "external_nameservers", "Managed DNS is disabled for this domain."
                )
            if domain.zone_revision != expected_revision:
                raise DomainProblem(
                    412,
                    "zone_revision_mismatch",
                    "The DNS zone changed; reload it before applying this changeset.",
                    extra={"current_revision": domain.zone_revision},
                )
            rows = list(
                await session.scalars(
                    select(DomainDNSRecordRow).where(DomainDNSRecordRow.fqdn == fqdn)
                )
            )
            desired = {(row.name, row.type): row for row in rows}
            for change in body.changes:
                rrset = validate_rrset(change.rrset, fqdn)
                if (
                    domain.vm_ipv6 is not None
                    and rrset.name == "@"
                    and rrset.type is ManagedRecordType.AAAA
                ):
                    raise DomainProblem(
                        409,
                        "vm_apex_record_managed",
                        "The apex AAAA record is managed by the attached VM; detach it before changing this record.",
                    )
                key = (rrset.name, rrset.type.value)
                existing = desired.get(key)
                if change.action is DNSChangeAction.DELETE:
                    if existing is not None:
                        await session.delete(existing)
                        desired.pop(key, None)
                    continue
                if existing is None:
                    existing = DomainDNSRecordRow(
                        fqdn=fqdn,
                        name=rrset.name,
                        type=rrset.type.value,
                        ttl=rrset.ttl,
                        values=rrset.values,
                    )
                    session.add(existing)
                    desired[key] = existing
                else:
                    existing.ttl = rrset.ttl
                    existing.values = rrset.values
            record_types_by_name: dict[str, set[str]] = {}
            for record_name, record_type in desired:
                record_types_by_name.setdefault(record_name, set()).add(record_type)
            if any(
                ManagedRecordType.CNAME.value in record_types and len(record_types) > 1
                for record_types in record_types_by_name.values()
            ):
                raise DomainProblem(
                    422,
                    "cname_conflict",
                    "A CNAME record cannot share its name with another DNS record type.",
                )
            if len(desired) > self.domain_config.max_dns_rrsets:
                raise DomainProblem(422, "zone_limit_exceeded", "This zone has too many RRsets.")
            revision = domain.zone_revision + 1
            payload = [self._record_payload(row) for row in desired.values()]
            try:
                await self.dns.apply_zone(fqdn, revision=revision, records=payload)
            except DNSControlError as exc:
                raise DomainProblem(
                    503, "managed_dns_unavailable", "Managed DNS is temporarily unavailable."
                ) from exc
            domain.zone_revision = revision
            response = DNSZoneResponse(
                domain=fqdn,
                revision=revision,
                records=[
                    DNSRRSet.model_validate(self._record_payload(row))
                    for row in sorted(desired.values(), key=lambda row: (row.name, row.type))
                ],
                dnssec_mode=DNSSECMode(domain.dnssec_mode),
                dnssec_status=domain.dnssec_status,
            )
            session.add(
                DomainIdempotencyRow(
                    owner_account_id=owner_account_id,
                    kind=kind,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    response_payload=response.model_dump(mode="json"),
                )
            )
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                winner = (
                    await session.execute(
                        select(DomainIdempotencyRow).where(
                            DomainIdempotencyRow.owner_account_id == owner_account_id,
                            DomainIdempotencyRow.kind == kind,
                            DomainIdempotencyRow.idempotency_key == idempotency_key,
                        )
                    )
                ).scalar_one_or_none()
                if winner is not None and winner.request_hash == request_hash:
                    return DNSZoneResponse.model_validate(winner.response_payload)
                raise DomainProblem(
                    409,
                    "idempotency_conflict",
                    "This Idempotency-Key is already bound to another request.",
                ) from exc
        return response

    async def enqueue_nameserver_update(
        self,
        owner_account_id: str,
        value: str,
        body: NameserverUpdateRequest,
        idempotency_key: str,
    ) -> DomainOperationResponse:
        nameservers = (
            self.domain_config.managed_nameservers
            if body.mode is NameserverMode.MANAGED
            else validate_nameservers(body.nameservers)
        )
        return await self._enqueue_domain_operation(
            owner_account_id,
            value,
            "nameservers",
            {"mode": body.mode.value, "nameservers": nameservers},
            idempotency_key,
            reject_vm_attachment=body.mode is NameserverMode.EXTERNAL,
        )

    async def enqueue_dnssec_update(
        self,
        owner_account_id: str,
        value: str,
        body: DNSSECUpdateRequest,
        idempotency_key: str,
    ) -> DomainOperationResponse:
        return await self._enqueue_domain_operation(
            owner_account_id,
            value,
            "dnssec",
            body.model_dump(mode="json"),
            idempotency_key,
        )

    async def enqueue_transfer_out(
        self,
        owner_account_id: str,
        value: str,
        idempotency_key: str,
    ) -> DomainOperationResponse:
        if not self.domain_config.authcode_fernet_key:
            raise DomainProblem(503, "transfer_unavailable", "Transfer-out is not configured.")
        try:
            Fernet(self.domain_config.authcode_fernet_key.encode())
        except (TypeError, ValueError) as exc:
            raise DomainProblem(
                503,
                "transfer_unavailable",
                "Transfer-out encryption is not configured correctly.",
            ) from exc
        return await self._enqueue_domain_operation(
            owner_account_id,
            value,
            "transfer_out",
            {},
            idempotency_key,
        )

    async def find_existing_operation(
        self,
        owner_account_id: str,
        value: str,
        kind: str,
        payload: dict[str, Any],
        idempotency_key: str,
    ) -> DomainOperationResponse | None:
        """Return an exact idempotent replay before consuming one-shot proof."""
        _, _, fqdn = normalize_registrable_domain(value)
        dedupe = self._operation_dedupe(owner_account_id, kind, idempotency_key)
        async with self.db() as session:
            job = (
                await session.execute(select(DomainJobRow).where(DomainJobRow.dedupe_key == dedupe))
            ).scalar_one_or_none()
            if job is None:
                return None
            operation = await session.get(DomainOperationRow, job.resource_id)
        if operation is None:
            return None
        self._validate_operation_replay(operation, fqdn, kind, payload)
        return self._operation_response(operation)

    async def get_operation(
        self,
        owner_account_id: str,
        operation_id: str,
        *,
        reveal_secret: bool = True,
    ) -> DomainOperationResponse:
        async with self.db() as session:
            row = await session.get(DomainOperationRow, operation_id)
            if row is None or row.owner_account_id != owner_account_id:
                raise DomainProblem(404, "operation_not_found", "Domain operation not found.")
            secret: str | None = None
            secret_expires_at = _aware(row.secret_expires_at)
            if (
                reveal_secret
                and row.kind == "transfer_out"
                and row.secret_ciphertext
                and row.secret_revealed_at is None
                and secret_expires_at is not None
                and secret_expires_at > _now()
            ):
                try:
                    secret = (
                        Fernet(self.domain_config.authcode_fernet_key.encode())
                        .decrypt(row.secret_ciphertext.encode())
                        .decode()
                    )
                except (InvalidToken, ValueError):
                    secret = None
                if secret is not None:
                    row.secret_revealed_at = _now()
                    row.secret_ciphertext = None
                    await session.commit()
                    await session.refresh(row)
            elif row.secret_ciphertext and (
                secret_expires_at is None or secret_expires_at <= _now()
            ):
                row.secret_ciphertext = None
                await session.commit()
                await session.refresh(row)
            return self._operation_response(row, secret=secret)

    async def claim_legacy_domain(
        self, owner_account_id: str, value: str, token: str
    ) -> DomainDetailResponse:
        _, _, fqdn = normalize_registrable_domain(value)
        async with self.db() as session:
            row = (
                await session.execute(
                    select(DomainRow).where(DomainRow.fqdn == fqdn).with_for_update()
                )
            ).scalar_one_or_none()
            if (
                row is None
                or row.owner_account_id is not None
                or not row.anon_management_token_hash
            ):
                raise DomainProblem(404, "domain_not_found", "Domain not found.")
            if row.anon_management_token_hash != hash_anon_token(token):
                raise DomainProblem(404, "domain_not_found", "Domain not found.")
            row.owner_account_id = owner_account_id
            row.anon_management_token_hash = None
            await session.commit()
        return await self.get_domain(owner_account_id, fqdn)

    async def process_jobs(self, *, worker_id: str | None = None, limit: int = 10) -> int:
        worker_id = worker_id or socket.gethostname()
        processed = 0
        for _ in range(limit):
            job = await self._claim_job(worker_id)
            if job is None:
                break
            try:
                await self._dispatch_job(job)
            except Exception as exc:
                await self._retry_or_fail_job(job.job_id, exc)
            else:
                async with self.db() as session:
                    current = await session.get(DomainJobRow, job.job_id)
                    if current is not None:
                        current.status = "completed"
                        current.completed_at = _now()
                        await session.commit()
            processed += 1
        return processed

    async def recover_bundle_provisioning(self) -> int:
        """Restart paid bundle VMs left provisioning by a worker restart.

        Only VMs durably linked from a domain order are selected. General VM
        API requests can still be provisioning in an API process, so sweeping
        every provisioning row here would risk two processes doing the work.
        """
        async with self.db() as session:
            vm_ids = list(
                await session.scalars(
                    select(VMRow.vm_id)
                    .join(DomainOrderRow, DomainOrderRow.vm_id == VMRow.vm_id)
                    .where(
                        VMRow.status == VMStatus.PROVISIONING.value,
                        VMRow.owner_wallet != "",
                    )
                )
            )
        for vm_id in vm_ids:
            self.orchestrator.start_provisioning(vm_id)
        return len(vm_ids)

    async def recover_x402_handoffs(self, *, limit: int = 200) -> int:
        """Replay settled domain payments whose order transition was lost."""
        if limit < 1:
            return 0
        recovered = 0
        seen: set[str] = set()
        cursor: tuple[datetime, str] | None = None
        while True:
            filters = [
                PaymentEventRow.event_type.in_(["settled", "dev_bypass"]),
                PaymentEventRow.resource_path == "/v1/domains/orders",
            ]
            if cursor is not None:
                created_at, event_id = cursor
                filters.append(
                    or_(
                        PaymentEventRow.created_at < created_at,
                        and_(
                            PaymentEventRow.created_at == created_at,
                            PaymentEventRow.event_id < event_id,
                        ),
                    )
                )
            async with self.db() as session:
                events = list(
                    await session.scalars(
                        select(PaymentEventRow)
                        .where(*filters)
                        .order_by(
                            PaymentEventRow.created_at.desc(),
                            PaymentEventRow.event_id.desc(),
                        )
                        .limit(limit)
                    )
                )
            if not events:
                break
            for event in events:
                extra = event.extra if isinstance(event.extra, dict) else {}
                order_id = str(extra.get("order_id") or "")
                if not order_id or order_id in seen:
                    continue
                seen.add(order_id)
                async with self.db() as session:
                    order = await session.get(DomainOrderRow, order_id)
                    awaiting = bool(
                        order is not None
                        and order.status == DomainOrderStatus.AWAITING_PAYMENT.value
                    )
                if not awaiting:
                    continue
                await self._mark_paid(
                    order_id,
                    payer=event.payer_wallet or "unknown",
                    tx_hash=event.tx_hash,
                    payment_network=event.network,
                    payment_asset=event.asset,
                )
                recovered += 1
            if len(events) < limit:
                break
            last = events[-1]
            cursor = (_aware(last.created_at), last.event_id)
        return recovered

    async def expire_quotes(self) -> int:
        now = _now()
        async with self.db() as session:
            unpaid_orders = list(
                await session.scalars(
                    select(DomainOrderRow)
                    .join(DomainQuoteRow, DomainQuoteRow.quote_id == DomainOrderRow.quote_id)
                    .where(
                        DomainOrderRow.status == DomainOrderStatus.AWAITING_PAYMENT.value,
                        DomainQuoteRow.status.in_(["active", "reserved"]),
                        DomainQuoteRow.expires_at < now,
                    )
                    .with_for_update(of=DomainOrderRow)
                )
            )
            for order in unpaid_orders:
                await self._expire_unpaid_order(session, order, now=now)
            result = await session.execute(
                update(DomainQuoteRow)
                .where(
                    DomainQuoteRow.status.in_(["active", "reserved"]),
                    DomainQuoteRow.expires_at < now,
                )
                .values(status="expired")
            )
            await session.commit()
            return int(getattr(result, "rowcount", 0) or 0)

    async def _expire_unpaid_order(
        self,
        session: Any,
        order: DomainOrderRow,
        *,
        now: datetime,
    ) -> None:
        if order.status != DomainOrderStatus.AWAITING_PAYMENT.value:
            return
        order.status = DomainOrderStatus.EXPIRED.value
        order.error_code = "quote_expired"
        if not order.vm_quote_id:
            return
        vm_quote = (
            await session.execute(
                select(VMQuoteRow)
                .where(VMQuoteRow.quote_id == order.vm_quote_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            vm_quote is not None
            and vm_quote.status == QuoteStatus.CONSUMED.value
            and vm_quote.vm_id is None
        ):
            vm_quote.status = (
                QuoteStatus.EXPIRED
                if _aware(vm_quote.expires_at) <= now
                else QuoteStatus.CREATED
            )

    async def reconcile_pending(self) -> int:
        scheduled = 0
        async with self.db() as session:
            domains = list(
                await session.scalars(
                    select(DomainRow).where(
                        or_(
                            DomainRow.openprovider_id.is_not(None),
                            DomainRow.provider_operation_id.is_not(None),
                        ),
                        DomainRow.status.in_(
                            [
                                DomainStatus.REGISTERING.value,
                                DomainStatus.PROVIDER_PENDING.value,
                                DomainStatus.ACTIVE.value,
                                DomainStatus.RENEWAL_DUE.value,
                                DomainStatus.TRANSFER_PENDING.value,
                            ]
                        ),
                    )
                )
            )
            for domain in domains:
                try:
                    async with session.begin_nested():
                        self._add_job(
                            session,
                            kind="reconcile_domain",
                            resource_id=domain.fqdn,
                            dedupe_key=(f"reconcile:{domain.fqdn}:{_now().date().isoformat()}"),
                            payload={},
                        )
                        await session.flush()
                except IntegrityError:
                    # The daily sweep is intentionally safe to repeat and
                    # multiple workers cannot enqueue the same reconciliation.
                    continue
                scheduled += 1
            await session.commit()
        return scheduled

    async def refresh_renewal_states(self) -> int:
        """Open/close the manual renewal window from stored registrar expiry."""
        now = _now()
        open_at = now + timedelta(days=self.domain_config.renewal_window_days)
        due_at = now + timedelta(days=self.domain_config.renewal_due_days)
        changed = 0
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(DomainRow).where(
                        DomainRow.expires_at.is_not(None),
                        DomainRow.status.in_(
                            [DomainStatus.ACTIVE.value, DomainStatus.RENEWAL_DUE.value]
                        ),
                    )
                )
            )
            for row in rows:
                expires_at = _aware(row.expires_at)
                if expires_at is None:
                    continue
                previous = (bool(row.can_renew), str(row.status))
                if expires_at <= now:
                    row.can_renew = False
                    row.status = DomainStatus.EXPIRED
                else:
                    row.can_renew = expires_at <= open_at
                    row.status = (
                        DomainStatus.RENEWAL_DUE if expires_at <= due_at else DomainStatus.ACTIVE
                    )
                if previous != (bool(row.can_renew), str(row.status)):
                    changed += 1
            await session.commit()
        return changed

    async def ingest_webhook(self, payload: dict[str, Any], *, event_id: str | None = None) -> None:
        """Persist an authenticated webhook and use it only as a reconcile hint."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        event_id = event_id or "opw_" + hashlib.sha256(canonical).hexdigest()
        event_type = str(payload.get("event") or payload.get("type") or "")[:64] or None
        fqdn = _find_webhook_domain(payload)
        async with self.db() as session:
            if await session.get(OpenproviderWebhookRow, event_id) is not None:
                return
            session.add(
                OpenproviderWebhookRow(
                    event_id=event_id[:128],
                    event_type=event_type,
                    payload=payload,
                )
            )
            if fqdn:
                self._add_job(
                    session,
                    kind="reconcile_domain",
                    resource_id=fqdn,
                    dedupe_key=f"webhook:{event_id[:128]}",
                    payload={"event_id": event_id[:128]},
                )
            await session.commit()

    async def claim_vm_attachment(
        self, owner_account_id: str, value: str, vm_id: str
    ) -> None:
        """Atomically reserve a managed domain before payment settles."""
        _, _, fqdn = normalize_registrable_domain(value)
        async with self.db() as session:
            domain = (
                await session.execute(
                    select(DomainRow)
                    .where(
                        DomainRow.fqdn == fqdn,
                        DomainRow.owner_account_id == owner_account_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if domain is None:
                raise DomainProblem(404, "domain_not_found", "Domain not found.")
            if str(domain.status) not in {
                DomainStatus.ACTIVE.value,
                DomainStatus.RENEWAL_DUE.value,
            }:
                raise DomainProblem(409, "domain_not_active", "The managed domain is not active.")
            if domain.nameserver_mode != NameserverMode.MANAGED.value:
                raise DomainProblem(
                    409,
                    "external_nameservers",
                    "The domain must use Hyrule managed nameservers.",
                )
            if domain.vm_id and domain.vm_id != vm_id:
                raise DomainProblem(
                    409,
                    "domain_already_attached",
                    "The managed domain is already attached to a VM.",
                )
            if domain.vm_id is None:
                apex = (
                    await session.execute(
                        select(DomainDNSRecordRow).where(
                            DomainDNSRecordRow.fqdn == fqdn,
                            DomainDNSRecordRow.name == "@",
                            DomainDNSRecordRow.type == ManagedRecordType.AAAA.value,
                        )
                    )
                ).scalar_one_or_none()
                if apex is not None:
                    raise DomainProblem(
                        409,
                        "apex_aaaa_in_use",
                        "The apex AAAA record is customer-managed and cannot be attached.",
                    )
                domain.vm_id = vm_id
                domain.vm_ipv6 = None
                await session.commit()

    async def release_vm_attachment_claim(self, vm_id: str) -> None:
        """Release an unpaid or failed pre-attachment reservation."""
        async with self.db() as session:
            domain = (
                await session.execute(
                    select(DomainRow).where(DomainRow.vm_id == vm_id).with_for_update()
                )
            ).scalar_one_or_none()
            if domain is not None and domain.vm_ipv6 is None:
                domain.vm_id = None
                await session.commit()

    async def enqueue_vm_attachment(
        self,
        owner_account_id: str,
        fqdn: str,
        vm_id: str,
        ipv6: str,
    ) -> None:
        await self._enqueue_vm_job(
            kind="attach_vm",
            vm_id=vm_id,
            payload={
                "owner_account_id": owner_account_id,
                "fqdn": fqdn,
                "vm_id": vm_id,
                "ipv6": ipv6,
            },
        )

    async def enqueue_vm_detachment(
        self,
        owner_account_id: str,
        fqdn: str,
        vm_id: str,
        *,
        release_prefix: bool = False,
    ) -> None:
        await self._enqueue_vm_job(
            kind="detach_vm",
            vm_id=vm_id,
            payload={
                "owner_account_id": owner_account_id,
                "fqdn": fqdn,
                "vm_id": vm_id,
                "release_prefix": release_prefix,
            },
        )

    async def _enqueue_vm_job(
        self, *, kind: str, vm_id: str, payload: dict[str, Any]
    ) -> None:
        dedupe_key = f"{kind}:{vm_id}"
        async with self.db() as session:
            existing = (
                await session.execute(
                    select(DomainJobRow).where(DomainJobRow.dedupe_key == dedupe_key)
                )
            ).scalar_one_or_none()
            if existing is not None:
                return
            self._add_job(
                session,
                kind=kind,
                resource_id=vm_id,
                dedupe_key=dedupe_key,
                payload=payload,
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()

    async def attach_vm(self, owner_account_id: str, fqdn: str, vm_id: str, ipv6: str) -> None:
        domain = await self._owned_domain(owner_account_id, fqdn)
        if str(domain.status) not in {DomainStatus.ACTIVE.value, DomainStatus.RENEWAL_DUE.value}:
            raise RuntimeError("managed domain is not active")
        async with self.db() as session:
            current = (
                await session.execute(
                    select(DomainRow).where(DomainRow.id == domain.id).with_for_update()
                )
            ).scalar_one_or_none()
            if current is None:
                raise RuntimeError("managed domain disappeared")
            previous_vm_id = current.vm_id
            previous_ipv6 = current.vm_ipv6
            if previous_vm_id and previous_vm_id != vm_id:
                raise RuntimeError("managed domain is already attached to another VM")
            if current.nameserver_mode != NameserverMode.MANAGED.value:
                raise RuntimeError("managed domain is using external nameservers")
            current.vm_id = vm_id
            record = (
                await session.execute(
                    select(DomainDNSRecordRow).where(
                        DomainDNSRecordRow.fqdn == fqdn,
                        DomainDNSRecordRow.name == "@",
                        DomainDNSRecordRow.type == ManagedRecordType.AAAA.value,
                    )
                )
            ).scalar_one_or_none()
            if record is None:
                record = DomainDNSRecordRow(
                    fqdn=fqdn,
                    name="@",
                    type=ManagedRecordType.AAAA.value,
                    ttl=300,
                    values=[ipv6],
                )
                session.add(record)
            else:
                if previous_ipv6 is None:
                    raise RuntimeError("the apex AAAA RRset is already customer-managed")
                if record.ttl != 300 or list(record.values) not in ([previous_ipv6], [ipv6]):
                    raise RuntimeError("the apex AAAA RRset was changed by the customer")
                record.ttl = 300
                record.values = [ipv6]
            records = list(
                await session.scalars(
                    select(DomainDNSRecordRow).where(DomainDNSRecordRow.fqdn == fqdn)
                )
            )
            if record not in records:
                records.append(record)
            revision = current.zone_revision + 1
            await self.dns.apply_zone(
                fqdn,
                revision=revision,
                records=[self._record_payload(item) for item in records],
            )
            current.zone_revision = revision
            current.vm_ipv6 = ipv6
            await session.commit()

    async def detach_vm(self, owner_account_id: str, fqdn: str, vm_id: str) -> None:
        domain = await self._owned_domain(owner_account_id, fqdn)
        async with self.db() as session:
            current = (
                await session.execute(
                    select(DomainRow).where(DomainRow.id == domain.id).with_for_update()
                )
            ).scalar_one_or_none()
            if current is None or current.vm_id != vm_id:
                return
            attached_ipv6 = current.vm_ipv6
            record = (
                await session.execute(
                    select(DomainDNSRecordRow).where(
                        DomainDNSRecordRow.fqdn == fqdn,
                        DomainDNSRecordRow.name == "@",
                        DomainDNSRecordRow.type == ManagedRecordType.AAAA.value,
                    )
                )
            ).scalar_one_or_none()
            managed_record = bool(
                record is not None
                and attached_ipv6 is not None
                and record.ttl == 300
                and list(record.values) == [attached_ipv6]
            )
            if managed_record and current.nameserver_mode == NameserverMode.MANAGED.value:
                assert record is not None
                await session.delete(record)
                records = list(
                    await session.scalars(
                        select(DomainDNSRecordRow).where(
                            DomainDNSRecordRow.fqdn == fqdn,
                            DomainDNSRecordRow.id != record.id,
                        )
                    )
                )
                revision = current.zone_revision + 1
                await self.dns.apply_zone(
                    fqdn,
                    revision=revision,
                    records=[self._record_payload(item) for item in records],
                )
                current.zone_revision = revision
            current.vm_id = None
            current.vm_ipv6 = None
            await session.commit()

    async def _dispatch_job(self, job: DomainJobRow) -> None:
        if job.kind == "fulfill_order":
            await self._fulfill_order(job.resource_id)
        elif job.kind == "nameservers":
            await self._apply_nameservers(job.resource_id)
        elif job.kind == "dnssec":
            await self._apply_dnssec(job.resource_id)
        elif job.kind == "transfer_out":
            await self._transfer_out(job.resource_id)
        elif job.kind == "reconcile_domain":
            await self._reconcile_domain(job.resource_id, retry_pending=True)
        elif job.kind == "attach_vm":
            payload = job.payload or {}
            await self.attach_vm(
                str(payload["owner_account_id"]),
                str(payload["fqdn"]),
                str(payload["vm_id"]),
                str(payload["ipv6"]),
            )
        elif job.kind == "detach_vm":
            payload = job.payload or {}
            await self.detach_vm(
                str(payload["owner_account_id"]),
                str(payload["fqdn"]),
                str(payload["vm_id"]),
            )
            if payload.get("release_prefix"):
                await self.orchestrator.release_destroyed_prefix(str(payload["vm_id"]))
        else:
            raise RuntimeError(f"unknown domain job: {job.kind}")

    async def _fulfill_order(self, order_id: str) -> None:
        async with self.db() as session:
            order = await session.get(DomainOrderRow, order_id)
            if order is None:
                return
            if order.status in {
                DomainOrderStatus.REFUND_DUE.value,
                DomainOrderStatus.REFUNDED.value,
            }:
                return
            if order.status == DomainOrderStatus.ACTIVE.value:
                if order.vm_quote_id and not order.vm_id:
                    await self._provision_bundle(order_id)
                return
            if order.status == DomainOrderStatus.PROVIDER_PENDING.value:
                await self._reconcile_domain(order.fqdn)
                return
            order.status = DomainOrderStatus.CHECKING.value
            operation = await session.get(DomainOperationRow, order.operation_id)
            if operation is not None:
                operation.status = DomainOperationStatus.RUNNING.value
            await session.commit()
        try:
            if order.action == DomainAction.RENEW.value:
                await self._fulfill_renewal(order_id)
            else:
                await self._fulfill_registration(order_id)
        except OpenproviderError as exc:
            if exc.retryable:
                raise
            await self._fail_paid_order(order_id, "registrar_rejected", str(exc))
        except DomainProblem as exc:
            await self._fail_paid_order(order_id, exc.code, exc.detail)

    async def _fulfill_registration(self, order_id: str) -> None:
        async with self.db() as session:
            order = await session.get(DomainOrderRow, order_id)
            if order is None:
                return
            quote = await session.get(DomainQuoteRow, order.quote_id)
        if quote is None:
            await self._fail_paid_order(
                order_id, "quote_missing", "The paid quote no longer exists."
            )
            return
        name, extension, fqdn = normalize_registrable_domain(order.fqdn)
        domain = await self._reserve_registration_domain(order, quote, name, extension)
        if domain is None:
            await self._fail_paid_order(
                order_id,
                "domain_order_conflict",
                "This domain is already assigned to another Hyrule order.",
            )
            return

        if domain.openprovider_id is not None:
            result = await self.provider.get_domain(domain.openprovider_id)
        else:
            submission_started = bool(domain.provider_operation_id)
            check = await self.provider.check_domain(name, extension)
            if bool(check.get("is_premium") or check.get("premium")):
                await self._fail_paid_order(
                    order_id,
                    "became_premium",
                    "The registrar marked this name premium.",
                )
                return
            existing_provider = await self.provider.search_domain(name, extension)
            if existing_provider is not None and not submission_started:
                # Search covers every domain in Hyrule's registrar account. An
                # unrelated legacy domain must never be assigned to whichever
                # customer happens to submit a new order for it.
                await self._fail_paid_order(
                    order_id,
                    "registrar_domain_conflict",
                    "The registrar account already contains this domain.",
                )
                return
            if existing_provider is not None:
                result = existing_provider
            elif submission_started:
                # A previous POST had an ambiguous transport outcome. Reconcile
                # it; never blindly submit a second registration.
                raise OpenproviderUnavailableError(
                    "registration_reconciliation_pending",
                    "The registrar has not exposed the submitted registration yet",
                    retryable=True,
                )
            else:
                if not _is_available(check):
                    await self._fail_paid_order(
                        order_id,
                        "domain_no_longer_available",
                        "The domain is no longer available.",
                    )
                    return
                price_amount = check.get("price_amount")
                currency = str(check.get("price_currency") or "").upper()
                if price_amount is None or not currency:
                    raise DomainProblem(
                        503,
                        "price_unavailable",
                        "The registrar returned no firm price.",
                    )
                current_price = price_domain(
                    Decimal(str(price_amount)),
                    await self._fx(currency),
                    self.domain_config,
                )[3]
                if current_price > Decimal(order.domain_amount_usd):
                    await self._fail_paid_order(
                        order_id,
                        "price_increased",
                        "The registrar price increased after payment.",
                    )
                    return
                async with self.db() as session:
                    current_domain = await session.get(DomainRow, domain.id)
                    current_order = await session.get(DomainOrderRow, order_id)
                    if current_domain is not None:
                        current_domain.provider_operation_id = f"register:{order_id}"
                    if current_order is not None:
                        current_order.status = DomainOrderStatus.SUBMITTING.value
                    await session.commit()
                result = await self.provider.register_domain(
                    name,
                    extension,
                    period=1,
                    nameservers=self.domain_config.managed_nameservers,
                )
        provider_id = _provider_id(result)
        if provider_id is None:
            found = await self.provider.search_domain(name, extension)
            if found is not None:
                result = found
                provider_id = _provider_id(found)
        if provider_id is None:
            raise RuntimeError("registrar accepted registration without a reconcilable domain id")
        provider_status = _provider_status(result)
        active = provider_status in {"ACT", "ACTIVE"}
        expires_at = _provider_expiry(result)
        async with self.db() as session:
            current_domain = await session.get(DomainRow, domain.id)
            if current_domain is None:
                raise RuntimeError("reserved domain disappeared")
            current_domain.openprovider_id = provider_id
            current_domain.provider_status = provider_status
            current_domain.status = (
                DomainStatus.REGISTERING if active else DomainStatus.PROVIDER_PENDING
            )
            current_domain.expires_at = expires_at or current_domain.expires_at
            current_order = await session.get(DomainOrderRow, order_id)
            if current_order is not None:
                current_order.provider_domain_id = provider_id
                current_order.provider_status = provider_status
                current_order.provider_response = jsonable_encoder(result)
                current_order.status = (
                    DomainOrderStatus.SUBMITTING.value
                    if active
                    else DomainOrderStatus.PROVIDER_PENDING.value
                )
            if not active:
                self._add_job(
                    session,
                    kind="reconcile_domain",
                    resource_id=fqdn,
                    dedupe_key=f"provider-pending:{order_id}",
                    payload={"order_id": order_id},
                    available_at=_now()
                    + timedelta(
                        seconds=self.domain_config.provider_reconcile_delay_seconds
                    ),
                )
            operation = await session.get(DomainOperationRow, order.operation_id)
            if operation is not None:
                operation.status = (
                    DomainOperationStatus.RUNNING.value
                    if active
                    else DomainOperationStatus.WAITING_PROVIDER.value
                )
                operation.result_payload = {"provider_status": provider_status}
            await session.commit()
        if active:
            try:
                await self._ensure_managed_zone(fqdn, provider_id)
            except Exception:
                log.exception("managed_zone_initialization_failed", domain=fqdn)
                async with self.db() as session:
                    current_domain = (
                        await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
                    ).scalar_one_or_none()
                    if current_domain is not None:
                        current_domain.dnssec_status = "error"
                        await session.commit()
                raise
            await self._finish_active_order(order_id, fqdn, provider_status)
            await self._provision_bundle(order_id)

    async def _reserve_registration_domain(
        self,
        order: DomainOrderRow,
        quote: DomainQuoteRow,
        name: str,
        extension: str,
    ) -> DomainRow | None:
        async with self.db() as session:
            domain = (
                await session.execute(
                    select(DomainRow).where(DomainRow.fqdn == order.fqdn).with_for_update()
                )
            ).scalar_one_or_none()
            if (
                domain is not None
                and domain.openprovider_id is None
                and str(domain.status) == DomainStatus.FAILED.value
            ):
                # A registrar submission never succeeded, so the failed row is
                # only a stale local reservation. Rebind it to this paid order
                # instead of making the name permanently unpurchasable.
                domain.name = name
                domain.extension = extension
                domain.owner_wallet = order.payer or order.order_id
                domain.owner_account_id = order.owner_account_id
                domain.status = DomainStatus.REGISTERING
                domain.client_order_id = order.order_id
                domain.registrar_price = quote.provider_cost
                domain.markup = quote.hyrule_fee_usd
                domain.total_price = quote.total_usd
                domain.currency = "USD"
                domain.error = None
                domain.provider_status = None
                domain.provider_operation_id = None
                domain.payment_tx = order.payment_tx
                domain.expires_at = None
                domain.vm_id = None
                domain.vm_ipv6 = None
                domain.nameserver_mode = NameserverMode.MANAGED.value
                domain.nameservers = self.domain_config.managed_nameservers
                domain.dnssec_mode = DNSSECMode.MANAGED.value
                domain.dnssec_status = "pending"
                domain.ds_records = []
                domain.zone_revision = 1
                domain.can_renew = False
                domain.transferred_at = None
                domain.registered_at = _now()
                await session.commit()
                await session.refresh(domain)
            if domain is None:
                domain = DomainRow(
                    name=name,
                    extension=extension,
                    fqdn=order.fqdn,
                    owner_wallet=order.payer or order.order_id,
                    owner_account_id=order.owner_account_id,
                    status=DomainStatus.REGISTERING,
                    client_order_id=order.order_id,
                    registrar_price=quote.provider_cost,
                    markup=quote.hyrule_fee_usd,
                    total_price=quote.total_usd,
                    currency="USD",
                    payment_tx=order.payment_tx,
                    nameserver_mode=NameserverMode.MANAGED.value,
                    nameservers=self.domain_config.managed_nameservers,
                    dnssec_mode=DNSSECMode.MANAGED.value,
                    dnssec_status="pending",
                    can_renew=False,
                )
                session.add(domain)
                try:
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    domain = (
                        await session.execute(select(DomainRow).where(DomainRow.fqdn == order.fqdn))
                    ).scalar_one_or_none()
                else:
                    await session.refresh(domain)
            if (
                domain is None
                or domain.client_order_id != order.order_id
                or domain.owner_account_id != order.owner_account_id
            ):
                return None
            return domain

    async def _finish_active_order(
        self,
        order_id: str,
        fqdn: str,
        provider_status: str,
    ) -> None:
        async with self.db() as session:
            domain = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
            ).scalar_one_or_none()
            order = await session.get(DomainOrderRow, order_id)
            operation = (
                await session.get(DomainOperationRow, order.operation_id)
                if order is not None and order.operation_id
                else None
            )
            if domain is not None:
                domain.status = DomainStatus.ACTIVE
                domain.provider_status = provider_status or domain.provider_status
            if order is not None:
                order.status = DomainOrderStatus.ACTIVE.value
                order.provider_status = provider_status or order.provider_status
                order.error_code = None
                order.error_detail = None
            if operation is not None:
                operation.status = DomainOperationStatus.SUCCEEDED.value
                operation.error_code = None
                operation.error_detail = None
            await session.commit()

    async def _fulfill_renewal(self, order_id: str) -> None:
        async with self.db() as session:
            order = await session.get(DomainOrderRow, order_id)
            if order is None:
                return
            domain = (
                await session.execute(
                    select(DomainRow).where(
                        DomainRow.fqdn == order.fqdn,
                        DomainRow.owner_account_id == order.owner_account_id,
                    )
                )
            ).scalar_one_or_none()
        if domain is None or domain.openprovider_id is None:
            await self._fail_paid_order(
                order_id, "domain_not_renewable", "The domain cannot be renewed."
            )
            return
        _, tld, _ = normalize_registrable_domain(domain.fqdn)
        live_tld = await self.provider.get_tld(tld)
        renewal_cost, currency = _operation_price(live_tld, {"renew", "renewal"})
        if renewal_cost is None or not currency:
            raise RuntimeError("registrar returned no live renewal price")
        current_total = price_domain(renewal_cost, await self._fx(currency), self.domain_config)[3]
        if current_total > Decimal(order.domain_amount_usd):
            await self._fail_paid_order(
                order_id,
                "price_increased",
                "The registrar renewal price increased after payment.",
            )
            return
        live = await self.provider.get_domain(domain.openprovider_id)
        live_expiry = _provider_expiry(live)
        metadata = dict(order.provider_response or {})
        baseline_raw = metadata.get("_hyrule_renewal_baseline")
        baseline = _parse_datetime(baseline_raw)
        if baseline is not None:
            if live_expiry is None or live_expiry <= baseline:
                # The prior renewal call had an ambiguous outcome. Do not
                # submit another paid year until the registrar exposes the
                # first operation's new expiry.
                raise OpenproviderUnavailableError(
                    "renewal_reconciliation_pending",
                    "The registrar has not exposed the submitted renewal yet",
                    retryable=True,
                )
            result = live
        else:
            baseline = live_expiry or _aware(domain.expires_at)
            if baseline is None:
                raise RuntimeError("registrar returned no renewal baseline expiry")
            async with self.db() as session:
                current_order = await session.get(DomainOrderRow, order_id)
                current_domain = await session.get(DomainRow, domain.id)
                if current_order is not None:
                    current_order.status = DomainOrderStatus.SUBMITTING.value
                    current_order.provider_response = {
                        "_hyrule_renewal_baseline": baseline.isoformat(),
                        "_hyrule_submission_started": True,
                    }
                if current_domain is not None and current_domain.expires_at is None:
                    current_domain.expires_at = baseline
                await session.commit()
            result = await self.provider.renew_domain(
                domain.openprovider_id,
                name=domain.name,
                extension=domain.extension,
                period=1,
            )
        status = _provider_status(result)
        active = status in {"ACT", "ACTIVE", ""}
        async with self.db() as session:
            current = await session.get(DomainRow, domain.id)
            order = await session.get(DomainOrderRow, order_id)
            operation = (
                await session.get(DomainOperationRow, order.operation_id)
                if order is not None and order.operation_id
                else None
            )
            if current is not None:
                current.provider_status = status or current.provider_status
                current.status = DomainStatus.ACTIVE if active else DomainStatus.PROVIDER_PENDING
                current.expires_at = _provider_expiry(result) or current.expires_at
                current.can_renew = False
            if order is not None:
                response_payload = jsonable_encoder(result)
                if isinstance(response_payload, dict):
                    response_payload["_hyrule_renewal_baseline"] = baseline.isoformat()
                order.provider_response = response_payload
                order.provider_status = status
                order.status = (
                    DomainOrderStatus.ACTIVE.value
                    if active
                    else DomainOrderStatus.PROVIDER_PENDING.value
                )
            if not active:
                self._add_job(
                    session,
                    kind="reconcile_domain",
                    resource_id=domain.fqdn,
                    dedupe_key=f"provider-pending:{order_id}",
                    payload={"order_id": order_id},
                    available_at=_now()
                    + timedelta(
                        seconds=self.domain_config.provider_reconcile_delay_seconds
                    ),
                )
            if operation is not None:
                operation.status = (
                    DomainOperationStatus.SUCCEEDED.value
                    if active
                    else DomainOperationStatus.WAITING_PROVIDER.value
                )
            await session.commit()

    async def _provision_bundle(
        self,
        order_id: str,
        *,
        fallback_auto_domain: bool = False,
    ) -> None:
        async with self.db() as session:
            order = (
                await session.execute(
                    select(DomainOrderRow)
                    .where(DomainOrderRow.order_id == order_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if order is None or not order.vm_quote_id:
                return
            quote = await session.get(VMQuoteRow, order.vm_quote_id)
            if quote is None:
                raise RuntimeError("the bundle VM quote disappeared")
            if quote.vm_id:
                order.vm_id = quote.vm_id
            elif not order.vm_id:
                # Plan the VM id before creating it. A worker crash between the
                # VM insert and quote/order linking can then replay safely.
                order.vm_id = generate_vm_id()
            planned_vm_id = order.vm_id
            await session.commit()
        spec = VMCreateRequest.model_validate(quote.order_payload)
        if fallback_auto_domain:
            spec = spec.model_copy(update={"domain_mode": DomainMode.AUTO, "domain": None})
        else:
            # The registered domain is active at this point, but the VM row does
            # not exist yet. Claim it for the durably planned VM id before any
            # provisioning call so a concurrent standalone VM purchase cannot
            # take the bundle's domain during that gap.
            await self.claim_vm_attachment(
                order.owner_account_id,
                order.fqdn,
                planned_vm_id,
            )
        vm, _ = await self.orchestrator.create_vm(
            spec,
            owner_wallet=order.payer or order.order_id,
            owner_account_id=order.owner_account_id,
            vm_id=planned_vm_id,
            start_provisioning=False,
        )
        await self.orchestrator.persist_charged_amount(vm.vm_id, Decimal(order.vm_amount_usd))
        await link_quote_vm(self.db, quote.quote_id, vm.vm_id)
        async with self.db() as session:
            current = await session.get(DomainOrderRow, order_id)
            if current is not None:
                current.vm_id = vm.vm_id
                await session.commit()
        if str(vm.status) == "failed":
            raise RuntimeError("the planned bundle VM is failed")
        if str(vm.status) == "provisioning":
            self.orchestrator.start_provisioning(vm.vm_id)

    async def _fail_paid_order(self, order_id: str, code: str, detail: str) -> None:
        async with self.db() as session:
            order = await session.get(DomainOrderRow, order_id)
        if order is None:
            return
        vm_kept = False
        if order.vm_quote_id and order.on_domain_failure == DomainFailurePolicy.KEEP_VM.value:
            try:
                await self._provision_bundle(order_id, fallback_auto_domain=True)
                vm_kept = True
            except Exception:
                log.exception("domain_bundle_keep_vm_failed", order_id=order_id)
        refund_amount = Decimal(order.domain_amount_usd) if vm_kept else Decimal(order.amount_usd)
        async with self.db() as session:
            current = (
                await session.execute(
                    select(DomainOrderRow)
                    .where(DomainOrderRow.order_id == order_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if current is None:
                return
            current.status = DomainOrderStatus.REFUND_DUE.value
            current.error_code = code
            current.error_detail = detail[:1000]
            operation = (
                await session.get(DomainOperationRow, current.operation_id)
                if current.operation_id
                else None
            )
            if operation is not None:
                operation.status = DomainOperationStatus.FAILED.value
                operation.error_code = code
                operation.error_detail = detail[:1000]
            domain = (
                await session.execute(
                    select(DomainRow).where(DomainRow.client_order_id == order_id)
                )
            ).scalar_one_or_none()
            if domain is not None and domain.openprovider_id is None:
                domain.status = DomainStatus.FAILED
                domain.error = detail[:1000]
            session.add(self._build_refund_event(current, code, amount=refund_amount))
            await session.commit()

    def _build_refund_event(
        self, order: DomainOrderRow, reason: str, *, amount: Decimal | None = None
    ) -> PaymentEventRow:
        builder = getattr(self.orchestrator.refunds, "build_owed_event", None)
        if builder is None:
            raise RuntimeError("atomic refund ledger is unavailable")
        native = order.payment_method in {
            DomainPaymentMethod.BTC.value,
            DomainPaymentMethod.XMR.value,
        }
        event: PaymentEventRow | None = builder(
            resource_path="/v1/domains/orders",
            payer=order.order_id if native else order.payer,
            amount=amount if amount is not None else Decimal(order.amount_usd),
            original_tx=order.payment_tx,
            reason=reason,
            network="native" if native else order.payment_network,
            asset=order.payment_method.upper() if native else order.payment_asset,
            extra={
                "order_id": order.order_id,
                "domain": order.fqdn,
                "refund_address": order.refund_address,
            },
        )
        if event is None:
            raise RuntimeError("paid domain order has no recordable refund target")
        return event

    async def _apply_nameservers(self, operation_id: str) -> None:
        operation, domain = await self._operation_and_domain(operation_id)
        payload = operation.request_payload or {}
        mode = NameserverMode(payload["mode"])
        nameservers = list(payload.get("nameservers") or [])
        if mode is NameserverMode.EXTERNAL:
            self._assert_external_delegation_allowed(domain)
        if domain.openprovider_id is None:
            raise RuntimeError("domain has no registrar id")
        incompatible_dnssec = (
            mode is NameserverMode.MANAGED and domain.dnssec_mode == DNSSECMode.EXTERNAL.value
        ) or (mode is NameserverMode.EXTERNAL and domain.dnssec_mode == DNSSECMode.MANAGED.value)
        if incompatible_dnssec:
            # Parent DS material for the previous authority must disappear
            # before delegation moves. Otherwise validating resolvers can use
            # the old DS records against the new zone and return SERVFAIL.
            await self.provider.set_dnssec_keys(domain.openprovider_id, [])
        if mode is NameserverMode.MANAGED:
            await self._ensure_managed_zone(
                domain.fqdn,
                domain.openprovider_id,
                dnssec_mode=DNSSECMode.OFF if incompatible_dnssec else None,
            )
        else:
            await self.provider.update_nameservers(domain.openprovider_id, nameservers)
        if (
            mode is NameserverMode.EXTERNAL
            and domain.nameserver_mode == NameserverMode.MANAGED.value
        ):
            # Do not report success while the old authoritative copy still
            # exists. The job is idempotent and will retry registrar state plus
            # de-cataloging until both sides converge.
            await self.dns.delete_zone(domain.fqdn)
        async with self.db() as session:
            current = await session.get(DomainRow, domain.id)
            op = await session.get(DomainOperationRow, operation_id)
            if current is not None:
                current.nameserver_mode = mode.value
                current.nameservers = nameservers
                if incompatible_dnssec:
                    current.dnssec_mode = DNSSECMode.OFF.value
                    current.dnssec_status = "off"
                    current.ds_records = []
            if op is not None:
                op.status = DomainOperationStatus.SUCCEEDED.value
                op.result_payload = {"mode": mode.value, "nameservers": nameservers}
            await session.commit()

    async def _apply_dnssec(self, operation_id: str) -> None:
        operation, domain = await self._operation_and_domain(operation_id)
        if domain.openprovider_id is None:
            raise RuntimeError("domain has no registrar id")
        payload = operation.request_payload or {}
        mode = DNSSECMode(payload["mode"])
        submitted_ds = payload.get("ds_records") or []
        if mode is DNSSECMode.MANAGED:
            if domain.nameserver_mode != NameserverMode.MANAGED.value:
                raise DomainProblem(
                    409, "managed_dns_disabled", "Managed DNSSEC requires managed nameservers."
                )
            await self._ensure_managed_zone(
                domain.fqdn,
                domain.openprovider_id,
                dnssec_mode=DNSSECMode.MANAGED,
            )
            ds_records: list[dict[str, Any]] = []
        elif mode is DNSSECMode.EXTERNAL:
            if domain.nameserver_mode != NameserverMode.EXTERNAL.value:
                raise DomainProblem(
                    409, "external_dns_required", "External DNSSEC requires external nameservers."
                )
            keys, ds_records = await self._resolve_matching_dnskeys(domain.fqdn, submitted_ds)
            await self.provider.set_dnssec_keys(domain.openprovider_id, keys)
        else:
            await self.provider.set_dnssec_keys(domain.openprovider_id, [])
            ds_records = []
        async with self.db() as session:
            current = await session.get(DomainRow, domain.id)
            op = await session.get(DomainOperationRow, operation_id)
            if current is not None:
                current.dnssec_mode = mode.value
                current.dnssec_status = "active" if mode is not DNSSECMode.OFF else "off"
                current.ds_records = ds_records
            if op is not None:
                op.status = DomainOperationStatus.SUCCEEDED.value
                op.result_payload = {"mode": mode.value, "ds_records": ds_records}
            await session.commit()

    async def _transfer_out(self, operation_id: str) -> None:
        _operation, domain = await self._operation_and_domain(operation_id)
        if domain.openprovider_id is None:
            raise RuntimeError("domain has no registrar id")
        await self.provider.unlock_domain(domain.openprovider_id)
        authcode = await self.provider.get_authcode(domain.openprovider_id)
        cipher = (
            Fernet(self.domain_config.authcode_fernet_key.encode())
            .encrypt(authcode.encode())
            .decode()
        )
        async with self.db() as session:
            current = await session.get(DomainRow, domain.id)
            op = await session.get(DomainOperationRow, operation_id)
            if current is not None:
                current.status = DomainStatus.TRANSFER_PENDING
            if op is not None:
                op.status = DomainOperationStatus.SUCCEEDED.value
                op.secret_ciphertext = cipher
                op.secret_expires_at = _now() + timedelta(
                    seconds=self.domain_config.transfer_authcode_ttl_seconds
                )
                op.result_payload = {"unlocked": True, "authcode_available": True}
            await session.commit()

    async def _reconcile_domain(self, fqdn: str, *, retry_pending: bool = False) -> None:
        async with self.db() as session:
            domain = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
            ).scalar_one_or_none()
        if domain is None:
            return
        provider_id = domain.openprovider_id
        if provider_id is None:
            # A registration POST can succeed at the registrar while its HTTP
            # response is lost. Only adopt a search result when the durable
            # marker proves Hyrule submitted this exact order; this prevents a
            # pre-existing registrar-account domain from being captured.
            expected_marker = (
                f"register:{domain.client_order_id}" if domain.client_order_id else None
            )
            if not expected_marker or domain.provider_operation_id != expected_marker:
                return
            name, extension, _ = normalize_registrable_domain(domain.fqdn)
            result = await self.provider.search_domain(name, extension)
            if result is None:
                return
            provider_id = _provider_id(result)
            if provider_id is None:
                raise RuntimeError(
                    "registrar search found the submitted domain without a domain id"
                )
        else:
            result = await self.provider.get_domain(provider_id)
        status = _provider_status(result)
        active = status in {"ACT", "ACTIVE"}
        departed = status in {"DEL", "DELETED", "TRA", "TRANSFERRED", "TRANSFERRED_AWAY"}
        transferred = str(domain.status) == DomainStatus.TRANSFER_PENDING.value and departed
        expired = status in {"EXP", "EXPIRED", "REDEMPTION", "QUARANTINE"} or (
            departed and not transferred
        )
        terminal_order_id: str | None = None
        if expired:
            async with self.db() as session:
                terminal_order_id = (
                    (
                        await session.execute(
                            select(DomainOrderRow.order_id)
                            .where(
                                DomainOrderRow.fqdn == fqdn,
                                DomainOrderRow.status.in_(
                                    [
                                        DomainOrderStatus.PROVIDER_PENDING.value,
                                        DomainOrderStatus.SUBMITTING.value,
                                    ]
                                ),
                            )
                            .order_by(DomainOrderRow.created_at.desc())
                        )
                    )
                    .scalars()
                    .first()
                )
            if terminal_order_id is not None:
                await self._fail_paid_order(
                    terminal_order_id,
                    "registrar_terminal_status",
                    f"The registrar reported terminal status {status} before the paid domain order completed.",
                )
        async with self.db() as session:
            current = await session.get(DomainRow, domain.id)
            if current is None:
                return
            current.openprovider_id = provider_id
            current.provider_status = status
            current.expires_at = _provider_expiry(result) or current.expires_at
            order = (
                (
                    await session.execute(
                        select(DomainOrderRow)
                        .where(
                            DomainOrderRow.fqdn == fqdn,
                            DomainOrderRow.status.in_(
                                [
                                    DomainOrderStatus.PROVIDER_PENDING.value,
                                    DomainOrderStatus.SUBMITTING.value,
                                ]
                            ),
                        )
                        .order_by(DomainOrderRow.created_at.desc())
                    )
                )
                .scalars()
                .first()
            )
            if order is None and terminal_order_id is not None:
                order = await session.get(DomainOrderRow, terminal_order_id)
            if transferred:
                current.status = DomainStatus.TRANSFERRED
                current.transferred_at = current.transferred_at or _now()
            elif expired:
                current.status = DomainStatus.EXPIRED
                current.can_renew = False
            elif active and str(current.status) not in {
                DomainStatus.TRANSFER_PENDING.value,
                DomainStatus.RENEWAL_DUE.value,
            }:
                current.status = DomainStatus.REGISTERING
            if order is not None:
                order.provider_domain_id = provider_id
                order.provider_status = status
                response_payload = jsonable_encoder(result)
                if order.action == DomainAction.RENEW.value and isinstance(
                    response_payload, dict
                ):
                    baseline = (order.provider_response or {}).get(
                        "_hyrule_renewal_baseline"
                    )
                    if baseline is not None:
                        response_payload["_hyrule_renewal_baseline"] = baseline
                order.provider_response = response_payload
                if not active and not expired:
                    order.status = DomainOrderStatus.PROVIDER_PENDING.value
                    operation = (
                        await session.get(DomainOperationRow, order.operation_id)
                        if order.operation_id
                        else None
                    )
                    if operation is not None:
                        operation.status = DomainOperationStatus.WAITING_PROVIDER.value
            await session.commit()
        if transferred or expired:
            return
        if not active:
            if retry_pending and order is not None:
                raise OpenproviderUnavailableError(
                    "domain_reconciliation_pending",
                    "The registrar still reports the domain operation as pending",
                    retryable=True,
                )
            return
        if str(domain.status) == DomainStatus.TRANSFER_PENDING.value:
            return
        if order is not None and order.action == DomainAction.RENEW.value:
            baseline = _parse_datetime(
                (order.provider_response or {}).get("_hyrule_renewal_baseline")
            )
            result_expiry = _provider_expiry(result)
            if baseline is not None and (result_expiry is None or result_expiry <= baseline):
                if retry_pending:
                    raise OpenproviderUnavailableError(
                        "renewal_reconciliation_pending",
                        "The registrar has not exposed the renewed expiry yet",
                        retryable=True,
                    )
                return
        if domain.nameserver_mode == NameserverMode.MANAGED.value:
            await self._ensure_managed_zone(fqdn, provider_id)
        if order is not None:
            await self._finish_active_order(order.order_id, fqdn, status)
            if order.action == DomainAction.REGISTER.value:
                await self._provision_bundle(order.order_id)
        else:
            async with self.db() as session:
                current = await session.get(DomainRow, domain.id)
                if current is not None and str(current.status) != DomainStatus.RENEWAL_DUE.value:
                    current.status = DomainStatus.ACTIVE
                    await session.commit()

    async def _ensure_managed_zone(
        self,
        fqdn: str,
        provider_id: int,
        *,
        dnssec_mode: DNSSECMode | None = None,
    ) -> None:
        async with self.db() as session:
            domain = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == fqdn))
            ).scalar_one_or_none()
            if domain is None:
                raise RuntimeError("managed domain disappeared before zone initialization")
            records = list(
                await session.scalars(
                    select(DomainDNSRecordRow).where(DomainDNSRecordRow.fqdn == fqdn)
                )
            )
        await self.dns.apply_zone(
            fqdn,
            revision=domain.zone_revision,
            records=[self._record_payload(row) for row in records],
        )
        managed_dnssec = (
            dnssec_mode is DNSSECMode.MANAGED
            if dnssec_mode is not None
            else domain.dnssec_mode == DNSSECMode.MANAGED.value
        )
        keys = await self.dns.dnssec_keys(fqdn) if managed_dnssec else []
        await self.provider.update_nameservers(provider_id, self.domain_config.managed_nameservers)
        if managed_dnssec:
            await self.provider.set_dnssec_keys(provider_id, keys)
        async with self.db() as session:
            current = await session.get(DomainRow, domain.id)
            if current is not None:
                current.nameserver_mode = NameserverMode.MANAGED.value
                current.nameservers = self.domain_config.managed_nameservers
                if current.dnssec_mode == DNSSECMode.MANAGED.value:
                    current.dnssec_status = "active"
                await session.commit()

    async def _resolve_matching_dnskeys(
        self, fqdn: str, submitted: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not submitted:
            raise DomainProblem(
                422,
                "dnssec_records_required",
                "At least one DS record is required for external DNSSEC.",
            )
        resolver = dns.asyncresolver.Resolver()
        try:
            answer = await resolver.resolve(fqdn, dns.rdatatype.DNSKEY, lifetime=8.0)
        except Exception as exc:
            raise DomainProblem(
                422, "dnskey_unavailable", "No authoritative DNSKEY could be resolved."
            ) from exc
        expected = {
            (
                int(item["key_tag"]),
                int(item["algorithm"]),
                int(item["digest_type"]),
                str(item["digest"]).upper(),
            )
            for item in submitted
        }
        matched_keys: list[dict[str, Any]] = []
        matched_ds: list[dict[str, Any]] = []
        owner = dns.name.from_text(f"{fqdn}.")
        for key in answer:
            tag = dns.dnssec.key_id(key)
            for digest_type, digest_name in ((1, "SHA1"), (2, "SHA256"), (4, "SHA384")):
                try:
                    ds = dns.dnssec.make_ds(owner, key, digest_name)
                except Exception:
                    continue
                fingerprint = (tag, int(key.algorithm), digest_type, ds.digest.hex().upper())
                if fingerprint not in expected:
                    continue
                key_payload = {
                    "flags": int(key.flags),
                    "protocol": int(key.protocol),
                    "alg": int(key.algorithm),
                    "pub_key": key.key,
                }
                if isinstance(key_payload["pub_key"], bytes):
                    import base64

                    key_payload["pub_key"] = base64.b64encode(key_payload["pub_key"]).decode()
                if key_payload not in matched_keys:
                    matched_keys.append(key_payload)
                matched_ds.append(
                    {
                        "key_tag": tag,
                        "algorithm": int(key.algorithm),
                        "digest_type": digest_type,
                        "digest": ds.digest.hex().upper(),
                    }
                )
        if not matched_keys or not expected.issubset(
            {
                (item["key_tag"], item["algorithm"], item["digest_type"], item["digest"])
                for item in matched_ds
            }
        ):
            raise DomainProblem(
                422,
                "dnssec_mismatch",
                "The submitted DS records do not match the authoritative DNSKEY set.",
            )
        return matched_keys, matched_ds

    async def _enqueue_domain_operation(
        self,
        owner_account_id: str,
        value: str,
        kind: str,
        payload: dict[str, Any],
        idempotency_key: str,
        *,
        reject_vm_attachment: bool = False,
    ) -> DomainOperationResponse:
        if not idempotency_key or len(idempotency_key) > 128:
            raise DomainProblem(
                400, "idempotency_key_required", "A valid Idempotency-Key header is required."
            )
        _, _, fqdn = normalize_registrable_domain(value)
        await self._owned_domain(owner_account_id, fqdn)
        dedupe = self._operation_dedupe(owner_account_id, kind, idempotency_key)
        async with self.db() as session:
            existing_job = (
                await session.execute(select(DomainJobRow).where(DomainJobRow.dedupe_key == dedupe))
            ).scalar_one_or_none()
            if existing_job is not None:
                operation = await session.get(DomainOperationRow, existing_job.resource_id)
                if operation is not None:
                    self._validate_operation_replay(operation, fqdn, kind, payload)
                    return self._operation_response(operation)
            if reject_vm_attachment:
                domain = (
                    await session.execute(
                        select(DomainRow)
                        .where(
                            DomainRow.fqdn == fqdn,
                            DomainRow.owner_account_id == owner_account_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if domain is None:
                    raise DomainProblem(404, "domain_not_found", "Domain not found.")
                self._assert_external_delegation_allowed(domain)
            operation = DomainOperationRow(
                operation_id=generate_domain_operation_id(),
                fqdn=fqdn,
                owner_account_id=owner_account_id,
                kind=kind,
                status=DomainOperationStatus.QUEUED.value,
                request_payload=payload,
            )
            session.add(operation)
            self._add_job(
                session,
                kind=kind,
                resource_id=operation.operation_id,
                dedupe_key=dedupe,
                payload={},
            )
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                winner_job = (
                    await session.execute(
                        select(DomainJobRow).where(DomainJobRow.dedupe_key == dedupe)
                    )
                ).scalar_one_or_none()
                winner = (
                    await session.get(DomainOperationRow, winner_job.resource_id)
                    if winner_job is not None
                    else None
                )
                if winner is None:
                    raise DomainProblem(
                        409, "operation_conflict", "The operation already exists."
                    ) from exc
                self._validate_operation_replay(winner, fqdn, kind, payload)
                return self._operation_response(winner)
            return self._operation_response(operation)

    @staticmethod
    def _operation_dedupe(owner_account_id: str, kind: str, idempotency_key: str) -> str:
        return (
            "op:"
            + hashlib.sha256(f"{owner_account_id}:{kind}:{idempotency_key}".encode()).hexdigest()
        )

    @staticmethod
    def _assert_external_delegation_allowed(domain: DomainRow) -> None:
        if domain.vm_id is not None or domain.vm_ipv6 is not None:
            raise DomainProblem(
                409,
                "domain_attached_to_vm",
                "Detach the VM before switching this domain to external nameservers.",
            )

    @staticmethod
    def _validate_operation_replay(
        operation: DomainOperationRow,
        fqdn: str,
        kind: str,
        payload: dict[str, Any],
    ) -> None:
        if (
            operation.fqdn != fqdn
            or operation.kind != kind
            or (operation.request_payload or {}) != payload
        ):
            raise DomainProblem(
                409,
                "idempotency_conflict",
                "This Idempotency-Key is already bound to a different operation.",
            )

    async def _operation_and_domain(
        self, operation_id: str
    ) -> tuple[DomainOperationRow, DomainRow]:
        async with self.db() as session:
            operation = await session.get(DomainOperationRow, operation_id)
            if operation is None:
                raise RuntimeError("domain operation disappeared")
            operation.status = DomainOperationStatus.RUNNING.value
            domain = (
                await session.execute(select(DomainRow).where(DomainRow.fqdn == operation.fqdn))
            ).scalar_one_or_none()
            if domain is None:
                raise RuntimeError("managed domain disappeared")
            await session.commit()
            return operation, domain

    async def _owned_domain(self, owner_account_id: str, fqdn: str) -> DomainRow:
        async with self.db() as session:
            row = (
                await session.execute(
                    select(DomainRow).where(
                        DomainRow.fqdn == fqdn,
                        DomainRow.owner_account_id == owner_account_id,
                    )
                )
            ).scalar_one_or_none()
        if row is None:
            raise DomainProblem(404, "domain_not_found", "Domain not found.")
        return row

    async def _claim_job(self, worker_id: str) -> DomainJobRow | None:
        async with self.db() as session:
            stale_before = _now() - timedelta(seconds=self.domain_config.job_lock_timeout_seconds)
            job = (
                await session.execute(
                    select(DomainJobRow)
                    .where(
                        or_(
                            and_(
                                DomainJobRow.status == "queued",
                                DomainJobRow.available_at <= _now(),
                            ),
                            and_(
                                DomainJobRow.status == "running",
                                DomainJobRow.locked_at < stale_before,
                            ),
                        )
                    )
                    .order_by(DomainJobRow.available_at, DomainJobRow.created_at)
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )
            ).scalar_one_or_none()
            if job is None:
                return None
            job.status = "running"
            job.locked_at = _now()
            job.locked_by = worker_id
            job.attempts += 1
            await session.commit()
            return job

    async def _retry_or_fail_job(self, job_id: str, exc: Exception) -> None:
        retryable = not isinstance(exc, DomainProblem)
        if isinstance(exc, OpenproviderError):
            retryable = exc.retryable
        if isinstance(exc, DNSControlError):
            retryable = exc.retryable
        failure_action = "none"
        async with self.db() as session:
            job = await session.get(DomainJobRow, job_id)
            if job is None:
                return
            job.last_error = str(exc)[:2000]
            if retryable and job.attempts < 10:
                job.status = "queued"
                job.available_at = _now() + timedelta(seconds=min(3600, 2**job.attempts * 5))
                job.locked_at = None
                job.locked_by = None
                await session.commit()
                return
            job.status = "failed"
            operation: DomainOperationRow | None = None
            if job.kind == "fulfill_order":
                order = await session.get(DomainOrderRow, job.resource_id)
                if order is not None and order.operation_id:
                    operation = await session.get(DomainOperationRow, order.operation_id)
                domain = (
                    (
                        await session.execute(select(DomainRow).where(DomainRow.fqdn == order.fqdn))
                    ).scalar_one_or_none()
                    if order is not None
                    else None
                )
                ambiguous_registration = (
                    order is not None
                    and order.action == DomainAction.REGISTER.value
                    and domain is not None
                    and domain.openprovider_id is None
                    and domain.provider_operation_id == f"register:{order.order_id}"
                )
                if ambiguous_registration:
                    assert order is not None and domain is not None
                    # The registrar submission crossed the point of no return,
                    # but its response was ambiguous. Refunding here could give
                    # the customer both the money and a real registered domain.
                    # Keep the order discoverable by the daily reconciler.
                    domain.status = DomainStatus.PROVIDER_PENDING
                    order.status = DomainOrderStatus.PROVIDER_PENDING.value
                    order.error_code = "registration_reconciliation_required"
                    order.error_detail = str(exc)[:1000]
                    if operation is not None:
                        operation.status = DomainOperationStatus.WAITING_PROVIDER.value
                        operation.error_code = "registration_reconciliation_required"
                        operation.error_detail = str(exc)[:1000]
                    failure_action = "none"
                elif domain is not None and domain.openprovider_id is not None:
                    if order is not None and order.action == DomainAction.RENEW.value:
                        # A timed-out renewal may still settle at the registry.
                        # Keep it pending for reconciliation; never refund and
                        # then discover that an extra year was delivered.
                        order.status = DomainOrderStatus.PROVIDER_PENDING.value
                        order.error_code = "renewal_reconciliation_required"
                        order.error_detail = str(exc)[:1000]
                        if operation is not None:
                            operation.status = DomainOperationStatus.FAILED.value
                        failure_action = "none"
                    elif domain.dnssec_status == "active" and order is not None:
                        # The registrar/DNS product was delivered. A terminal
                        # bundle-VM failure refunds only the VM component.
                        domain.status = DomainStatus.ACTIVE
                        order.status = DomainOrderStatus.ACTIVE.value
                        order.error_code = "bundle_vm_failed"
                        order.error_detail = str(exc)[:1000]
                        if (
                            order.vm_id
                            and domain.vm_id == order.vm_id
                            and domain.vm_ipv6 is None
                        ):
                            bundle_vm = await session.get(VMRow, order.vm_id)
                            if bundle_vm is None or str(bundle_vm.status) in {
                                VMStatus.PROVISIONING.value,
                                VMStatus.FAILED.value,
                            }:
                                # No provisioned VM owns this attachment. Clear
                                # the planned claim atomically with the terminal
                                # partial-refund state so later custom checkouts
                                # can use the delivered domain.
                                domain.vm_id = None
                                if bundle_vm is not None:
                                    bundle_vm.status = VMStatus.FAILED
                                    bundle_vm.error = str(exc)[:1000]
                                    bundle_vm.ipv6_prefix_index = None
                                    bundle_vm.ipv6_prefix = None
                        if Decimal(order.vm_amount_usd) > 0:
                            # The terminal job/order state and the partial refund
                            # obligation are one atomic commit. If ledger event
                            # construction or persistence fails, neither side is
                            # left terminal and the stale job remains recoverable.
                            session.add(
                                self._build_refund_event(
                                    order,
                                    "bundle_vm_failed",
                                    amount=Decimal(order.vm_amount_usd),
                                )
                            )
                        if operation is not None:
                            operation.status = DomainOperationStatus.SUCCEEDED.value
                    else:
                        # Registration exists, so refunding it could give away a
                        # real domain. Leave it pending for operator recovery.
                        domain.status = DomainStatus.PROVIDER_PENDING
                        domain.dnssec_status = "error"
                        if order is not None:
                            order.status = DomainOrderStatus.PROVIDER_PENDING.value
                            order.error_code = "managed_dns_failed"
                            order.error_detail = str(exc)[:1000]
                        if operation is not None:
                            operation.status = DomainOperationStatus.FAILED.value
                        failure_action = "none"
                else:
                    failure_action = "full_refund"
            elif job.kind in {"nameservers", "dnssec", "transfer_out"}:
                operation = await session.get(DomainOperationRow, job.resource_id)
            if operation is not None and job.kind != "fulfill_order":
                operation.status = DomainOperationStatus.FAILED.value
                operation.error_code = getattr(exc, "code", "operation_failed")
                operation.error_detail = str(exc)[:1000]
            elif operation is not None and failure_action == "full_refund":
                operation.status = DomainOperationStatus.FAILED.value
                operation.error_code = getattr(exc, "code", "operation_failed")
                operation.error_detail = str(exc)[:1000]
            await session.commit()
        if failure_action == "full_refund":
            await self._fail_paid_order(
                job.resource_id,
                getattr(exc, "code", "fulfillment_failed"),
                str(exc),
            )
        log.error("domain_job_failed", job_id=job_id, kind=job.kind, error=str(exc))

    def _add_job(
        self,
        session: Any,
        *,
        kind: str,
        resource_id: str,
        dedupe_key: str,
        payload: dict[str, Any],
        available_at: datetime | None = None,
    ) -> None:
        session.add(
            DomainJobRow(
                job_id=generate_domain_job_id(),
                kind=kind,
                resource_id=resource_id,
                dedupe_key=dedupe_key[:160],
                payload=payload,
                status="queued",
                available_at=available_at or _now(),
            )
        )

    async def _set_order_error(self, order_id: str, code: str, detail: str, *, paid: bool) -> None:
        async with self.db() as session:
            order = await session.get(DomainOrderRow, order_id)
            if order is not None:
                order.status = (
                    DomainOrderStatus.REFUND_DUE.value if paid else DomainOrderStatus.FAILED.value
                )
                order.error_code = code
                order.error_detail = detail[:1000]
                await session.commit()

    async def _fx(self, currency: str) -> Decimal:
        try:
            return await self.rates.get_usd_per_fiat(currency)
        except Exception as exc:
            raise DomainProblem(
                503,
                "fx_unavailable",
                "Registrar currency conversion is temporarily unavailable.",
            ) from exc

    def _quote_response(self, row: DomainQuoteRow) -> DomainQuoteResponse:
        return DomainQuoteResponse(
            quote_id=row.quote_id,
            domain=row.fqdn,
            action=DomainAction(row.action),
            period_years=1,
            price=money_breakdown(
                Decimal(row.provider_cost_usd),
                Decimal(row.hyrule_fee_usd),
                Decimal(row.tax_usd),
                Decimal(row.total_usd),
            ),
            available=bool(row.available),
            expires_at=row.expires_at,
            terms_version=row.terms_version,
        )

    def _order_response(
        self, row: DomainOrderRow, intent: CryptoIntentRow | None
    ) -> DomainOrderResponse:
        payment: NativePaymentInstructions | None = None
        payable_intent = bool(
            intent is not None
            and row.status == DomainOrderStatus.AWAITING_PAYMENT.value
            and str(intent.status)
            in {
                CryptoIntentStatus.CREATED.value,
                CryptoIntentStatus.WAITING_PAYMENT.value,
                CryptoIntentStatus.PENDING.value,
            }
            and _aware(intent.expires_at) > _now()
        )
        if payable_intent:
            assert intent is not None
            if intent.asset not in {"BTC", "XMR"}:
                raise RuntimeError("native domain intent has an unsupported asset")
            asset = cast(Asset, intent.asset)
            payment = NativePaymentInstructions(
                intent_id=intent.intent_id,
                asset=asset,
                address=intent.address,
                amount_crypto=str(intent.amount_crypto),
                amount_usd=str(intent.amount_usd),
                qr_code_uri=NativeCryptoProvider.build_uri(
                    asset, intent.address, intent.amount_crypto
                ),
                rate_valid_until=intent.rate_valid_until,
                expires_at=intent.expires_at,
            )
        return DomainOrderResponse(
            order_id=row.order_id,
            domain=row.fqdn,
            action=DomainAction(row.action),
            status=DomainOrderStatus(row.status),
            amount_usd=f"{Decimal(row.amount_usd):.2f}",
            payment_method=DomainPaymentMethod(row.payment_method),
            payment=payment,
            operation_id=row.operation_id,
            vm_id=row.vm_id,
            error_code=row.error_code,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _domain_summary(self, row: DomainRow) -> DomainSummary:
        expires_at = _aware(row.expires_at)
        return DomainSummary(
            domain=row.fqdn,
            status=str(row.status),
            expires_at=row.expires_at,
            renewal_notice_days=(
                max(0, (expires_at - _now()).days) if expires_at is not None else None
            ),
            nameserver_mode=NameserverMode(row.nameserver_mode),
            nameservers=list(row.nameservers or []),
            dnssec_mode=DNSSECMode(row.dnssec_mode),
            dnssec_status=row.dnssec_status,
        )

    def _operation_response(
        self, row: DomainOperationRow, *, secret: str | None = None
    ) -> DomainOperationResponse:
        return DomainOperationResponse(
            operation_id=row.operation_id,
            domain=row.fqdn,
            kind=row.kind,
            status=DomainOperationStatus(row.status),
            error_code=row.error_code,
            error_detail=row.error_detail,
            result=row.result_payload,
            secret=secret,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _record_payload(row: DomainDNSRecordRow) -> dict[str, Any]:
        return {"name": row.name, "type": row.type, "ttl": row.ttl, "values": row.values}


def _is_available(result: dict[str, Any]) -> bool:
    status = str(result.get("status") or result.get("availability") or "").lower()
    return status in {"free", "available", "yes"} or result.get("available") is True


def _provider_id(result: dict[str, Any]) -> int | None:
    raw = result.get("id")
    if raw is None and isinstance(result.get("domain"), dict):
        raw = result["domain"].get("id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _provider_status(result: dict[str, Any]) -> str:
    return str(result.get("status") or result.get("domain_status") or "").upper()[:32]


def _provider_expiry(result: dict[str, Any]) -> datetime | None:
    raw: Any = (
        result.get("expiration_date") or result.get("expires_at") or result.get("renewal_date")
    )
    if isinstance(raw, dict):
        raw = raw.get("value") or raw.get("date")
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _find_webhook_domain(payload: dict[str, Any]) -> str | None:
    for key in ("domain_name", "domain", "name"):
        value = payload.get(key)
        if isinstance(value, str) and "." in value:
            try:
                return normalize_registrable_domain(value)[2]
            except DomainProblem:
                pass
        if isinstance(value, dict):
            name = value.get("name")
            extension = value.get("extension")
            if isinstance(name, str) and isinstance(extension, str):
                try:
                    return normalize_registrable_domain(f"{name}.{extension}")[2]
                except DomainProblem:
                    pass
    for value in payload.values():
        if isinstance(value, dict):
            found = _find_webhook_domain(value)
            if found:
                return found
    return None
