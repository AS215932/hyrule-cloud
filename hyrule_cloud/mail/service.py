from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from email.utils import getaddresses
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import httpx
import structlog
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
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
)
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import DomainAction, DomainOrderStatus
from hyrule_cloud.domains.service import DomainService
from hyrule_cloud.mail.backend import (
    MailAttachmentTooLargeError,
    MailBackendError,
    MailDNSIncompleteError,
    StalwartClient,
)
from hyrule_cloud.mail.models import (
    MailAccountQuoteRequest,
    MailAccountResponse,
    MailAttachment,
    MailboxMode,
    MailboxStatus,
    MailCapabilitiesResponse,
    MailEventResponse,
    MailEventsResponse,
    MailMessageDetail,
    MailMessagesResponse,
    MailMessageSummary,
    MailPricingResponse,
    MailProduct,
    MailProductsResponse,
    MailQuoteResponse,
    MailQuoteStatus,
    MailSendQuoteRequest,
    MailSendResponse,
    MailWebhookCreateRequest,
    MailWebhookListResponse,
    MailWebhookResponse,
    amount,
    generate_mail_id,
)
from hyrule_cloud.mail.security import hash_token, sanitize_html, validate_webhook_url
from hyrule_cloud.middleware.x402 import PaymentReconciliation
from hyrule_cloud.models import DomainStatus
from hyrule_cloud.services.refunds import RefundService

log = structlog.get_logger().bind(component="agent_mail")

_MAIL_CAPACITY_LOCK_ID = 0x4D41494C
_MAIL_SEND_CAPACITY_LOCK_ID = 0x4D53454E
_MAIL_CAPACITY_STATUSES = (
    MailboxStatus.PENDING_DOMAIN.value,
    MailboxStatus.PROVISIONING.value,
    MailboxStatus.ACTIVE.value,
    MailboxStatus.SUSPENDED.value,
    MailboxStatus.GRACE.value,
)
_SEND_RESERVED_STATUSES = ("pending", "submitting", "accepted")
_SEND_SUBMISSION_LEASE = timedelta(minutes=5)
_PAYMENT_HANDOFF_GRACE = timedelta(hours=1)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _mailbox_occupies_capacity() -> Any:
    return or_(
        MailAccountRow.status.in_(_MAIL_CAPACITY_STATUSES),
        and_(
            MailAccountRow.status == MailboxStatus.AWAITING_PAYMENT.value,
            MailAccountRow.capacity_reserved_at.is_not(None),
        ),
    )


def _mailbox_occupies_domain() -> Any:
    """Reserve a custom domain until any service-owned DNS cleanup completes."""

    return or_(
        _mailbox_occupies_capacity(),
        MailAccountRow.dns_cleanup_pending.is_(True),
        MailAccountRow.provision_error == "dns_cleanup_pending",
    )


class MailProblem(DomainProblem):
    pass


class MailService:
    def __init__(
        self,
        config: HyruleConfig,
        session_factory: async_sessionmaker[AsyncSession],
        domains: DomainService,
        refunds: RefundService,
        backend: StalwartClient | None = None,
    ) -> None:
        self.config = config
        self.mail_config = config.mail
        self.db = session_factory
        self.domains = domains
        self.refunds = refunds
        self.backend = backend or StalwartClient(config.mail)

    async def close(self) -> None:
        await self.backend.close()

    def require_launch(self) -> None:
        if not self.mail_config.public_ready:
            raise MailProblem(
                503,
                "mail_not_launched",
                "Agent Mail is not available until launch approvals and control-plane secrets are configured.",
                headers={"Retry-After": "3600"},
            )

    async def require_backend(self) -> None:
        self.require_launch()
        if not await self.backend.ready():
            raise MailProblem(
                503,
                "mail_backend_unavailable",
                "Agent Mail is temporarily unavailable.",
                headers={"Retry-After": "60"},
            )

    def _fernet(self) -> Fernet:
        try:
            return Fernet(self.mail_config.credential_fernet_key.encode())
        except (ValueError, TypeError) as exc:
            raise MailProblem(
                503, "mail_secret_storage_unavailable", "Mail secret storage is unavailable."
            ) from exc

    def products(self) -> MailProductsResponse:
        ready = self.mail_config.public_ready
        custom_ready = ready and self.domains.dns.configured
        constraints = [
            "API-only submission and retrieval; no public SMTP submission, IMAP, or webmail",
            (
                f"{self.mail_config.active_days}-day activation; "
                f"{self._storage_quota_label()} mailbox storage"
            ),
            f"one recipient, {self.mail_config.mailbox_send_limit_per_day} outbound/day",
            f"{self.mail_config.mailbox_new_recipient_limit_per_day} new recipients/day",
            "outbound attachments disabled; inbound attachments retained",
            f"inbound attachment downloads capped at {self.mail_config.max_attachment_bytes} bytes",
            f"{self.mail_config.retention_days}-day rolling message retention",
        ]
        return MailProductsResponse(
            available=ready,
            terms_version=self.mail_config.terms_version,
            products=[
                MailProduct(
                    id="agent-mail-hosted",
                    title=f"Agent mailbox on @{self.mail_config.hosted_domain}",
                    price_usd=amount(self.config.payment.price_mail_activation),
                    billing=f"{self.mail_config.active_days} days, no auto-renew",
                    available=ready,
                    constraints=constraints,
                ),
                MailProduct(
                    id="agent-mail-custom",
                    title="Agent mailbox on a Hyrule-managed domain",
                    price_usd=amount(self.config.payment.price_mail_activation),
                    billing=(
                        f"{self.mail_config.active_days} days; "
                        "domain quote plus activation; no auto-renew"
                    ),
                    available=custom_ready,
                    constraints=constraints,
                ),
                MailProduct(
                    id="agent-mail-domain-bundle",
                    title="Hyrule-managed domain and Agent Mail mailbox",
                    price_usd=amount(self.config.payment.price_mail_activation),
                    billing=(
                        f"{self.mail_config.active_days} days; "
                        "live domain quote plus activation; no auto-renew"
                    ),
                    available=custom_ready and self.config.domain.agent_purchases_enabled,
                    constraints=constraints,
                ),
            ],
        )

    def pricing(self) -> MailPricingResponse:
        return MailPricingResponse(
            activation_usd=amount(self.config.payment.price_mail_activation),
            outbound_message_usd=amount(self.config.payment.price_mail_send),
            storage_gb=float(Decimal(self.mail_config.storage_quota_bytes) / Decimal(1024**3)),
            storage_bytes=self.mail_config.storage_quota_bytes,
            active_days=self.mail_config.active_days,
            grace_days=self.mail_config.grace_days,
        )

    def capabilities(self) -> MailCapabilitiesResponse:
        return MailCapabilitiesResponse(
            outbound_per_day=self.mail_config.mailbox_send_limit_per_day,
            new_recipients_per_day=self.mail_config.mailbox_new_recipient_limit_per_day,
            inbound_attachment_max_bytes=self.mail_config.max_attachment_bytes,
        )

    async def create_account_quote(self, body: MailAccountQuoteRequest) -> MailQuoteResponse:
        self.require_launch()
        if body.terms_version != self.mail_config.terms_version:
            raise MailProblem(
                409, "terms_changed", "The Agent Mail terms changed; review and re-quote."
            )
        domain = body.domain or self.mail_config.hosted_domain
        address = f"{body.local_part}@{domain}"
        domain_quote_id: str | None = None
        domain_authority_hash: str | None = None
        domain_amount = Decimal("0")
        activation_amount = Decimal(self.config.payment.price_mail_activation)

        if body.mode is not MailboxMode.HOSTED and not self.domains.dns.configured:
            raise MailProblem(
                503,
                "managed_dns_not_ready",
                "Custom-domain Agent Mail is unavailable until managed DNS is configured.",
                headers={"Retry-After": "3600"},
            )
        if body.mode is MailboxMode.CUSTOM:
            managed_domain = await self._assert_managed_domain_token(
                domain,
                body.domain_management_token or "",
            )
            domain_authority_hash = managed_domain.anon_management_token_hash
        elif body.mode is MailboxMode.DOMAIN_AND_MAILBOX:
            if body.domain_terms_version != self.config.domain.terms_version:
                raise MailProblem(
                    409,
                    "domain_terms_changed",
                    "The managed-domain terms changed; review and re-quote.",
                )
            domain_quote = await self.domains.create_quote(domain, DomainAction.REGISTER, None)
            domain_quote_id = domain_quote.quote_id
            domain_amount = Decimal(domain_quote.price.total_usd)

        async with self.db() as session:
            existing = await session.scalar(
                select(func.count())
                .select_from(MailAccountRow)
                .where(
                    MailAccountRow.address == address,
                    MailAccountRow.status != MailboxStatus.DELETED.value,
                )
            )
            if existing:
                raise MailProblem(
                    409, "address_unavailable", "This mailbox address is unavailable."
                )
            if body.mode is not MailboxMode.HOSTED:
                domain_in_use = await session.scalar(
                    select(func.count())
                    .select_from(MailAccountRow)
                    .where(
                        MailAccountRow.domain == domain,
                        _mailbox_occupies_domain(),
                    )
                )
                if domain_in_use:
                    raise MailProblem(
                        409,
                        "domain_mailbox_exists",
                        "The MVP supports one Agent Mail mailbox per custom domain.",
                    )
            active_count = await session.scalar(
                select(func.count()).select_from(MailAccountRow).where(_mailbox_occupies_capacity())
            )
            if int(active_count or 0) >= self.mail_config.max_active_mailboxes:
                raise MailProblem(
                    503, "mail_capacity_reached", "Agent Mail launch capacity is full."
                )

            payload = {
                "local_part": body.local_part,
                "domain": domain,
                "address": address,
                "mode": body.mode.value,
                "domain_quote_id": domain_quote_id,
                "domain_authority_hash": domain_authority_hash,
                "domain_terms_version": body.domain_terms_version,
                "activation_amount_usd": str(activation_amount),
            }
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            now = _now()
            total = domain_amount + activation_amount
            row = MailQuoteRow(
                quote_id=generate_mail_id("mailq"),
                kind="activation",
                status=MailQuoteStatus.ACTIVE.value,
                address=address,
                request_hash=hashlib.sha256(canonical).hexdigest(),
                request_payload=payload,
                amount_usd=total,
                domain_quote_id=domain_quote_id,
                terms_version=body.terms_version,
                created_at=now,
                expires_at=now + timedelta(seconds=self.mail_config.quote_ttl_seconds),
            )
            session.add(row)
            await session.commit()
        return self._quote_response(row)

    async def get_quote(self, quote_id: str) -> MailQuoteResponse:
        async with self.db() as session:
            row = await session.get(MailQuoteRow, quote_id)
            if row is None:
                raise MailProblem(404, "mail_quote_not_found", "Mail quote not found.")
            expires_at = _aware(row.expires_at)
            if row.status == MailQuoteStatus.ACTIVE.value and (
                expires_at is None or expires_at <= _now()
            ):
                row.status = MailQuoteStatus.EXPIRED.value
                await session.commit()
        return self._quote_response(row)

    async def prepare_activation(
        self,
        quote_id: str,
        *,
        idempotency_key: str,
    ) -> tuple[MailAccountRow, str, bool]:
        await self.require_backend()
        if len(idempotency_key) < 16 or len(idempotency_key) > 128:
            raise MailProblem(
                400,
                "idempotency_key_required",
                "Activation requires a high-entropy 16-128 character Idempotency-Key.",
            )
        idem_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        fernet = self._fernet()
        async with self.db() as session:
            existing = await session.scalar(
                select(MailAccountRow).where(MailAccountRow.idempotency_hash == idem_hash)
            )
            if existing is not None:
                if existing.quote_id != quote_id:
                    raise MailProblem(
                        409,
                        "idempotency_conflict",
                        "This Idempotency-Key is bound to another activation.",
                    )
                if (
                    existing.status == MailboxStatus.AWAITING_PAYMENT.value
                    and existing.terms_version != self.mail_config.terms_version
                ):
                    raise MailProblem(
                        409,
                        "terms_changed",
                        "The Agent Mail terms changed; review and re-quote.",
                    )
                if not existing.management_token_ciphertext:
                    status = 410 if existing.status == MailboxStatus.DELETED.value else 409
                    raise MailProblem(
                        status,
                        "mail_activation_closed",
                        "This activation is closed and its capability cannot be reissued.",
                    )
                return existing, self._decrypt(fernet, existing.management_token_ciphertext), False
            quote = await session.get(MailQuoteRow, quote_id)
            if quote is None or quote.kind != "activation":
                raise MailProblem(404, "mail_quote_not_found", "Mail quote not found.")
            quote_expires_at = _aware(quote.expires_at)
            if (
                quote.status != MailQuoteStatus.ACTIVE.value
                or quote_expires_at is None
                or quote_expires_at <= _now()
            ):
                raise MailProblem(409, "mail_quote_expired", "This mail quote is not payable.")
            if quote.terms_version != self.mail_config.terms_version:
                raise MailProblem(
                    409,
                    "terms_changed",
                    "The Agent Mail terms changed; review and re-quote.",
                )
            payload = dict(quote.request_payload)

        token = "hyr_identity_" + secrets.token_urlsafe(32)
        mode = MailboxMode(payload["mode"])
        if mode is MailboxMode.CUSTOM:
            await self._assert_managed_domain_authority(
                str(payload["domain"]),
                str(payload.get("domain_authority_hash") or ""),
            )
        activation_amount = Decimal(str(payload["activation_amount_usd"]))
        domain_order_id: str | None = None
        if mode is MailboxMode.DOMAIN_AND_MAILBOX:
            order, domain_token, _created = await self.domains.create_agent_order(
                quote_id=str(payload["domain_quote_id"]),
                terms_version=str(payload["domain_terms_version"]),
                idempotency_key=f"mail:{idem_hash}",
                additional_amount_usd=activation_amount,
                management_token=token,
            )
            domain_order_id = order.order_id
            # The domain order may have committed before a previous mailbox
            # insert failed. Its replayed capability remains authoritative so
            # both resources continue to share one recoverable identity token.
            token = domain_token

        now = _now()
        mailbox = MailAccountRow(
            mailbox_id=generate_mail_id("mbx"),
            address=str(payload["address"]),
            owner_wallet=None,
            management_token_hash=hash_token(token),
            management_token_ciphertext=fernet.encrypt(token.encode()).decode(),
            plan=mode.value,
            status=MailboxStatus.AWAITING_PAYMENT.value,
            features={
                "api_only": True,
                "outbound_attachments": False,
                "retention_days": self.mail_config.retention_days,
            },
            backend="stalwart",
            domain=str(payload["domain"]),
            local_part=str(payload["local_part"]),
            domain_order_id=domain_order_id,
            domain_authority_hash=(
                str(payload.get("domain_authority_hash"))
                if payload.get("domain_authority_hash")
                else None
            ),
            quote_id=quote_id,
            idempotency_hash=idem_hash,
            terms_version=quote.terms_version,
            activation_amount_usd=activation_amount,
            total_amount_usd=quote.amount_usd,
            created_at=now,
        )
        async with self.db() as session:
            winner = await session.scalar(
                select(MailAccountRow).where(MailAccountRow.idempotency_hash == idem_hash)
            )
            if winner is not None:
                if winner.quote_id != quote_id:
                    raise MailProblem(
                        409,
                        "idempotency_conflict",
                        "This Idempotency-Key is bound to another activation.",
                    )
                return winner, self._decrypt(fernet, winner.management_token_ciphertext), False
            if session.get_bind().dialect.name == "postgresql":
                await session.execute(select(func.pg_advisory_xact_lock(_MAIL_CAPACITY_LOCK_ID)))
            deleted_account = await session.scalar(
                select(MailAccountRow)
                .where(
                    MailAccountRow.address == mailbox.address,
                    MailAccountRow.status == MailboxStatus.DELETED.value,
                )
                .with_for_update()
            )
            active_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(MailAccountRow)
                    .where(_mailbox_occupies_capacity())
                )
                or 0
            )
            if active_count >= self.mail_config.max_active_mailboxes:
                raise MailProblem(
                    503, "mail_capacity_reached", "Agent Mail launch capacity is full."
                )
            reserved = await session.execute(
                update(MailQuoteRow)
                .where(
                    MailQuoteRow.quote_id == quote_id,
                    MailQuoteRow.status == MailQuoteStatus.ACTIVE.value,
                    MailQuoteRow.expires_at > now,
                )
                .values(status="reserved")
                .execution_options(synchronize_session=False)
            )
            if int(getattr(reserved, "rowcount", 0) or 0) != 1:
                await session.rollback()
                raise MailProblem(
                    409, "mail_quote_unavailable", "This mail quote is already reserved."
                )
            if deleted_account is None:
                session.add(mailbox)
            else:
                for field in (
                    "owner_wallet",
                    "owner_account_id",
                    "management_token_hash",
                    "management_token_ciphertext",
                    "plan",
                    "status",
                    "display_name",
                    "features",
                    "backend",
                    "backend_id",
                    "backend_credential_ciphertext",
                    "domain",
                    "local_part",
                    "domain_order_id",
                    "domain_authority_hash",
                    "quote_id",
                    "idempotency_hash",
                    "terms_version",
                    "activation_amount_usd",
                    "total_amount_usd",
                    "created_at",
                ):
                    setattr(deleted_account, field, getattr(mailbox, field))
                deleted_account.capacity_reserved_at = None
                deleted_account.provision_claim_token = None
                deleted_account.provision_claimed_at = None
                deleted_account.provision_retry_count = 0
                deleted_account.provision_next_attempt_at = None
                deleted_account.dns_cleanup_pending = False
                deleted_account.activated_at = None
                deleted_account.grace_ends_at = None
                deleted_account.deleted_at = None
                deleted_account.provision_error = None
                deleted_account.suspended_reason = None
                deleted_account.expires_at = None
                deleted_account.payment_tx = None
                deleted_account.payment_network = None
                deleted_account.payment_asset = None
                deleted_account.payment_settlement_pending_at = None
                deleted_account.payment_settled_at = None
                deleted_account.payment_authorization_header = None
                mailbox = deleted_account
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                winner = await session.scalar(
                    select(MailAccountRow).where(MailAccountRow.idempotency_hash == idem_hash)
                )
                if winner is None or winner.quote_id != quote_id:
                    raise MailProblem(
                        409, "mailbox_conflict", "This mailbox activation conflicts."
                    ) from exc
                return winner, self._decrypt(fernet, winner.management_token_ciphertext), False
        return mailbox, token, True

    async def reserve_activation_capacity(
        self, mailbox_id: str, *, quote_id: str | None = None
    ) -> MailAccountRow:
        """Reserve paid launch capacity before x402 settlement."""

        async with self.db() as session:
            if session.get_bind().dialect.name == "postgresql":
                await session.execute(select(func.pg_advisory_xact_lock(_MAIL_CAPACITY_LOCK_ID)))
            row = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
            if quote_id is not None and row.quote_id != quote_id:
                raise MailProblem(
                    409,
                    "mail_activation_superseded",
                    "This payment belongs to an earlier mailbox activation.",
                )
            recoverable_expiry = (
                row.status == MailboxStatus.FAILED.value
                and row.provision_error == "payment_window_expired"
                and bool(row.management_token_ciphertext)
            )
            if row.status != MailboxStatus.AWAITING_PAYMENT.value and not recoverable_expiry:
                return row
            if row.capacity_reserved_at is not None and not recoverable_expiry:
                return row
            active_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(MailAccountRow)
                    .where(
                        MailAccountRow.mailbox_id != mailbox_id,
                        _mailbox_occupies_capacity(),
                    )
                )
                or 0
            )
            if active_count >= self.mail_config.max_active_mailboxes:
                raise MailProblem(
                    503, "mail_capacity_reached", "Agent Mail launch capacity is full."
                )
            if row.plan != MailboxMode.HOSTED.value:
                domain_in_use = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(MailAccountRow)
                        .where(
                            MailAccountRow.mailbox_id != mailbox_id,
                            MailAccountRow.domain == row.domain,
                            _mailbox_occupies_domain(),
                        )
                    )
                    or 0
                )
                if domain_in_use:
                    raise MailProblem(
                        409,
                        "domain_mailbox_exists",
                        "The MVP supports one Agent Mail mailbox per custom domain.",
                    )
            if row.plan == MailboxMode.CUSTOM.value:
                authority = (
                    await session.execute(
                        select(DomainRow).where(DomainRow.fqdn == row.domain).with_for_update()
                    )
                ).scalar_one_or_none()
                if not self._domain_authority_matches(
                    authority,
                    row.domain_authority_hash,
                ):
                    raise MailProblem(
                        409,
                        "managed_domain_authority_changed",
                        "The managed-domain capability changed; create a new quote.",
                    )
            if recoverable_expiry:
                row.status = MailboxStatus.AWAITING_PAYMENT.value
                row.provision_error = None
            row.capacity_reserved_at = _now()
            await session.commit()
            return row

    async def release_activation_capacity(self, mailbox_id: str) -> None:
        async with self.db() as session:
            row = await session.get(MailAccountRow, mailbox_id)
            if row is not None and row.status == MailboxStatus.AWAITING_PAYMENT.value:
                row.capacity_reserved_at = None
                await session.commit()

    async def begin_activation_settlement(
        self,
        mailbox_id: str,
        quote_id: str,
        *,
        payer: str,
        payment_network: str | None,
        payment_asset: str | None,
        payment_authorization: str | None = None,
    ) -> MailAccountRow:
        """Persist an activation settlement intent before money can move."""

        async with self.db() as session:
            row = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
            if row.quote_id != quote_id:
                raise MailProblem(
                    409,
                    "mail_activation_superseded",
                    "This payment belongs to an earlier mailbox activation.",
                )
            if row.status != MailboxStatus.AWAITING_PAYMENT.value:
                raise MailProblem(
                    409,
                    "mail_activation_closed",
                    "This mailbox activation is no longer awaiting payment.",
                )
            if row.payment_settled_at is None:
                row.owner_wallet = payer[:64]
                row.payment_network = payment_network
                row.payment_asset = payment_asset
                row.payment_authorization_header = payment_authorization
                row.payment_settlement_pending_at = row.payment_settlement_pending_at or _now()
                await session.commit()
            return row

    async def clear_activation_settlement(self, mailbox_id: str, quote_id: str) -> None:
        """Clear a pre-settlement intent after a definitive failed settlement."""

        async with self.db() as session:
            row = await session.get(MailAccountRow, mailbox_id)
            if row is not None and row.quote_id == quote_id and row.payment_settled_at is None:
                row.owner_wallet = None
                row.payment_network = None
                row.payment_asset = None
                row.payment_authorization_header = None
                row.payment_settlement_pending_at = None
                await session.commit()

    async def fail_activation_settlement(
        self,
        mailbox_id: str,
        quote_id: str,
        *,
        reason: str,
    ) -> None:
        """Close an authorization that provably can no longer pay this quote."""

        async with self.db() as session:
            row = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if (
                row is None
                or row.quote_id != quote_id
                or row.status != MailboxStatus.AWAITING_PAYMENT.value
                or row.payment_settled_at is not None
            ):
                return
            row.owner_wallet = None
            row.payment_network = None
            row.payment_asset = None
            row.payment_authorization_header = None
            row.payment_settlement_pending_at = None
            row.capacity_reserved_at = None
            row.status = MailboxStatus.DELETED.value
            row.provision_error = f"payment_authorization_{reason}"[:2000]
            row.deleted_at = _now()
            row.management_token_ciphertext = None
            quote = await session.get(MailQuoteRow, quote_id)
            if quote is not None:
                quote.status = MailQuoteStatus.EXPIRED.value
                quote.request_payload = {"redacted": True}
            await session.commit()

    async def record_activation_settlement(
        self,
        mailbox_id: str,
        quote_id: str,
        *,
        payer: str,
        tx_hash: str | None,
        payment_network: str | None,
        payment_asset: str | None,
    ) -> MailAccountRow:
        """Durably record a successful settlement before external handoff work."""

        async with self.db() as session:
            row = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
            if row.quote_id != quote_id:
                raise MailProblem(
                    409,
                    "mail_activation_superseded",
                    "This payment belongs to an earlier mailbox activation.",
                )
            if (
                row.status != MailboxStatus.AWAITING_PAYMENT.value
                and row.payment_settled_at is None
            ):
                raise MailProblem(
                    409,
                    "mail_activation_closed",
                    "This mailbox activation is no longer awaiting payment.",
                )
            row.owner_wallet = payer[:64]
            row.payment_tx = tx_hash
            row.payment_network = payment_network
            row.payment_asset = payment_asset
            row.payment_authorization_header = None
            row.payment_settlement_pending_at = None
            row.payment_settled_at = row.payment_settled_at or _now()
            await session.commit()
            return row

    async def bind_payment_authorization(self, fingerprint: str, quote_id: str) -> None:
        """Bind one verified authorization to exactly one mail quote forever."""

        async with self.db() as session:
            session.add(
                MailPaymentAuthorizationRow(
                    fingerprint=fingerprint,
                    quote_id=quote_id,
                    created_at=_now(),
                )
            )
            try:
                await session.commit()
                return
            except IntegrityError:
                await session.rollback()
            existing_fingerprint = await session.get(MailPaymentAuthorizationRow, fingerprint)
            if existing_fingerprint is not None:
                if existing_fingerprint.quote_id == quote_id:
                    return
                raise MailProblem(
                    409,
                    "payment_authorization_reused",
                    "This payment authorization is already bound to another mail payment.",
                )
            existing_quote = await session.scalar(
                select(MailPaymentAuthorizationRow).where(
                    MailPaymentAuthorizationRow.quote_id == quote_id
                )
            )
            if existing_quote is not None:
                raise MailProblem(
                    409,
                    "mail_quote_payment_bound",
                    "This mail quote is already bound to another payment authorization; "
                    "retry the original authorization.",
                )
            raise MailProblem(
                409,
                "payment_authorization_conflict",
                "The payment authorization could not be bound to this mail quote.",
            )

    async def mark_activation_paid(
        self,
        mailbox_id: str,
        quote_id: str,
        *,
        payer: str,
        tx_hash: str | None,
        payment_network: str | None,
        payment_asset: str | None,
    ) -> MailAccountRow:
        await self.reserve_activation_capacity(mailbox_id, quote_id=quote_id)
        async with self.db() as session:
            row = await session.get(MailAccountRow, mailbox_id)
            if row is None:
                raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
            if row.quote_id != quote_id:
                raise MailProblem(
                    409,
                    "mail_activation_superseded",
                    "This payment belongs to an earlier mailbox activation.",
                )
            domain_order_id = row.domain_order_id
        if domain_order_id:
            domain_order = await self.domains.mark_x402_paid(
                domain_order_id,
                payer=payer,
                tx_hash=tx_hash,
                payment_network=payment_network,
                payment_asset=payment_asset,
                payment_handoff_grace=_PAYMENT_HANDOFF_GRACE,
            )
            if domain_order.status not in {
                DomainOrderStatus.PAID.value,
                DomainOrderStatus.QUEUED.value,
                DomainOrderStatus.ACTIVE.value,
            }:
                await self._fail_activation(
                    mailbox_id, "domain_payment_refund_pending", refund=False
                )
                async with self.db() as session:
                    failed = await session.get(MailAccountRow, mailbox_id)
                if failed is None:
                    raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
                return failed
        async with self.db() as session:
            row = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one()
            if row.quote_id != quote_id:
                raise MailProblem(
                    409,
                    "mail_activation_superseded",
                    "This payment belongs to an earlier mailbox activation.",
                )
            recoverable_expiry = (
                row.status == MailboxStatus.FAILED.value
                and row.provision_error == "payment_window_expired"
                and bool(row.management_token_ciphertext)
            )
            if row.status == MailboxStatus.AWAITING_PAYMENT.value or recoverable_expiry:
                row.owner_wallet = payer[:64]
                row.payment_tx = tx_hash
                row.payment_network = payment_network
                row.payment_asset = payment_asset
                row.payment_authorization_header = None
                row.payment_settlement_pending_at = None
                row.payment_settled_at = row.payment_settled_at or _now()
                row.capacity_reserved_at = None
                row.provision_claim_token = None
                row.provision_claimed_at = None
                row.provision_retry_count = 0
                row.provision_next_attempt_at = None
                row.status = (
                    MailboxStatus.PENDING_DOMAIN.value
                    if row.domain_order_id
                    else MailboxStatus.PROVISIONING.value
                )
                quote = await session.get(MailQuoteRow, row.quote_id)
                if quote is not None:
                    quote.status = MailQuoteStatus.CONSUMED.value
                    quote.consumed_at = _now()
                await session.commit()
            return row

    async def activation_response(
        self, row: MailAccountRow, *, management_token: str | None = None
    ) -> MailAccountResponse:
        async with self.db() as session:
            current = await session.get(MailAccountRow, row.mailbox_id)
        if current is None:
            raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
        return self._account_response(current, management_token=management_token)

    async def get_account(self, mailbox_id: str, token: str) -> MailAccountResponse:
        row = await self._authorized_account(mailbox_id, token, allow_grace=True)
        return self._account_response(row)

    async def create_send_quote(self, body: MailSendQuoteRequest, token: str) -> MailQuoteResponse:
        self.require_launch()
        row = await self._authorized_account(body.mailbox_id, token)
        self._assert_sendable(row)
        if len(body.subject) > self.mail_config.max_subject_chars:
            raise MailProblem(422, "subject_too_large", "The message subject is too large.")
        if (
            len(body.text) > self.mail_config.max_text_chars
            or len(body.html or "") > self.mail_config.max_html_chars
        ):
            raise MailProblem(422, "message_too_large", "The message body is too large.")
        sanitized_html = sanitize_html(body.html)
        reply_reference: str | None = None
        if body.in_reply_to:
            reply_reference = await self._resolve_reply_reference(row, body.in_reply_to, body.to)
        payload = body.model_dump()
        payload["html"] = sanitized_html
        payload["in_reply_to"] = reply_reference
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        now = _now()
        quote = MailQuoteRow(
            quote_id=generate_mail_id("mailq"),
            kind="send",
            status=MailQuoteStatus.ACTIVE.value,
            mailbox_id=row.mailbox_id,
            address=row.address,
            request_hash=hashlib.sha256(canonical).hexdigest(),
            request_payload=payload,
            amount_usd=self.config.payment.price_mail_send,
            terms_version=self.mail_config.terms_version,
            created_at=now,
            expires_at=now + timedelta(seconds=self.mail_config.quote_ttl_seconds),
        )
        async with self.db() as session:
            session.add(quote)
            await session.commit()
        return self._quote_response(quote)

    async def deliver_send(self, quote_id: str, token: str) -> MailSendResponse:
        self.require_launch()
        async with self.db() as session:
            quote = await session.get(MailQuoteRow, quote_id)
            if quote is None or quote.kind != "send" or not quote.mailbox_id:
                raise MailProblem(404, "mail_quote_not_found", "Mail send quote not found.")
            row = await session.get(MailAccountRow, quote.mailbox_id)
            if row is None or not self._token_matches(row, token):
                raise MailProblem(404, "mail_quote_not_found", "Mail send quote not found.")
            existing: MailSendRow | None = await session.scalar(
                select(MailSendRow).where(MailSendRow.quote_id == quote_id)
            )
        send = existing or await self._reserve_send_intent(quote_id)
        if send.status == "accepted":
            return self._send_response(send)
        return await self._submit_send_intent(send.send_id)

    async def settled_send_response(self, quote_id: str, token: str) -> MailSendResponse | None:
        """Return an already-paid send without asking the payer to settle again."""

        async with self.db() as session:
            quote = await session.get(MailQuoteRow, quote_id)
            if quote is None or quote.kind != "send" or not quote.mailbox_id:
                raise MailProblem(404, "mail_quote_not_found", "Mail send quote not found.")
            account = await session.get(MailAccountRow, quote.mailbox_id)
            if account is None or not self._token_matches(account, token):
                raise MailProblem(404, "mail_quote_not_found", "Mail send quote not found.")
            send = await session.scalar(select(MailSendRow).where(MailSendRow.quote_id == quote_id))
            if send is None or send.status != "accepted":
                return None
            if send.payment_tx:
                return self._send_response(send)
            settlement = await session.scalar(
                select(PaymentEventRow.event_id)
                .where(
                    PaymentEventRow.event_type.in_(["settled", "dev_bypass"]),
                    PaymentEventRow.resource_path == "/v1/mail/messages/send",
                    PaymentEventRow.amount_usd == send.amount_usd,
                    PaymentEventRow.extra["quote_id"].as_string() == quote_id,
                )
                .limit(1)
            )
            return self._send_response(send) if settlement is not None else None

    async def _reserve_send_intent(self, quote_id: str) -> MailSendRow:
        """Commit the paid operation intent before the first external write."""

        now = _now()
        day_start = datetime(now.year, now.month, now.day, tzinfo=UTC)
        async with self.db() as session:
            winner: MailSendRow | None = await session.scalar(
                select(MailSendRow).where(MailSendRow.quote_id == quote_id)
            )
            if winner is not None:
                return winner
            if session.get_bind().dialect.name == "postgresql":
                await session.execute(
                    select(func.pg_advisory_xact_lock(_MAIL_SEND_CAPACITY_LOCK_ID))
                )
            locked_quote = (
                await session.execute(
                    select(MailQuoteRow).where(MailQuoteRow.quote_id == quote_id).with_for_update()
                )
            ).scalar_one()
            existing: MailSendRow | None = await session.scalar(
                select(MailSendRow).where(MailSendRow.quote_id == quote_id)
            )
            if existing is not None:
                return existing
            if not locked_quote.mailbox_id:
                raise MailProblem(404, "mail_quote_not_found", "Mail send quote not found.")
            account = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == locked_quote.mailbox_id)
                    .with_for_update()
                )
            ).scalar_one()
            self._assert_sendable(account)
            quote_expires_at = _aware(locked_quote.expires_at)
            if (
                locked_quote.status != MailQuoteStatus.ACTIVE.value
                or quote_expires_at is None
                or quote_expires_at <= now
            ):
                raise MailProblem(409, "mail_quote_expired", "This send quote is not payable.")
            mailbox_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(MailSendRow)
                    .where(
                        MailSendRow.mailbox_id == account.mailbox_id,
                        MailSendRow.created_at >= day_start,
                        MailSendRow.status.in_(_SEND_RESERVED_STATUSES),
                    )
                )
                or 0
            )
            global_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(MailSendRow)
                    .where(
                        MailSendRow.created_at >= day_start,
                        MailSendRow.status.in_(_SEND_RESERVED_STATUSES),
                    )
                )
                or 0
            )
            if mailbox_count >= self.mail_config.mailbox_send_limit_per_day:
                raise MailProblem(
                    429, "mailbox_send_limit", "The mailbox daily send limit is reached."
                )
            if global_count >= self.mail_config.global_send_limit_per_day:
                raise MailProblem(
                    503, "global_send_limit", "The Agent Mail daily safety limit is reached."
                )
            payload = dict(locked_quote.request_payload)
            recipient = str(payload["to"])
            recipient_row = await session.scalar(
                select(MailRecipientRow).where(
                    MailRecipientRow.mailbox_id == account.mailbox_id,
                    MailRecipientRow.recipient == recipient,
                )
            )
            if recipient_row is None and not payload.get("in_reply_to"):
                known_recipients = set(
                    await session.scalars(
                        select(MailRecipientRow.recipient).where(
                            MailRecipientRow.mailbox_id == account.mailbox_id
                        )
                    )
                )
                new_recipients_today = set(
                    await session.scalars(
                        select(MailRecipientRow.recipient).where(
                            MailRecipientRow.mailbox_id == account.mailbox_id,
                            MailRecipientRow.first_sent_at >= day_start,
                        )
                    )
                )
                pending_recipients = set(
                    await session.scalars(
                        select(MailSendRow.recipient).where(
                            MailSendRow.mailbox_id == account.mailbox_id,
                            MailSendRow.created_at >= day_start,
                            MailSendRow.status.in_(("pending", "submitting")),
                        )
                    )
                )
                new_count = len(new_recipients_today | (pending_recipients - known_recipients))
                if new_count >= self.mail_config.mailbox_new_recipient_limit_per_day:
                    raise MailProblem(
                        429,
                        "new_recipient_limit",
                        "The mailbox daily new-recipient limit is reached.",
                    )
            send = MailSendRow(
                send_id=generate_mail_id("send"),
                mailbox_id=account.mailbox_id,
                quote_id=quote_id,
                recipient=recipient,
                in_reply_to=payload.get("in_reply_to"),
                status="pending",
                amount_usd=locked_quote.amount_usd,
                created_at=now,
            )
            session.add(send)
            locked_quote.status = "reserved"
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                winner = await session.scalar(
                    select(MailSendRow).where(MailSendRow.quote_id == quote_id)
                )
                if winner is None:
                    raise
                return winner
            return send

    async def _submit_send_intent(self, send_id: str) -> MailSendResponse:
        async with self.db() as session:
            send = await session.get(MailSendRow, send_id)
            if send is None:
                raise MailProblem(404, "mail_send_not_found", "Mail send not found.")
            if send.status == "accepted":
                return self._send_response(send)
            account = await session.get(MailAccountRow, send.mailbox_id)
            quote = await session.get(MailQuoteRow, send.quote_id)
            if account is None or quote is None:
                raise MailProblem(
                    409, "mail_send_state_unavailable", "Mail send state is incomplete."
                )
            self._assert_sendable(account)
            password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
            address = account.address
            payload = dict(quote.request_payload)

        try:
            recovered_id = await self.backend.find_message_by_send_id(
                address=address, password=password, send_id=send_id
            )
        except MailBackendError as exc:
            raise MailProblem(
                502,
                "mail_submission_status_unavailable",
                "Message submission status is unavailable.",
            ) from exc
        if recovered_id:
            return await self._finalize_send(send_id, recovered_id)

        now = _now()
        async with self.db() as session:
            current = (
                await session.execute(
                    select(MailSendRow).where(MailSendRow.send_id == send_id).with_for_update()
                )
            ).scalar_one()
            if current.status == "accepted":
                return self._send_response(current)
            started_at = _aware(current.submission_started_at)
            if (
                current.status == "submitting"
                and started_at is not None
                and started_at > now - _SEND_SUBMISSION_LEASE
            ):
                raise MailProblem(
                    409,
                    "mail_submission_in_flight",
                    "This message submission is still being reconciled.",
                    headers={"Retry-After": "15"},
                )
            current.status = "submitting"
            current.submission_started_at = now
            current.error = None
            await session.commit()

        try:
            message_id = await self.backend.send_message(
                address=address,
                password=password,
                recipient=send.recipient,
                subject=str(payload["subject"]),
                text=str(payload.get("text") or ""),
                html=payload.get("html"),
                in_reply_to=payload.get("in_reply_to"),
                send_id=send_id,
            )
        except MailBackendError as exc:
            async with self.db() as session:
                failed_send = await session.get(MailSendRow, send_id)
                if failed_send is not None and failed_send.status != "accepted":
                    failed_send.error = str(exc)[:2000]
                    await session.commit()
            raise MailProblem(
                502, "mail_submission_failed", "The message was not accepted."
            ) from exc
        return await self._finalize_send(send_id, message_id)

    async def _finalize_send(self, send_id: str, message_id: str) -> MailSendResponse:
        now = _now()
        async with self.db() as session:
            send = (
                await session.execute(
                    select(MailSendRow).where(MailSendRow.send_id == send_id).with_for_update()
                )
            ).scalar_one()
            if send.status == "accepted":
                return self._send_response(send)
            account = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == send.mailbox_id)
                    .with_for_update()
                )
            ).scalar_one()
            quote = (
                await session.execute(
                    select(MailQuoteRow)
                    .where(MailQuoteRow.quote_id == send.quote_id)
                    .with_for_update()
                )
            ).scalar_one()
            payload = dict(quote.request_payload)
            if payload.get("redacted"):
                raise MailProblem(
                    409, "mail_send_state_unavailable", "Mail send payload is unavailable."
                )
            recipient_row = await session.scalar(
                select(MailRecipientRow).where(
                    MailRecipientRow.mailbox_id == account.mailbox_id,
                    MailRecipientRow.recipient == send.recipient,
                )
            )
            if recipient_row is None:
                session.add(
                    MailRecipientRow(
                        mailbox_id=account.mailbox_id,
                        recipient=send.recipient,
                        first_sent_at=now,
                        last_sent_at=now,
                    )
                )
            else:
                recipient_row.last_sent_at = now
            send.message_id = message_id
            send.status = "accepted"
            send.error = None
            send.accepted_at = now
            quote.status = MailQuoteStatus.CONSUMED.value
            quote.consumed_at = now
            quote.request_payload = {"redacted": True}
            if (
                await session.get(
                    MailMessageIndexRow,
                    (account.mailbox_id, message_id),
                )
                is None
            ):
                session.add(
                    MailMessageIndexRow(
                        message_id=message_id,
                        mailbox_id=account.mailbox_id,
                        folder="sent",
                        sender=account.address,
                        recipients=[send.recipient],
                        subject=str(payload["subject"]),
                        flags=["$seen"],
                        has_attachments=False,
                        created_at=now,
                    )
                )
            await session.commit()
            return self._send_response(send)

    async def reconcile_send_intents(self, *, limit: int = 100) -> int:
        """Finalize submissions accepted by Stalwart before a process interruption."""

        if limit < 1:
            return 0
        async with self.db() as session:
            send_ids = list(
                await session.scalars(
                    select(MailSendRow.send_id)
                    .where(MailSendRow.status == "submitting")
                    .order_by(MailSendRow.created_at)
                    .limit(limit)
                )
            )
        reconciled = 0
        for send_id in send_ids:
            try:
                async with self.db() as session:
                    send = await session.get(MailSendRow, send_id)
                    account = await session.get(MailAccountRow, send.mailbox_id) if send else None
                if send is None or account is None or not account.backend_credential_ciphertext:
                    continue
                password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
                message_id = await self.backend.find_message_by_send_id(
                    address=account.address,
                    password=password,
                    send_id=send_id,
                )
                if message_id:
                    await self._finalize_send(send_id, message_id)
                    reconciled += 1
            except Exception:
                log.exception("mail_send_intent_reconciliation_failed", send_id=send_id)
        return reconciled

    async def attribute_send_payment(self, send_id: str, tx_hash: str | None) -> None:
        async with self.db() as session:
            row = await session.get(MailSendRow, send_id)
            if row is not None and not row.payment_tx:
                row.payment_tx = tx_hash
                await session.commit()

    async def list_messages(
        self, mailbox_id: str, token: str, *, limit: int = 50
    ) -> MailMessagesResponse:
        account = await self._authorized_account(mailbox_id, token, allow_grace=True)
        password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
        try:
            payloads = await self.backend.list_messages(
                address=account.address,
                password=password,
                limit=min(max(limit, 1), 100),
            )
        except MailBackendError as exc:
            raise MailProblem(
                502, "mailbox_listing_unavailable", "Mailbox messages are unavailable."
            ) from exc
        rows: list[MailMessageIndexRow] = []
        async with self.db() as session:
            for payload in payloads:
                fields = self._message_index_fields(payload)
                message_id = fields.pop("message_id")
                row = await session.get(
                    MailMessageIndexRow,
                    (mailbox_id, message_id),
                )
                if row is None:
                    row = MailMessageIndexRow(
                        message_id=message_id,
                        mailbox_id=mailbox_id,
                        **fields,
                    )
                    session.add(row)
                else:
                    for field, value in fields.items():
                        setattr(row, field, value)
                rows.append(row)
            await session.commit()
        return MailMessagesResponse(
            mailbox_id=mailbox_id,
            messages=[
                MailMessageSummary(
                    message_id=row.message_id,
                    folder=row.folder,
                    sender=row.sender,
                    recipients=list(row.recipients or []),
                    subject=row.subject,
                    flags=list(row.flags or []),
                    has_attachments=bool(row.has_attachments),
                    created_at=row.created_at,
                )
                for row in rows
            ],
        )

    async def get_message(self, mailbox_id: str, message_id: str, token: str) -> MailMessageDetail:
        account = await self._authorized_account(mailbox_id, token, allow_grace=True)
        password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
        try:
            payload = await self.backend.get_message(
                address=account.address,
                password=password,
                message_id=message_id,
            )
        except MailBackendError as exc:
            raise MailProblem(404, "message_not_found", "Message not found.") from exc
        fields = self._message_index_fields(payload)
        authoritative_id = fields.pop("message_id")
        if authoritative_id != message_id:
            raise MailProblem(404, "message_not_found", "Message not found.")
        async with self.db() as session:
            indexed = await session.get(
                MailMessageIndexRow,
                (mailbox_id, message_id),
            )
            if indexed is None:
                indexed = MailMessageIndexRow(
                    message_id=message_id,
                    mailbox_id=mailbox_id,
                    **fields,
                )
                session.add(indexed)
            else:
                for field, value in fields.items():
                    setattr(indexed, field, value)
            await session.commit()
        body_values = payload.get("bodyValues") or {}
        text = "\n".join(
            str((body_values.get(part.get("partId")) or {}).get("value") or "")
            for part in payload.get("textBody") or []
        )
        html_body = (
            "\n".join(
                str((body_values.get(part.get("partId")) or {}).get("value") or "")
                for part in payload.get("htmlBody") or []
            )
            or None
        )
        attachments = [
            MailAttachment(
                blob_id=str(item.get("blobId")),
                name=str(item.get("name")) if item.get("name") else None,
                type=str(item.get("type")) if item.get("type") else None,
                size=int(item["size"]) if item.get("size") is not None else None,
                download_url=(
                    f"/v1/mail/accounts/{mailbox_id}/attachments/"
                    f"{quote(str(item.get('blobId')), safe='')}"
                    "?"
                    + urlencode(
                        {
                            "name": item.get("name") or "attachment",
                            "type": item.get("type") or "application/octet-stream",
                        }
                    )
                ),
            )
            for item in payload.get("attachments") or []
            if item.get("blobId")
        ]
        return MailMessageDetail(
            message_id=indexed.message_id,
            folder=indexed.folder,
            sender=indexed.sender,
            recipients=list(indexed.recipients or []),
            subject=indexed.subject,
            flags=list(indexed.flags or []),
            has_attachments=bool(attachments),
            created_at=indexed.created_at,
            text=text,
            html=html_body,
            attachments=attachments,
        )

    async def download_attachment(
        self,
        mailbox_id: str,
        blob_id: str,
        token: str,
        *,
        name: str,
        media_type: str,
    ) -> tuple[bytes, str]:
        account = await self._authorized_account(mailbox_id, token, allow_grace=True)
        password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
        try:
            return await self.backend.download_blob(
                address=account.address,
                password=password,
                blob_id=blob_id,
                name=name,
                media_type=media_type,
            )
        except MailAttachmentTooLargeError as exc:
            raise MailProblem(
                413, "attachment_too_large", "Attachment exceeds the download limit."
            ) from exc
        except MailBackendError as exc:
            raise MailProblem(404, "attachment_not_found", "Attachment not found.") from exc

    async def list_events(
        self, mailbox_id: str, token: str, *, limit: int = 100
    ) -> MailEventsResponse:
        await self._authorized_account(mailbox_id, token, allow_grace=True)
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(MailEventRow)
                    .where(MailEventRow.mailbox_id == mailbox_id)
                    .order_by(MailEventRow.created_at.desc())
                    .limit(min(max(limit, 1), 200))
                )
            )
        return MailEventsResponse(
            mailbox_id=mailbox_id,
            events=[
                MailEventResponse(
                    event_id=row.event_id,
                    type=row.type,
                    message_id=row.message_id,
                    payload=dict(row.payload or {}),
                    created_at=row.created_at,
                )
                for row in rows
            ],
        )

    async def create_webhook(
        self, mailbox_id: str, token: str, body: MailWebhookCreateRequest
    ) -> MailWebhookResponse:
        account = await self._authorized_account(mailbox_id, token)
        if account.status != MailboxStatus.ACTIVE.value:
            raise MailProblem(409, "mailbox_not_active", "Webhooks require an active mailbox.")
        try:
            url, _addresses = await validate_webhook_url(body.url)
        except ValueError as exc:
            raise MailProblem(422, "unsafe_webhook_url", str(exc)) from exc
        allowed = {"message.received", "message.delivery", "mailbox.suspended"}
        events = sorted(set(body.events))
        if not events or any(item not in allowed for item in events):
            raise MailProblem(422, "invalid_webhook_events", "Webhook events are invalid.")
        secret = "hyr_whsec_" + secrets.token_urlsafe(32)
        now = _now()
        row = MailWebhookRow(
            webhook_id=generate_mail_id("wh"),
            mailbox_id=mailbox_id,
            url=url,
            events=events,
            secret_hash=hash_token(secret),
            secret_ciphertext=self._fernet().encrypt(secret.encode()).decode(),
            status="active",
            created_at=now,
        )
        async with self.db() as session:
            locked_account = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if locked_account is None or locked_account.status != MailboxStatus.ACTIVE.value:
                raise MailProblem(409, "mailbox_not_active", "Webhooks require an active mailbox.")
            active_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(MailWebhookRow)
                    .where(
                        MailWebhookRow.mailbox_id == mailbox_id,
                        MailWebhookRow.status == "active",
                    )
                )
                or 0
            )
            if active_count >= self.mail_config.max_webhooks_per_mailbox:
                raise MailProblem(
                    409,
                    "mail_webhook_limit",
                    "The mailbox webhook limit is reached.",
                )
            session.add(row)
            await session.commit()
        return self._webhook_response(row, signing_secret=secret)

    async def list_webhooks(self, mailbox_id: str, token: str) -> MailWebhookListResponse:
        await self._authorized_account(mailbox_id, token, allow_grace=True)
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(MailWebhookRow)
                    .where(MailWebhookRow.mailbox_id == mailbox_id)
                    .order_by(MailWebhookRow.created_at)
                )
            )
        return MailWebhookListResponse(webhooks=[self._webhook_response(row) for row in rows])

    async def delete_webhook(self, mailbox_id: str, webhook_id: str, token: str) -> None:
        await self._authorized_account(mailbox_id, token)
        async with self.db() as session:
            row = await session.get(MailWebhookRow, webhook_id)
            if row is None or row.mailbox_id != mailbox_id:
                raise MailProblem(404, "webhook_not_found", "Webhook not found.")
            row.status = "deleted"
            await session.commit()

    async def ingest_stalwart_events(self, events: list[dict[str, Any]]) -> int:
        accepted = 0
        for event in events:
            raw_data = event.get("data")
            data: dict[str, Any] = (
                {str(key): value for key, value in raw_data.items()}
                if isinstance(raw_data, dict)
                else {}
            )
            raw_type = str(event.get("type") or "unknown")
            backend_id = str(data.get("accountId") or data.get("account_id") or "")
            addresses = self._directional_event_addresses(raw_type, data)
            async with self.db() as session:
                query = select(MailAccountRow)
                if backend_id:
                    query = query.where(MailAccountRow.backend_id == backend_id)
                elif addresses:
                    query = query.where(MailAccountRow.address.in_(addresses))
                else:
                    continue
                matches = list(await session.scalars(query.limit(2)))
                if len(matches) != 1:
                    continue
                account = matches[0]
                if account.status in {
                    MailboxStatus.DELETED.value,
                    MailboxStatus.FAILED.value,
                    MailboxStatus.REFUND_DUE.value,
                }:
                    continue
                canonical = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
                source_event_id = str(event.get("id") or "")
                event_id = (
                    source_event_id
                    if source_event_id and len(source_event_id) <= 36
                    else "evt_"
                    + hashlib.sha256(source_event_id.encode() or canonical).hexdigest()[:32]
                )
                if await session.get(MailEventRow, event_id) is not None:
                    continue
                public_type = self._public_event_type(raw_type)
                message_id = str(data.get("messageId") or data.get("emailId") or "") or None
                stored = MailEventRow(
                    event_id=event_id,
                    mailbox_id=account.mailbox_id,
                    type=public_type,
                    message_id=message_id,
                    payload={"source_type": raw_type, "data": data},
                    created_at=_now(),
                )
                session.add(stored)
                if public_type == "message.received" and message_id:
                    senders = self._event_addresses(
                        {"from": data.get("sender") or data.get("from")}
                    )
                    sender = senders[0] if senders else None
                    index_values = {
                        "message_id": message_id,
                        "mailbox_id": account.mailbox_id,
                        "folder": "inbox",
                        "sender": sender,
                        "recipients": [account.address],
                        "subject": str(data.get("subject") or "") or None,
                        "flags": [],
                        "has_attachments": bool(data.get("hasAttachments")),
                        "created_at": _now(),
                    }
                    dialect = session.get_bind().dialect.name
                    if dialect == "postgresql":
                        await session.execute(
                            postgresql_insert(MailMessageIndexRow)
                            .values(**index_values)
                            .on_conflict_do_nothing(
                                index_elements=[
                                    MailMessageIndexRow.mailbox_id,
                                    MailMessageIndexRow.message_id,
                                ]
                            )
                        )
                    elif dialect == "sqlite":
                        await session.execute(
                            sqlite_insert(MailMessageIndexRow)
                            .values(**index_values)
                            .on_conflict_do_nothing(
                                index_elements=[
                                    MailMessageIndexRow.mailbox_id,
                                    MailMessageIndexRow.message_id,
                                ]
                            )
                        )
                    elif (
                        await session.get(
                            MailMessageIndexRow,
                            (account.mailbox_id, message_id),
                        )
                        is None
                    ):
                        session.add(MailMessageIndexRow(**index_values))
                suspend_reason = self._suspension_reason(raw_type, data)
                if suspend_reason and account.status not in {
                    MailboxStatus.DELETED.value,
                    MailboxStatus.EXPIRED.value,
                }:
                    account.status = MailboxStatus.SUSPENDED.value
                    account.suspended_reason = suspend_reason
                hooks = list(
                    await session.scalars(
                        select(MailWebhookRow).where(
                            MailWebhookRow.mailbox_id == account.mailbox_id,
                            MailWebhookRow.status == "active",
                        )
                    )
                )
                for hook in hooks:
                    if public_type in list(hook.events or []):
                        session.add(
                            MailWebhookDeliveryRow(
                                delivery_id=generate_mail_id("whd"),
                                webhook_id=hook.webhook_id,
                                event_id=event_id,
                                status="pending",
                                next_attempt_at=_now(),
                                created_at=_now(),
                            )
                        )
                try:
                    await session.commit()
                except IntegrityError:
                    await session.rollback()
                    continue
                accepted += 1
        return accepted

    async def provision_pending(self, *, limit: int = 10) -> int:
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(MailAccountRow)
                    .where(
                        MailAccountRow.status.in_(
                            [MailboxStatus.PENDING_DOMAIN.value, MailboxStatus.PROVISIONING.value]
                        ),
                        or_(
                            MailAccountRow.provision_next_attempt_at.is_(None),
                            MailAccountRow.provision_next_attempt_at <= _now(),
                        ),
                    )
                    .order_by(MailAccountRow.created_at)
                    .limit(limit)
                )
            )
        changed = 0
        for row in rows:
            if row.status == MailboxStatus.PENDING_DOMAIN.value and row.domain_order_id:
                async with self.db() as session:
                    domain_order = await session.get(DomainOrderRow, row.domain_order_id)
                if domain_order is None:
                    await self._fail_activation(
                        row.mailbox_id, "domain_order_missing", refund=False
                    )
                    changed += 1
                    continue
                if domain_order.status == DomainOrderStatus.ACTIVE.value:
                    async with self.db() as session:
                        current = await session.get(MailAccountRow, row.mailbox_id)
                        if current is not None:
                            current.status = MailboxStatus.PROVISIONING.value
                            await session.commit()
                    row.status = MailboxStatus.PROVISIONING.value
                elif domain_order.status in {
                    DomainOrderStatus.FAILED.value,
                    DomainOrderStatus.REFUND_DUE.value,
                    DomainOrderStatus.CANCELLED.value,
                    DomainOrderStatus.EXPIRED.value,
                }:
                    # The domain lifecycle records the full combined refund.
                    await self._fail_activation(
                        row.mailbox_id, "domain_registration_failed", refund=False
                    )
                    changed += 1
                    continue
                else:
                    continue
            try:
                changed += int(await self._provision_one(row.mailbox_id))
            except Exception:
                log.exception(
                    "mailbox_provision_orchestration_failed",
                    mailbox_id=row.mailbox_id,
                )
        return changed

    async def sweep_retention(self) -> int:
        """Delete expired mailbox content from Stalwart, then its local index."""

        cutoff = _now() - timedelta(days=self.mail_config.retention_days)
        async with self.db() as session:
            accounts = list(
                await session.scalars(
                    select(MailAccountRow).where(
                        MailAccountRow.backend_id.is_not(None),
                        MailAccountRow.backend_credential_ciphertext.is_not(None),
                        MailAccountRow.status.in_(
                            [
                                MailboxStatus.ACTIVE.value,
                                MailboxStatus.GRACE.value,
                                MailboxStatus.SUSPENDED.value,
                            ]
                        ),
                    )
                )
            )
        deleted_total = 0
        for account in accounts:
            try:
                password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
                deleted_total += await self.backend.delete_messages_before(
                    address=account.address,
                    password=password,
                    cutoff=cutoff,
                )
            except (MailBackendError, MailProblem):
                log.exception(
                    "mail_retention_backend_delete_failed",
                    mailbox_id=account.mailbox_id,
                )
                continue
            async with self.db() as session:
                await session.execute(
                    delete(MailMessageIndexRow).where(
                        MailMessageIndexRow.mailbox_id == account.mailbox_id,
                        MailMessageIndexRow.created_at < cutoff,
                    )
                )
                await session.commit()
        return deleted_total

    async def process_lifecycle(self) -> int:
        now = _now()
        changed = 0

        async with self.db() as session:
            active = list(
                await session.scalars(
                    select(MailAccountRow).where(
                        MailAccountRow.status.in_(
                            [
                                MailboxStatus.ACTIVE.value,
                                MailboxStatus.SUSPENDED.value,
                            ]
                        ),
                        or_(
                            MailAccountRow.expires_at.is_(None),
                            MailAccountRow.expires_at <= now,
                        ),
                    )
                )
            )
            for row in active:
                row.status = MailboxStatus.GRACE.value
                row.grace_ends_at = row.grace_ends_at or (
                    (_aware(row.expires_at) or now) + timedelta(days=self.mail_config.grace_days)
                )
                changed += 1
            await session.commit()
            expired = list(
                await session.scalars(
                    select(MailAccountRow).where(
                        MailAccountRow.status == MailboxStatus.GRACE.value,
                        or_(
                            MailAccountRow.grace_ends_at.is_(None),
                            MailAccountRow.grace_ends_at <= now,
                        ),
                    )
                )
            )
        for row in expired:
            if row.backend_id:
                try:
                    await self.backend.delete_account(row.backend_id)
                except MailBackendError:
                    log.exception("mailbox_delete_backend_failed", mailbox_id=row.mailbox_id)
                    continue
            dns_cleanup_pending = False
            if row.plan != MailboxMode.HOSTED.value and row.domain:
                try:
                    await self.domains.remove_service_records(row.domain, managed_by="agent_mail")
                except Exception:
                    log.exception("mailbox_delete_dns_failed", mailbox_id=row.mailbox_id)
                    dns_cleanup_pending = True
            async with self.db() as session:
                current_account = await session.get(MailAccountRow, row.mailbox_id)
                if current_account is not None:
                    current_account.status = MailboxStatus.DELETED.value
                    current_account.deleted_at = now
                    current_account.backend_id = None
                    current_account.backend_credential_ciphertext = None
                    current_account.management_token_ciphertext = None
                    current_account.capacity_reserved_at = None
                    current_account.dns_cleanup_pending = dns_cleanup_pending
                    if dns_cleanup_pending:
                        current_account.provision_error = "dns_cleanup_pending"
                    event_ids = select(MailEventRow.event_id).where(
                        MailEventRow.mailbox_id == row.mailbox_id
                    )
                    webhook_ids = select(MailWebhookRow.webhook_id).where(
                        MailWebhookRow.mailbox_id == row.mailbox_id
                    )
                    await session.execute(
                        delete(MailWebhookDeliveryRow).where(
                            or_(
                                MailWebhookDeliveryRow.event_id.in_(event_ids),
                                MailWebhookDeliveryRow.webhook_id.in_(webhook_ids),
                            )
                        )
                    )
                    await session.execute(
                        delete(MailEventRow).where(MailEventRow.mailbox_id == row.mailbox_id)
                    )
                    await session.execute(
                        delete(MailMessageIndexRow).where(
                            MailMessageIndexRow.mailbox_id == row.mailbox_id
                        )
                    )
                    await session.execute(
                        delete(MailRecipientRow).where(
                            MailRecipientRow.mailbox_id == row.mailbox_id
                        )
                    )
                    await session.execute(
                        delete(MailSendRow).where(MailSendRow.mailbox_id == row.mailbox_id)
                    )
                    await session.execute(
                        delete(MailWebhookRow).where(MailWebhookRow.mailbox_id == row.mailbox_id)
                    )
                    await session.commit()
                    changed += 1
        async with self.db() as session:
            cleanup_pending = list(
                await session.scalars(
                    select(MailAccountRow).where(
                        MailAccountRow.status.in_(
                            [
                                MailboxStatus.DELETED.value,
                                MailboxStatus.FAILED.value,
                                MailboxStatus.REFUND_DUE.value,
                            ]
                        ),
                        or_(
                            MailAccountRow.dns_cleanup_pending.is_(True),
                            MailAccountRow.provision_error == "dns_cleanup_pending",
                        ),
                    )
                )
            )
        for row in cleanup_pending:
            if not row.domain:
                continue
            try:
                await self.domains.remove_service_records(row.domain, managed_by="agent_mail")
            except Exception:
                log.exception("mailbox_delete_dns_retry_failed", mailbox_id=row.mailbox_id)
                continue
            async with self.db() as session:
                current = await session.get(MailAccountRow, row.mailbox_id)
                if current is not None and (
                    current.dns_cleanup_pending or current.provision_error == "dns_cleanup_pending"
                ):
                    current.dns_cleanup_pending = False
                    if current.provision_error == "dns_cleanup_pending":
                        current.provision_error = None
                    await session.commit()
                    changed += 1
        return changed

    async def expire_quotes(self) -> int:
        result = 0
        now = _now()
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(MailQuoteRow).where(
                        MailQuoteRow.status.in_([MailQuoteStatus.ACTIVE.value, "reserved"]),
                        MailQuoteRow.expires_at <= now,
                    )
                )
            )
            for row in rows:
                if row.kind == "send":
                    send = await session.scalar(
                        select(MailSendRow).where(MailSendRow.quote_id == row.quote_id)
                    )
                    if send is not None and send.status in {"pending", "submitting"}:
                        continue
                    row.status = MailQuoteStatus.EXPIRED.value
                    row.request_payload = {"redacted": True}
                    result += 1
                    continue
                account = await session.scalar(
                    select(MailAccountRow).where(MailAccountRow.quote_id == row.quote_id)
                )
                if account is None or account.status == MailboxStatus.AWAITING_PAYMENT.value:
                    expires_at = _aware(row.expires_at)
                    if account is not None and (
                        expires_at is None or expires_at > now - _PAYMENT_HANDOFF_GRACE
                    ):
                        continue
                    if account is not None:
                        if (
                            account.payment_settlement_pending_at is not None
                            or account.payment_settled_at is not None
                        ):
                            continue
                        settled = await session.scalar(
                            select(PaymentEventRow.event_id)
                            .where(
                                PaymentEventRow.event_type.in_(["settled", "dev_bypass"]),
                                PaymentEventRow.resource_path == "/v1/mail/accounts",
                                PaymentEventRow.extra["mailbox_id"].as_string()
                                == account.mailbox_id,
                                PaymentEventRow.extra["quote_id"].as_string() == account.quote_id,
                            )
                            .limit(1)
                        )
                        if settled is not None:
                            continue
                    row.status = MailQuoteStatus.EXPIRED.value
                    if account is not None:
                        # The one-hour handoff grace and durable-ledger lookup
                        # above protect settled payments. A still-unpaid row is
                        # now a tombstone, releasing its address while keeping
                        # the old idempotency key permanently closed.
                        account.status = MailboxStatus.DELETED.value
                        account.provision_error = "payment_window_expired"
                        account.deleted_at = now
                        account.management_token_ciphertext = None
                        account.capacity_reserved_at = None
                        account.provision_claim_token = None
                        account.provision_claimed_at = None
                        account.provision_next_attempt_at = None
                    result += 1
            await session.commit()
        return result

    async def recover_x402_handoffs(
        self,
        *,
        gate: Any | None = None,
        limit: int = 200,
    ) -> int:
        """Replay settled activation payments whose state handoff was lost."""

        if limit < 1:
            return 0
        recovered = 0
        seen: set[tuple[str, str]] = set()
        if gate is not None:
            async with self.db() as session:
                pending = list(
                    await session.scalars(
                        select(MailAccountRow)
                        .where(
                            MailAccountRow.status == MailboxStatus.AWAITING_PAYMENT.value,
                            MailAccountRow.payment_settlement_pending_at.is_not(None),
                            MailAccountRow.payment_settled_at.is_(None),
                            MailAccountRow.payment_authorization_header.is_not(None),
                        )
                        .order_by(MailAccountRow.payment_settlement_pending_at)
                        .limit(limit)
                    )
                )
            for pending_account in pending:
                if (
                    not pending_account.quote_id
                    or pending_account.total_amount_usd is None
                    or not pending_account.payment_authorization_header
                ):
                    continue
                try:
                    reconciliation: PaymentReconciliation = await gate.reconcile_settlement(
                        pending_account.payment_authorization_header,
                        Decimal(pending_account.total_amount_usd),
                        pending_since=_aware(pending_account.payment_settlement_pending_at),
                    )
                    if reconciliation.terminal_unsettled:
                        await self.fail_activation_settlement(
                            pending_account.mailbox_id,
                            pending_account.quote_id,
                            reason=reconciliation.reason or "unsettled",
                        )
                        continue
                    settlement = reconciliation.payment
                    if settlement is None:
                        continue
                    await self.record_activation_settlement(
                        pending_account.mailbox_id,
                        pending_account.quote_id,
                        payer=settlement.payer,
                        tx_hash=settlement.tx_hash,
                        payment_network=settlement.network,
                        payment_asset=settlement.asset,
                    )
                except Exception:
                    log.warning(
                        "mail_payment_authorization_reconciliation_deferred",
                        mailbox_id=pending_account.mailbox_id,
                        exc_info=True,
                    )
        async with self.db() as session:
            durable = list(
                await session.scalars(
                    select(MailAccountRow)
                    .where(
                        MailAccountRow.payment_settled_at.is_not(None),
                        or_(
                            MailAccountRow.status == MailboxStatus.AWAITING_PAYMENT.value,
                            and_(
                                MailAccountRow.status == MailboxStatus.FAILED.value,
                                MailAccountRow.provision_error == "payment_window_expired",
                                MailAccountRow.management_token_ciphertext.is_not(None),
                            ),
                        ),
                    )
                    .order_by(MailAccountRow.payment_settled_at)
                    .limit(limit)
                )
            )
        for durable_account in durable:
            if not durable_account.quote_id:
                continue
            activation = (durable_account.mailbox_id, durable_account.quote_id)
            seen.add(activation)
            try:
                await self.mark_activation_paid(
                    durable_account.mailbox_id,
                    durable_account.quote_id,
                    payer=durable_account.owner_wallet or "unknown",
                    tx_hash=durable_account.payment_tx,
                    payment_network=durable_account.payment_network,
                    payment_asset=durable_account.payment_asset,
                )
            except DomainProblem:
                log.warning(
                    "mail_durable_payment_handoff_recovery_deferred",
                    mailbox_id=durable_account.mailbox_id,
                    exc_info=True,
                )
                continue
            recovered += 1
        cursor: tuple[datetime, str] | None = None
        while True:
            filters = [
                PaymentEventRow.event_type.in_(["settled", "dev_bypass"]),
                PaymentEventRow.resource_path == "/v1/mail/accounts",
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
                mailbox_id = str(extra.get("mailbox_id") or "")
                quote_id = str(extra.get("quote_id") or "")
                activation = (mailbox_id, quote_id)
                if not mailbox_id or not quote_id or activation in seen:
                    continue
                async with self.db() as session:
                    account = await session.get(MailAccountRow, mailbox_id)
                    awaiting = bool(
                        account is not None
                        and account.quote_id == quote_id
                        and account.total_amount_usd is not None
                        and event.amount_usd is not None
                        and Decimal(account.total_amount_usd) == Decimal(event.amount_usd)
                        and (
                            account.status == MailboxStatus.AWAITING_PAYMENT.value
                            or (
                                account.status == MailboxStatus.FAILED.value
                                and account.provision_error == "payment_window_expired"
                                and account.management_token_ciphertext
                            )
                        )
                    )
                if not awaiting:
                    continue
                seen.add(activation)
                try:
                    await self.mark_activation_paid(
                        mailbox_id,
                        quote_id,
                        payer=event.payer_wallet or "unknown",
                        tx_hash=event.tx_hash,
                        payment_network=event.network,
                        payment_asset=event.asset,
                    )
                except DomainProblem:
                    # One temporarily unrecoverable activation (for example,
                    # capacity contention) must not starve later settled
                    # handoffs. The durable payment event remains available
                    # for the next worker pass.
                    log.warning(
                        "mail_payment_handoff_recovery_deferred",
                        mailbox_id=mailbox_id,
                        exc_info=True,
                    )
                    continue
                recovered += 1
            if len(events) < limit:
                break
            last = events[-1]
            last_created_at = _aware(last.created_at)
            if last_created_at is None:
                break
            cursor = (last_created_at, last.event_id)
        return recovered

    async def deliver_webhooks(self, *, limit: int = 20) -> int:
        now = _now()
        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(MailWebhookDeliveryRow)
                    .where(
                        MailWebhookDeliveryRow.status == "pending",
                        MailWebhookDeliveryRow.next_attempt_at <= now,
                    )
                    .order_by(MailWebhookDeliveryRow.created_at)
                    .limit(limit)
                )
            )
        completed = 0
        for delivery in rows:
            async with self.db() as session:
                hook = await session.get(MailWebhookRow, delivery.webhook_id)
                event = await session.get(MailEventRow, delivery.event_id)
            if hook is None or event is None or hook.status != "active":
                await self._set_delivery(delivery.delivery_id, "cancelled", "webhook unavailable")
                continue
            payload = {
                "id": event.event_id,
                "type": event.type,
                "mailbox_id": event.mailbox_id,
                "message_id": event.message_id,
                "data": event.payload,
                "created_at": event.created_at.isoformat(),
            }
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            secret = self._decrypt(self._fernet(), hook.secret_ciphertext)
            signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            try:
                url, addresses = await validate_webhook_url(hook.url)
                last_error: Exception | None = None
                for address in addresses:
                    try:
                        await self._post_pinned(
                            url,
                            address,
                            raw,
                            signature,
                            event.event_id,
                        )
                    except Exception as exc:
                        last_error = exc
                        continue
                    break
                else:
                    raise last_error or RuntimeError(
                        "webhook hostname has no reachable validated address"
                    )
            except Exception as exc:
                attempts = int(delivery.attempt_count or 0) + 1
                if attempts >= 5:
                    await self._set_delivery(delivery.delivery_id, "failed", str(exc), attempts)
                    async with self.db() as session:
                        current_hook = await session.get(MailWebhookRow, hook.webhook_id)
                        if current_hook is not None:
                            current_hook.failure_count = int(current_hook.failure_count or 0) + 1
                            if current_hook.failure_count >= 5:
                                current_hook.status = "disabled"
                            await session.commit()
                else:
                    async with self.db() as session:
                        current = await session.get(MailWebhookDeliveryRow, delivery.delivery_id)
                        if current is not None:
                            current.attempt_count = attempts
                            current.last_error = str(exc)[:1000]
                            current.next_attempt_at = _now() + timedelta(minutes=2**attempts)
                            await session.commit()
                continue
            await self._set_delivery(
                delivery.delivery_id, "delivered", None, int(delivery.attempt_count or 0) + 1
            )
            async with self.db() as session:
                current_hook = await session.get(MailWebhookRow, hook.webhook_id)
                if current_hook is not None:
                    current_hook.last_delivered_at = _now()
                    current_hook.failure_count = 0
                    await session.commit()
            completed += 1
        return completed

    async def _claim_provisioning(self, mailbox_id: str) -> tuple[MailAccountRow, str, str] | None:
        """Lease one provisioning row before any external backend write."""

        now = _now()
        stale_before = now - timedelta(seconds=self.mail_config.provision_lease_seconds)
        claim_token = generate_mail_id("pclaim")
        async with self.db() as session:
            claimed = await session.execute(
                update(MailAccountRow)
                .where(
                    MailAccountRow.mailbox_id == mailbox_id,
                    MailAccountRow.status == MailboxStatus.PROVISIONING.value,
                    or_(
                        MailAccountRow.provision_next_attempt_at.is_(None),
                        MailAccountRow.provision_next_attempt_at <= now,
                    ),
                    or_(
                        MailAccountRow.provision_claim_token.is_(None),
                        MailAccountRow.provision_claimed_at.is_(None),
                        MailAccountRow.provision_claimed_at <= stale_before,
                    ),
                )
                .values(
                    provision_claim_token=claim_token,
                    provision_claimed_at=now,
                )
                .execution_options(synchronize_session=False)
            )
            if int(getattr(claimed, "rowcount", 0) or 0) != 1:
                await session.rollback()
                return None
            row = await session.get(MailAccountRow, mailbox_id)
            if row is None:
                await session.rollback()
                return None
            if row.backend_credential_ciphertext:
                password = self._decrypt(self._fernet(), row.backend_credential_ciphertext)
            else:
                # Persist the credential in the same transaction as the lease.
                # A process death after Stalwart creates the account can then
                # replay with the same password instead of orphaning it.
                password = secrets.token_urlsafe(36)
                row.backend_credential_ciphertext = (
                    self._fernet().encrypt(password.encode()).decode()
                )
            await session.commit()
            return row, claim_token, password

    async def _defer_incomplete_dns(self, mailbox_id: str, claim_token: str, reason: str) -> bool:
        """Record a visible bounded DNS retry, refunding after exhaustion."""

        exhausted = False
        attempts = 0
        async with self.db() as session:
            current = (
                await session.execute(
                    select(MailAccountRow)
                    .where(MailAccountRow.mailbox_id == mailbox_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if (
                current is None
                or current.status != MailboxStatus.PROVISIONING.value
                or current.provision_claim_token != claim_token
            ):
                return False
            attempts = int(current.provision_retry_count or 0) + 1
            current.provision_retry_count = attempts
            exhausted = attempts >= self.mail_config.provision_dns_max_attempts
            current.provision_error = (
                f"mailbox DNS remained incomplete after {attempts}/"
                f"{self.mail_config.provision_dns_max_attempts} attempts: {reason}"
            )[:2000]
            if not exhausted:
                current.provision_claim_token = None
                current.provision_claimed_at = None
                current.provision_next_attempt_at = _now() + timedelta(
                    seconds=self.mail_config.provision_dns_retry_seconds
                )
            await session.commit()
        log.warning(
            "mailbox_dns_not_ready",
            mailbox_id=mailbox_id,
            attempt=attempts,
            max_attempts=self.mail_config.provision_dns_max_attempts,
        )
        if exhausted:
            return await self._fail_activation(
                mailbox_id,
                f"mailbox_dns_incomplete_after_{attempts}_attempts",
                refund=True,
                claim_token=claim_token,
            )
        return False

    async def _run_claimed_provisioning(
        self,
        row: MailAccountRow,
        claim_token: str,
        password: str,
    ) -> bool:
        if row.plan == MailboxMode.CUSTOM.value:
            await self._assert_managed_domain_authority(
                str(row.domain),
                str(row.domain_authority_hash or ""),
            )
        domain_id, records = await self.backend.ensure_domain(str(row.domain))
        backend_id = await self.backend.ensure_account(
            address=row.address,
            domain_id=domain_id,
            password=password,
            quota_bytes=self.mail_config.storage_quota_bytes,
        )
        async with self.db() as session:
            current = await session.get(MailAccountRow, row.mailbox_id)
            if (
                current is None
                or current.status != MailboxStatus.PROVISIONING.value
                or current.provision_claim_token != claim_token
            ):
                # Another worker may have completed the same idempotent backend
                # account after this lease expired. Never delete that account.
                return False
            # Make cleanup recoverable before the DNS control-plane write and
            # refresh the lease for that final external operation.
            current.backend_id = backend_id
            current.provision_claimed_at = _now()
            await session.commit()
        if row.plan != MailboxMode.HOSTED.value:
            await self.domains.replace_service_records(
                str(row.domain), records, managed_by="agent_mail"
            )
        now = _now()
        async with self.db() as session:
            current = await session.get(MailAccountRow, row.mailbox_id)
            if (
                current is None
                or current.status != MailboxStatus.PROVISIONING.value
                or current.provision_claim_token != claim_token
            ):
                return False
            current.backend_id = backend_id
            current.status = MailboxStatus.ACTIVE.value
            current.activated_at = now
            current.expires_at = now + timedelta(days=self.mail_config.active_days)
            current.grace_ends_at = current.expires_at + timedelta(days=self.mail_config.grace_days)
            current.provision_error = None
            current.provision_claim_token = None
            current.provision_claimed_at = None
            current.provision_retry_count = 0
            current.provision_next_attempt_at = None
            await session.commit()
        return True

    async def _provision_one(self, mailbox_id: str) -> bool:
        claimed = await self._claim_provisioning(mailbox_id)
        if claimed is None:
            return False
        row, claim_token, password = claimed
        try:
            return await self._run_claimed_provisioning(
                row,
                claim_token,
                password,
            )
        except MailDNSIncompleteError as exc:
            return await self._defer_incomplete_dns(mailbox_id, claim_token, str(exc))
        except Exception as exc:
            log.exception("mailbox_provision_failed", mailbox_id=mailbox_id)
            return await self._fail_activation(
                mailbox_id,
                str(exc),
                refund=True,
                claim_token=claim_token,
            )

    async def _fail_activation(
        self,
        mailbox_id: str,
        reason: str,
        *,
        refund: bool,
        claim_token: str | None = None,
    ) -> bool:
        async with self.db() as session:
            row = await session.get(MailAccountRow, mailbox_id)
            if row is None or row.status in {
                MailboxStatus.REFUND_DUE.value,
                MailboxStatus.FAILED.value,
                MailboxStatus.DELETED.value,
            }:
                return False
            if claim_token is not None and row.provision_claim_token != claim_token:
                return False
            refund_event = None
            if refund:
                refund_event = self.refunds.build_owed_event(
                    resource_path="/v1/mail/accounts",
                    payer=row.owner_wallet,
                    amount=Decimal(row.activation_amount_usd or 0),
                    original_tx=row.payment_tx,
                    network=row.payment_network,
                    asset=row.payment_asset,
                    reason="mailbox_provisioning_failed",
                    extra={
                        "mailbox_id": row.mailbox_id,
                        "quote_id": row.quote_id,
                        "domain_order_id": row.domain_order_id,
                    },
                )
                if (
                    row.owner_wallet
                    and Decimal(row.activation_amount_usd or 0) > 0
                    and refund_event is None
                ):
                    log.error(
                        "mailbox_refund_ledger_unavailable",
                        mailbox_id=row.mailbox_id,
                    )
                    return False
                if refund_event is not None:
                    session.add(refund_event)
            row.status = MailboxStatus.REFUND_DUE.value if refund else MailboxStatus.FAILED.value
            row.provision_error = reason[:2000]
            row.capacity_reserved_at = None
            row.provision_claim_token = None
            row.provision_claimed_at = None
            row.provision_next_attempt_at = None
            await session.commit()
        backend_deleted = not row.backend_id
        if row.backend_id:
            try:
                await self.backend.delete_account(row.backend_id)
                backend_deleted = True
            except MailBackendError:
                log.exception(
                    "mailbox_failed_activation_cleanup_failed",
                    mailbox_id=row.mailbox_id,
                    backend_id=row.backend_id,
                )
        dns_cleanup_pending = False
        if row.plan != MailboxMode.HOSTED.value and row.domain:
            try:
                await self.domains.remove_service_records(row.domain, managed_by="agent_mail")
            except Exception:
                log.exception(
                    "mailbox_failed_activation_dns_cleanup_failed",
                    mailbox_id=row.mailbox_id,
                )
                dns_cleanup_pending = True
        if backend_deleted or dns_cleanup_pending:
            async with self.db() as session:
                current = await session.get(MailAccountRow, mailbox_id)
                if current is not None:
                    if backend_deleted:
                        current.backend_id = None
                        current.backend_credential_ciphertext = None
                    if dns_cleanup_pending:
                        current.dns_cleanup_pending = True
                    await session.commit()
        return True

    async def retry_failed_backend_cleanup(self, *, limit: int = 20) -> int:
        """Retry deletion of backend accounts retained by terminal activations."""

        async with self.db() as session:
            rows = list(
                await session.scalars(
                    select(MailAccountRow)
                    .where(
                        MailAccountRow.status.in_(
                            [
                                MailboxStatus.FAILED.value,
                                MailboxStatus.REFUND_DUE.value,
                            ]
                        ),
                        MailAccountRow.backend_id.is_not(None),
                    )
                    .order_by(MailAccountRow.created_at)
                    .limit(limit)
                )
            )
        cleaned = 0
        for row in rows:
            backend_id = str(row.backend_id)
            try:
                await self.backend.delete_account(backend_id)
            except MailBackendError:
                log.exception(
                    "mailbox_failed_activation_cleanup_retry_failed",
                    mailbox_id=row.mailbox_id,
                    backend_id=backend_id,
                )
                continue
            async with self.db() as session:
                current = await session.get(MailAccountRow, row.mailbox_id)
                if (
                    current is not None
                    and current.status
                    in {MailboxStatus.FAILED.value, MailboxStatus.REFUND_DUE.value}
                    and current.backend_id == backend_id
                ):
                    current.backend_id = None
                    current.backend_credential_ciphertext = None
                    await session.commit()
                    cleaned += 1
        return cleaned

    async def _authorized_account(
        self, mailbox_id: str, token: str, *, allow_grace: bool = False
    ) -> MailAccountRow:
        async with self.db() as session:
            row = await session.get(MailAccountRow, mailbox_id)
        if row is None or not self._token_matches(row, token):
            raise MailProblem(404, "mailbox_not_found", "Mailbox not found.")
        if row.status == MailboxStatus.DELETED.value:
            raise MailProblem(410, "mailbox_deleted", "Mailbox data has been deleted.")
        if row.status in {
            MailboxStatus.FAILED.value,
            MailboxStatus.REFUND_DUE.value,
        }:
            raise MailProblem(
                410,
                "mailbox_activation_failed",
                "Mailbox activation failed and backend access is closed.",
            )
        if not allow_grace and row.status == MailboxStatus.GRACE.value:
            raise MailProblem(
                402, "mailbox_expired", "Mailbox send access expired; reads remain in grace."
            )
        return row

    async def _assert_managed_domain_token(self, domain: str, token: str) -> DomainRow:
        async with self.db() as session:
            row = await session.scalar(select(DomainRow).where(DomainRow.fqdn == domain))
        if (
            row is None
            or str(row.status) not in {DomainStatus.ACTIVE.value, DomainStatus.RENEWAL_DUE.value}
            or not row.anon_management_token_hash
            or not secrets.compare_digest(row.anon_management_token_hash, hash_token(token))
        ):
            raise MailProblem(404, "managed_domain_not_found", "Managed domain not found.")
        return row

    @staticmethod
    def _domain_authority_matches(
        row: DomainRow | None,
        expected_hash: str | None,
    ) -> bool:
        return bool(
            row is not None
            and str(row.status) in {DomainStatus.ACTIVE.value, DomainStatus.RENEWAL_DUE.value}
            and expected_hash
            and row.anon_management_token_hash
            and secrets.compare_digest(row.anon_management_token_hash, expected_hash)
        )

    async def _assert_managed_domain_authority(
        self,
        domain: str,
        expected_hash: str,
    ) -> DomainRow:
        async with self.db() as session:
            row = await session.scalar(select(DomainRow).where(DomainRow.fqdn == domain))
        if not self._domain_authority_matches(row, expected_hash):
            raise MailProblem(
                409,
                "managed_domain_authority_changed",
                "The managed-domain capability changed; create a new quote.",
            )
        assert row is not None
        return row

    def _storage_quota_label(self) -> str:
        storage_gib = Decimal(self.mail_config.storage_quota_bytes) / Decimal(1024**3)
        rendered = format(storage_gib.normalize(), "f")
        return f"{rendered} GiB ({self.mail_config.storage_quota_bytes} bytes)"

    async def _resolve_reply_reference(
        self, account: MailAccountRow, message_id: str, recipient: str
    ) -> str:
        async with self.db() as session:
            original = await session.get(
                MailMessageIndexRow,
                (account.mailbox_id, message_id),
            )
        if (
            original is None
            or original.folder != "inbox"
            or (original.sender or "").lower() != recipient.lower()
        ):
            raise MailProblem(
                422,
                "invalid_reply_reference",
                "in_reply_to must name an inbound message from the sole recipient.",
            )
        password = self._decrypt(self._fernet(), account.backend_credential_ciphertext)
        try:
            payload = await self.backend.get_message(
                address=account.address,
                password=password,
                message_id=message_id,
            )
        except MailBackendError as exc:
            raise MailProblem(
                422,
                "invalid_reply_reference",
                "The referenced inbound message is no longer available.",
            ) from exc
        raw_message_ids = payload.get("messageId")
        message_ids = raw_message_ids if isinstance(raw_message_ids, list) else [raw_message_ids]
        reference = next(
            (
                str(value).strip()
                for value in message_ids
                if isinstance(value, str) and value.strip()
            ),
            "",
        )
        if not reference:
            raise MailProblem(
                422,
                "invalid_reply_reference",
                "The referenced message has no RFC Message-ID.",
            )
        return reference

    @staticmethod
    def _message_index_fields(payload: dict[str, Any]) -> dict[str, Any]:
        message_id = str(payload.get("id") or "")
        if not message_id:
            raise MailProblem(502, "mail_message_invalid", "Mailbox returned an invalid message.")

        def addresses(value: Any) -> list[str]:
            if not isinstance(value, list):
                return []
            return [
                str(item.get("email"))
                for item in value
                if isinstance(item, dict) and item.get("email")
            ]

        raw_created_at = payload.get("receivedAt")
        try:
            created_at = datetime.fromisoformat(str(raw_created_at).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            created_at = _now()
        keywords = payload.get("keywords")
        flags = (
            [str(key) for key, enabled in keywords.items() if enabled]
            if isinstance(keywords, dict)
            else []
        )
        senders = addresses(payload.get("from"))
        return {
            "message_id": message_id,
            "folder": str(payload.get("folder") or "other"),
            "sender": senders[0] if senders else None,
            "recipients": addresses(payload.get("to")),
            "subject": str(payload.get("subject")) if payload.get("subject") is not None else None,
            "flags": flags,
            "has_attachments": bool(payload.get("attachments")),
            "created_at": created_at,
        }

    def _assert_sendable(self, row: MailAccountRow) -> None:
        if row.status == MailboxStatus.SUSPENDED.value:
            raise MailProblem(403, "mailbox_suspended", "Mailbox outbound access is suspended.")
        expires_at = _aware(row.expires_at)
        if row.status != MailboxStatus.ACTIVE.value or (expires_at is None or expires_at <= _now()):
            raise MailProblem(409, "mailbox_not_active", "Mailbox is not active for outbound mail.")

    @staticmethod
    def _token_matches(row: MailAccountRow, token: str) -> bool:
        return bool(
            token
            and row.management_token_hash
            and secrets.compare_digest(row.management_token_hash, hash_token(token))
        )

    @staticmethod
    def _decrypt(fernet: Fernet, ciphertext: str | None) -> str:
        try:
            return fernet.decrypt(str(ciphertext).encode()).decode()
        except (InvalidToken, AttributeError) as exc:
            raise MailProblem(
                503, "mail_secret_unavailable", "A mailbox secret cannot be recovered."
            ) from exc

    def _quote_response(self, row: MailQuoteRow) -> MailQuoteResponse:
        payload = dict(row.request_payload)
        if row.kind == "activation":
            mode = MailboxMode(payload["mode"])
            activation_amount = Decimal(str(payload["activation_amount_usd"]))
            domain_amount = Decimal(row.amount_usd) - activation_amount
            path = "/v1/mail/accounts"
            outbound_amount = Decimal("0")
            address = str(row.address)
        else:
            mode = None
            domain_amount = Decimal("0")
            path = "/v1/mail/messages/send"
            activation_amount = Decimal("0")
            outbound_amount = Decimal(row.amount_usd)
            address = str(row.address)
        return MailQuoteResponse(
            quote_id=row.quote_id,
            kind=row.kind,
            address=address,
            mode=mode,
            amount_usd=amount(Decimal(row.amount_usd)),
            domain_amount_usd=amount(domain_amount),
            activation_amount_usd=amount(activation_amount),
            outbound_amount_usd=amount(outbound_amount),
            terms_version=row.terms_version,
            expires_at=row.expires_at,
            payable_path=path,
            constraints=(
                ["one recipient", "no CC/BCC", "no outbound attachments"]
                if row.kind == "send"
                else [
                    f"{self.mail_config.active_days} days",
                    self._storage_quota_label(),
                    "no auto-renew",
                ]
            ),
        )

    def _account_response(
        self, row: MailAccountRow, *, management_token: str | None = None
    ) -> MailAccountResponse:
        return MailAccountResponse(
            mailbox_id=row.mailbox_id,
            address=row.address,
            mode=MailboxMode(row.plan),
            status=MailboxStatus(row.status),
            management_token=management_token,
            status_url=f"/v1/mail/accounts/{row.mailbox_id}",
            messages_url=f"/v1/mail/accounts/{row.mailbox_id}/messages",
            send_quote_url="/v1/mail/messages/send/quote",
            domain_order_id=row.domain_order_id,
            domain_status_url=(
                f"/v1/domains/agent/orders/{row.domain_order_id}" if row.domain_order_id else None
            ),
            active_until=row.expires_at,
            grace_ends_at=row.grace_ends_at,
            charged_amount_usd=amount(
                Decimal(row.total_amount_usd or row.activation_amount_usd or 0)
            ),
            error=row.provision_error,
        )

    def _send_response(self, row: MailSendRow) -> MailSendResponse:
        return MailSendResponse(
            send_id=row.send_id,
            mailbox_id=row.mailbox_id,
            message_id=row.message_id,
            status=row.status,
            recipient=row.recipient,
            accepted_at=row.accepted_at,
            charged_amount_usd=amount(Decimal(row.amount_usd)),
        )

    @staticmethod
    def _webhook_response(
        row: MailWebhookRow, *, signing_secret: str | None = None
    ) -> MailWebhookResponse:
        return MailWebhookResponse(
            webhook_id=row.webhook_id,
            url=row.url,
            events=list(row.events or []),
            status=row.status,
            signing_secret=signing_secret,
            created_at=row.created_at,
        )

    @staticmethod
    def _public_event_type(value: str) -> str:
        lower = value.lower()
        if lower == "store.ingest" or lower in {
            "message-ingest.ham",
            "message-ingest.spam",
        }:
            return "message.received"
        if any(
            token in lower
            for token in (
                "complaint",
                "abuse-report",
                "fraud-report",
                "malware",
                "virus-report",
            )
        ):
            return "mailbox.suspended"
        if any(token in lower for token in ("delivery", "dsn", "bounce")):
            return "message.delivery"
        return "mail.system"

    @staticmethod
    def _suspension_reason(value: str, data: dict[str, Any]) -> str | None:
        lower = f"{value} {data.get('status', '')} {data.get('reason', '')}".lower()
        if "complaint" in lower or "abuse-report" in lower:
            return "recipient_complaint"
        if "malware" in lower or "virus" in lower:
            return "malware_detected"
        if "fraud-report" in lower:
            return "fraud_report"
        return None

    @staticmethod
    def _event_addresses(data: dict[str, Any]) -> list[str]:
        raw_values: list[str] = []

        def collect(value: Any) -> None:
            if isinstance(value, str):
                raw_values.append(value)
            elif isinstance(value, dict):
                collect(value.get("email") or value.get("address"))
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        for key in ("address", "recipient", "from", "sender", "to"):
            collect(data.get(key))
        addresses: list[str] = []
        for _name, address in getaddresses(raw_values):
            normalized = address.strip().lower()
            if "@" in normalized and normalized not in addresses:
                addresses.append(normalized)
        return addresses

    @classmethod
    def _directional_event_addresses(cls, event_type: str, data: dict[str, Any]) -> list[str]:
        lower = event_type.lower()
        keys: tuple[str, ...]
        if lower == "store.ingest" or lower in {
            "message-ingest.ham",
            "message-ingest.spam",
        }:
            keys = ("recipient", "to", "address")
        elif lower in {
            "message-ingest.imap-append",
            "message-ingest.jmap-append",
        }:
            # Appends are not directional. They must carry the backend account id.
            return []
        elif any(
            token in lower
            for token in (
                "delivery",
                "dsn",
                "bounce",
                "complaint",
                "abuse-report",
                "fraud-report",
                "malware",
                "virus-report",
            )
        ):
            keys = ("from", "sender", "address")
        else:
            keys = ("address",)
        return cls._event_addresses({key: data.get(key) for key in keys})

    async def _post_pinned(
        self, url: str, address: str, body: bytes, signature: str, event_id: str
    ) -> None:
        parsed = urlsplit(url)
        host = str(parsed.hostname)
        literal = f"[{address}]" if ":" in address else address
        pinned = urlunsplit(("https", literal, parsed.path or "/", parsed.query, ""))
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(
                pinned,
                content=body,
                headers={
                    "Host": host,
                    "Content-Type": "application/json",
                    "X-Hyrule-Event-Id": event_id,
                    "X-Hyrule-Signature": f"sha256={signature}",
                },
                extensions={"sni_hostname": host.encode()},
            )
            response.raise_for_status()

    async def _set_delivery(
        self, delivery_id: str, status: str, error: str | None, attempts: int | None = None
    ) -> None:
        async with self.db() as session:
            row = await session.get(MailWebhookDeliveryRow, delivery_id)
            if row is not None:
                row.status = status
                row.last_error = error[:1000] if error else None
                if attempts is not None:
                    row.attempt_count = attempts
                if status == "delivered":
                    row.delivered_at = _now()
                await session.commit()
