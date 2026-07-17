"""Block E: crypto-intent service — create + poll + provision.

Holds the LENIENT off-amount policy (overpay → provision; late-paid →
re-quote and provision if within 1% slippage; underpay → operator review)
and the atomic exactly-once provisioning trigger.

Architecture:
  create_intent()       — called from POST /v1/intent/create
  poll_one_intent()     — called repeatedly by the background poller
  scan_pending_intents()— iterates all CREATED/WAITING_PAYMENT/LATE_PAID rows

The orchestrator's create_vm() does the heavy lifting once the policy
decides to provision.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import structlog
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from hyrule_cloud.db import CryptoIntentRow, DomainOrderRow
from hyrule_cloud.models import (
    CryptoIntentStatus,
    DomainMode,
    QuoteStatus,
    VMCreateRequest,
    generate_vm_id,
)
from hyrule_cloud.providers.native_crypto import AddressScanResult, NativeCryptoProvider
from hyrule_cloud.providers.rates import RateProvider
from hyrule_cloud.services.quotes import (
    claim_quote,
    get_quote,
    is_expired,
    link_quote_vm,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from hyrule_cloud.orchestrator import Orchestrator

log = structlog.get_logger()

# Intent expires after this if no payment is seen.
INTENT_TTL = timedelta(minutes=60)
# Rate snapshot lock. After this, payment is LATE_PAID and triggers re-quote.
RATE_VALID_TTL = timedelta(minutes=15)
# LENIENT late-paid slippage tolerance: if current rate yields an amount
# within ±1% of what was received, re-quote and provision anyway.
LATE_PAID_SLIPPAGE = Decimal("0.01")
# BTC confirmations to consider SETTLED.
BTC_MIN_CONFIRMATIONS = 1
# XMR confirmations to consider SETTLED.
XMR_MIN_CONFIRMATIONS = 10
# Payments must match the quote within this tolerance to count as on-the-nose.
EXACT_AMOUNT_TOLERANCE = Decimal("0.001")  # 0.1%


def _now() -> datetime:
    return datetime.now(UTC)


async def get_intent_by_client_order_id(
    session_factory: async_sessionmaker,
    client_order_id: str,
) -> CryptoIntentRow | None:
    """Idempotency lookup for POST /v1/intent/create replays."""
    async with session_factory() as db:
        result = await db.execute(
            select(CryptoIntentRow).where(CryptoIntentRow.client_order_id == client_order_id)
        )
        return result.scalar_one_or_none()


class IntentExistsError(Exception):
    """Returned for repeated POSTs with the same client_order_id (idempotency)."""

    def __init__(self, existing: CryptoIntentRow) -> None:
        super().__init__(f"intent already exists: {existing.intent_id}")
        self.existing = existing


async def create_intent(
    *,
    session_factory: async_sessionmaker,
    provider: NativeCryptoProvider,
    rates: RateProvider,
    asset: str,
    order_payload: BaseModel | dict[str, Any],
    amount_usd: Decimal,
    client_order_id: str | None,
    owner_account_id: str | None,
    expires_at: datetime | None = None,
    resource_type: str = "vm",
    resource_id: str | None = None,
    refund_address: str | None = None,
    planned_vm_id: str | None = None,
    pricing_snapshot: dict[str, Any] | None = None,
) -> CryptoIntentRow:
    """Insert a fresh CryptoIntentRow and derive a receive address for it.

    Idempotent on `client_order_id`: a duplicate POST returns the existing
    intent unchanged (caller can detect via IntentExistsError).
    """
    asset = asset.upper()
    if asset not in ("BTC", "XMR"):
        raise ValueError("asset must be BTC or XMR")

    # Idempotency check before allocating an address.
    if client_order_id:
        async with session_factory() as db:
            existing = await db.execute(
                select(CryptoIntentRow).where(CryptoIntentRow.client_order_id == client_order_id)
            )
            row = existing.scalar_one_or_none()
            if row is not None:
                raise IntentExistsError(row)

    rate = await rates.get_usd_per(asset)
    amount_crypto = (amount_usd / rate).quantize(Decimal("0.000000000001"))
    now = _now()
    intent_expires_at = now + INTENT_TTL
    if expires_at is not None:
        quote_expires_at = expires_at
        if quote_expires_at.tzinfo is None:
            quote_expires_at = quote_expires_at.replace(tzinfo=UTC)
        else:
            quote_expires_at = quote_expires_at.astimezone(UTC)
        intent_expires_at = min(intent_expires_at, quote_expires_at)
    intent_id = str(uuid.uuid4())

    async with session_factory() as db:
        bip32_index: int | None = None
        xmr_subaddr_index: int | None = None
        if asset == "BTC":
            res = await db.execute(
                select(func.max(CryptoIntentRow.bip32_index)).where(CryptoIntentRow.asset == "BTC")
            )
            max_idx = res.scalar() or 0
            bip32_index = max_idx + 1
            address = provider.derive_btc_address(bip32_index)
        else:  # XMR
            label = f"hyr-intent-{intent_id[:8]}"
            address, xmr_subaddr_index = await provider.create_xmr_subaddress(label=label)

        row = CryptoIntentRow(
            intent_id=intent_id,
            asset=asset,
            amount_usd=amount_usd,
            amount_crypto=amount_crypto,
            rate_snapshot=rate,
            rate_valid_until=min(now + RATE_VALID_TTL, intent_expires_at),
            address=address,
            bip32_index=bip32_index,
            xmr_subaddr_index=xmr_subaddr_index,
            expires_at=intent_expires_at,
            status=CryptoIntentStatus.CREATED,
            client_order_id=client_order_id,
            order_payload=(
                order_payload.model_dump(mode="json")
                if isinstance(order_payload, BaseModel)
                else order_payload
            ),
            pricing_snapshot=pricing_snapshot,
            owner_account_id=owner_account_id,
            resource_type=resource_type,
            resource_id=resource_id,
            refund_address=refund_address,
            vm_id=planned_vm_id,
        )
        db.add(row)
        try:
            await db.commit()
        except IntegrityError as exc:
            # Lost a concurrent race on the unique client_order_id index — the
            # pre-insert SELECT above is best-effort; the DB constraint is the
            # real guard. Return the winner's intent instead of a duplicate.
            await db.rollback()
            if client_order_id:
                existing = await db.execute(
                    select(CryptoIntentRow).where(
                        CryptoIntentRow.client_order_id == client_order_id
                    )
                )
                won = existing.scalar_one_or_none()
                if won is not None:
                    raise IntentExistsError(won) from exc
            raise
        await db.refresh(row)
        return row


def _within_tolerance(actual: Decimal, target: Decimal, tolerance: Decimal) -> bool:
    """True if |actual - target| / target <= tolerance."""
    if target == 0:
        return actual == 0
    return abs(actual - target) / target <= tolerance


async def poll_one_intent(
    *,
    intent_id: str,
    session_factory: async_sessionmaker,
    provider: NativeCryptoProvider,
    rates: RateProvider,
    orch: Orchestrator,
) -> CryptoIntentRow | None:
    """Scan a single intent's address and advance its state per LENIENT policy.

    Returns the (possibly updated) row, or None if the intent vanished.
    """
    async with session_factory() as db:
        row = await db.get(CryptoIntentRow, intent_id)
        if row is None:
            return None
        # Terminal states never re-process.
        if row.status in (
            CryptoIntentStatus.PROVISIONED,
            CryptoIntentStatus.PROVISIONING,
            CryptoIntentStatus.REFUND_MANUAL,
            CryptoIntentStatus.FAILED,
            CryptoIntentStatus.EXPIRED,
        ):
            return row

    # Scan on-chain. Held outside the DB session because Esplora/RPC can take a while.
    try:
        if row.asset == "BTC":
            scan = await provider.scan_btc_address(row.address)
            min_confs = BTC_MIN_CONFIRMATIONS
        else:
            scan = await provider.scan_xmr_subaddress(row.xmr_subaddr_index or 0)
            min_confs = XMR_MIN_CONFIRMATIONS
    except Exception:
        log.exception("intent_scan_failed", intent_id=intent_id, asset=row.asset)
        return row

    # Apply LENIENT policy and persist.
    async with session_factory() as db:
        row = await db.get(CryptoIntentRow, intent_id)
        if row is None:
            return None
        # A concurrent poll may have completed while this network scan was in
        # flight. Never overwrite its terminal transition.
        if row.status in (
            CryptoIntentStatus.PROVISIONED,
            CryptoIntentStatus.PROVISIONING,
            CryptoIntentStatus.REFUND_MANUAL,
            CryptoIntentStatus.FAILED,
            CryptoIntentStatus.EXPIRED,
        ):
            return row
        row.last_scanned_at = _now()
        row.confirmations = scan.confirmations
        row.amount_received_crypto = scan.received_total
        if scan.tx_hash and not row.tx_hash:
            row.tx_hash = scan.tx_hash

        # Expiry means "no payment was observed before the address window
        # closed", so it must be decided from the fresh chain scan. Checking
        # the stale DB amount first can permanently discard a deposit that was
        # sent near expiry and still needs provisioning or an explicit refund.
        expires_at = row.expires_at
        if expires_at is not None:
            expires_at = expires_at.replace(tzinfo=expires_at.tzinfo or UTC)
        if expires_at is not None and expires_at < _now() and scan.received_total == 0:
            row.status = CryptoIntentStatus.EXPIRED
            await db.commit()
            await db.refresh(row)
            return row

        new_status = _decide_status(
            row=row,
            scan=scan,
            min_confs=min_confs,
            current_rate=await _maybe_requote(row, rates),
        )
        row.status = new_status
        if new_status == CryptoIntentStatus.SETTLED and not row.paid_at:
            row.paid_at = _now()
        await db.commit()
        await db.refresh(row)

    # SETTLED → trigger atomic provisioning. Exactly-once via UPDATE...RETURNING.
    if row.status == CryptoIntentStatus.SETTLED:
        await _trigger_provisioning(intent_id=intent_id, session_factory=session_factory, orch=orch)
        # Re-fetch terminal state after provisioning
        async with session_factory() as db:
            row = await db.get(CryptoIntentRow, intent_id) or row
    return row


async def _maybe_requote(row: CryptoIntentRow, rates: RateProvider) -> Decimal | None:
    """If we're past rate_valid_until, fetch a fresh rate. Else return None."""
    if row.rate_valid_until is None:
        return None
    if row.rate_valid_until.replace(tzinfo=row.rate_valid_until.tzinfo or UTC) >= _now():
        return None
    try:
        return await rates.get_usd_per(row.asset)  # type: ignore[arg-type]
    except Exception:
        log.warning("requote_failed", intent_id=row.intent_id)
        return None


def _decide_status(
    *,
    row: CryptoIntentRow,
    scan: AddressScanResult,
    min_confs: int,
    current_rate: Decimal | None,
) -> CryptoIntentStatus:
    """LENIENT policy decision table:

    no payment yet                           → WAITING_PAYMENT
    paid but below min confs                 → keep current (WAITING_PAYMENT)
    paid >= quote (within slip) + confirmed  → SETTLED (advances)
    paid > quote (overpay) + confirmed       → SETTLED (overpay → still provisions)
    paid < quote (underpay) + confirmed      → REFUND_MANUAL (manual)
    paid after rate snapshot expired:
      - amount matches fresh quote ±1%       → SETTLED (auto re-quote)
      - amount drifted > 1%                  → REFUND_MANUAL
    """
    received = scan.received_total
    if received == 0:
        return CryptoIntentStatus.WAITING_PAYMENT

    if scan.confirmations < min_confs:
        # Money seen but not yet confirmed enough — mark waiting.
        return CryptoIntentStatus.WAITING_PAYMENT

    target = row.amount_crypto
    if current_rate is not None and row.amount_usd is not None:
        # Late-paid path: compare against the FRESH amount.
        fresh_target = (row.amount_usd / current_rate).quantize(Decimal("0.000000000001"))
        if _within_tolerance(received, fresh_target, LATE_PAID_SLIPPAGE):
            return CryptoIntentStatus.SETTLED
        # Rate moved against the customer beyond slippage.
        return CryptoIntentStatus.REFUND_MANUAL

    # In-window: lenient comparison
    if received >= target * (Decimal("1") - EXACT_AMOUNT_TOLERANCE):
        # Includes exact + overpay
        return CryptoIntentStatus.SETTLED
    return CryptoIntentStatus.REFUND_MANUAL


async def _trigger_provisioning(
    *,
    intent_id: str,
    session_factory: async_sessionmaker,
    orch: Orchestrator,
) -> None:
    """Atomic single-shot provisioning trigger.

    The UPDATE ... WHERE provisioning_triggered_at IS NULL RETURNING
    ensures exactly one caller observes the transition CREATED→PROVISIONING.
    """
    async with session_factory() as db:
        result = await db.execute(
            update(CryptoIntentRow)
            .where(
                CryptoIntentRow.intent_id == intent_id,
                CryptoIntentRow.provisioning_triggered_at.is_(None),
            )
            .values(
                provisioning_triggered_at=_now(),
                status=CryptoIntentStatus.PROVISIONING,
            )
            .returning(CryptoIntentRow.intent_id)
        )
        won = result.scalar_one_or_none()
        if won is None:
            return  # another worker already triggered
        await db.commit()
        row = await db.get(CryptoIntentRow, intent_id)
        if row is None or row.order_payload is None:
            return

    # Domain purchases reuse the native receive-address and confirmation
    # machinery, but have their own fulfillment outbox. Handing a settled
    # intent to that outbox is the exactly-once side effect for this resource;
    # it must never be parsed as a VMCreateRequest.
    if row.resource_type == "domain_order":
        domains = getattr(orch, "domains", None)
        if domains is None or not row.resource_id:
            await orch.record_native_intent_refund(
                intent_id,
                reason="domain_fulfillment_unavailable",
            )
            return
        try:
            domain_order = await domains.native_order_settled(row.resource_id, row)
            terminal_status = (
                CryptoIntentStatus.REFUND_MANUAL
                if str(domain_order.status) in {"refund_due", "refunded"}
                else CryptoIntentStatus.PROVISIONED
            )
            async with session_factory() as db:
                current = await db.get(CryptoIntentRow, intent_id)
                if current is not None:
                    current.status = terminal_status
                    await db.commit()
            log.info(
                "native_domain_order_handed_off",
                intent_id=intent_id,
                order_id=row.resource_id,
            )
        except Exception:
            log.exception(
                "native_domain_order_handoff_failed",
                intent_id=intent_id,
                order_id=row.resource_id,
            )
            # The order commit can succeed even if the response/connection is
            # lost. Re-read its durable state before recording a refund, or a
            # queued registration could later fulfill after we refunded it.
            handed_off = False
            async with session_factory() as db:
                domain_order = await db.get(DomainOrderRow, row.resource_id)
                handed_off = domain_order is not None and str(domain_order.status) != "awaiting_payment"
                if handed_off:
                    current = await db.get(CryptoIntentRow, intent_id)
                    if current is not None:
                        current.status = (
                            CryptoIntentStatus.REFUND_MANUAL
                            if str(domain_order.status) in {"refund_due", "refunded"}
                            else CryptoIntentStatus.PROVISIONED
                        )
                        await db.commit()
            if not handed_off:
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="domain_fulfillment_handoff_failed",
                )
        return

    # Provision the VM. owner_wallet carries the bounded intent_id, NOT the
    # deposit address: XMR subaddresses (~95 chars) overflow VMRow.owner_wallet
    # (String(64)) and the insert would fail before the intent is linked or any
    # refund could be recorded. The refund path finds the intent by vm_id and
    # reads the real deposit address from it.
    vm_row = None
    reservation_row = None
    planned_vm_id: str | None = None
    claimed_domain = False
    domains = getattr(orch, "domains", None)
    try:
        order = VMCreateRequest.model_validate(row.order_payload)
        quote_id = order.quote_id
        if quote_id is not None:
            quote = await get_quote(session_factory, quote_id)
            if quote is None:
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="quote_missing_at_settlement",
                )
                return
            if QuoteStatus(quote.status) == QuoteStatus.CONSUMED:
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="quote_already_consumed",
                )
                return
            if is_expired(quote):
                # A native deposit can confirm long after its address was
                # issued. Never consume a stale locked price at settlement.
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="quote_expired_at_settlement",
                )
                return
            # Route checks protect new HTTP-created intents, but settlement is
            # the irreversible trust boundary. Revalidate the complete durable
            # quote binding for legacy rows and internal create_intent callers
            # before consuming somebody else's quote or a changed price/spec.
            expected_payload = order.model_dump(mode="json", exclude={"quote_id"})
            if (
                (
                    quote.owner_account_id is not None
                    and quote.owner_account_id != row.owner_account_id
                )
                or quote.order_payload != expected_payload
                or row.amount_usd is None
                or row.amount_usd != quote.amount_usd
            ):
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="quote_binding_mismatch_at_settlement",
                )
                return
            if not await claim_quote(session_factory, quote_id):
                # Another EVM/native payment won after the read above. Funds are
                # settled, so fail closed to an explicit refund instead of
                # creating a second VM from the same locked order.
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="quote_already_consumed",
                )
                return
        if order.domain_mode == DomainMode.CUSTOM:
            if domains is None or row.owner_account_id is None or not order.domain:
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="custom_domain_unavailable_at_settlement",
                )
                return

        # Settlement admission must use the same serialized check+reservation
        # boundary as EVM checkout. A standalone ensure_vm_capacity() followed
        # by create_vm() lets two separately paid native intents both pass the
        # check before either row becomes visible to the other.
        planned_vm_id = row.vm_id or generate_vm_id()
        try:
            reservation_row, anon_token = await orch.reserve_vm_with_capacity(
                order,
                owner_account_id=row.owner_account_id,
                vm_id=planned_vm_id,
                pricing_snapshot=row.pricing_snapshot,
                legacy_billing=row.pricing_snapshot is None,
            )
        except RuntimeError:
            log.warning(
                "native_vm_capacity_unavailable_at_settlement",
                intent_id=intent_id,
                exc_info=True,
            )
            await orch.record_native_intent_refund(
                intent_id,
                reason="vm_capacity_unavailable_at_settlement",
                vm_id=planned_vm_id,
            )
            return

        if order.domain_mode == DomainMode.CUSTOM:
            # The route-level check happened when the deposit address was
            # issued, potentially many confirmations ago. Settlement is the
            # irreversible trust boundary: claim the domain for the exact VM
            # reservation or refund and release that reservation.
            try:
                await domains.claim_vm_attachment(
                    row.owner_account_id,
                    order.domain,
                    planned_vm_id,
                )
            except Exception:
                log.warning(
                    "native_custom_domain_claim_failed",
                    intent_id=intent_id,
                    domain=order.domain,
                    vm_id=planned_vm_id,
                    exc_info=True,
                )
                try:
                    await orch.release_vm_reservation(planned_vm_id)
                except Exception:
                    log.exception(
                        "native_vm_reservation_release_failed",
                        intent_id=intent_id,
                        vm_id=planned_vm_id,
                    )
                await orch.record_native_intent_refund(
                    intent_id,
                    reason="custom_domain_unavailable_at_settlement",
                    vm_id=planned_vm_id,
                )
                return
            claimed_domain = True

        # Convert the unpaid reservation into a paid VM but DON'T start
        # provisioning yet: link the intent first, so an immediate XO/API
        # failure can always find the paying record and issue a refund.
        vm_row = await orch.activate_vm_reservation(
            reservation_row.vm_id,
            row.intent_id,
            start_provisioning=False,
        )
        if vm_row is None:
            raise RuntimeError("native VM reservation disappeared before activation")
        if row.amount_usd is not None:
            amount_persisted = False
            for attempt in range(3):
                try:
                    await orch.persist_charged_amount(vm_row.vm_id, row.amount_usd)
                    amount_persisted = True
                    break
                except Exception:
                    log.warning(
                        "native_charged_amount_attempt_failed",
                        intent_id=intent_id,
                        vm_id=vm_row.vm_id,
                        attempt=attempt,
                        exc_info=True,
                    )
                    if attempt < 2:
                        await asyncio.sleep(0.1 * (attempt + 1))
            if not amount_persisted:
                # The intent itself retains the settled USD/crypto amounts,
                # so a later native refund remains accurate. Do not fail a
                # paid, provisionable VM over this denormalized copy.
                log.error(
                    "native_charged_amount_failed_post_settlement",
                    intent_id=intent_id,
                    vm_id=vm_row.vm_id,
                )
        if quote_id is not None:
            linked = False
            for attempt in range(3):
                try:
                    await link_quote_vm(session_factory, quote_id, vm_row.vm_id)
                    linked = True
                    break
                except Exception:
                    log.warning(
                        "native_quote_link_attempt_failed",
                        intent_id=intent_id,
                        vm_id=vm_row.vm_id,
                        quote_id=quote_id,
                        attempt=attempt,
                        exc_info=True,
                    )
                    if attempt < 2:
                        await asyncio.sleep(0.1 * (attempt + 1))
            if not linked:
                # The intent-to-VM link below remains the authoritative native
                # recovery path, so provisioning is safer than refunding a
                # working paid VM solely because quote bookkeeping is down.
                log.error(
                    "native_quote_link_failed_post_settlement",
                    intent_id=intent_id,
                    vm_id=vm_row.vm_id,
                    quote_id=quote_id,
                )
        async with session_factory() as db:
            r = await db.get(CryptoIntentRow, intent_id)
            if r is None:
                raise RuntimeError("native intent disappeared before VM linkage")
            r.vm_id = vm_row.vm_id
            r.status = CryptoIntentStatus.PROVISIONED
            # One-shot reveal: the next successful GET /v1/intent/{id} returns
            # this cleartext and immediately nulls the column. Sha256 is on VMRow.
            r.anon_token_cleartext = anon_token
            await db.commit()
        # The intent↔vm link is committed; now it is safe to provision.
        orch.start_provisioning(vm_row.vm_id)
        log.info("intent_provisioned", intent_id=intent_id, vm_id=vm_row.vm_id)
    except Exception:
        log.exception("intent_provisioning_failed", intent_id=intent_id)
        # Funds are already SETTLED. If create_vm raised before a vm_id was
        # linked (capacity exhausted, DB insert failure, unsupported old order),
        # _provision_vm never runs, so record the refund obligation here — a paid
        # native customer must never be left without a refund_owed row. Fall back
        # to marking the intent FAILED only if recording the refund itself errors.
        try:
            await orch.record_native_intent_refund(
                intent_id,
                reason="provisioning_failed",
                vm_id=planned_vm_id,
            )
        except Exception:
            log.exception("native_refund_record_failed", intent_id=intent_id)
            async with session_factory() as db:
                await db.execute(
                    update(CryptoIntentRow)
                    .where(CryptoIntentRow.intent_id == intent_id)
                    .values(status=CryptoIntentStatus.FAILED)
                )
                await db.commit()
        if reservation_row is not None and planned_vm_id is not None:
            # If activation did not commit, release the unpaid reservation. If
            # it did commit, release is intentionally a no-op and mark_vm_failed
            # terminally cleans the paid row instead.
            try:
                await orch.release_vm_reservation(planned_vm_id)
            except Exception:
                log.exception(
                    "native_vm_reservation_release_failed",
                    intent_id=intent_id,
                    vm_id=planned_vm_id,
                )
            try:
                await orch.mark_vm_failed(
                    planned_vm_id,
                    "native provisioning failed post-settlement",
                )
            except Exception:
                log.exception(
                    "native_failed_vm_cleanup_failed",
                    intent_id=intent_id,
                    vm_id=planned_vm_id,
                )
        if claimed_domain and domains is not None and planned_vm_id is not None:
            # Real Orchestrator.mark_vm_failed() already performs this release,
            # but keep it explicit and idempotent for failures before insertion
            # and for alternative orchestrator implementations.
            try:
                await domains.release_vm_attachment_claim(planned_vm_id)
            except Exception:
                log.exception(
                    "native_custom_domain_claim_release_failed",
                    intent_id=intent_id,
                    vm_id=planned_vm_id,
                )


async def scan_pending_intents(
    *,
    session_factory: async_sessionmaker,
    provider: NativeCryptoProvider,
    rates: RateProvider,
    orch: Orchestrator,
) -> int:
    """One polling pass. Returns the number of intents touched."""
    async with session_factory() as db:
        result = await db.execute(
            select(CryptoIntentRow.intent_id).where(
                CryptoIntentRow.status.in_(
                    (
                        # LATE_PAID is a reserved enum value but never a resting
                        # state: the late-paid decision collapses inline to
                        # SETTLED (re-quote within slippage) or REFUND_MANUAL in
                        # _decide_status, so no row is ever stored as LATE_PAID.
                        CryptoIntentStatus.CREATED,
                        CryptoIntentStatus.WAITING_PAYMENT,
                    )
                )
            )
        )
        intent_ids = [r[0] for r in result.all()]
        domain_handoffs = list(
            await db.scalars(
                select(CryptoIntentRow.intent_id).where(
                    CryptoIntentRow.status == CryptoIntentStatus.PROVISIONING,
                    CryptoIntentRow.resource_type == "domain_order",
                )
            )
        )

    touched = 0
    for iid in domain_handoffs:
        if await _resume_domain_handoff(
            intent_id=iid,
            session_factory=session_factory,
            orch=orch,
        ):
            touched += 1
    for iid in intent_ids:
        try:
            await poll_one_intent(
                intent_id=iid,
                session_factory=session_factory,
                provider=provider,
                rates=rates,
                orch=orch,
            )
            touched += 1
        except Exception:
            log.exception("poll_one_intent_failed", intent_id=iid)
    return touched


async def _resume_domain_handoff(
    *,
    intent_id: str,
    session_factory: async_sessionmaker,
    orch: Orchestrator,
) -> bool:
    """Recover a settled domain payment after a worker/process crash."""
    domains = getattr(orch, "domains", None)
    if domains is None:
        return False
    async with session_factory() as db:
        intent = await db.get(CryptoIntentRow, intent_id)
        if (
            intent is None
            or intent.status != CryptoIntentStatus.PROVISIONING
            or intent.resource_type != "domain_order"
            or not intent.resource_id
        ):
            return False
    try:
        order = await domains.native_order_settled(intent.resource_id, intent)
    except Exception:
        log.exception(
            "native_domain_order_handoff_recovery_failed",
            intent_id=intent_id,
            order_id=intent.resource_id,
        )
        return False
    async with session_factory() as db:
        current = await db.get(CryptoIntentRow, intent_id)
        if current is not None and current.status == CryptoIntentStatus.PROVISIONING:
            current.status = (
                CryptoIntentStatus.REFUND_MANUAL
                if str(order.status) in {"refund_due", "refunded"}
                else CryptoIntentStatus.PROVISIONED
            )
            await db.commit()
    log.info(
        "native_domain_order_handoff_recovered",
        intent_id=intent_id,
        order_id=intent.resource_id,
    )
    return True
