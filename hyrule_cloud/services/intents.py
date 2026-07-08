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

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from hyrule_cloud.db import CryptoIntentRow
from hyrule_cloud.models import (
    CryptoIntentStatus,
    VMCreateRequest,
)
from hyrule_cloud.providers.native_crypto import AddressScanResult, NativeCryptoProvider
from hyrule_cloud.providers.rates import RateProvider

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
    order_payload: VMCreateRequest,
    amount_usd: Decimal,
    client_order_id: str | None,
    owner_account_id: str | None,
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
            rate_valid_until=now + RATE_VALID_TTL,
            address=address,
            bip32_index=bip32_index,
            xmr_subaddr_index=xmr_subaddr_index,
            expires_at=now + INTENT_TTL,
            status=CryptoIntentStatus.CREATED,
            client_order_id=client_order_id,
            order_payload=order_payload.model_dump(mode="json"),
            owner_account_id=owner_account_id,
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

        now = _now()
        # Expiry check first — no payment ever arrived.
        if row.expires_at and row.expires_at.replace(tzinfo=row.expires_at.tzinfo or UTC) < now:
            # Only expire if nothing has been received yet
            if not row.amount_received_crypto or row.amount_received_crypto == 0:
                row.status = CryptoIntentStatus.EXPIRED
                await db.commit()
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
        row.last_scanned_at = _now()
        row.confirmations = scan.confirmations
        row.amount_received_crypto = scan.received_total
        if scan.tx_hash and not row.tx_hash:
            row.tx_hash = scan.tx_hash

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
        await _trigger_provisioning(
            intent_id=intent_id, session_factory=session_factory, orch=orch
        )
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

    # Provision the VM. The wallet address is the deposit address (informational).
    try:
        order = VMCreateRequest.model_validate(row.order_payload)
        vm_row, anon_token = await orch.create_vm(
            order,
            owner_wallet=row.address,
            owner_account_id=row.owner_account_id,
        )
        async with session_factory() as db:
            r = await db.get(CryptoIntentRow, intent_id)
            if r is None:
                return
            r.vm_id = vm_row.vm_id
            r.status = CryptoIntentStatus.PROVISIONED
            # One-shot reveal: the next successful GET /v1/intent/{id} returns
            # this cleartext and immediately nulls the column. Sha256 is on VMRow.
            r.anon_token_cleartext = anon_token
            await db.commit()
        log.info("intent_provisioned", intent_id=intent_id, vm_id=vm_row.vm_id)
    except Exception:
        log.exception("intent_provisioning_failed", intent_id=intent_id)
        async with session_factory() as db:
            await db.execute(
                update(CryptoIntentRow)
                .where(CryptoIntentRow.intent_id == intent_id)
                .values(status=CryptoIntentStatus.FAILED)
            )
            await db.commit()


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

    touched = 0
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
