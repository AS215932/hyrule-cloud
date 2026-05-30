"""Durable VM order quotes (issue #14).

A quote is the single order object the UI and agents pay against: it carries the
full VM spec (`order_payload`), a price locked at creation, and a TTL. The review
page restores it by `quote_id` so the order survives reloads / mobile wallet
handoffs, and POST /v1/vm/create consumes it at the locked price.

Mirrors services/intents.py: idempotency on `client_order_id` (pre-insert SELECT
plus a unique-index IntegrityError fallback) with the order payload stored as
JSON. Difference from intents: a duplicate key with the SAME spec is an
idempotent return (QuoteExistsError); a duplicate key with a DIFFERENT spec is a
conflict (QuoteConflictError → 409), so a client can't silently rebind a key.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select
from sqlalchemy import update as _sql_update
from sqlalchemy.exc import IntegrityError

from hyrule_cloud.db import VMQuoteRow
from hyrule_cloud.models import QuoteStatus, VMCreateRequest, generate_quote_id

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker

log = structlog.get_logger()

# A quote's price is locked for this long; after it the quote is EXPIRED and a
# fresh one must be created. Matches the intent-engine TTL.
QUOTE_TTL = timedelta(minutes=60)


def _now() -> datetime:
    return datetime.now(UTC)


def _payload_json(order_payload: VMCreateRequest) -> dict:
    # `quote_id` is a create-time binding, never part of the stored spec, so it
    # is excluded for a stable idempotency / body-match comparison.
    return order_payload.model_dump(mode="json", exclude={"quote_id"})


class QuoteExistsError(Exception):
    """Idempotent replay: same `client_order_id` + same spec → return existing."""

    def __init__(self, existing: VMQuoteRow) -> None:
        super().__init__(f"quote already exists: {existing.quote_id}")
        self.existing = existing


class QuoteConflictError(Exception):
    """Same `client_order_id` but a DIFFERENT spec → 409 (key bound to a spec)."""

    def __init__(self, existing: VMQuoteRow) -> None:
        super().__init__(f"client_order_id reused with a different spec: {existing.quote_id}")
        self.existing = existing


def is_expired(row: VMQuoteRow, *, now: datetime | None = None) -> bool:
    # Postgres returns tz-aware datetimes; SQLite (tests) returns naive ones —
    # normalise to UTC so the comparison works on both.
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return (now or _now()) > expires


def _existing_error(existing: VMQuoteRow, payload: dict) -> Exception:
    return (
        QuoteExistsError(existing)
        if existing.order_payload == payload
        else QuoteConflictError(existing)
    )


async def create_quote(
    *,
    session_factory: async_sessionmaker,
    order_payload: VMCreateRequest,
    amount_usd: Decimal,
    client_order_id: str | None,
    owner_account_id: str | None = None,
) -> VMQuoteRow:
    """Insert a fresh, priced quote. Idempotent on `client_order_id`."""
    payload = _payload_json(order_payload)

    # Best-effort pre-insert check; the unique index below is the real guard.
    if client_order_id:
        async with session_factory() as db:
            existing = (
                await db.execute(
                    select(VMQuoteRow).where(VMQuoteRow.client_order_id == client_order_id)
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise _existing_error(existing, payload)

    row = VMQuoteRow(
        quote_id=generate_quote_id(),
        order_payload=payload,
        amount_usd=amount_usd,
        status=QuoteStatus.CREATED,
        client_order_id=client_order_id,
        owner_account_id=owner_account_id,
        expires_at=_now() + QUOTE_TTL,
    )
    async with session_factory() as db:
        db.add(row)
        try:
            await db.commit()
        except IntegrityError as exc:
            # Lost a concurrent race on the unique client_order_id index — return
            # the winner instead of a duplicate (or a conflict if specs differ).
            await db.rollback()
            if client_order_id:
                won = (
                    await db.execute(
                        select(VMQuoteRow).where(VMQuoteRow.client_order_id == client_order_id)
                    )
                ).scalar_one_or_none()
                if won is not None:
                    raise _existing_error(won, payload) from exc
            raise
        await db.refresh(row)
        return row


async def get_quote(session_factory: async_sessionmaker, quote_id: str) -> VMQuoteRow | None:
    async with session_factory() as db:
        return await db.get(VMQuoteRow, quote_id)


async def mark_consumed(session_factory: async_sessionmaker, quote_id: str, vm_id: str) -> bool:
    """Flip CREATED → CONSUMED and link the provisioned VM.

    Atomic and idempotent: only the caller whose UPDATE matches a still-CREATED
    row (rowcount == 1) wins, so two concurrent paid creates can't both consume.
    Returns True if this call performed the transition.
    """
    async with session_factory() as db:
        result = await db.execute(
            _sql_update(VMQuoteRow)
            .where(
                VMQuoteRow.quote_id == quote_id,
                VMQuoteRow.status == QuoteStatus.CREATED,
            )
            .values(status=QuoteStatus.CONSUMED, vm_id=vm_id)
        )
        await db.commit()
        return result.rowcount == 1
