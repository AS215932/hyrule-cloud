"""Scoped API key resolution + lifecycle helpers (Block D).

Bearer format: `hyr_sk_<32 base62>` (~190 bits). Cleartext is revealed ONCE
at creation; only sha256(cleartext) is stored. Mirrors anon management
tokens conceptually — high-entropy bearer, fast hash, no slow path needed.

Resolution rules enforced here so routes never have to think about expiry
or revocation directly:
  - revoked_at IS NOT NULL → reject
  - expires_at IS NOT NULL AND expires_at < now → reject

Scope checks are NOT done here — the middleware attaches the key's scope
set to request.state, and each route asks `require_scope(...)` to enforce.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from collections.abc import Iterable

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import ApiKeyRow
from hyrule_cloud.models import (
    DEFAULT_API_KEY_SCOPES,
    all_api_key_scopes,
    generate_api_key,
    hash_api_key,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def normalize_scopes(scopes: Iterable[str] | None) -> list[str]:
    """Validate + dedupe + sort. Empty/None → DEFAULT_API_KEY_SCOPES.

    Rejects unknown scopes (raises ValueError) so a typo in a client never
    silently produces a key that 403s on every route.
    """
    if not scopes:
        return sorted(s.value for s in DEFAULT_API_KEY_SCOPES)
    known = all_api_key_scopes()
    unknown = sorted(set(scopes) - known)
    if unknown:
        raise ValueError(f"Unknown scopes: {', '.join(unknown)}")
    return sorted(set(scopes))


async def create_api_key(
    session: AsyncSession,
    *,
    account_id: str,
    name: str,
    scopes: Iterable[str] | None = None,
    expires_at: datetime | None = None,
) -> tuple[ApiKeyRow, str]:
    """Insert a fresh key row and return (row, cleartext_bearer).

    The cleartext is the ONLY way to authenticate; the caller MUST hand it
    to the user in the response and never retain it server-side.
    """
    cleartext = generate_api_key()
    row = ApiKeyRow(
        key_id=str(uuid.uuid4()),
        account_id=account_id,
        key_hash=hash_api_key(cleartext),
        name=name[:64],
        scopes=normalize_scopes(scopes),
        expires_at=expires_at,
    )
    session.add(row)
    await session.commit()
    return row, cleartext


async def lookup_api_key(
    session: AsyncSession, cleartext: str | None
) -> ApiKeyRow | None:
    """Resolve a cleartext bearer to a row, enforcing revoke + expiry."""
    if not cleartext or not cleartext.startswith("hyr_sk_"):
        return None
    kh = hash_api_key(cleartext)
    result = await session.execute(select(ApiKeyRow).where(ApiKeyRow.key_hash == kh))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    if row.revoked_at is not None:
        return None
    if row.expires_at is not None and _aware(row.expires_at) < _now():
        return None
    return row


async def touch_api_key(session: AsyncSession, key_id: str) -> None:
    """Update last_used_at iff stale by >5min. Write-storm guard."""
    result = await session.execute(
        select(ApiKeyRow.last_used_at).where(ApiKeyRow.key_id == key_id)
    )
    last = result.scalar_one_or_none()
    if last is not None and (_now() - _aware(last)) < timedelta(minutes=5):
        return
    await session.execute(
        update(ApiKeyRow).where(ApiKeyRow.key_id == key_id).values(last_used_at=_now())
    )
    await session.commit()


async def list_api_keys(
    session: AsyncSession, account_id: str
) -> list[ApiKeyRow]:
    """List a caller's keys (never returns the cleartext — that's gone forever)."""
    result = await session.execute(
        select(ApiKeyRow)
        .where(ApiKeyRow.account_id == account_id)
        .order_by(ApiKeyRow.created_at.desc())
    )
    return list(result.scalars().all())


async def revoke_api_key(
    session: AsyncSession, *, account_id: str, key_id: str
) -> bool:
    """Mark a key revoked. Hard-delete instead of soft-delete to keep audit cheap.

    Returns True iff a row was removed. Scoped by account_id so one account
    cannot revoke another's keys even by guessing key_id.
    """
    result = await session.execute(
        delete(ApiKeyRow).where(
            ApiKeyRow.key_id == key_id,
            ApiKeyRow.account_id == account_id,
        )
    )
    await session.commit()
    return (result.rowcount or 0) > 0
