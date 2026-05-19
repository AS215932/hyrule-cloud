"""Scoped API key lifecycle (Block D / Wave 3).

One module owns the entire shape: token generation, hashing, scope
validation, lookup, last-used touch, revocation. Routes call into here so
the cleartext token only exists for a single function-call lifetime.

Cleartext shape: `hyr_sk_<32 base62>`. 32 base62 chars ≈ 190 bits of
entropy — well above session tokens (130 bits) because keys persist far
longer than 30 days. At rest we keep sha256(cleartext); high-entropy
inputs make argon2 unnecessary and a fast hash a feature, not a bug
(lookup is a single B-tree probe).
"""

from __future__ import annotations

import hashlib
import secrets
import string
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import ApiKeyRow

_ALPHABET = string.ascii_letters + string.digits  # base62
API_KEY_PREFIX = "hyr_sk_"
_RANDOM_LEN = 32  # base62 chars -> ~190 bits


class ApiKeyScope(StrEnum):
    """The full scope vocabulary. Keep narrow — every new entry is forever.

    Order matches the dashboard's "Create key" UI flow. Reads first, mutating
    actions next, destructive actions last."""

    VM_READ = "vm:read"
    VM_CREATE = "vm:create"
    VM_REBOOT = "vm:reboot"
    VM_EXTEND = "vm:extend"
    VM_DESTROY = "vm:destroy"
    INTENT_CREATE = "intent:create"
    INTENT_READ = "intent:read"
    DOMAIN_REGISTER = "domain:register"
    API_KEYS_READ = "api_keys:read"
    API_KEYS_WRITE = "api_keys:write"


# The starter key minted by `/v1/auth/register` with `with_api_key=true`.
# Read-mostly so an agent's first key can never destroy a VM it didn't
# explicitly opt into; the dashboard surfaces a clear upgrade button.
DEFAULT_BOOTSTRAP_SCOPES: tuple[ApiKeyScope, ...] = (
    ApiKeyScope.VM_READ,
    ApiKeyScope.VM_CREATE,
    ApiKeyScope.INTENT_CREATE,
    ApiKeyScope.INTENT_READ,
)


def generate_api_key() -> str:
    """Mint a cleartext bearer. ONE caller exposes this — and that caller
    must return it to the user immediately, never store it."""
    return API_KEY_PREFIX + "".join(secrets.choice(_ALPHABET) for _ in range(_RANDOM_LEN))


def hash_api_key(cleartext: str) -> str:
    """sha256 — fast, deterministic, single B-tree probe at lookup."""
    return hashlib.sha256(cleartext.encode("utf-8")).hexdigest()


def looks_like_api_key(token: str) -> bool:
    """Cheap pre-check before we go to the DB. Used by the middleware to
    skip the api-key lookup entirely for cookies / management tokens."""
    return token.startswith(API_KEY_PREFIX) and len(token) == len(API_KEY_PREFIX) + _RANDOM_LEN


def validate_scopes(scopes: list[str]) -> list[str]:
    """Reject anything we don't recognise so a typo doesn't quietly become
    an unbounded scope. Returns the validated list (preserves insertion order)."""
    out: list[str] = []
    seen: set[str] = set()
    valid = {s.value for s in ApiKeyScope}
    for s in scopes:
        if s not in valid:
            raise ValueError(f"unknown scope: {s!r}")
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def assert_key_scopes_subset(
    issuing_key_scopes: list[str],
    requested_scopes: list[str],
) -> None:
    """When an API key tries to mint another API key (api_keys:write), the
    new key's scopes must be a subset of the issuing key's scopes. Without
    this, a `vm:read`-only key could escalate by minting a `vm:destroy` key.

    Cookie sessions skip this check — a session is full account access.
    """
    issuing = set(issuing_key_scopes)
    requested = set(requested_scopes)
    extra = requested - issuing
    if extra:
        raise ValueError(
            f"requested scopes exceed issuing key's: {sorted(extra)}"
        )


async def create_api_key(
    session: AsyncSession,
    *,
    account_id: str,
    name: str,
    scopes: list[str],
    expires_at: datetime | None = None,
) -> tuple[str, ApiKeyRow]:
    """Mint a fresh key, persist (caller commits), return (cleartext, row).

    Caller is responsible for surfacing the cleartext to the user exactly
    once and then dropping the reference. Caller also owns the transaction
    boundary — `flush` queues the INSERT and assigns the row's defaults
    without ending the transaction, so the register flow can atomically
    write the account + session + key together (per Sourcery cloud#7
    review)."""
    cleartext = generate_api_key()
    row = ApiKeyRow(
        key_id=str(uuid.uuid4()),
        account_id=account_id,
        key_hash=hash_api_key(cleartext),
        name=name[:64] or "(unnamed)",
        scopes=validate_scopes(scopes),
        expires_at=expires_at,
    )
    session.add(row)
    await session.flush()
    return cleartext, row


async def lookup_api_key(session: AsyncSession, cleartext: str) -> ApiKeyRow | None:
    """O(1) lookup by sha256. Returns the row only if not revoked and not
    expired. Bumps last_used_at on a successful lookup (best-effort: if the
    commit fails the auth still succeeds, last_used_at just drifts)."""
    if not looks_like_api_key(cleartext):
        return None
    row = await session.scalar(
        select(ApiKeyRow).where(ApiKeyRow.key_hash == hash_api_key(cleartext))
    )
    if row is None:
        return None
    if row.revoked_at is not None:
        return None
    now = datetime.now(UTC)
    if row.expires_at is not None and _aware(row.expires_at) < now:
        return None
    try:
        await session.execute(
            update(ApiKeyRow).where(ApiKeyRow.key_id == row.key_id).values(last_used_at=now)
        )
        await session.commit()
    except Exception:
        await session.rollback()
    return row


async def list_keys_for_account(session: AsyncSession, account_id: str) -> list[ApiKeyRow]:
    rows = await session.scalars(
        select(ApiKeyRow)
        .where(ApiKeyRow.account_id == account_id)
        .where(ApiKeyRow.revoked_at.is_(None))
        .order_by(ApiKeyRow.created_at.desc())
    )
    return list(rows)


async def revoke_api_key(
    session: AsyncSession, *, account_id: str, key_id: str,
) -> bool:
    """Revoke. Idempotent (revoking an already-revoked key is a no-op 200).
    Returns True if a row was found and account-scoped; False if the key_id
    doesn't belong to this account (route surfaces a 404 in that case).

    Caller commits — keeps the helper composable with any wider
    transaction (per Sourcery cloud#7)."""
    row = await session.scalar(
        select(ApiKeyRow).where(ApiKeyRow.key_id == key_id)
    )
    if row is None or row.account_id != account_id:
        return False
    if row.revoked_at is not None:
        return True
    await session.execute(
        update(ApiKeyRow)
        .where(ApiKeyRow.key_id == key_id)
        .values(revoked_at=datetime.now(UTC))
    )
    await session.flush()
    return True


def _aware(dt: datetime) -> datetime:
    """SQLite stores naive datetimes — normalize so cross-dialect comparisons
    don't TypeError. Mirrors the pattern in services/sessions.py."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
