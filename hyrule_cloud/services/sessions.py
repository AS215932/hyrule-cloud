"""Server-side opaque session tokens.

- Cleartext token format: `hyr_sess_<43-char base62>` (~256 bits).
- Stored as sha256 hex in `sessions.token_hash` (primary key).
- Set as cookie `hyr_sess` with HttpOnly + Secure + SameSite=Lax.
- Revocable: deleting the row invalidates immediately. Wallet-sig recovery
  (Block F) revokes ALL of an account's sessions in a single SQL DELETE.

JWT was deliberately not chosen — we need server-side revocation and there
is no PII to put in a stateless token. Opaque tokens are simpler and safer.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import SessionRow

SESSION_COOKIE_NAME = "hyr_sess"
CSRF_COOKIE_NAME = "hyr_csrf"
SESSION_TTL = timedelta(days=30)
_SESSION_ALPHABET = string.ascii_letters + string.digits


def generate_session_token() -> str:
    """43-char base62 ≈ 256 bits. Cleartext form; never stored at rest."""
    return "hyr_sess_" + "".join(secrets.choice(_SESSION_ALPHABET) for _ in range(43))


def generate_csrf_token() -> str:
    """Independent 256-bit token readable by same-origin browser code."""
    return "hyr_csrf_" + "".join(secrets.choice(_SESSION_ALPHABET) for _ in range(43))


def hash_session_token(token: str) -> str:
    """sha256 hex. Session tokens are high-entropy, fast hash is fine."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_csrf_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SessionCredentials:
    token: str
    csrf_token: str


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    """SQLite (tests) returns naive datetimes; Postgres returns timezone-aware.
    Normalize so comparisons against `_now()` don't TypeError on SQLite."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


async def create_session(
    session: AsyncSession,
    account_id: str,
    *,
    user_agent: str | None = None,
    ip_prefix_hash: str | None = None,
) -> SessionCredentials:
    """Insert a fresh session row and return its one-time cookie values."""
    token = generate_session_token()
    csrf_token = generate_csrf_token()
    row = SessionRow(
        token_hash=hash_session_token(token),
        csrf_token_hash=hash_csrf_token(csrf_token),
        account_id=account_id,
        expires_at=_now() + SESSION_TTL,
        user_agent=(user_agent or "")[:256] or None,
        ip_prefix_hash=ip_prefix_hash,
    )
    session.add(row)
    await session.commit()
    return SessionCredentials(token=token, csrf_token=csrf_token)


async def lookup_session(
    session: AsyncSession, token: str | None
) -> SessionRow | None:
    """Resolve a cleartext token to a row, enforcing expiry."""
    if not token:
        return None
    th = hash_session_token(token)
    row = await session.get(SessionRow, th)
    if row is None:
        return None
    if _aware(row.expires_at) < _now():
        return None
    return row


async def touch_session(session: AsyncSession, row: SessionRow) -> None:
    """Update last_seen_at iff stale by >5min, to avoid a write per request."""
    if (_now() - _aware(row.last_seen_at)) < timedelta(minutes=5):
        return
    await session.execute(
        update(SessionRow)
        .where(SessionRow.token_hash == row.token_hash)
        .values(last_seen_at=_now())
    )
    await session.commit()


async def revoke_session(session: AsyncSession, token: str | None) -> None:
    """Delete a single session by cleartext token (no-op if not found)."""
    if not token:
        return
    th = hash_session_token(token)
    await session.execute(delete(SessionRow).where(SessionRow.token_hash == th))
    await session.commit()


async def revoke_all_sessions_for(session: AsyncSession, account_id: str) -> int:
    """Used on password change, recovery, and explicit logout-all. Returns rows deleted."""
    result = await session.execute(
        delete(SessionRow).where(SessionRow.account_id == account_id)
    )
    await session.commit()
    return result.rowcount or 0


async def purge_expired_sessions(session: AsyncSession) -> int:
    """Best-effort cleanup; safe to run on a schedule. Returns rows deleted.

    Both sides of the comparison are explicit about timezone (per Sourcery
    cloud#6 review): on Postgres `expires_at` is `timestamptz`, on SQLite it
    becomes naive. We dispatch on the bind's dialect so the bound `_now()`
    matches the column type — never mix aware-on-PG with naive-on-Python
    silently.
    """
    bind = session.get_bind()
    cutoff: datetime
    if bind is not None and bind.dialect.name == "sqlite":
        cutoff = _now().replace(tzinfo=None)
    else:
        cutoff = _now()
    result = await session.execute(
        delete(SessionRow).where(SessionRow.expires_at < cutoff)
    )
    await session.commit()
    return result.rowcount or 0


def cookie_kwargs_for_set(*, secure: bool = True) -> dict:
    """Standard cookie options for set_cookie. `secure=False` for local http dev only."""
    return {
        "key": SESSION_COOKIE_NAME,
        "httponly": True,
        "secure": secure,
        "samesite": "lax",
        "path": "/",
        "max_age": int(SESSION_TTL.total_seconds()),
    }


def csrf_cookie_kwargs_for_set(*, secure: bool = True) -> dict:
    """Readable double-submit cookie bound to the opaque server session."""
    return {
        "key": CSRF_COOKIE_NAME,
        "httponly": False,
        "secure": secure,
        "samesite": "strict",
        "path": "/",
        "max_age": int(SESSION_TTL.total_seconds()),
    }


async def find_session_token_in_cookies(
    db_session: AsyncSession, cookie_value: str | None
) -> tuple[SessionRow | None, str | None]:
    """Convenience for middleware: lookup, return (row, raw_token)."""
    if not cookie_value:
        return None, None
    row = await lookup_session(db_session, cookie_value)
    return row, cookie_value
