"""`current_account` FastAPI dependency.

Resolution order:
  1. `Authorization: Bearer hyr_sk_...` — API keys (Block D). Resolves to an
     AccountRow AND stamps `request.state.api_key_scopes` (a set[str]) +
     `request.state.api_key_id` so per-route deps can enforce scopes.
  2. `Cookie: hyr_sess=...` — browser session, opaque server-side token.
     Sessions are unrestricted (a session = full account access).

Returns `AccountRow | None`. `None` is the anon path (preserved everywhere
the existing routes treat anon-by-vm_id as valid).

Per-IP rate limiting for `/auth/*` lives in `api/auth.py`, not here, so this
dependency stays cheap.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import TYPE_CHECKING, Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import async_sessionmaker

from hyrule_cloud.db import AccountRow
from hyrule_cloud.services.api_keys import lookup_api_key, touch_api_key
from hyrule_cloud.services.sessions import (
    SESSION_COOKIE_NAME,
    lookup_session,
    touch_session,
)
from hyrule_cloud.state import AppState, get_app_state

if TYPE_CHECKING:
    pass


# Pepper for IP prefix hashing. In production this should come from secrets;
# for now it's process-local and rotates on restart (acceptable — abuse-only).
_IP_PEPPER = "hyrule-ip-pepper-A1-rotate-via-vault"


def derive_ip_prefix_hash(ip: str | None) -> str | None:
    """sha256(/64 prefix + pepper). For IPv4, hash the /24."""
    if not ip:
        return None
    if ":" in ip:
        parts = ip.split(":")
        prefix = ":".join(parts[:4])
    else:
        octets = ip.split(".")
        prefix = ".".join(octets[:3])
    return hashlib.sha256((prefix + _IP_PEPPER).encode("utf-8")).hexdigest()


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


def _get_session_factory(app_state: AppState) -> async_sessionmaker | None:
    """The orchestrator owns the session factory. Tests may not wire one."""
    orch = getattr(app_state, "orchestrator", None)
    if orch is None:
        return None
    db = getattr(orch, "db", None)
    return db if callable(db) else None


def _extract_bearer(request: Request, prefix: str) -> str | None:
    """Return the value of `Authorization: Bearer <prefix>...` if present."""
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header:
        return None
    scheme, _, value = auth_header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value if value.startswith(prefix) else None


async def current_account(
    request: Request,
    app_state: AppState = Depends(get_app_state),
) -> AccountRow | None:
    """Resolve the caller's account from API key bearer or session cookie.

    Stamps `request.state` with:
      - `is_api_key` (bool) — True iff resolved via Bearer hyr_sk_
      - `api_key_scopes` (set[str]) — empty set for session/anon, populated for key
      - `api_key_id` (str | None)
    """
    # Default state stamping so deps can read these unconditionally.
    request.state.is_api_key = False
    request.state.api_key_scopes = set()
    request.state.api_key_id = None

    factory = _get_session_factory(app_state)
    if factory is None:
        return None

    # 1. Bearer API key.
    sk_token = _extract_bearer(request, "hyr_sk_")
    if sk_token:
        async with factory() as db_session:
            key_row = await lookup_api_key(db_session, sk_token)
            if key_row is None:
                # Invalid/expired/revoked bearer: do NOT silently fall through to
                # cookie auth. A presented-but-bad key is always 401 — letting
                # it fall through would mask credential-rotation bugs in clients.
                raise HTTPException(status_code=401, detail="Invalid API key")
            account = await db_session.get(AccountRow, key_row.account_id)
            if account is None:
                raise HTTPException(status_code=401, detail="Invalid API key")
            request.state.is_api_key = True
            request.state.api_key_scopes = set(key_row.scopes or [])
            request.state.api_key_id = key_row.key_id
            # Touch is best-effort and de-noised to >5min stale.
            try:
                await touch_api_key(db_session, key_row.key_id)
            except Exception:
                pass
            return account

    # 2. Session cookie.
    cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie_val:
        return None

    async with factory() as db_session:
        row = await lookup_session(db_session, cookie_val)
        if row is None:
            return None
        account = await db_session.get(AccountRow, row.account_id)
        if account is None:
            return None
        # Best-effort touch (no-op unless >5min stale).
        try:
            await touch_session(db_session, row)
        except Exception:
            pass
        return account


async def require_account(
    account: AccountRow | None = Depends(current_account),
) -> AccountRow:
    """Variant of `current_account` that returns 401 instead of None.

    Used as a dependency on /me/* routes that have no anon fallback.
    """
    if account is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return account


async def require_browser_session(
    request: Request,
    account: AccountRow = Depends(require_account),
) -> AccountRow:
    """Reject API-key-authed callers; require a real cookie session.

    Used for password change, recovery-code rotation, and account deletion —
    the operations that, per the plan, MUST NOT be reachable via API key
    even with `api_keys:write`. A leaked agent key should never destroy the
    account it belongs to.
    """
    if getattr(request.state, "is_api_key", False):
        raise HTTPException(
            status_code=403,
            detail="This action requires a browser session, not an API key",
        )
    return account


def require_scope(*needed: str):
    """Dep factory: enforce that the call has at least one of `needed` scopes.

    Sessions are unrestricted (a logged-in user can do anything their account
    can do; API keys are how you carve down). So this dep is a no-op for
    session-authed callers. Anon (None) is rejected — these routes always
    sit behind `require_account` upstream.
    """

    needed_set = set(needed)

    async def _dep(
        request: Request,
        account: AccountRow = Depends(require_account),
    ) -> AccountRow:
        if not getattr(request.state, "is_api_key", False):
            return account
        scopes: set[str] = getattr(request.state, "api_key_scopes", set()) or set()
        if not (scopes & needed_set):
            raise HTTPException(
                status_code=403,
                detail=f"API key missing required scope: {sorted(needed_set)}",
            )
        return account

    return _dep


def enforce_api_key_scope(request: Request, *needed: str) -> None:
    """If (and only if) the request is API-key-authed, require one of `needed`.

    Used by routes that accept multiple auth paths (anon-by-token, session
    cookie, OR API key). Session/anon paths are unaffected — scopes are an
    API-key carve-down, not a session restriction. See plan §5.
    """
    if not getattr(request.state, "is_api_key", False):
        return
    scopes: set[str] = getattr(request.state, "api_key_scopes", set()) or set()
    if not (scopes & set(needed)):
        raise HTTPException(
            status_code=403,
            detail=f"API key missing required scope: {sorted(set(needed))}",
        )


def assert_key_scopes_subset(
    *,
    granting_scopes: Iterable[str] | None,
    requested_scopes: Iterable[str],
) -> None:
    """No-escalation rule: a key with api_keys:write may not mint keys with
    scopes the granting key doesn't itself hold.

    Browser sessions bypass this (they hold all scopes implicitly). Callers
    pass `granting_scopes=None` for the session path to short-circuit the
    check.
    """
    if granting_scopes is None:
        return
    granting = set(granting_scopes)
    requested = set(requested_scopes)
    extra = sorted(requested - granting)
    if extra:
        raise HTTPException(
            status_code=403,
            detail=f"Cannot grant scopes the calling API key does not hold: {extra}",
        )


# Convenience type alias for routes that accept either signed-in or anon.
OptionalAccount = Optional[AccountRow]
