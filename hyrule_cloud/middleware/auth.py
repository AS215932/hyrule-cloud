"""`current_account` FastAPI dependency.

Wave 2 (Block A1) ships the session-cookie resolution only. Scoped API
keys (Block D) land in Wave 3 and add a Bearer-token resolution step
upstream of the cookie path; this file will be REPLACED then. Until
that wave ships, `request.state.is_api_key` is always False and
`request.state.api_key_scopes` is always an empty set so route handlers
that already check those fields (post-Wave-3) remain correct.

Returns `AccountRow | None`. `None` is the anon path — preserved
everywhere routes treat anon-by-vm_id (or anon-by-management-token, per
Block A0) as valid.

Per-IP rate limiting for `/auth/*` lives in `api/auth.py`, not here, so
this dependency stays cheap.
"""

from __future__ import annotations

import hashlib

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import AccountRow
from hyrule_cloud.services.sessions import (
    SESSION_COOKIE_NAME,
    lookup_session,
    touch_session,
)
from hyrule_cloud.state import AppState, get_app_state

# Single source of truth: read once at import via pydantic-settings, which
# resolves from env / .env. Keeps HyruleConfig.ip_prefix_pepper as THE field
# rather than two parallel readers diverging.
_FALLBACK_PEPPER = "hyrule-ip-pepper-wave2-rotate-via-vault"


def _ip_pepper() -> str:
    """Pepper for IP prefix hashing.

    Read from HyruleConfig.ip_prefix_pepper (sourced from
    HYRULE_IP_PREFIX_PEPPER — production: Vault-rendered into
    /opt/hyrule-cloud/.env). Falls back to a process-local constant when
    unset — abuse-only metric, rotates on every restart.
    """
    return HyruleConfig().ip_prefix_pepper or _FALLBACK_PEPPER


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
    return hashlib.sha256((prefix + _ip_pepper()).encode("utf-8")).hexdigest()


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


async def current_account(
    request: Request,
    app_state: AppState = Depends(get_app_state),
) -> AccountRow | None:
    """Resolve the caller's account from the session cookie.

    Wave 2 stamps `request.state` with placeholder values so future
    scope-checking helpers added in Wave 3 keep working unchanged:
      - `is_api_key` (bool) — always False until Wave 3
      - `api_key_scopes` (set[str]) — always empty until Wave 3
      - `api_key_id` (str | None) — always None until Wave 3
    """
    request.state.is_api_key = False
    request.state.api_key_scopes = set()
    request.state.api_key_id = None

    factory = _get_session_factory(app_state)
    if factory is None:
        return None

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

    In Wave 2 this is effectively a no-op beyond `require_account` (because
    `is_api_key` is always False until Wave 3), but the dep is wired now so
    the route signatures and tests are stable across waves.
    """
    if getattr(request.state, "is_api_key", False):
        raise HTTPException(
            status_code=403,
            detail="This action requires a browser session, not an API key",
        )
    return account


# Convenience type alias for routes that accept either signed-in or anon.
OptionalAccount = AccountRow | None
