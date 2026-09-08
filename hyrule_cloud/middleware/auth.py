"""`current_account` FastAPI dependency.

Resolves the caller's identity from one of two paths:

  1. `Authorization: Bearer hyr_sk_...` — scoped API keys (Block D / Wave 3).
     Stamps `request.state.is_api_key = True` plus `api_key_scopes` and
     `api_key_id` so per-route deps can enforce scopes.
  2. `hyr_sess` cookie — opaque session token (Block A1 / Wave 2). The cookie
     path is used by the dashboard and by any browser-driven flow.

The two paths are independent: if a Bearer is present and valid we never
even read the cookie. There is intentionally no fallback chain from key to
cookie — a leaked agent bearer must not silently gain destructive-session
powers (see [[feedback_security_split]]).

Anon (`None`) is still a valid return — the management-token middleware
(Block A0) and the anon vm/create path depend on it. Per-IP rate limits
for /auth/* live in api/auth.py, not here, so this dep stays cheap.
"""

from __future__ import annotations

import hashlib

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import AccountRow
from hyrule_cloud.services.api_keys import (
    API_KEY_PREFIX,
    looks_like_api_key,
    lookup_api_key,
)
from hyrule_cloud.services.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    constant_time_eq,
    hash_csrf_token,
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


def _extract_bearer(request: Request, prefix: str) -> str | None:
    """Pull `Authorization: Bearer <prefix>...` (RFC 7235 §2.1 — scheme is
    case-insensitive, credential is preserved verbatim).

    We accept *only* bearers that start with `prefix` so the Block-A0 anon
    management-token middleware and the Block-D account-key middleware can
    share the Authorization header without colliding."""
    auth = (request.headers.get("authorization") or "").strip()
    if not auth:
        return None
    scheme, _, credential = auth.partition(" ")
    if scheme.lower() != "bearer":
        return None
    candidate = credential.strip()
    if not candidate.startswith(prefix):
        return None
    return candidate


async def current_account(
    request: Request,
    app_state: AppState = Depends(get_app_state),
) -> AccountRow | None:
    """Resolve the caller's account from a Bearer API key OR session cookie.

    Stamps `request.state` so downstream deps and route handlers can
    differentiate the two:
      - `is_api_key` (bool)
      - `api_key_scopes` (set[str])
      - `api_key_id` (str | None)
    """
    request.state.is_api_key = False
    request.state.api_key_scopes = set()
    request.state.api_key_id = None
    request.state.session_token_hash = None
    request.state.session_csrf_token_hash = None
    request.state.admin_elevated_at = None

    factory = _get_session_factory(app_state)
    if factory is None:
        return None

    # Path 1: Bearer hyr_sk_... — scoped API key.
    sk_token = _extract_bearer(request, API_KEY_PREFIX)
    if sk_token and looks_like_api_key(sk_token):
        async with factory() as db_session:
            key_row = await lookup_api_key(db_session, sk_token)
            if key_row is None:
                # Invalid/revoked/expired key — DO NOT fall through to the
                # cookie path. Treating a bad bearer as an anon caller is a
                # footgun: a leaked-then-revoked agent key would silently
                # pick up whatever cookie the browser happens to attach.
                raise HTTPException(401, "Invalid or revoked API key")
            account = await db_session.get(AccountRow, key_row.account_id)
            if account is None:
                raise HTTPException(401, "API key references missing account")
            if account.disabled_at is not None:
                raise HTTPException(403, "Account disabled")
            request.state.is_api_key = True
            request.state.api_key_scopes = set(key_row.scopes or [])
            request.state.api_key_id = key_row.key_id
            return account

    # Path 2: hyr_sess cookie — browser session.
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
        if account.disabled_at is not None:
            raise HTTPException(403, "Account disabled")
        request.state.session_token_hash = row.token_hash
        request.state.session_csrf_token_hash = row.csrf_token_hash
        request.state.admin_elevated_at = row.admin_elevated_at
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
    the operations that MUST NOT be reachable via API key even with
    `api_keys:write`. A leaked agent key should never destroy the account
    it belongs to. See [[feedback_security_split]].
    """
    if getattr(request.state, "is_api_key", False):
        raise HTTPException(
            status_code=403,
            detail="This action requires a browser session, not an API key",
        )
    return account


def verify_session_csrf(request: Request) -> None:
    """Require a header matching the CSRF digest on this exact session."""
    expected = getattr(request.state, "session_csrf_token_hash", None)
    supplied = request.headers.get("X-CSRF-Token")
    cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not expected or not supplied or not cookie:
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    if not constant_time_eq(supplied, cookie) or not constant_time_eq(
        hash_csrf_token(supplied), expected
    ):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


async def require_admin_session(
    request: Request,
    account: AccountRow = Depends(require_browser_session),
) -> AccountRow:
    """A live, enabled administrator browser session."""
    if not account.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return account


async def require_admin_csrf(
    request: Request,
    account: AccountRow = Depends(require_admin_session),
) -> AccountRow:
    verify_session_csrf(request)
    return account


def require_admin_step_up(max_age_seconds: int | None = None):
    """Dependency factory for recent password-confirmed admin sessions."""

    async def _dep(
        request: Request,
        account: AccountRow = Depends(require_admin_csrf),
        app_state: AppState = Depends(get_app_state),
    ) -> AccountRow:
        from datetime import UTC, datetime

        elevated_at = getattr(request.state, "admin_elevated_at", None)
        ttl = max_age_seconds or app_state.config.admin_step_up_seconds
        if elevated_at is not None and elevated_at.tzinfo is None:
            elevated_at = elevated_at.replace(tzinfo=UTC)
        if elevated_at is None or (datetime.now(UTC) - elevated_at).total_seconds() > ttl:
            raise HTTPException(status_code=403, detail="admin_step_up_required")
        return account

    return _dep


def require_scope(*needed: str):
    """Dependency factory: enforce that an API-key caller carries every
    `needed` scope. Cookie sessions bypass — a session = full account access.

    Usage:
        @router.post("/v1/vm/create", dependencies=[Depends(require_scope("vm:create"))])
        async def create_vm(...): ...

    Returns 401 if no account is authenticated, 403 if the key is missing
    any required scope. The exception detail names the missing scope so an
    agent can fix its key shape without guesswork.
    """

    async def _dep(
        request: Request,
        account: AccountRow = Depends(require_account),
    ) -> AccountRow:
        if not getattr(request.state, "is_api_key", False):
            return account  # cookie session = full access
        held: set[str] = getattr(request.state, "api_key_scopes", set())
        missing = [s for s in needed if s not in held]
        if missing:
            raise HTTPException(
                status_code=403,
                detail=f"API key missing required scope(s): {missing}",
            )
        return account

    return _dep


# Convenience type alias for routes that accept either signed-in or anon.
OptionalAccount = AccountRow | None
