"""Block A1 auth endpoints — register/login/logout/recover/me/vms/claim.

Design notes that lock in plan intent:
- No email, no PII, no chosen username. account_id is server-generated `H<10 hex>`.
- argon2id for both password and recovery code (see services/passwords.py).
- Server-side opaque session cookies (see services/sessions.py).
- Generic "invalid credentials" errors; account_id existence is never leaked.
- Per-IP rate limiting via cachetools TTL counters (5 reg/hr, 10 login/hr, 3 recover/hr).
- Recovery code is single-use; on consumption a new code is auto-issued and revealed.
- Wallet-signature recovery is Block F (not here). Code recovery is here.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

import structlog
from cachetools import TTLCache
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from hyrule_cloud.db import (
    AccountRow,
    ApiKeyRow,
    RecoveryAttemptRow,
    RecoveryChallengeRow,
    VMRow,
    generate_account_id,
)
from hyrule_cloud.middleware.auth import (
    _client_ip,
    _get_session_factory,
    assert_key_scopes_subset,
    derive_ip_prefix_hash,
    require_account,
    require_browser_session,
    require_scope,
)
from hyrule_cloud.models import (
    ApiKeyScope,
    VMStatus,
    generate_anon_management_token,
    hash_anon_management_token,
    verify_anon_management_token,
)
from hyrule_cloud.services.api_keys import (
    create_api_key as svc_create_api_key,
)
from hyrule_cloud.services.api_keys import (
    list_api_keys as svc_list_api_keys,
)
from hyrule_cloud.services.api_keys import (
    normalize_scopes,
)
from hyrule_cloud.services.api_keys import (
    revoke_api_key as svc_revoke_api_key,
)
from hyrule_cloud.services.passwords import (
    generate_recovery_code,
    hash_password,
    hash_recovery_code,
    verify_password,
    verify_recovery_code,
)
from hyrule_cloud.services.sessions import (
    SESSION_COOKIE_NAME,
    cookie_kwargs_for_set,
    create_session,
    revoke_all_sessions_for,
    revoke_session,
)
from hyrule_cloud.state import AppState, get_app_state

log = structlog.get_logger()

router = APIRouter(prefix="/v1")


# --- Rate limiting (per IP-prefix hash, TTL=1h) ---

_RATE_REGISTER = TTLCache(maxsize=10_000, ttl=3600)
_RATE_LOGIN = TTLCache(maxsize=10_000, ttl=3600)
_RATE_RECOVER = TTLCache(maxsize=10_000, ttl=3600)


def _check_rate(bucket: TTLCache, key: str, limit: int) -> None:
    """Raise 429 if `key` has hit `limit` in the bucket's TTL window."""
    if not key:
        return
    current = bucket.get(key, 0)
    if current >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")
    bucket[key] = current + 1


def _now() -> datetime:
    return datetime.now(UTC)


# --- Request/response models ---


class AuthRegisterRequest(BaseModel):
    password: str = Field(min_length=12, max_length=256)
    with_api_key: bool = False
    api_key_name: str | None = Field(default=None, max_length=64)


class AuthRegisterResponse(BaseModel):
    account_id: str
    recovery_code: str
    api_key: str | None = None
    api_key_id: str | None = None
    api_key_scopes: list[str] | None = None
    message: str = (
        "Save your recovery code somewhere safe. It is the ONLY way to "
        "reset your password if you forget it. We cannot recover it for you."
    )


class AuthLoginRequest(BaseModel):
    account_id: str = Field(min_length=11, max_length=11)
    password: str = Field(min_length=1, max_length=256)


class AuthLoginResponse(BaseModel):
    account_id: str


class RecoveryCodeRequest(BaseModel):
    account_id: str = Field(min_length=11, max_length=11)
    recovery_code: str = Field(min_length=10, max_length=80)
    new_password: str = Field(min_length=12, max_length=256)


class RecoveryCodeResponse(BaseModel):
    account_id: str
    new_recovery_code: str  # auto-rotated; save this one now
    message: str = "Password reset. All previous sessions have been revoked."


class WalletChallengeRequest(BaseModel):
    account_id: str = Field(min_length=11, max_length=11)


class WalletChallengeResponse(BaseModel):
    nonce: str
    challenge_text: str
    expires_at: datetime
    message: str = (
        "Sign challenge_text verbatim with the EVM wallet that paid for one of "
        "this account's VMs (personal_sign / EIP-191). Submit the signature to "
        "/v1/auth/recover/wallet/verify within 5 minutes."
    )


class WalletVerifyRequest(BaseModel):
    nonce: str = Field(min_length=16, max_length=64)
    signature: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=12, max_length=256)


class WalletVerifyResponse(BaseModel):
    account_id: str
    message: str = "Password reset. All previous sessions have been revoked."


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class RotateRecoveryCodeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)


class RotateRecoveryCodeResponse(BaseModel):
    new_recovery_code: str
    message: str = "New recovery code issued. Save it; the old one is no longer valid."


class MeResponse(BaseModel):
    account_id: str
    created_at: datetime
    last_login_at: datetime | None
    is_admin: bool
    vm_count: int


class MeVMSummary(BaseModel):
    vm_id: str
    status: VMStatus
    os: str | None = None
    size: str | None = None
    ipv6: str | None = None
    hostname: str | None = None
    expires_at: datetime | None = None
    created_at: datetime | None = None


class MeVMsResponse(BaseModel):
    vms: list[MeVMSummary]


class ClaimByTokenRequest(BaseModel):
    proof: Literal["management_token"] = "management_token"
    token: str = Field(min_length=10, max_length=128)


class ClaimByWalletRequest(BaseModel):
    proof: Literal["wallet_signature"] = "wallet_signature"
    # The challenge text the client signed (server-prescribed format below)
    challenge: str = Field(min_length=20, max_length=512)
    signature: str = Field(min_length=10, max_length=200)


class ClaimBySSHRequest(BaseModel):
    proof: Literal["ssh_signature"] = "ssh_signature"
    # Output of `ssh-keygen -Y sign -n hyrule-claim -f key < challenge`
    challenge: str = Field(min_length=20, max_length=512)
    signature_armor: str = Field(min_length=20, max_length=8192)


class ClaimResponse(BaseModel):
    vm_id: str
    owner_account_id: str
    message: str = "VM claimed. It now appears in your dashboard."


class AccountDeleteResponse(BaseModel):
    account_id: str
    vm_policy: str
    detached_vms: list[dict] = []  # only populated for vm_policy=detach


# --- API keys (Block D) ---


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    scopes: list[str] | None = None
    expires_at: datetime | None = None


class ApiKeySummary(BaseModel):
    key_id: str
    name: str
    scopes: list[str]
    created_at: datetime
    last_used_at: datetime | None = None
    expires_at: datetime | None = None


class ApiKeyCreateResponse(BaseModel):
    """One-shot reveal — `key` is the only chance to copy the bearer."""
    key_id: str
    key: str
    name: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None = None
    message: str = (
        "This is the only time the key will be shown. Save it now. "
        "It grants only the listed scopes; rotate or revoke from /v1/me/api-keys."
    )


class ApiKeyListResponse(BaseModel):
    keys: list[ApiKeySummary]


# --- Endpoints: auth ---


@router.post("/auth/register", response_model=AuthRegisterResponse)
async def register(
    body: AuthRegisterRequest,
    request: Request,
    response: Response,
    app_state: AppState = Depends(get_app_state),
) -> AuthRegisterResponse:
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    ip_hash = derive_ip_prefix_hash(_client_ip(request))
    _check_rate(_RATE_REGISTER, ip_hash or "anon", limit=5)

    account_id = generate_account_id()
    password_hash = hash_password(body.password)
    recovery_code = generate_recovery_code()
    recovery_code_hash_v = hash_recovery_code(recovery_code)

    async with factory() as db:
        # Loop on the (vanishingly unlikely) account_id collision.
        for _ in range(5):
            try:
                acct = AccountRow(
                    account_id=account_id,
                    password_hash=password_hash,
                    recovery_code_hash=recovery_code_hash_v,
                    recovery_code_issued_at=_now(),
                    password_changed_at=_now(),
                )
                db.add(acct)
                await db.commit()
                break
            except Exception:  # IntegrityError or transient
                await db.rollback()
                account_id = generate_account_id()
        else:
            raise HTTPException(500, "Account creation failed")

        token = await create_session(
            db,
            account_id,
            user_agent=request.headers.get("user-agent"),
            ip_prefix_hash=ip_hash,
        )

        api_key_cleartext: str | None = None
        api_key_id: str | None = None
        api_key_scopes: list[str] | None = None
        if body.with_api_key:
            key_row, api_key_cleartext = await svc_create_api_key(
                db,
                account_id=account_id,
                name=(body.api_key_name or "agent-bootstrap")[:64],
                scopes=None,  # → DEFAULT_API_KEY_SCOPES
            )
            api_key_id = key_row.key_id
            api_key_scopes = list(key_row.scopes or [])

    response.set_cookie(value=token, **cookie_kwargs_for_set(secure=_should_secure(request)))
    log.info(
        "account_registered",
        account_id=account_id,
        with_api_key=body.with_api_key,
    )
    return AuthRegisterResponse(
        account_id=account_id,
        recovery_code=recovery_code,
        api_key=api_key_cleartext,
        api_key_id=api_key_id,
        api_key_scopes=api_key_scopes,
    )


@router.post("/auth/login", response_model=AuthLoginResponse)
async def login(
    body: AuthLoginRequest,
    request: Request,
    response: Response,
    app_state: AppState = Depends(get_app_state),
) -> AuthLoginResponse:
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    ip_hash = derive_ip_prefix_hash(_client_ip(request))
    _check_rate(_RATE_LOGIN, ip_hash or "anon", limit=10)

    async with factory() as db:
        acct = await db.get(AccountRow, body.account_id)
        # Always perform a hash compare even on missing account to avoid
        # leaking existence through timing — verify_password handles the
        # "no hash" case by returning False quickly, but we burn some CPU
        # by computing a throwaway hash if the account doesn't exist.
        if acct is None:
            _ = hash_password(body.password)  # constant-time-ish defense
            raise HTTPException(401, "Invalid credentials")
        if not verify_password(acct.password_hash, body.password):
            raise HTTPException(401, "Invalid credentials")

        acct.last_login_at = _now()
        await db.commit()

        token = await create_session(
            db,
            acct.account_id,
            user_agent=request.headers.get("user-agent"),
            ip_prefix_hash=ip_hash,
        )

    response.set_cookie(value=token, **cookie_kwargs_for_set(secure=_should_secure(request)))
    log.info("account_logged_in", account_id=body.account_id)
    return AuthLoginResponse(account_id=body.account_id)


@router.post("/auth/logout")
async def logout(
    response: Response,
    app_state: AppState = Depends(get_app_state),
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
):
    factory = _get_session_factory(app_state)
    if factory is not None and session_cookie:
        async with factory() as db:
            await revoke_session(db, session_cookie)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "ok"}


@router.post("/auth/recover/code", response_model=RecoveryCodeResponse)
async def recover_with_code(
    body: RecoveryCodeRequest,
    request: Request,
    app_state: AppState = Depends(get_app_state),
) -> RecoveryCodeResponse:
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    ip_hash = derive_ip_prefix_hash(_client_ip(request))
    _check_rate(_RATE_RECOVER, ip_hash or "anon", limit=3)

    async with factory() as db:
        acct = await db.get(AccountRow, body.account_id)
        valid = (
            acct is not None
            and acct.recovery_code_hash is not None
            and acct.recovery_code_used_at is None
            and verify_recovery_code(acct.recovery_code_hash, body.recovery_code)
        )

        db.add(
            RecoveryAttemptRow(
                account_id=acct.account_id if acct else None,
                method="code",
                success=valid,
                ip_prefix_hash=ip_hash,
            )
        )
        await db.commit()

        if not valid or acct is None:
            raise HTTPException(401, "Invalid recovery code")

        # Rotate password + recovery code; revoke all sessions.
        acct.password_hash = hash_password(body.new_password)
        new_code = generate_recovery_code()
        acct.recovery_code_hash = hash_recovery_code(new_code)
        acct.recovery_code_issued_at = _now()
        acct.recovery_code_used_at = _now()  # mark old code as consumed
        acct.password_changed_at = _now()
        await db.commit()

        revoked = await revoke_all_sessions_for(db, acct.account_id)

    log.info("recovery_code_used", account_id=acct.account_id, sessions_revoked=revoked)
    return RecoveryCodeResponse(
        account_id=acct.account_id,
        new_recovery_code=new_code,
    )


# --- Wallet-signature recovery (Block F) ---

# Origin for the recovery challenge text. Hardcoded — the message MUST be a
# stable string the wallet UI displays verbatim. If we ever move the public
# origin we issue a coordinated rotation, not silent environment drift.
_RECOVERY_ORIGIN = "https://hyrule.host"

# Challenge TTL. Five minutes is enough for a wallet popup round-trip and
# short enough that a stale signed payload can't sit in someone's clipboard.
_RECOVERY_CHALLENGE_TTL = timedelta(minutes=5)


def _build_recovery_challenge_text(
    account_id: str, nonce: str, issued: datetime, expires: datetime
) -> str:
    """Origin- and time-bound challenge.

    Including the origin defeats cross-site replay (a signature minted for
    some other dApp's "Sign in" prompt can't recover here). Including the
    expiry in the visible text means the wallet UX shows the user how long
    the proof is valid for.
    """
    return (
        f"Recover Hyrule account {account_id}\n"
        f"Origin: {_RECOVERY_ORIGIN}\n"
        f"Nonce: {nonce}\n"
        f"Issued: {issued.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"Expires: {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    )


@router.post(
    "/auth/recover/wallet/challenge", response_model=WalletChallengeResponse
)
async def recover_wallet_challenge(
    body: WalletChallengeRequest,
    request: Request,
    app_state: AppState = Depends(get_app_state),
) -> WalletChallengeResponse:
    """Issue a single-use, time-bound challenge for wallet-signature recovery.

    We always insert + return a challenge — even for unknown account_ids —
    so an attacker cannot enumerate which accounts exist. Verification will
    fail at the signer-match step if no VM on this account was ever paid for
    by the signing wallet.
    """
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    ip_hash = derive_ip_prefix_hash(_client_ip(request))
    _check_rate(_RATE_RECOVER, ip_hash or "anon", limit=3)

    nonce = secrets.token_urlsafe(24)  # ~192 bits, URL-safe base64
    now = _now()
    expires = now + _RECOVERY_CHALLENGE_TTL
    text = _build_recovery_challenge_text(body.account_id, nonce, now, expires)

    async with factory() as db:
        db.add(
            RecoveryChallengeRow(
                nonce=nonce,
                account_id=body.account_id,
                challenge_text=text,
                expires_at=expires,
            )
        )
        await db.commit()

    log.info("recovery_wallet_challenge_issued", account_id=body.account_id)
    return WalletChallengeResponse(
        nonce=nonce, challenge_text=text, expires_at=expires
    )


@router.post("/auth/recover/wallet/verify", response_model=WalletVerifyResponse)
async def recover_wallet_verify(
    body: WalletVerifyRequest,
    request: Request,
    app_state: AppState = Depends(get_app_state),
) -> WalletVerifyResponse:
    """Verify an EIP-191 signature against a stored challenge + reset password.

    Success requires ALL of:
      - The challenge row exists, is not used, and is not expired.
      - The signature recovers to an address that owns at least one VM under
        the challenge's account_id (i.e. that wallet paid for one of its VMs).

    On success: mark challenge used, set new password, revoke ALL sessions.
    """
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    ip_hash = derive_ip_prefix_hash(_client_ip(request))
    _check_rate(_RATE_RECOVER, ip_hash or "anon", limit=3)

    # Generic error reused on every failure path. Distinct exceptions for
    # "bad nonce" vs "bad signer" would let an attacker probe which step
    # they failed at; one message keeps the failure-mode opaque.
    invalid = HTTPException(401, "Invalid or expired recovery challenge")

    async with factory() as db:
        chal = await db.get(RecoveryChallengeRow, body.nonce)

        # Use the same "always log an attempt" pattern as code recovery so
        # the audit trail captures both real and probe traffic.
        if chal is None:
            db.add(
                RecoveryAttemptRow(
                    account_id=None,
                    method="wallet",
                    success=False,
                    ip_prefix_hash=ip_hash,
                )
            )
            await db.commit()
            raise invalid

        now = _now()
        chal_expires = (
            chal.expires_at.replace(tzinfo=UTC)
            if chal.expires_at.tzinfo is None
            else chal.expires_at
        )
        if chal.used_at is not None or chal_expires < now:
            db.add(
                RecoveryAttemptRow(
                    account_id=chal.account_id,
                    method="wallet",
                    success=False,
                    ip_prefix_hash=ip_hash,
                )
            )
            await db.commit()
            raise invalid

        # Recover the signer. Any exception path (malformed signature,
        # eth_account parse error) collapses to the generic 401.
        try:
            from eth_account import Account
            from eth_account.messages import encode_defunct
            msg = encode_defunct(text=chal.challenge_text)
            recovered = Account.recover_message(msg, signature=body.signature)
        except Exception:
            db.add(
                RecoveryAttemptRow(
                    account_id=chal.account_id,
                    method="wallet",
                    success=False,
                    ip_prefix_hash=ip_hash,
                )
            )
            await db.commit()
            raise invalid

        # Does the recovered address own any VM on this account? (case-insens.)
        from sqlalchemy import func as sa_func
        res = await db.execute(
            select(sa_func.count()).select_from(VMRow).where(
                VMRow.owner_account_id == chal.account_id,
                sa_func.lower(VMRow.owner_wallet) == recovered.lower(),
            )
        )
        match_count = int(res.scalar() or 0)

        if match_count == 0:
            db.add(
                RecoveryAttemptRow(
                    account_id=chal.account_id,
                    method="wallet",
                    success=False,
                    ip_prefix_hash=ip_hash,
                )
            )
            await db.commit()
            raise invalid

        # Burn the challenge BEFORE doing anything else so a racing duplicate
        # request can't double-spend the same signature.
        chal.used_at = now
        await db.commit()

        acct = await db.get(AccountRow, chal.account_id)
        if acct is None:
            # The wallet+account pair matched a VM row but the account row
            # itself is gone — treat as opaque failure.
            db.add(
                RecoveryAttemptRow(
                    account_id=chal.account_id,
                    method="wallet",
                    success=False,
                    ip_prefix_hash=ip_hash,
                )
            )
            await db.commit()
            raise invalid

        acct.password_hash = hash_password(body.new_password)
        acct.password_changed_at = now
        # Don't auto-rotate recovery_code on this path — the user can do that
        # explicitly from the dashboard. The code endpoint rotates because the
        # code is consumed in that flow; signatures aren't consumed analogously.
        await db.commit()

        revoked = await revoke_all_sessions_for(db, acct.account_id)

        db.add(
            RecoveryAttemptRow(
                account_id=acct.account_id,
                method="wallet",
                success=True,
                ip_prefix_hash=ip_hash,
            )
        )
        await db.commit()

    log.info(
        "recovery_wallet_used",
        account_id=acct.account_id,
        sessions_revoked=revoked,
    )
    return WalletVerifyResponse(account_id=acct.account_id)


# --- Endpoints: /me ---


@router.get("/me", response_model=MeResponse)
async def get_me(
    account: AccountRow = Depends(require_scope(ApiKeyScope.ACCOUNT_READ.value)),
    app_state: AppState = Depends(get_app_state),
) -> MeResponse:
    factory = _get_session_factory(app_state)
    vm_count = 0
    if factory is not None:
        async with factory() as db:
            from sqlalchemy import func
            res = await db.execute(
                select(func.count())
                .select_from(VMRow)
                .where(
                    VMRow.owner_account_id == account.account_id,
                    VMRow.status != VMStatus.DESTROYED,
                )
            )
            vm_count = int(res.scalar() or 0)

    return MeResponse(
        account_id=account.account_id,
        created_at=account.created_at,
        last_login_at=account.last_login_at,
        is_admin=account.is_admin,
        vm_count=vm_count,
    )


@router.post("/me/password")
async def change_password(
    body: ChangePasswordRequest,
    account: AccountRow = Depends(require_browser_session),
    app_state: AppState = Depends(get_app_state),
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
):
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")
    if not verify_password(account.password_hash, body.current_password):
        raise HTTPException(401, "Current password is incorrect")

    async with factory() as db:
        acct = await db.get(AccountRow, account.account_id)
        if acct is None:
            raise HTTPException(404, "Account not found")
        acct.password_hash = hash_password(body.new_password)
        acct.password_changed_at = _now()
        await db.commit()
        # Revoke all other sessions; keep this one alive for UX continuity.
        await db.execute(
            select(AccountRow).where(AccountRow.account_id == account.account_id)
        )
        from sqlalchemy import delete

        from hyrule_cloud.db import SessionRow
        from hyrule_cloud.services.sessions import hash_session_token
        keep_hash = hash_session_token(session_cookie) if session_cookie else None
        if keep_hash:
            await db.execute(
                delete(SessionRow).where(
                    SessionRow.account_id == account.account_id,
                    SessionRow.token_hash != keep_hash,
                )
            )
        else:
            await revoke_all_sessions_for(db, account.account_id)
        await db.commit()
    log.info("password_changed", account_id=account.account_id)
    return {"status": "ok"}


@router.post("/me/recovery-code", response_model=RotateRecoveryCodeResponse)
async def rotate_recovery_code(
    body: RotateRecoveryCodeRequest,
    account: AccountRow = Depends(require_browser_session),
    app_state: AppState = Depends(get_app_state),
) -> RotateRecoveryCodeResponse:
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")
    if not verify_password(account.password_hash, body.current_password):
        raise HTTPException(401, "Current password is incorrect")

    new_code = generate_recovery_code()
    async with factory() as db:
        acct = await db.get(AccountRow, account.account_id)
        if acct is None:
            raise HTTPException(404, "Account not found")
        acct.recovery_code_hash = hash_recovery_code(new_code)
        acct.recovery_code_issued_at = _now()
        acct.recovery_code_used_at = None
        await db.commit()
    log.info("recovery_code_rotated", account_id=account.account_id)
    return RotateRecoveryCodeResponse(new_recovery_code=new_code)


@router.get("/me/vms", response_model=MeVMsResponse)
async def list_my_vms(
    account: AccountRow = Depends(require_scope(ApiKeyScope.VM_READ.value)),
    app_state: AppState = Depends(get_app_state),
) -> MeVMsResponse:
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    async with factory() as db:
        result = await db.execute(
            select(VMRow)
            .where(VMRow.owner_account_id == account.account_id)
            .order_by(VMRow.created_at.desc())
        )
        rows = result.scalars().all()

    return MeVMsResponse(
        vms=[
            MeVMSummary(
                vm_id=r.vm_id,
                status=VMStatus(r.status),
                os=r.os,
                size=str(r.size) if r.size else None,
                ipv6=r.ipv6,
                hostname=r.hostname,
                expires_at=r.expires_at,
                created_at=r.created_at,
            )
            for r in rows
        ]
    )


@router.delete("/me", response_model=AccountDeleteResponse)
async def delete_me(
    request: Request,
    response: Response,
    account: AccountRow = Depends(require_browser_session),
    app_state: AppState = Depends(get_app_state),
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> AccountDeleteResponse:
    """Deletes the account. `vm_policy` controls what happens to owned VMs:
      - destroy: immediately destroy all owned VMs, then delete the account
      - detach: generate fresh anon management tokens for each VM, return ONCE
    """
    vm_policy = request.query_params.get("vm_policy", "detach")
    if vm_policy not in ("destroy", "detach"):
        raise HTTPException(400, "vm_policy must be 'destroy' or 'detach'")

    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    detached: list[dict] = []

    async with factory() as db:
        result = await db.execute(
            select(VMRow).where(
                VMRow.owner_account_id == account.account_id,
                VMRow.status != VMStatus.DESTROYED,
            )
        )
        owned_vms = list(result.scalars().all())

        if vm_policy == "detach":
            for vm in owned_vms:
                fresh_token = generate_anon_management_token()
                vm.anon_management_token_hash = hash_anon_management_token(fresh_token)
                vm.owner_account_id = None
                detached.append(
                    {
                        "vm_id": vm.vm_id,
                        "management_token": fresh_token,
                        "management_url": (
                            f"{str(request.base_url).rstrip('/')}/v1/vm/{vm.vm_id}?token={fresh_token}"
                        ),
                    }
                )
            await db.commit()
        else:  # destroy
            orch = getattr(app_state, "orchestrator", None)
            for vm in owned_vms:
                if orch is not None:
                    try:
                        await orch.destroy_vm(vm.vm_id)
                    except Exception:
                        log.warning("vm_destroy_during_account_delete_failed", vm_id=vm.vm_id)

        # Revoke all sessions, then delete the account row.
        await revoke_all_sessions_for(db, account.account_id)
        acct = await db.get(AccountRow, account.account_id)
        if acct is not None:
            await db.delete(acct)
            await db.commit()

    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    log.info(
        "account_deleted",
        account_id=account.account_id,
        vm_policy=vm_policy,
        vms_affected=len(owned_vms),
    )
    return AccountDeleteResponse(
        account_id=account.account_id,
        vm_policy=vm_policy,
        detached_vms=detached,
    )


# --- VM claim ---


@router.post("/me/vms/{vm_id}/claim", response_model=ClaimResponse)
async def claim_vm(
    vm_id: str,
    body: ClaimByTokenRequest | ClaimByWalletRequest | ClaimBySSHRequest,
    request: Request,
    account: AccountRow = Depends(require_account),
    app_state: AppState = Depends(get_app_state),
) -> ClaimResponse:
    """Attach an anon (ownerless) VM to the calling account."""
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    async with factory() as db:
        vm = await db.get(VMRow, vm_id)
        if vm is None:
            raise HTTPException(404, "VM not found")
        if vm.owner_account_id is not None:
            raise HTTPException(409, "VM already claimed")

        proven = False

        if isinstance(body, ClaimByTokenRequest):
            proven = verify_anon_management_token(body.token, vm.anon_management_token_hash)

        elif isinstance(body, ClaimByWalletRequest):
            # EIP-191 personal_sign recovery. The challenge text MUST be the
            # client-supplied string (we don't issue server challenges in A1 —
            # challenge issuance is Block F for recovery; for claim we trust the
            # signature ONLY iff the recovered address matches owner_wallet AND
            # the challenge contains the vm_id to bind context).
            if vm_id not in body.challenge:
                raise HTTPException(400, "Challenge must contain the vm_id")
            try:
                from eth_account import Account
                from eth_account.messages import encode_defunct
                msg = encode_defunct(text=body.challenge)
                recovered = Account.recover_message(msg, signature=body.signature)
                proven = bool(
                    vm.owner_wallet
                    and recovered.lower() == vm.owner_wallet.lower()
                )
            except Exception:
                proven = False

        elif isinstance(body, ClaimBySSHRequest):
            # Verify via `ssh-keygen -Y verify`. Public-key match alone is NOT
            # proof — the user must produce a signature with the private key.
            if vm_id not in body.challenge:
                raise HTTPException(400, "Challenge must contain the vm_id")
            proven = await _verify_ssh_signature(
                challenge=body.challenge,
                signature_armor=body.signature_armor,
                allowed_pubkey=vm.ssh_pubkey or "",
                namespace="hyrule-claim",
            )

        if not proven:
            raise HTTPException(403, "Proof of ownership rejected")

        vm.owner_account_id = account.account_id
        # Burn the anon token once claimed — account auth now supersedes.
        vm.anon_management_token_hash = None
        await db.commit()

    log.info("vm_claimed", vm_id=vm_id, account_id=account.account_id, proof=body.proof)
    return ClaimResponse(vm_id=vm_id, owner_account_id=account.account_id)


# --- Endpoints: /me/api-keys (Block D) ---


def _key_summary(row: ApiKeyRow) -> ApiKeySummary:
    return ApiKeySummary(
        key_id=row.key_id,
        name=row.name,
        scopes=list(row.scopes or []),
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        expires_at=row.expires_at,
    )


@router.get("/me/api-keys", response_model=ApiKeyListResponse)
async def list_my_api_keys(
    account: AccountRow = Depends(require_scope(ApiKeyScope.API_KEYS_READ.value)),
    app_state: AppState = Depends(get_app_state),
) -> ApiKeyListResponse:
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")
    async with factory() as db:
        rows = await svc_list_api_keys(db, account.account_id)
    return ApiKeyListResponse(keys=[_key_summary(r) for r in rows])


@router.post("/me/api-keys", response_model=ApiKeyCreateResponse)
async def create_my_api_key(
    body: ApiKeyCreateRequest,
    request: Request,
    account: AccountRow = Depends(require_scope(ApiKeyScope.API_KEYS_WRITE.value)),
    app_state: AppState = Depends(get_app_state),
) -> ApiKeyCreateResponse:
    """Mint a new key. Requires api_keys:write; if the caller authed via an API
    key, the new key's scopes must be a subset of the granting key's scopes
    (no privilege escalation). Browser sessions bypass that check.
    """
    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    try:
        wanted = normalize_scopes(body.scopes)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Enforce no-escalation when the caller is an API-keyed agent.
    granting = (
        getattr(request.state, "api_key_scopes", set())
        if getattr(request.state, "is_api_key", False)
        else None
    )
    assert_key_scopes_subset(granting_scopes=granting, requested_scopes=wanted)

    async with factory() as db:
        row, cleartext = await svc_create_api_key(
            db,
            account_id=account.account_id,
            name=body.name,
            scopes=wanted,
            expires_at=body.expires_at,
        )

    log.info(
        "api_key_created",
        account_id=account.account_id,
        key_id=row.key_id,
        scopes=wanted,
        via_api_key=getattr(request.state, "is_api_key", False),
    )
    return ApiKeyCreateResponse(
        key_id=row.key_id,
        key=cleartext,
        name=row.name,
        scopes=list(row.scopes or []),
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


@router.delete("/me/api-keys/{key_id}")
async def revoke_my_api_key(
    key_id: str,
    request: Request,
    account: AccountRow = Depends(require_scope(ApiKeyScope.API_KEYS_WRITE.value)),
    app_state: AppState = Depends(get_app_state),
) -> dict:
    """Hard-delete a key. Scoped by account_id so cross-account guessing fails.

    A key cannot revoke itself — that path is too easy to abuse (a stolen key
    could lock the legitimate owner out of rotating it). The owner must use
    a browser session or a different key.
    """
    if (
        getattr(request.state, "is_api_key", False)
        and getattr(request.state, "api_key_id", None) == key_id
    ):
        raise HTTPException(
            status_code=403,
            detail="An API key cannot revoke itself; use a browser session or another key",
        )

    factory = _get_session_factory(app_state)
    if factory is None:
        raise HTTPException(503, "Database not available")

    async with factory() as db:
        removed = await svc_revoke_api_key(
            db, account_id=account.account_id, key_id=key_id
        )
    if not removed:
        raise HTTPException(404, "API key not found")

    log.info("api_key_revoked", account_id=account.account_id, key_id=key_id)
    return {"status": "ok", "key_id": key_id}


# --- helpers ---


def _should_secure(request: Request) -> bool:
    """Use Secure cookies in production; disable for plain-http local dev."""
    if request.url.scheme == "https":
        return True
    if request.url.hostname in ("localhost", "127.0.0.1", "::1"):
        return False
    return True


async def _verify_ssh_signature(
    *,
    challenge: str,
    signature_armor: str,
    allowed_pubkey: str,
    namespace: str,
) -> bool:
    """Verify a sig produced by `ssh-keygen -Y sign -n <namespace> ...`.

    Implementation: write the pubkey to an allowed_signers file, write the
    signature armor and challenge to tempfiles, then shell out to
    `ssh-keygen -Y verify`. Returns True on exit code 0.
    """
    import asyncio
    import tempfile

    if not allowed_pubkey.strip():
        return False

    try:
        with tempfile.TemporaryDirectory() as td:
            allowed = f"{td}/allowed_signers"
            sigfile = f"{td}/sig"
            with open(allowed, "w") as f:
                f.write(f'claim-identity {allowed_pubkey.strip()}\n')
            with open(sigfile, "w") as f:
                f.write(signature_armor)

            proc = await asyncio.create_subprocess_exec(
                "ssh-keygen",
                "-Y", "verify",
                "-f", allowed,
                "-I", "claim-identity",
                "-n", namespace,
                "-s", sigfile,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.communicate(input=challenge.encode())
            return proc.returncode == 0
    except FileNotFoundError:
        log.error("ssh_keygen_not_found")
        return False
    except Exception:
        log.exception("ssh_signature_verify_failed")
        return False


# Silence the structlog/logger linter
_ = logging
