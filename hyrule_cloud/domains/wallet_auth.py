"""SIWE-compatible wallet login, account linking, and signed rotation."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from urllib.parse import urlparse

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    AccountWalletRow,
    WalletChallengeRow,
    generate_account_id,
)
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.middleware.auth import (
    _client_ip,
    current_account,
    derive_ip_prefix_hash,
    require_browser_session,
)
from hyrule_cloud.services.passwords import hash_password
from hyrule_cloud.services.sessions import cookie_kwargs_for_set, create_session
from hyrule_cloud.state import AppState, get_app_state


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class WalletAction(StrEnum):
    LOGIN = "login"
    LINK = "link"
    ROTATE = "rotate"
    TRANSFER = "transfer"


class WalletChallengeRequest(BaseModel):
    action: WalletAction
    address: str = Field(pattern=r"^0x[0-9A-Fa-f]{40}$")
    chain_id: int = Field(gt=0)
    resource: str | None = Field(default=None, max_length=253)

    @model_validator(mode="after")
    def resource_for_transfer(self) -> WalletChallengeRequest:
        if self.action is WalletAction.TRANSFER and not self.resource:
            raise ValueError("resource is required for transfer challenges")
        if self.action is not WalletAction.TRANSFER and self.resource:
            raise ValueError("resource is only accepted for transfer challenges")
        return self


class WalletChallengeResponse(BaseModel):
    nonce: str
    message: str
    expires_at: datetime


class WalletVerifyRequest(BaseModel):
    nonce: str = Field(min_length=16, max_length=64)
    signature: str = Field(min_length=64, max_length=256)
    secondary_signature: str | None = Field(default=None, min_length=64, max_length=256)


class WalletAuthResponse(BaseModel):
    account_id: str
    address: str
    action: WalletAction
    created: bool = False


class WalletInfoResponse(BaseModel):
    address: str | None
    chain_id: int | None
    linked_at: datetime | None


class WalletAuthService:
    def __init__(
        self,
        config: HyruleConfig,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self.config = config
        self.db = session_factory

    async def get_wallet(self, account_id: str) -> AccountWalletRow | None:
        async with self.db() as session:
            return (
                await session.execute(
                    select(AccountWalletRow).where(AccountWalletRow.account_id == account_id)
                )
            ).scalar_one_or_none()

    async def create_challenge(
        self,
        body: WalletChallengeRequest,
        *,
        account: AccountRow | None,
    ) -> WalletChallengeRow:
        if body.action in {WalletAction.LINK, WalletAction.ROTATE, WalletAction.TRANSFER}:
            if account is None:
                raise DomainProblem(401, "authentication_required", "A browser session is required.")
        allowed_chains = {
            network.chain_id
            for network in self.config.payment.enabled_networks()
            if network.chain_id is not None
        }
        if allowed_chains and body.chain_id not in allowed_chains:
            raise DomainProblem(422, "unsupported_chain", "This wallet chain is not supported.")
        address = _normalize_address(body.address)
        if body.action is WalletAction.LINK and account is not None:
            async with self.db() as session:
                existing = (
                    await session.execute(
                        select(AccountWalletRow).where(AccountWalletRow.account_id == account.account_id)
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    raise DomainProblem(409, "wallet_already_linked", "This account already has a wallet.")
        if body.action is WalletAction.ROTATE and account is not None:
            async with self.db() as session:
                existing = (
                    await session.execute(
                        select(AccountWalletRow).where(AccountWalletRow.account_id == account.account_id)
                    )
                ).scalar_one_or_none()
                if existing is None:
                    raise DomainProblem(409, "wallet_not_linked", "This account has no wallet to rotate.")
                current_address = existing.address
        else:
            current_address = None
        nonce = secrets.token_urlsafe(24)
        now = _now()
        ttl = (
            self.config.domain.transfer_challenge_ttl_seconds
            if body.action is WalletAction.TRANSFER
            else 300
        )
        expires = now + timedelta(seconds=ttl)
        message = self._message(
            action=body.action,
            address=address,
            chain_id=body.chain_id,
            nonce=nonce,
            issued_at=now,
            expires_at=expires,
            account_id=account.account_id if account else None,
            current_address=current_address,
            resource=body.resource,
        )
        row = WalletChallengeRow(
            nonce=nonce,
            action=body.action.value,
            address=address,
            chain_id=body.chain_id,
            account_id=account.account_id if account else None,
            resource=body.resource,
            message=message,
            issued_at=now,
            expires_at=expires,
        )
        async with self.db() as session:
            session.add(row)
            await session.commit()
        return row

    async def verify_login_or_account_action(
        self,
        body: WalletVerifyRequest,
        *,
        account: AccountRow | None,
        request: Request,
    ) -> tuple[AccountRow, AccountWalletRow, WalletAction, bool, str | None]:
        async with self.db() as session:
            challenge = (
                await session.execute(
                    select(WalletChallengeRow)
                    .where(WalletChallengeRow.nonce == body.nonce)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            self._validate_challenge(challenge)
            assert challenge is not None
            action = WalletAction(challenge.action)
            if action is WalletAction.TRANSFER:
                raise DomainProblem(422, "wrong_challenge_action", "Use this challenge on transfer-out.")
            recovered = _recover(challenge.message, body.signature)
            created = False
            if action is WalletAction.LOGIN:
                if recovered.lower() != challenge.address.lower():
                    raise DomainProblem(401, "invalid_wallet_signature", "The wallet signature is invalid.")
                wallet = (
                    await session.execute(
                        select(AccountWalletRow).where(
                            AccountWalletRow.address == challenge.address
                        )
                    )
                ).scalar_one_or_none()
                if wallet is None:
                    account_row = AccountRow(
                        account_id=generate_account_id(),
                        password_hash=hash_password(secrets.token_urlsafe(48)),
                        recovery_code_hash=None,
                        password_changed_at=_now(),
                    )
                    session.add(account_row)
                    await session.flush()
                    wallet = AccountWalletRow(
                        wallet_id=str(uuid.uuid4()),
                        account_id=account_row.account_id,
                        address=challenge.address,
                        chain_id=challenge.chain_id,
                    )
                    session.add(wallet)
                    created = True
                else:
                    loaded_account = await session.get(AccountRow, wallet.account_id)
                    if loaded_account is None:
                        raise DomainProblem(401, "invalid_wallet_account", "The wallet account is unavailable.")
                    account_row = loaded_account
                challenge.used_at = _now()
                await session.commit()
                token = await create_session(
                    session,
                    account_row.account_id,
                    user_agent=request.headers.get("user-agent"),
                    ip_prefix_hash=derive_ip_prefix_hash(_client_ip(request)),
                )
                return account_row, wallet, action, created, token
            if account is None or challenge.account_id != account.account_id:
                raise DomainProblem(401, "authentication_required", "The session does not match this challenge.")
            if action is WalletAction.LINK:
                if recovered.lower() != challenge.address.lower():
                    raise DomainProblem(401, "invalid_wallet_signature", "The wallet signature is invalid.")
                wallet = AccountWalletRow(
                    wallet_id=str(uuid.uuid4()),
                    account_id=account.account_id,
                    address=challenge.address,
                    chain_id=challenge.chain_id,
                )
                session.add(wallet)
            elif action is WalletAction.ROTATE:
                wallet = (
                    await session.execute(
                        select(AccountWalletRow)
                        .where(AccountWalletRow.account_id == account.account_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if wallet is None:
                    raise DomainProblem(409, "wallet_not_linked", "This account has no linked wallet.")
                if recovered.lower() != wallet.address.lower():
                    raise DomainProblem(401, "invalid_wallet_signature", "The current-wallet signature is invalid.")
                if not body.secondary_signature:
                    raise DomainProblem(422, "new_wallet_signature_required", "The new wallet must also sign.")
                new_recovered = _recover(challenge.message, body.secondary_signature)
                if new_recovered.lower() != challenge.address.lower():
                    raise DomainProblem(401, "invalid_wallet_signature", "The new-wallet signature is invalid.")
                wallet.address = challenge.address
                wallet.chain_id = challenge.chain_id
                wallet.rotated_at = _now()
            else:
                raise DomainProblem(422, "wrong_challenge_action", "Unsupported wallet action.")
            challenge.used_at = _now()
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise DomainProblem(409, "wallet_already_in_use", "That wallet is linked to another account.") from exc
            return account, wallet, action, created, None

    async def consume_transfer_challenge(
        self,
        *,
        nonce: str,
        signature: str,
        account_id: str,
        resource: str,
    ) -> None:
        async with self.db() as session:
            challenge = (
                await session.execute(
                    select(WalletChallengeRow)
                    .where(WalletChallengeRow.nonce == nonce)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            self._validate_challenge(challenge)
            assert challenge is not None
            if (
                challenge.action != WalletAction.TRANSFER.value
                or challenge.account_id != account_id
                or challenge.resource != resource
            ):
                raise DomainProblem(401, "invalid_transfer_challenge", "The transfer challenge is invalid.")
            wallet = (
                await session.execute(
                    select(AccountWalletRow)
                    .where(AccountWalletRow.account_id == account_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if wallet is None or challenge.address.lower() != wallet.address.lower():
                raise DomainProblem(401, "wallet_not_linked", "A linked wallet is required for transfer-out.")
            recovered = _recover(challenge.message, signature)
            if recovered.lower() != wallet.address.lower():
                raise DomainProblem(401, "invalid_wallet_signature", "The wallet signature is invalid.")
            challenge.used_at = _now()
            await session.commit()

    @staticmethod
    def _validate_challenge(challenge: WalletChallengeRow | None) -> None:
        if challenge is None or challenge.used_at is not None or _aware(challenge.expires_at) <= _now():
            raise DomainProblem(401, "challenge_expired", "The wallet challenge is invalid or expired.")

    def _message(
        self,
        *,
        action: WalletAction,
        address: str,
        chain_id: int,
        nonce: str,
        issued_at: datetime,
        expires_at: datetime,
        account_id: str | None,
        current_address: str | None,
        resource: str | None,
    ) -> str:
        origin = self.config.recovery_origin.rstrip("/")
        host = urlparse(origin).hostname or "hyrule.host"
        statement = {
            WalletAction.LOGIN: "Sign in to Hyrule with this wallet.",
            WalletAction.LINK: "Link this wallet as the account's primary wallet.",
            WalletAction.ROTATE: "Authorize primary-wallet rotation from both wallets.",
            WalletAction.TRANSFER: f"Authorize transfer-out for {resource}.",
        }[action]
        resources = [f"urn:hyrule:action:{action.value}"]
        if account_id:
            resources.append(f"urn:hyrule:account:{account_id}")
        if current_address:
            resources.append(f"urn:hyrule:current-wallet:{current_address}")
        if resource:
            resources.append(f"urn:hyrule:domain:{resource}")
        resource_lines = "\n".join(f"- {item}" for item in resources)
        return (
            f"{host} wants you to sign in with your Ethereum account:\n"
            f"{address}\n\n{statement}\n\n"
            f"URI: {origin}\n"
            "Version: 1\n"
            f"Chain ID: {chain_id}\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {issued_at.isoformat().replace('+00:00', 'Z')}\n"
            f"Expiration Time: {expires_at.isoformat().replace('+00:00', 'Z')}\n"
            f"Resources:\n{resource_lines}"
        )


def _normalize_address(value: str) -> str:
    # eth-account's recover path returns a checksum address. Challenge storage
    # only needs a stable, case-insensitive representation.
    return "0x" + value[2:].lower()


def _recover(message: str, signature: str) -> str:
    try:
        return str(Account.recover_message(encode_defunct(text=message), signature=signature))
    except Exception as exc:
        raise DomainProblem(401, "invalid_wallet_signature", "The wallet signature is invalid.") from exc


router = APIRouter(prefix="/v1/auth/wallet", tags=["wallet-auth"])


async def _wallet_service(state: AppState = Depends(get_app_state)) -> WalletAuthService:
    service = state.wallet_auth
    if service is None:
        raise DomainProblem(503, "wallet_auth_unavailable", "Wallet authentication is unavailable.")
    return service


@router.post("/challenge", response_model=WalletChallengeResponse)
async def wallet_challenge(
    body: WalletChallengeRequest,
    request: Request,
    account: AccountRow | None = Depends(current_account),
    service: WalletAuthService = Depends(_wallet_service),
) -> WalletChallengeResponse:
    if body.action in {WalletAction.LINK, WalletAction.ROTATE, WalletAction.TRANSFER} and getattr(
        request.state, "is_api_key", False
    ):
        raise DomainProblem(403, "browser_session_required", "This action requires a browser session.")
    row = await service.create_challenge(body, account=account)
    return WalletChallengeResponse(nonce=row.nonce, message=row.message, expires_at=row.expires_at)


@router.get("", response_model=WalletInfoResponse)
async def wallet_info(
    account: AccountRow = Depends(require_browser_session),
    service: WalletAuthService = Depends(_wallet_service),
) -> WalletInfoResponse:
    wallet = await service.get_wallet(account.account_id)
    return WalletInfoResponse(
        address=wallet.address if wallet else None,
        chain_id=wallet.chain_id if wallet else None,
        linked_at=wallet.created_at if wallet else None,
    )


@router.post("/verify", response_model=WalletAuthResponse)
async def wallet_verify(
    body: WalletVerifyRequest,
    request: Request,
    response: Response,
    account: AccountRow | None = Depends(current_account),
    service: WalletAuthService = Depends(_wallet_service),
) -> WalletAuthResponse:
    if getattr(request.state, "is_api_key", False):
        raise DomainProblem(
            403,
            "browser_session_required",
            "Wallet login and account changes require a browser session.",
        )
    account_row, wallet, action, created, token = await service.verify_login_or_account_action(
        body, account=account, request=request
    )
    if action in {WalletAction.LINK, WalletAction.ROTATE}:
        await require_browser_session(request, account_row)
    if token:
        secure = request.url.scheme == "https" or request.url.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        response.set_cookie(value=token, **cookie_kwargs_for_set(secure=secure))
    return WalletAuthResponse(
        account_id=account_row.account_id,
        address=wallet.address,
        action=action,
        created=created,
    )
