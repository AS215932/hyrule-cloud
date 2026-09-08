"""Authenticated, immutable guest completion receipts; no guest log content."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import VMGuestResultRow, VMRow
from hyrule_cloud.models import VMStatus


class GuestResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    outcome: Literal["succeeded", "failed"]
    stage: Literal["cloud_init", "setup_script"]
    exit_code: int = Field(ge=0, le=255)

    @model_validator(mode="after")
    def consistent_result(self) -> GuestResult:
        if self.outcome == "succeeded" and (self.stage != "cloud_init" or self.exit_code != 0):
            raise ValueError("success requires completed cloud-init")
        if self.outcome == "failed" and self.exit_code == 0:
            raise ValueError("failure requires a nonzero exit status")
        return self


class GuestResultRejectedError(Exception):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__("Guest completion report rejected")


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def prepare_guest_result(session: AsyncSession, vm_id: str, deadline: datetime) -> tuple[str, str]:
    """Call under the clone capacity lock, after old untracked guests are removed.

    Commit before injecting the returned token into a NEW guest. Never call for
    an already tracked guest: its existing receipt identity must survive retry.
    """
    vm = await session.scalar(select(VMRow).where(VMRow.vm_id == vm_id).with_for_update())
    if vm is None or vm.status != VMStatus.PROVISIONING or vm.xcpng_uuid is not None:
        raise GuestResultRejectedError(409)
    if utc(deadline) <= datetime.now(UTC):
        raise GuestResultRejectedError(410)
    row = await session.scalar(select(VMGuestResultRow).where(VMGuestResultRow.vm_id == vm_id).with_for_update())
    if row is None:
        row = VMGuestResultRow(vm_id=vm_id)
        session.add(row)
    token = secrets.token_urlsafe(32)
    row.generation = secrets.token_hex(16)
    row.token_hash = hashlib.sha256(token.encode()).hexdigest()
    row.deadline = utc(deadline)
    row.outcome = row.stage = row.exit_code = row.received_at = None
    await session.flush()
    return row.generation, token


async def accept_guest_result(
    session: AsyncSession, vm_id: str, generation: str, token: str,
    result: GuestResult, *, now: datetime | None = None,
) -> None:
    """Caller commits; row locking serializes competing reports across workers."""
    if len(token) > 128 or len(generation) != 32:
        raise GuestResultRejectedError(404)
    row = await session.scalar(select(VMGuestResultRow).where(VMGuestResultRow.vm_id == vm_id).with_for_update())
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if row is None or row.generation != generation or not hmac.compare_digest(row.token_hash, token_hash):
        raise GuestResultRejectedError(404)
    values = (result.outcome, result.stage, result.exit_code)
    if row.received_at is not None:
        if (row.outcome, row.stage, row.exit_code) != values:
            raise GuestResultRejectedError(409)
        return  # Safe retry even if acknowledgement was lost beyond the deadline.
    observed = utc(now or datetime.now(UTC))
    if observed > utc(row.deadline):
        raise GuestResultRejectedError(410)
    row.outcome, row.stage, row.exit_code = values
    row.received_at = observed
    await session.flush()
