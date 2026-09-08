"""Shared transaction fence for privileged resource acceptance."""
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyrule_cloud.db import AccountRow


async def validate_admin_dispatch(session: AsyncSession, actor_id: str) -> AccountRow:
    # Match role/disable ordering before any owner or resource locks. Non-key
    # locks allow independent payment-quota FK checks while fencing demotion.
    await session.scalars(select(AccountRow.account_id).where(
        AccountRow.is_admin.is_(True), AccountRow.disabled_at.is_(None))
        .order_by(AccountRow.account_id).with_for_update(key_share=True))
    actor = await session.scalar(select(AccountRow).where(AccountRow.account_id == actor_id)
        .with_for_update(key_share=True).execution_options(populate_existing=True))
    if actor is None or not actor.is_admin or actor.disabled_at is not None:
        raise HTTPException(403, "Administrator access was revoked")
    return actor
