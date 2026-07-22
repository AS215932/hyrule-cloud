"""Reverse-SSH tunnel lease lifecycle.

Owns the cloud-side DB record and coordinates the hyrule-tunnel-proxy daemon.
The x402 payment flow (verify -> provision -> settle) stays in the route; this
service performs the daemon call + persistence and the expiry sweep. Kept out of
the VM Orchestrator to avoid coupling tunnels to XCP-NG.
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import cast

import structlog
from sqlalchemy import delete as sql_delete
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import ReverseTunnelRow
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.providers.tunnel_client import LeaseResult, TunnelProvider

log = structlog.get_logger()


def new_tunnel_id() -> str:
    return f"rtun_{secrets.token_hex(8)}"


def _now() -> datetime:
    return datetime.now(UTC)


class TunnelService:
    def __init__(
        self,
        config: HyruleConfig,
        session_factory: async_sessionmaker[AsyncSession],
        provider: TunnelProvider,
    ):
        self.config = config
        self.session_factory = session_factory
        self.provider = provider

    async def provision(
        self,
        *,
        tunnel_id: str,
        hours: int,
        allowlist_cidrs: list[str] | None,
        owner_wallet: str,
        owner_account_id: str | None,
    ) -> tuple[ReverseTunnelRow, LeaseResult]:
        """Create the daemon lease and persist the row (payment not yet settled).

        Raises TunnelDaemonError if the daemon rejects the create; the caller
        must then NOT settle (no charge for an unprovisioned tunnel).
        """
        duration = hours * 3600
        lease = await self.provider.create_lease(tunnel_id, duration, allowlist_cidrs)
        row = ReverseTunnelRow(
            tunnel_id=tunnel_id,
            owner_wallet=owner_wallet or "",
            owner_account_id=owner_account_id,
            token_hash=hash_anon_token(lease.token or ""),
            allocated_port=lease.port,
            endpoint_host=lease.endpoint_host,
            ssh_port=lease.ssh_port,
            allowlist_cidrs=allowlist_cidrs,
            status="active",
            expires_at=_parse_ts(lease.expires_at, default=_now() + timedelta(hours=hours)),
            payment_tx=None,
        )
        try:
            async with self.session_factory() as session:
                session.add(row)
                await session.commit()
        except Exception:
            # The daemon already allocated a port; a persistence failure would
            # otherwise leak it (unpaid retries could exhaust the range). Best-
            # effort revoke on the daemon before surfacing the error.
            log.error("tunnel_persist_failed", tunnel_id=tunnel_id, exc_info=True)
            await self.provider.revoke_lease(tunnel_id)
            raise
        return row, lease

    async def mark_settled(self, tunnel_id: str, payment_tx: str) -> None:
        async with self.session_factory() as session:
            await session.execute(
                update(ReverseTunnelRow)
                .where(ReverseTunnelRow.tunnel_id == tunnel_id)
                .values(payment_tx=payment_tx)
            )
            await session.commit()

    async def revoke(self, tunnel_id: str) -> bool:
        """Strictly tear down a tunnel: delete the row ONLY after the daemon has
        confirmed revocation. Returns False (row retained) if the daemon revoke
        fails, so the owner can retry the emergency teardown and we never report
        a still-live tunnel as revoked. Used by the user endpoint and the
        settle-failure cleanup.
        """
        if not await self.provider.revoke_lease(tunnel_id):
            return False
        async with self.session_factory() as session:
            await session.execute(
                sql_delete(ReverseTunnelRow).where(ReverseTunnelRow.tunnel_id == tunnel_id)
            )
            await session.commit()
        return True

    async def extend(self, tunnel_id: str, hours: int) -> ReverseTunnelRow | None:
        lease = await self.provider.extend_lease(tunnel_id, hours * 3600)
        async with self.session_factory() as session:
            row = await session.get(ReverseTunnelRow, tunnel_id)
            if row is None:
                return None
            row.expires_at = _parse_ts(lease.expires_at, default=row.expires_at)
            await session.commit()
            await session.refresh(row)
            return row

    async def get(self, tunnel_id: str) -> ReverseTunnelRow | None:
        async with self.session_factory() as session:
            return cast("ReverseTunnelRow | None", await session.get(ReverseTunnelRow, tunnel_id))

    async def live_stats(self, tunnel_id: str) -> LeaseResult | None:
        """Fetch live connection stats from the daemon for the status endpoint."""
        return await self.provider.get_lease(tunnel_id)

    async def sweep_expiries(self) -> int:
        """Revoke tunnels past expiry + grace on the daemon and delete the rows.

        Belt-and-braces with the daemon's own time-based expiry.
        """
        cutoff = _now() - timedelta(minutes=self.config.tunnel_grace_period_minutes)
        async with self.session_factory() as session:
            expired = list(
                await session.scalars(
                    select(ReverseTunnelRow.tunnel_id).where(
                        ReverseTunnelRow.expires_at < cutoff
                    )
                )
            )
        for tunnel_id in expired:
            await self.provider.revoke_lease(tunnel_id)
            async with self.session_factory() as session:
                await session.execute(
                    sql_delete(ReverseTunnelRow).where(
                        ReverseTunnelRow.tunnel_id == tunnel_id
                    )
                )
                await session.commit()
        if expired:
            log.info("tunnel_expiry_sweep", reaped=len(expired))
        return len(expired)


def _parse_ts(value: str | None, *, default: datetime) -> datetime:
    if not value:
        return default
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return default
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
