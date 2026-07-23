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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import ReverseTunnelRow
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.providers.tunnel_client import LeaseResult, TunnelDaemonError, TunnelProvider

log = structlog.get_logger()


class TunnelReconcileError(Exception):
    """The daemon applied a change but persisting it failed — needs refund/alert."""


class TunnelIdempotencyConflictError(Exception):
    """Another replica won the create idempotency race; recover the winning row."""


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

    async def find_by_idempotency_key(self, key: str) -> ReverseTunnelRow | None:
        async with self.session_factory() as session:
            return (
                await session.execute(
                    select(ReverseTunnelRow).where(ReverseTunnelRow.idempotency_key == key)
                )
            ).scalar_one_or_none()

    async def recover_lease(self, tunnel_id: str) -> LeaseResult | None:
        """Re-fetch the daemon lease (idempotent create) to recover its token for
        an idempotent create replay. Returns None only if the row is gone;
        propagates TunnelDaemonError on an operational failure so the caller can
        return a retryable 503 rather than a permanent-looking gone response.

        If the daemon had LOST the lease and recreated it with a different token/
        port/endpoint, the row is re-synced so its token_hash matches the token
        we return (else the management gate would reject it) and the advertised
        port is current.
        """
        row = await self.get(tunnel_id)
        if row is None:
            return None
        expires = row.expires_at
        if expires.tzinfo is None:  # SQLite (tests) returns naive; Postgres keeps tz
            expires = expires.replace(tzinfo=UTC)
        duration = max(1, int((expires - _now()).total_seconds()))
        lease = await self.provider.create_lease(tunnel_id, duration, row.allowlist_cidrs)
        new_hash = hash_anon_token(lease.token or "")
        # Re-sync the row (only if it still exists) so its token_hash matches the
        # token we return. Use a conditional UPDATE keyed on the row still being
        # present: if a concurrent owner revoke deleted the row while we were
        # recreating the daemon lease, the UPDATE affects 0 rows — then revoke the
        # lease we just recreated (don't leave an unmanageable orphan) and report
        # gone. This bounds the recovery-vs-revocation race.
        async with self.session_factory() as session:
            result = await session.execute(
                update(ReverseTunnelRow)
                .where(ReverseTunnelRow.tunnel_id == tunnel_id)
                .values(
                    token_hash=new_hash,
                    allocated_port=lease.port,
                    endpoint_host=lease.endpoint_host,
                    ssh_port=lease.ssh_port,
                )
            )
            await session.commit()
            rows_updated: int = getattr(result, "rowcount", 0)
        if rows_updated == 0:
            # Row was revoked concurrently; don't orphan the recreated lease.
            await self.provider.revoke_lease(tunnel_id)
            return None
        return lease

    async def provision(
        self,
        *,
        tunnel_id: str,
        hours: int,
        allowlist_cidrs: list[str] | None,
        owner_wallet: str,
        owner_account_id: str | None,
        idempotency_key: str | None,
        request_hash: str | None = None,
    ) -> tuple[ReverseTunnelRow, LeaseResult]:
        """Create the daemon lease and persist the row (payment not yet settled).

        Raises TunnelDaemonError if the daemon rejects the create, or if it
        returns no token (an unusable/unmanageable tunnel); the caller must then
        NOT settle (no charge for an unprovisioned tunnel).
        """
        duration = hours * 3600
        lease = await self.provider.create_lease(tunnel_id, duration, allowlist_cidrs)
        if not lease.token:
            # No token means the customer could neither connect nor manage the
            # tunnel; treat as a provisioning failure and free the daemon lease.
            # If the revoke doesn't confirm, persist a provisional row so the
            # sweep retries the daemon teardown (otherwise the port would be
            # untracked and pinned for the full lease).
            if not await self.provider.revoke_lease(tunnel_id):
                await self._persist_provisional_marker(
                    tunnel_id, lease, owner_wallet, owner_account_id, allowlist_cidrs, hours
                )
            raise TunnelDaemonError("daemon returned a lease without a token")
        row = ReverseTunnelRow(
            tunnel_id=tunnel_id,
            owner_wallet=owner_wallet or "",
            owner_account_id=owner_account_id,
            token_hash=hash_anon_token(lease.token),
            allocated_port=lease.port,
            endpoint_host=lease.endpoint_host,
            ssh_port=lease.ssh_port,
            allowlist_cidrs=allowlist_cidrs,
            status="active",
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            expires_at=_parse_ts(lease.expires_at, default=_now() + timedelta(hours=hours)),
            payment_tx=None,
        )
        try:
            async with self.session_factory() as session:
                session.add(row)
                await session.commit()
        except IntegrityError:
            # Another replica committed first with the same idempotency key
            # (unique). Free our just-allocated daemon lease and tell the caller
            # to recover the winning row instead of provisioning a duplicate. If
            # the revoke doesn't confirm, persist a provisional marker (no
            # idempotency_key, so it doesn't re-conflict) so the sweep retries.
            if not await self.provider.revoke_lease(tunnel_id):
                await self._persist_provisional_marker(
                    tunnel_id, lease, owner_wallet, owner_account_id, allowlist_cidrs, hours
                )
            raise TunnelIdempotencyConflictError from None
        except Exception:
            # The daemon already allocated a port; a persistence failure would
            # otherwise leak it (unpaid retries could exhaust the range). Best-
            # effort revoke on the daemon; if that doesn't confirm, persist a
            # provisional marker so the sweep retries the teardown.
            log.error("tunnel_persist_failed", tunnel_id=tunnel_id, exc_info=True)
            if not await self.provider.revoke_lease(tunnel_id):
                await self._persist_provisional_marker(
                    tunnel_id, lease, owner_wallet, owner_account_id, allowlist_cidrs, hours
                )
            raise
        return row, lease

    async def _persist_provisional_marker(
        self,
        tunnel_id: str,
        lease: LeaseResult,
        owner_wallet: str,
        owner_account_id: str | None,
        allowlist_cidrs: list[str] | None,
        hours: int,
    ) -> None:
        """Record a provisional row for a daemon lease whose immediate cleanup
        failed, so sweep_expiries retries the teardown (payment_tx stays NULL, so
        the provisional reap picks it up)."""
        try:
            async with self.session_factory() as session:
                session.add(
                    ReverseTunnelRow(
                        tunnel_id=tunnel_id,
                        owner_wallet=owner_wallet or "",
                        owner_account_id=owner_account_id,
                        token_hash=hash_anon_token(lease.token or ""),
                        allocated_port=lease.port,
                        endpoint_host=lease.endpoint_host,
                        ssh_port=lease.ssh_port,
                        allowlist_cidrs=allowlist_cidrs,
                        status="provisioning",
                        expires_at=_parse_ts(lease.expires_at, default=_now() + timedelta(hours=hours)),
                        payment_tx=None,
                    )
                )
                await session.commit()
        except Exception:
            log.error("tunnel_provisional_marker_failed", tunnel_id=tunnel_id, exc_info=True)

    async def mark_settled(
        self, tunnel_id: str, payment_tx: str, settlement_header: str | None = None
    ) -> bool:
        """Stamp payment_tx (+ the replayable settlement header) after settlement.
        Retries transient DB failures; returns whether the stamp was persisted.
        A settled row must not look provisional to the sweep.
        """
        for attempt in range(5):
            try:
                async with self.session_factory() as session:
                    await session.execute(
                        update(ReverseTunnelRow)
                        .where(ReverseTunnelRow.tunnel_id == tunnel_id)
                        .values(payment_tx=payment_tx, settlement_header=settlement_header)
                    )
                    await session.commit()
                return True
            except Exception:
                log.warning("tunnel_mark_settled_retry", tunnel_id=tunnel_id, attempt=attempt)
        log.error("tunnel_mark_settled_failed", tunnel_id=tunnel_id)
        return False

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
        """Extend the daemon lease, then persist the new expiry (with retry). If
        the daemon succeeds but the DB write ultimately fails, raise
        TunnelReconcileError — the daemon has the paid time but the sweep would
        revoke early off the stale DB expiry, so the caller must refund/alert.
        Raises TunnelDaemonError if the daemon extend fails (before any DB write).
        """
        lease = await self.provider.extend_lease(tunnel_id, hours * 3600)
        new_expiry = _parse_ts(lease.expires_at, default=_now() + timedelta(hours=hours))
        for attempt in range(5):
            try:
                async with self.session_factory() as session:
                    if await session.get(ReverseTunnelRow, tunnel_id) is None:
                        return None
                    # Monotonic: only advance the expiry. Two concurrent extends
                    # whose commits land out of order can't regress it (the older
                    # value's UPDATE no-ops because expires_at is already later).
                    await session.execute(
                        update(ReverseTunnelRow)
                        .where(
                            ReverseTunnelRow.tunnel_id == tunnel_id,
                            ReverseTunnelRow.expires_at < new_expiry,
                        )
                        .values(expires_at=new_expiry)
                    )
                    await session.commit()
                    row = await session.get(ReverseTunnelRow, tunnel_id)
                    return row
            except Exception:
                log.warning("tunnel_extend_persist_retry", tunnel_id=tunnel_id, attempt=attempt)
        raise TunnelReconcileError(
            f"daemon extended {tunnel_id} but the DB expiry write failed"
        )

    async def get(self, tunnel_id: str) -> ReverseTunnelRow | None:
        async with self.session_factory() as session:
            return cast("ReverseTunnelRow | None", await session.get(ReverseTunnelRow, tunnel_id))

    async def live_stats(self, tunnel_id: str) -> LeaseResult | None:
        """Fetch live connection stats from the daemon for the status endpoint."""
        return await self.provider.get_lease(tunnel_id)

    async def sweep_expiries(self) -> int:
        """Reap tunnels past expiry + grace, AND explicit 'provisioning' cleanup
        markers past the provisional TTL (a tokenless/loser lease whose immediate
        daemon revoke failed).

        The fast provisional reap targets only status=='provisioning' markers, NOT
        unsettled 'active' rows: a lease that settled but whose payment_tx stamp
        failed to persist stays 'active', so it is never reaped early — only at
        its legitimate expiry. (A normal create that crashed before settle is
        'active' too; it is reaped at expiry, and is self-healing meanwhile via
        the idempotent-create retry.)

        The row is deleted only after the daemon confirms teardown; if the daemon
        is unreachable the row is kept and retried on the next sweep, so a
        still-reachable lease is never orphaned by dropping its record.
        """
        now = _now()
        expiry_cutoff = now - timedelta(minutes=self.config.tunnel_grace_period_minutes)
        provisional_cutoff = now - timedelta(minutes=self.config.tunnel_provisional_ttl_minutes)
        async with self.session_factory() as session:
            candidates = list(
                await session.scalars(
                    select(ReverseTunnelRow.tunnel_id).where(
                        (ReverseTunnelRow.expires_at < expiry_cutoff)
                        | (
                            (ReverseTunnelRow.status == "provisioning")
                            & (ReverseTunnelRow.created_at < provisional_cutoff)
                        )
                    )
                )
            )
        reaped = 0
        for tunnel_id in candidates:
            if not await self.provider.revoke_lease(tunnel_id):
                # Daemon unreachable/errored — keep the row and retry next sweep
                # rather than orphan a possibly-live lease.
                log.warning("tunnel_sweep_revoke_failed", tunnel_id=tunnel_id)
                continue
            async with self.session_factory() as session:
                await session.execute(
                    sql_delete(ReverseTunnelRow).where(
                        ReverseTunnelRow.tunnel_id == tunnel_id
                    )
                )
                await session.commit()
            reaped += 1
        if reaped:
            log.info("tunnel_expiry_sweep", reaped=reaped)
        return reaped


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
