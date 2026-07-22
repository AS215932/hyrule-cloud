"""Append-only x402 payment ledger.

PaymentGate records every payment-gate outcome here (402 issued, verify/settle
failures, settlements, dev bypasses). The ledger is the revenue source of
truth for /metrics and the operator dashboard; writes are best-effort and must
never break the payment flow itself.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

import structlog
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.db import PaymentAuthorizationRow, PaymentEventRow

log = structlog.get_logger()

# Path-prefix → dashboard service group. Order matters only for readability;
# prefixes are disjoint.
_SERVICE_GROUPS: tuple[tuple[str, str], ...] = (
    ("/v1/vm", "vm"),
    ("/v1/domains", "domain"),
    # Historic rows retain their original retired resource paths.
    ("/v1/domain", "domain"),
    ("/v1/zone", "domain"),
    ("/v1/network", "network_proxy"),
    ("/v1/bgp", "network_intel"),
    ("/v1/ip", "network_intel"),
    ("/v1/dns", "network_intel"),
    ("/v1/rdap", "network_intel"),
    ("/v1/whois", "network_intel"),
    ("/v1/web", "network_intel"),
    ("/v1/mx", "network_intel"),
    ("/v1/path", "network_intel"),
    ("/v1/ports", "network_intel"),
    ("/v1/nat", "network_intel"),
    ("/v1/threat", "network_intel"),
    ("/v1/voip", "network_intel"),
    ("/v1/speedtest", "network_intel"),
    ("/v1/mail", "mail"),
)


def service_group_for_path(path: str) -> str:
    for prefix, group in _SERVICE_GROUPS:
        if path == prefix or path.startswith(prefix + "/"):
            return group
    return "other"


class PaymentLedger:
    """Best-effort writer for payment_events rows."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def claim_authorization(
        self,
        *,
        fingerprint: str,
        resource_key: str,
        resource_path: str,
    ) -> bool:
        """Atomically bind an authorization to one logical paid resource.

        Unlike metrics-ledger writes, this security decision is strict: a
        database failure propagates so the payment gate fails closed.
        """

        async with self._session_factory() as session:
            existing = await session.get(PaymentAuthorizationRow, fingerprint)
            if existing is not None:
                return existing.resource_key == resource_key
            session.add(
                PaymentAuthorizationRow(
                    fingerprint=fingerprint,
                    resource_key=resource_key,
                    resource_path=resource_path[:256],
                )
            )
            try:
                await session.commit()
                return True
            except IntegrityError:
                await session.rollback()
            winner = await session.scalar(
                select(PaymentAuthorizationRow).where(
                    PaymentAuthorizationRow.fingerprint == fingerprint
                )
            )
            return winner is not None and winner.resource_key == resource_key

    async def record(
        self,
        *,
        event_type: str,
        request: Request,
        amount: Decimal | None,
        network: str | None = None,
        asset: str | None = None,
        payer: str | None = None,
        tx_hash: str | None = None,
        facilitator_host: str | None = None,
        error: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record a payment-gate outcome derived from an HTTP request."""
        await self.record_event(
            event_type=event_type,
            resource_path=request.url.path,
            method=request.method,
            amount=amount,
            network=network,
            asset=asset,
            payer=payer,
            tx_hash=tx_hash,
            facilitator_host=facilitator_host,
            error=error,
            extra=extra,
        )

    async def record_event(
        self,
        *,
        event_type: str,
        resource_path: str,
        method: str = "",
        amount: Decimal | None = None,
        network: str | None = None,
        asset: str | None = None,
        payer: str | None = None,
        tx_hash: str | None = None,
        facilitator_host: str | None = None,
        error: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record an event from explicit fields (no HTTP request required).

        Used by background flows — e.g. a refund obligation raised when a paid
        VM fails to provision, long after the request that charged for it.
        """
        try:
            async with self._session_factory() as session:
                session.add(
                    self.build_event(
                        event_type=event_type,
                        resource_path=resource_path,
                        method=method,
                        amount=amount,
                        network=network,
                        asset=asset,
                        payer=payer,
                        tx_hash=tx_hash,
                        facilitator_host=facilitator_host,
                        error=error,
                        extra=extra,
                    )
                )
                await session.commit()
        except Exception:
            # The ledger must never take down the payment flow.
            log.warning("payment_ledger_write_failed", event_type=event_type, exc_info=True)

    def build_event(
        self,
        *,
        event_type: str,
        resource_path: str,
        method: str = "",
        amount: Decimal | None = None,
        network: str | None = None,
        asset: str | None = None,
        payer: str | None = None,
        tx_hash: str | None = None,
        facilitator_host: str | None = None,
        error: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> PaymentEventRow:
        """Build a PaymentEventRow without persisting it, so a caller can add it
        to its own session and commit it atomically with related writes (e.g. a
        refund obligation together with the intent's terminal status flip)."""
        path = resource_path or ""
        return PaymentEventRow(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            resource_path=path[:256],
            method=(method or "")[:8],
            service_group=service_group_for_path(path),
            amount_usd=amount,
            network=network,
            asset=asset,
            payer_wallet=payer,
            tx_hash=tx_hash or None,
            facilitator_host=facilitator_host,
            error_reason=str(error)[:256] if error else None,
            extra=extra,
        )
