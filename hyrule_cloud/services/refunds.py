"""Refund obligations for paid work we fail to deliver.

The x402 exact scheme settles the customer's payment immediately, but VM
provisioning is asynchronous: the charge lands at create time and provisioning
can fail minutes later (a bad template, an XCP-NG memory constraint, a host out
of capacity). When that happens the customer has paid for a VM they never got,
so we owe them a refund.

On-chain auto-refund needs a funded hot wallet + an RPC endpoint to broadcast a
USDC transfer back to the payer. That is an operator decision (fund + secure the
wallet, validate on testnet) and is not configured yet, so today we make the
obligation *explicit and alertable* instead of leaving "your payment will be
refunded" as an empty promise:

- a ``refund_owed`` row in ``payment_events`` (payer, amount, original tx),
  which flows straight into ``/metrics`` and the Grafana refund worklist, and
- a ``vm_refund_owed`` structured log line for alerting.

The operator settles it from the receiver wallet per docs/runbooks/x402-launch.md.
``record_owed`` is the single choke point, so wiring an automated sender later
touches exactly one place.
"""

from __future__ import annotations

from decimal import Decimal

import structlog

from hyrule_cloud.services.payments_ledger import PaymentLedger

log = structlog.get_logger()

REFUND_OWED_EVENT = "refund_owed"


class RefundService:
    """Records refund obligations for failed paid provisioning."""

    def __init__(self, ledger: PaymentLedger | None) -> None:
        self._ledger = ledger

    async def record_owed(
        self,
        *,
        resource_path: str,
        payer: str | None,
        amount: Decimal | None,
        original_tx: str | None,
        reason: str,
        vm_id: str | None = None,
    ) -> bool:
        """Record that a refund is owed to ``payer``.

        Returns True if an obligation was recorded, False when there is nothing
        to refund (an unpaid/simulated VM with no settled charge). Best-effort:
        a ledger write failure is logged but never raised into the caller's
        failure-handling path.
        """
        if not payer or amount is None or amount <= 0:
            # No settled payment (free subdomain VM, dev bypass, sim) — nothing
            # was charged, so nothing is owed.
            log.info("refund_not_owed_no_payment", vm_id=vm_id, reason=reason)
            return False

        # Alert signal: this is money we owe a customer until it is sent back.
        log.warning(
            "vm_refund_owed",
            vm_id=vm_id,
            payer=payer,
            amount=str(amount),
            original_tx=original_tx,
            reason=reason,
        )

        if self._ledger is not None:
            await self._ledger.record_event(
                event_type=REFUND_OWED_EVENT,
                resource_path=resource_path,
                amount=amount,
                payer=payer,
                tx_hash=original_tx or None,
                error=reason,
                extra={"vm_id": vm_id, "original_tx": original_tx},
            )
        return True
