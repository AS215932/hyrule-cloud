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
from typing import TYPE_CHECKING

import structlog

from hyrule_cloud.db import PaymentEventRow
from hyrule_cloud.services.payments_ledger import PaymentLedger
from hyrule_cloud.trust.models import ReceiptKind

if TYPE_CHECKING:
    from hyrule_cloud.trust.receipts import ReceiptService

log = structlog.get_logger()

REFUND_OWED_EVENT = "refund_owed"


class RefundService:
    """Records refund obligations for failed paid provisioning."""

    def __init__(
        self, ledger: PaymentLedger | None, receipts: ReceiptService | None = None
    ) -> None:
        self._ledger = ledger
        # Trust layer: refund-kind receipts minted alongside the obligation.
        self._receipts = receipts

    async def record_owed(
        self,
        *,
        resource_path: str,
        payer: str | None,
        amount: Decimal | None,
        original_tx: str | None,
        reason: str,
        network: str | None = None,
        asset: str | None = None,
        vm_id: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> bool:
        """Record that a refund is owed to ``payer``.

        ``network``/``asset`` carry the chain the original payment settled on so
        the operator refunds from the right receiver wallet (multi-chain
        deployments). ``extra`` merges into the ledger event payload — used to
        stash identifiers that don't fit the fixed columns (e.g. a long native
        deposit address that overflows ``payer_wallet``). Returns True if an
        obligation was recorded, False when there is nothing to refund (an
        unpaid/simulated VM with no settled charge). Best-effort: a ledger write
        failure is logged but never raised into the caller's failure path.
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
            network=network,
            asset=asset,
            original_tx=original_tx,
            reason=reason,
        )

        event_id: str | None = None
        if self._ledger is not None:
            event_extra: dict[str, object] = {"vm_id": vm_id, "original_tx": original_tx}
            if extra:
                event_extra.update(extra)
            event_id = await self._ledger.record_event(
                event_type=REFUND_OWED_EVENT,
                resource_path=resource_path,
                amount=amount,
                network=network,
                asset=asset,
                payer=payer,
                tx_hash=original_tx or None,
                error=reason,
                extra=event_extra,
            )
        if self._receipts is not None:
            rail = "x402-exact-evm"
            if network == "native":
                rail = f"native-{(asset or 'btc').lower()}"
            raw_intent = extra.get("intent_id") if extra else None
            intent_id = raw_intent if isinstance(raw_intent, str) else None
            await self._receipts.mint(
                kind=ReceiptKind.REFUND,
                outcome="refund_owed",
                resource_path=resource_path,
                method="POST",
                rail=rail,
                network=network,
                asset=asset,
                amount_usd=amount,
                payer=payer,
                tx_hash=original_tx or None,
                payment_event_id=event_id,
                vm_id=vm_id,
                intent_id=intent_id,
                outcome_detail=reason,
            )
        return True

    def build_owed_event(
        self,
        *,
        resource_path: str,
        payer: str | None,
        amount: Decimal | None,
        original_tx: str | None,
        reason: str,
        network: str | None = None,
        asset: str | None = None,
        vm_id: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> PaymentEventRow | None:
        """Build the ``refund_owed`` ledger row for an ATOMIC write, or None when
        nothing is owed (unpaid/dev-bypass) or no ledger is wired.

        Unlike ``record_owed`` (which persists best-effort in its own session),
        this returns the row so the caller can add it to a session that also
        makes another change — e.g. flipping an intent to its terminal
        REFUND_MANUAL status — so the obligation and the terminal status commit
        together or not at all. Emits the ``vm_refund_owed`` alert log when owed.
        """
        if not payer or amount is None or amount <= 0:
            log.info("refund_not_owed_no_payment", vm_id=vm_id, reason=reason)
            return None
        log.warning(
            "vm_refund_owed",
            vm_id=vm_id,
            payer=payer,
            amount=str(amount),
            network=network,
            asset=asset,
            original_tx=original_tx,
            reason=reason,
        )
        if self._ledger is None:
            return None
        event_extra: dict[str, object] = {"vm_id": vm_id, "original_tx": original_tx}
        if extra:
            event_extra.update(extra)
        return self._ledger.build_event(
            event_type=REFUND_OWED_EVENT,
            resource_path=resource_path,
            amount=amount,
            network=network,
            asset=asset,
            payer=payer,
            tx_hash=original_tx or None,
            error=reason,
            extra=event_extra,
        )
