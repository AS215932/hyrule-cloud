"""Customer-visible provisioning events for `GET /v1/vm/{vm_id}/logs`.

Two responsibilities, both security-relevant:

1. **Emission.** `record_vm_event` appends one durable row per real stage
   boundary or failure. It NEVER raises: observability is not allowed to fail a
   paid customer's VM, so every failure is swallowed into a log line.
2. **Sanitization.** Provisioning failures carry provider text (XO/XAPI error
   dicts, template UUIDs, internal management addresses, tracebacks). None of
   that may reach a customer. `customer_failure_message` therefore maps an
   exception to one of a small set of FIXED strings chosen by exception type —
   an allowlist, not a scrub. No substring of the internal error is ever
   forwarded, so there is nothing to leak even for error shapes nobody
   anticipated. The raw text stays in structlog for the operator.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import select

from hyrule_cloud.db import VMEventRow
from hyrule_cloud.models import VMEventKey, VMLogEvent

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

log = structlog.get_logger()

# Cap on a single event's stored message. Messages are ours, not provider text,
# but the column is customer-visible and unbounded text is never worth it.
_MAX_MESSAGE = 500


class ProvisioningFailedError(RuntimeError):
    """A provisioning failure whose customer-facing message is already known.

    Raise this when the call site (not the exception type) knows which safe
    message applies. The `reason` is the fixed customer string; the cause chain
    keeps the internal detail for the operator log.
    """

    def __init__(self, customer_message: str) -> None:
        self.customer_message = customer_message
        super().__init__(customer_message)


# --- Fixed customer-facing failure messages (the entire allowlist) ---

FAILURE_GUEST_SETUP = (
    "Your setup script failed. The VM is retained for diagnosis; "
    "check /var/log/hyrule-setup.log in your VM. Contact support for recovery or refund status."
)
FAILURE_GUEST_INIT = (
    "Cloud-init did not complete successfully. The VM is retained for diagnosis; "
    "check cloud-init status in your VM. Contact support for recovery or refund status."
)
FAILURE_GUEST_REPORT = (
    "Guest initialization could not be verified before the deadline. "
    "The VM is retained for diagnosis. Contact support for recovery or refund status."
)
FAILURE_GUEST_RECOVERY = (
    "Provisioning was interrupted and needs operator recovery. "
    "Contact support for guest recovery or refund status."
)

FAILURE_TIMEOUT = (
    "Your VM did not come online within the provisioning window. "
    "The order was stopped. Contact support to review any payment or refund."
)
FAILURE_CAPACITY = (
    "There was not enough free capacity to build your VM. "
    "The order was stopped. Contact support to review any payment or refund."
)
FAILURE_DNS = (
    "Your VM's DNS record could not be published. "
    "The order was stopped. Contact support to review any payment or refund."
)
FAILURE_INTERNAL = (
    "Provisioning failed because of a problem on our side. "
    "The order was stopped. Contact support to review any payment or refund."
)


# Exact legacy public templates only: retain arbitrary operator diagnostics and
# stored history, but do not repeat an obsolete payment claim in new responses.
_LEGACY_FAILURE_MESSAGES = {
    message.replace(
        "The order was stopped. Contact support to review any payment or refund.",
        "The order was stopped and any payment is refunded.",
    ): message
    for message in (FAILURE_TIMEOUT, FAILURE_CAPACITY, FAILURE_DNS, FAILURE_INTERNAL)
}


def normalize_legacy_failure_message(message: str) -> str:
    return _LEGACY_FAILURE_MESSAGES.get(message, message)


# Deliberately NOT keyed on message text — only on exception type, so provider
# strings can never steer (or leak into) the customer-facing outcome. Failures
# that are only distinguishable by where they happened (DNS, network) are
# classified at the call site by raising ProvisioningFailedError.
_TYPE_NAME_MESSAGES: dict[str, str] = {
    "TimeoutError": FAILURE_TIMEOUT,
    "VMCapacityError": FAILURE_CAPACITY,
}


def customer_failure_message(error: BaseException | str | None) -> str:
    """Map an internal provisioning failure to a fixed customer-safe message.

    A plain string (legacy callers pass pre-formatted internal reasons) always
    collapses to the generic internal message — its content is never echoed.
    """
    if isinstance(error, ProvisioningFailedError):
        return error.customer_message
    if isinstance(error, BaseException):
        for klass in type(error).__mro__:
            mapped = _TYPE_NAME_MESSAGES.get(klass.__name__)
            if mapped is not None:
                return mapped
    return FAILURE_INTERNAL


def internal_failure_detail(error: BaseException) -> str:
    """Operator-facing description of a failure (logs + refund ledger only).

    NEVER store this on a customer-visible surface; use
    `customer_failure_message` for those.
    """
    cause = error.__cause__
    if cause is not None:
        return f"{type(error).__name__}: {error} <- {type(cause).__name__}: {cause}"
    return f"{type(error).__name__}: {error}"


async def record_vm_event(
    session_factory: async_sessionmaker[AsyncSession] | None,
    vm_id: str,
    event: VMEventKey,
    *,
    message: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append one customer-visible event. Never raises.

    Callers must pass only customer-safe content: this function does not (and
    cannot) know which parts of an arbitrary payload are internal.
    """
    if session_factory is None:
        return
    try:
        async with session_factory() as session:
            session.add(
                VMEventRow(
                    vm_id=vm_id,
                    event=str(event),
                    message=message[:_MAX_MESSAGE] if message else None,
                    detail=detail,
                )
            )
            await session.commit()
    except Exception:
        # An observability write must never fail a paid customer's VM. Note the
        # `vm_event` key: `event` is structlog's own reserved message field.
        log.warning("vm_event_write_failed", vm_id=vm_id, vm_event=str(event), exc_info=True)


async def list_vm_events(
    session_factory: async_sessionmaker[AsyncSession] | None,
    vm_id: str,
) -> list[VMEventRow]:
    """Read a VM's events in chronological order. Never raises."""
    if session_factory is None:
        return []
    try:
        async with session_factory() as session:
            result = await session.execute(
                select(VMEventRow)
                .where(VMEventRow.vm_id == vm_id)
                .order_by(VMEventRow.created_at, VMEventRow.event_id)
            )
            return list(result.scalars().all())
    except Exception:
        log.warning("vm_event_read_failed", vm_id=vm_id, exc_info=True)
        return []


async def vm_log_events(orchestrator: object, row: object) -> list[VMLogEvent]:
    """Build the `/logs` response events for a VM row.

    Back-compat: a VM provisioned before this feature (or one whose event writes
    were lost) has no stored events, so the legacy single `provisioning_started`
    entry derived from `created_at` is synthesized instead of returning nothing.
    """
    session_factory = getattr(orchestrator, "db", None)
    vm_id = str(getattr(row, "vm_id", "") or "")
    rows = await list_vm_events(session_factory, vm_id) if vm_id else []
    if rows:
        return [
            VMLogEvent(
                ts=r.created_at.isoformat(),
                event=r.event,
                message=r.message,
                detail=r.detail,
            )
            for r in rows
        ]
    created_at = getattr(row, "created_at", None)
    if created_at is None:
        return []
    return [
        VMLogEvent(
            ts=created_at.isoformat(),
            event=VMEventKey.PROVISIONING_STARTED,
            message="Provisioning started.",
        )
    ]
