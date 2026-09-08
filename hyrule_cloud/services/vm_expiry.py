"""Customer-visible expiry policy; never infer the cause of a suspension."""
from datetime import UTC, datetime, timedelta

from hyrule_cloud.models import VMExpiryInfo, VMExpiryState, VMStatus


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def build_vm_expiry(
    status: VMStatus, expires_at: datetime | None, grace_period_hours: int,
    *, now: datetime | None = None, deletion_started_at: datetime | None = None,
) -> VMExpiryInfo:
    observed = _utc(now or datetime.now(UTC))
    if status == VMStatus.DESTROYED:
        return VMExpiryInfo(state=VMExpiryState.DESTROYED, observed_at=observed, message="The VM is destroyed.")
    if deletion_started_at is not None:
        return VMExpiryInfo(state=VMExpiryState.DELETING, observed_at=observed,
                            deletion_eligible=True,
                            message="VM deletion has started. Contact support for the remaining recovery options.")
    if status == VMStatus.FAILED:
        return VMExpiryInfo(state=VMExpiryState.NOT_APPLICABLE, observed_at=observed,
                            message="Automatic expiry processing does not apply to this failed VM.")
    if expires_at is None:
        return VMExpiryInfo(state=VMExpiryState.NOT_SET, observed_at=observed,
                            message="No expiry is recorded for this VM.")
    expiry = _utc(expires_at)
    grace_end = expiry + timedelta(hours=grace_period_hours)
    if observed <= expiry:
        state, message = VMExpiryState.ACTIVE, "The VM has not expired."
    elif observed <= grace_end:
        state, message = VMExpiryState.EXPIRED, "The VM has expired. Renew before the grace period ends to avoid deletion."
    else:
        state, message = VMExpiryState.DELETION_ELIGIBLE, "The grace period has ended. The VM is eligible for deletion; contact support immediately."
    return VMExpiryInfo(state=state, observed_at=observed, grace_ends_at=grace_end,
                        deletion_eligible=state == VMExpiryState.DELETION_ELIGIBLE, message=message)
