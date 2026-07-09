"""Source-health helpers for diagnostic products."""

from __future__ import annotations

from datetime import UTC, datetime

from hyrule_cloud.models import SourceHealth, SourceStatus

# Statuses in which a source is actually configured AND able to return real
# data (possibly degraded). Everything else — not_configured, disabled,
# unavailable, error, unknown, informational — means "cannot answer", so a paid
# route backed only by such sources must 501 before charging.
# Statuses where a configured source can actually answer right now. STALE and
# DEGRADED still return (old/partial) data; RATE_LIMITED is deliberately
# EXCLUDED — a throttled source can't return fresh data, and these gates exist
# to 501 before charging when the backing source can't answer.
_USABLE_SOURCE_STATUSES = frozenset(
    {
        SourceStatus.OK,
        SourceStatus.STALE,
        SourceStatus.DEGRADED,
    }
)


def source_usable(health: SourceHealth) -> bool:
    """Whether a source is configured and can return real data right now."""
    return health.status in _USABLE_SOURCE_STATUSES


def _source(
    status: SourceStatus,
    *,
    age_seconds: int | None = None,
    message: str | None = None,
    source_url: str | None = None,
) -> SourceHealth:
    return SourceHealth(
        status=status,
        age_seconds=age_seconds,
        message=message,
        checked_at=datetime.now(UTC),
        source_url=source_url,
    )


def source_ok(*, age_seconds: int | None = None, source_url: str | None = None) -> SourceHealth:
    return _source(SourceStatus.OK, age_seconds=age_seconds, source_url=source_url)


def source_degraded(message: str, *, source_url: str | None = None) -> SourceHealth:
    return _source(SourceStatus.DEGRADED, message=message, source_url=source_url)


def source_unavailable(message: str, *, source_url: str | None = None) -> SourceHealth:
    return _source(SourceStatus.UNAVAILABLE, message=message, source_url=source_url)


def source_error(message: str, *, source_url: str | None = None) -> SourceHealth:
    return _source(SourceStatus.ERROR, message=message, source_url=source_url)


def source_disabled(message: str = "source disabled", *, source_url: str | None = None) -> SourceHealth:
    return _source(SourceStatus.DISABLED, message=message, source_url=source_url)


def source_not_configured(
    message: str = "source not configured",
    *,
    source_url: str | None = None,
) -> SourceHealth:
    return _source(SourceStatus.SOURCE_NOT_CONFIGURED, message=message, source_url=source_url)
