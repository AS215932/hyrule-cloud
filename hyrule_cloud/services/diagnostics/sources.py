"""Source-health helpers for diagnostic products."""

from __future__ import annotations

from datetime import UTC, datetime

from hyrule_cloud.models import SourceHealth, SourceStatus


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
