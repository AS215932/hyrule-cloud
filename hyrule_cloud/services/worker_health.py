"""DB-backed readiness for the native-payment/domain worker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from hyrule_cloud.db import ServiceHeartbeatRow

PAYMENT_WORKER_SERVICE = "hyrule-cloud-worker"


@dataclass(frozen=True)
class WorkerHealth:
    ready: bool
    last_seen_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def record_payment_worker_heartbeat(
    session_factory: Any,
    *,
    worker_id: str,
    scan_succeeded: bool,
    error: str | None = None,
    now: datetime | None = None,
) -> None:
    observed = now or datetime.now(UTC)
    async with session_factory() as session:
        row = await session.get(ServiceHeartbeatRow, PAYMENT_WORKER_SERVICE)
        if row is None:
            row = ServiceHeartbeatRow(
                service_name=PAYMENT_WORKER_SERVICE,
                worker_id=worker_id,
                last_seen_at=observed,
                last_success_at=observed if scan_succeeded else None,
                last_error=None if scan_succeeded else (error or "intent scan failed"),
            )
            session.add(row)
        else:
            row.worker_id = worker_id
            row.last_seen_at = observed
            if scan_succeeded:
                row.last_success_at = observed
                row.last_error = None
            else:
                row.last_error = error or "intent scan failed"
        await session.commit()


async def payment_worker_health(
    session_factory: Any,
    *,
    max_age_seconds: int,
    now: datetime | None = None,
) -> WorkerHealth:
    if session_factory is None:
        return WorkerHealth(ready=False, last_error="worker heartbeat storage unavailable")
    observed = now or datetime.now(UTC)
    async with session_factory() as session:
        row = await session.get(ServiceHeartbeatRow, PAYMENT_WORKER_SERVICE)
    if row is None:
        return WorkerHealth(ready=False, last_error="worker heartbeat not observed")
    last_seen = _utc(row.last_seen_at)
    last_success = _utc(row.last_success_at)
    fresh = bool(last_seen and last_seen >= observed - timedelta(seconds=max_age_seconds))
    successful = bool(
        last_success and last_success >= observed - timedelta(seconds=max_age_seconds)
    )
    return WorkerHealth(
        ready=fresh and successful and not row.last_error,
        last_seen_at=last_seen,
        last_success_at=last_success,
        last_error=row.last_error,
    )
