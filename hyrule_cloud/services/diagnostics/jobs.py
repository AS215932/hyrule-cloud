"""Generic async diagnostic job helpers.

These helpers are intentionally small and product-neutral. Concrete APIs such
as /v1/web, /v1/path, /v1/voip, and /v1/speedtest can use them to issue the
same ownerless job id/token shape while storing the durable row in their route
or service layer.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from hyrule_cloud.models import (
    DiagnosticJobKind,
    DiagnosticJobResponse,
    DiagnosticJobStatus,
    generate_diagnostic_job_access_token,
    generate_diagnostic_job_id,
)


def hash_job_access_token(token: str) -> str:
    """Hash a high-entropy job access token for storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_job_identity() -> tuple[str, str, str]:
    """Return `(job_id, cleartext_token, token_hash)` for a new diagnostic job."""
    token = generate_diagnostic_job_access_token()
    return generate_diagnostic_job_id(), token, hash_job_access_token(token)


def build_job_response(
    *,
    service: str,
    kind: DiagnosticJobKind | str,
    job_id: str | None = None,
    job_access_token: str | None = None,
    status: DiagnosticJobStatus = DiagnosticJobStatus.QUEUED,
    charged_amount_usd: Decimal | str | None = None,
    ttl: timedelta = timedelta(hours=24),
    created_at: datetime | None = None,
    error: str | None = None,
) -> DiagnosticJobResponse:
    """Build the stable public response for an async diagnostic job."""
    created = created_at or datetime.now(UTC)
    job = DiagnosticJobResponse(
        job_id=job_id or generate_diagnostic_job_id(),
        job_access_token=job_access_token,
        service=service,
        kind=kind,
        status=status,
        charged_amount_usd=str(charged_amount_usd) if charged_amount_usd is not None else None,
        error=error,
        created_at=created,
        expires_at=created + ttl,
    )
    job.status_url = f"/v1/{service}/jobs/{job.job_id}"
    job.download_url = f"/v1/{service}/jobs/{job.job_id}/download"
    return job
