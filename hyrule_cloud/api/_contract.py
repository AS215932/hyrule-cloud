"""Shared helpers for contract-first network intelligence route skeletons."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.models import (
    DiagnosticJobResponse,
    DiagnosticJobStatus,
    PaidEndpointQuote,
    QuoteLineItem,
)


def now_utc() -> datetime:
    return datetime.now(UTC)


def config_from_request(request: Request) -> HyruleConfig:
    state = getattr(request.app.state, "_typed_state", None)
    cfg = getattr(state, "config", None)
    if cfg is not None:
        return cast(HyruleConfig, cfg)
    return HyruleConfig()


def payment_price(request: Request, attr: str, default: str) -> Decimal:
    cfg = config_from_request(request)
    payment = getattr(cfg, "payment", None)
    return Decimal(str(getattr(payment, attr, default)))


def quote(amount: Decimal, name: str, paid_endpoint: str, quantity: int = 1) -> PaidEndpointQuote:
    return PaidEndpointQuote(
        amount_usd=str(amount * quantity),
        billable_units=[
            QuoteLineItem(name=name, quantity=quantity, unit_price_usd=str(amount))
        ],
        paid_endpoint=paid_endpoint,
    )


def quote_lines(line_items: list[QuoteLineItem], paid_endpoint: str) -> PaidEndpointQuote:
    total = sum(
        Decimal(str(item.unit_price_usd)) * item.quantity
        for item in line_items
    )
    return PaidEndpointQuote(
        amount_usd=str(total),
        billable_units=line_items,
        paid_endpoint=paid_endpoint,
    )


def diagnostic_quote(
    request: Request,
    *,
    price_attr: str,
    default: str,
    name: str,
    paid_endpoint: str,
    quantity: int = 1,
) -> PaidEndpointQuote:
    return quote(payment_price(request, price_attr, default), name, paid_endpoint, quantity)


def diagnostic_job_response(
    *,
    service: str,
    kind: str,
    status: DiagnosticJobStatus = DiagnosticJobStatus.QUEUED,
    charged_amount_usd: Decimal | str | None = None,
    job_id: str | None = None,
    job_access_token: str | None = None,
    expires_at: datetime | None = None,
) -> DiagnosticJobResponse:
    job = DiagnosticJobResponse(
        service=service,
        kind=kind,
        status=status,
        job_access_token=job_access_token,
        charged_amount_usd=str(charged_amount_usd) if charged_amount_usd is not None else None,
        expires_at=expires_at,
    )
    if job_id is not None:
        job.job_id = job_id
    job.status_url = f"/v1/{service}/jobs/{job.job_id}"
    job.download_url = f"/v1/{service}/jobs/{job.job_id}/download"
    return job


async def require_paid_diagnostic(
    request: Request,
    *,
    price_attr: str,
    default: str,
    description: str,
    extra_body: dict[str, Any] | None = None,
) -> Response | None:
    amount = payment_price(request, price_attr, default)
    result = await require_payment(request, amount, description, extra_body or {})
    return result if isinstance(result, Response) else None


async def require_payment(
    request: Request,
    amount: Decimal,
    description: str,
    extra_body: dict[str, Any] | None = None,
) -> Response | str | None:
    """Run the configured PaymentGate, or return a local 402 when app state is not wired.

    Tests and OpenAPI generation often import the ASGI app without executing the
    lifespan that constructs AppState. In that case paid routes should still be
    safely closed instead of accidentally free.
    """
    state = getattr(request.app.state, "_typed_state", None)
    gate = getattr(state, "payment_gate", None)
    if gate is None:
        return JSONResponse(
            status_code=402,
            content={
                "payment_required": True,
                "amount": str(amount),
                "description": description,
            },
        )
    return cast(Response | str | None, await gate.check_payment(request, amount, description, extra_body or {}))


def not_implemented(service: str, detail: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {
        "error": "not_implemented",
        "service": service,
        "message": detail or "API contract is finalized; implementation is scheduled in a later plan step.",
    }
    return JSONResponse(status_code=501, content=body)
