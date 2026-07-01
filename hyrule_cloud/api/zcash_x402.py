"""Zcash x402 facilitator endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from x402.schemas import SettleRequest, VerifyRequest

from hyrule_cloud.payments.zcash import ZcashPaymentService
from hyrule_cloud.state import AppState, get_app_state

router = APIRouter(prefix="/x402/zcash")


def get_zcash_payment(request: Request) -> ZcashPaymentService:
    state: AppState = get_app_state(request)
    service = getattr(state, "zcash_payment", None)
    if service is None or not service.enabled:
        raise HTTPException(503, "Zcash x402 facilitator is not configured")
    return service


@router.get("/supported")
async def zcash_supported(service: ZcashPaymentService = Depends(get_zcash_payment)):
    return service.supported_response().model_dump(by_alias=True, exclude_none=True)


@router.post("/verify")
async def zcash_verify(
    body: VerifyRequest,
    service: ZcashPaymentService = Depends(get_zcash_payment),
):
    result = await service.verify(body.payment_payload, body.payment_requirements)
    return result.model_dump(by_alias=True, exclude_none=True)


@router.post("/settle")
async def zcash_settle(
    body: SettleRequest,
    service: ZcashPaymentService = Depends(get_zcash_payment),
):
    result = await service.settle(body.payment_payload, body.payment_requirements)
    return result.model_dump(by_alias=True, exclude_none=True)
