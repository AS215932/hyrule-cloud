"""Trust-layer endpoints: receipt retrieval + JWKS.

M3 adds /.well-known/agent-card.json here; M6 adds POST /v1/x401/proof.
All responses are sanitized by construction: a receipt response contains
nothing beyond the signed payload, its signatures, and the verification
pointers — no management tokens, no native-rail payment details.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from hyrule_cloud.trust.identity import build_agent_registration, build_jwks

if TYPE_CHECKING:
    from hyrule_cloud.trust import TrustServices

router = APIRouter(tags=["trust"])


def _trust_from_request(request: Request) -> TrustServices | None:
    state = getattr(request.app.state, "_typed_state", None)
    return getattr(state, "trust", None)


def _not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "not_found"})


@router.get("/v1/receipts/{receipt_id}")
async def get_receipt(receipt_id: str, request: Request) -> JSONResponse:
    """Fetch a dual-signed receipt by its unguessable capability id.

    Public by design (same philosophy as anon management tokens): the id is
    the credential. Verify offline: the `jws` against `jwks_url`, and the
    EIP-712 `evm_signature` by recovering `evm_signer` from the sha256 of
    the canonical payload bytes.
    """
    trust = _trust_from_request(request)
    if trust is None or not trust.receipts.enabled:
        return _not_found()
    row = await trust.receipts.get(receipt_id)
    if row is None:
        return _not_found()
    body: dict[str, Any] = {
        "receipt_id": row.receipt_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "payload": row.payload,
        "jws": row.jws,
        "evm_signer": row.evm_signer,
        "evm_signature": row.evm_signature,
        "jwks_url": trust.receipts.jwks_url,
        "profile": "x402-compute-fulfillment-receipt/0.1",
    }
    return JSONResponse(content=body)


@router.get("/.well-known/agent-registration.json")
async def agent_registration(request: Request) -> JSONResponse:
    """ERC-8004 agent registration document (same-origin proof of endpoint
    control). Served only when TRUST_AGENT_CARD_ENABLED; built from config,
    never from chain state."""
    trust = _trust_from_request(request)
    if trust is None or not trust.receipts.config.agent_card_enabled:
        return _not_found()
    service = trust.receipts
    return JSONResponse(
        content=build_agent_registration(
            service.config,
            public_base_url=service.public_base_url,
            api_version=service.api_version,
            keys=service.keys,
        )
    )


@router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    """Receipt-verification keys: active signing key first, then retired
    keys so pre-rotation receipts stay verifiable. Empty key set while
    receipts are disabled."""
    trust = _trust_from_request(request)
    if trust is None:
        return JSONResponse(content={"keys": []})
    return JSONResponse(
        content=build_jwks(trust.receipts.keys, trust.receipts.config)
    )
