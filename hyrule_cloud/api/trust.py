"""Trust-layer endpoints: receipt retrieval + JWKS.

M3 adds /.well-known/agent-card.json here; M6 adds POST /v1/x401/proof.
All responses are sanitized by construction: a receipt response contains
nothing beyond the signed payload, its signatures, and the verification
pointers — no management tokens, no native-rail payment details.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from hyrule_cloud.trust.identity import build_agent_registration, build_jwks
from hyrule_cloud.trust.x401 import (
    PROOF_RESULT_HEADER,
    X401_VERSION,
    b64url_encode_json,
    quote_hash,
)

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
        content=build_jwks(
            trust.receipts.keys,
            trust.receipts.config,
            measurement_signer=getattr(trust, "measurements", None),
        )
    )


class X401ProofSubmission(BaseModel):
    """PROOF-RESPONSE presentation for one quoted purchase.

    The binding fields must repeat exactly what the PROOF-REQUEST was issued
    for — the verification token is scoped to sha256(quote|amount|route|
    method) and is useless for any other purchase.
    """

    route: str = Field(default="/v1/vm/create")
    method: str = Field(default="POST")
    quote_id: str | None = None
    amount_usd: str | None = None
    # x401 v0.2 Result Artifact (credential_result / credential_result_uri).
    result_artifact: dict[str, Any]


def _proof_result_headers(payload: dict[str, Any]) -> dict[str, str]:
    return {PROOF_RESULT_HEADER: b64url_encode_json(payload)}


@router.post("/v1/x401/proof")
async def x401_proof(body: X401ProofSubmission, request: Request) -> JSONResponse:
    """Verify an x401 Result Artifact and issue a short-lived verification
    token bound to the quoted purchase. 404 while TRUST_X401_MODE=off."""
    trust = _trust_from_request(request)
    x401 = getattr(trust, "x401", None)
    if x401 is None or not x401.enabled:
        return _not_found()

    amount: Decimal | None = None
    if body.amount_usd is not None:
        try:
            amount = Decimal(body.amount_usd)
        except InvalidOperation:
            return JSONResponse(status_code=422, content={"error": "invalid amount_usd"})

    claims = await x401.verifier.verify(body.result_artifact)
    if claims is None:
        # Honest failure: either the artifact is malformed, or no real
        # credential verifier is configured yet (StructuralVerifier only
        # satisfies under the test-only TRUST_X401_ACCEPT_STRUCTURAL flag).
        error_payload = {
            "scheme": "x401",
            "version": X401_VERSION,
            "error": "verification_unavailable_or_failed",
            "detail": (
                "The presented Result Artifact was not accepted. No external "
                "credential verifier is configured on this deployment yet."
            ),
        }
        return JSONResponse(
            status_code=503,
            content=error_payload,
            headers=_proof_result_headers(error_payload),
        )

    bound = quote_hash(
        quote_id=body.quote_id, amount=amount, route=body.route, method=body.method
    )
    token = await x401.issue_proof_token(
        bound_quote_hash=bound, route=body.route, method=body.method, claims=claims
    )
    token_object = {
        "scheme": "x401",
        "version": X401_VERSION,
        "verification_token": token,
    }
    result_payload = {
        "scheme": "x401",
        "version": X401_VERSION,
        "result": "satisfied",
        "claims": claims,
        "expires_in": x401.config.x401_proof_token_ttl_seconds,
    }
    return JSONResponse(
        content={
            **result_payload,
            # One-shot cleartext; retry the purchase with this in the
            # PROOF-RESPONSE request header (base64url token_object).
            "verification_token": token,
            "proof_response_header": b64url_encode_json(token_object),
        },
        headers=_proof_result_headers(result_payload),
    )
