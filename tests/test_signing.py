"""Phase 4b: ed25519 signed measurements (the x402 trust layer).

Covers the signer/verifier, the published key document, the ASGI middleware
(paid 2xx JSON is signed and verifies; 402/501/non-JSON/free paths are not),
and the manifest + well-known advertisement.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.middleware.signing import ResponseSigningMiddleware
from hyrule_cloud.services.discovery import build_x402_manifest
from hyrule_cloud.services.signing import (
    ResponseSigner,
    load_signer,
    signing_key_document,
    verify_signature,
)

_SEED_B64 = base64.b64encode(bytes(range(32))).decode()
_KEY_ID = "hyrule-test-2026-07"


def _signer() -> ResponseSigner:
    return ResponseSigner(_SEED_B64, _KEY_ID)


# --- signer / verifier -------------------------------------------------------


def test_signer_roundtrip_verifies():
    signer = _signer()
    body = b'{"measured": true}'
    signature = signer.sign(body)
    assert verify_signature(signer.public_key_b64, body, signature) is True
    # Tampered body fails.
    assert verify_signature(signer.public_key_b64, body + b" ", signature) is False


def test_signer_rejects_bad_seed():
    with pytest.raises(ValueError):
        ResponseSigner(base64.b64encode(b"tooshort").decode(), _KEY_ID)
    with pytest.raises(ValueError):
        ResponseSigner(_SEED_B64, "   ")


def test_load_signer_disabled_when_unconfigured():
    assert load_signer(HyruleConfig()) is None
    assert load_signer(HyruleConfig(response_signing_key=_SEED_B64)) is None  # no key id
    signer = load_signer(
        HyruleConfig(response_signing_key=_SEED_B64, response_signing_key_id=_KEY_ID)
    )
    assert signer is not None and signer.key_id == _KEY_ID


def test_signing_key_document_shape():
    doc = signing_key_document(_signer())
    assert doc["algorithm"] == "ed25519"
    assert doc["activeKeyId"] == _KEY_ID
    key = doc["keys"][0]
    assert key["kid"] == _KEY_ID
    assert key["crv"] == "Ed25519"
    # The published raw key must verify a real signature.
    signer = _signer()
    body = b'{"x": 1}'
    assert verify_signature(key["publicKeyBase64"], body, signer.sign(body)) is True


# --- middleware --------------------------------------------------------------


def _mw_app(signer: ResponseSigner | None) -> FastAPI:
    test_app = FastAPI()
    test_app.add_middleware(ResponseSigningMiddleware)
    test_app.state._typed_state = SimpleNamespace(response_signer=signer)

    # /v1/dns/lookup is an enabled paid catalog op -> signable.
    @test_app.post("/v1/dns/lookup")
    async def _paid_json():
        return JSONResponse({"measured": True, "answers": ["2001:db8::1"]})

    # A paid op returning 402 (unpaid) -> must NOT be signed.
    @test_app.post("/v1/mx/check")
    async def _paid_402():
        return JSONResponse({"payment_required": True}, status_code=402)

    # A paid op returning non-JSON -> must NOT be signed.
    @test_app.post("/v1/whois/lookup")
    async def _paid_text():
        return PlainTextResponse("not json")

    # A free (non-catalog) endpoint -> must NOT be signed.
    @test_app.get("/health")
    async def _free_json():
        return JSONResponse({"status": "ok"})

    return test_app


async def _post(test_app: FastAPI, path: str, method: str = "post"):
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        return await getattr(client, method)(path)


@pytest.mark.asyncio
async def test_paid_2xx_json_is_signed_and_verifies():
    signer = _signer()
    res = await _post(_mw_app(signer), "/v1/dns/lookup")
    assert res.status_code == 200
    sig_header = res.headers.get("hyrule-signature")
    assert sig_header and sig_header.startswith("ed25519=")
    assert res.headers.get("hyrule-signature-key") == _KEY_ID
    signature = sig_header.split("=", 1)[1]
    # Verifies against the exact bytes the client received.
    assert verify_signature(signer.public_key_b64, res.content, signature) is True
    # And is exposed for CORS readers.
    assert "Hyrule-Signature" in res.headers.get("access-control-expose-headers", "")


@pytest.mark.asyncio
async def test_402_response_is_not_signed():
    res = await _post(_mw_app(_signer()), "/v1/mx/check")
    assert res.status_code == 402
    assert "hyrule-signature" not in res.headers


@pytest.mark.asyncio
async def test_non_json_paid_response_is_not_signed():
    res = await _post(_mw_app(_signer()), "/v1/whois/lookup")
    assert res.status_code == 200
    assert "hyrule-signature" not in res.headers


@pytest.mark.asyncio
async def test_free_endpoint_is_not_signed():
    res = await _post(_mw_app(_signer()), "/health", method="get")
    assert res.status_code == 200
    assert "hyrule-signature" not in res.headers


@pytest.mark.asyncio
async def test_no_signer_means_no_headers():
    res = await _post(_mw_app(None), "/v1/dns/lookup")
    assert res.status_code == 200
    assert "hyrule-signature" not in res.headers


# --- manifest + well-known advertisement -------------------------------------


def test_manifest_advertises_signing_key_only_when_configured():
    assert "signingKey" not in build_x402_manifest(HyruleConfig())
    cfg = HyruleConfig(response_signing_key=_SEED_B64, response_signing_key_id=_KEY_ID)
    signing_key = build_x402_manifest(cfg)["signingKey"]
    assert signing_key["algorithm"] == "ed25519"
    assert signing_key["keyId"] == _KEY_ID
    assert signing_key["wellKnown"] == "/.well-known/hyrule-signing-key.json"


@pytest.mark.asyncio
async def test_well_known_key_route_reflects_configuration():
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        # Not configured -> 404.
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            missing = await client.get("/.well-known/hyrule-signing-key.json")
        # Configured -> serves the key.
        app.state._typed_state = SimpleNamespace(config=HyruleConfig(), response_signer=_signer())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            present = await client.get("/.well-known/hyrule-signing-key.json")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")
    assert missing.status_code == 404
    assert present.status_code == 200
    assert present.json()["activeKeyId"] == _KEY_ID
