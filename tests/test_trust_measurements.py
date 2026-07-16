"""Signed measurements (ed25519 response-body signatures) folded into the
trust layer. Covers the signer, the unified JWKS, the ASGI middleware, the
agent-registration advertisement, and the startup guard.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.config import HyruleConfig, TrustConfig
from hyrule_cloud.middleware.signing import ResponseSigningMiddleware
from hyrule_cloud.trust.identity import build_agent_registration, build_jwks
from hyrule_cloud.trust.measurements import (
    MeasurementSigner,
    enforce_measurement_key_guard,
    load_measurement_signer,
    verify_measurement_signature,
)

_SEED_B64 = base64.b64encode(bytes(range(32))).decode()


def _signer() -> MeasurementSigner:
    return MeasurementSigner(_SEED_B64)


def _trust_cfg(**kw) -> TrustConfig:
    return TrustConfig(
        measurement_signing_enabled=True,
        measurement_signing_key=_SEED_B64,
        **kw,
    )


# --- signer ------------------------------------------------------------------


def test_signer_roundtrip_and_tamper():
    signer = _signer()
    body = b'{"measured": true}'
    sig = signer.sign(body)
    assert verify_measurement_signature(signer.public_key_b64, body, sig) is True
    assert verify_measurement_signature(signer.public_key_b64, body + b"x", sig) is False


def test_default_kid_is_derived():
    assert _signer().key_id.startswith("hyr-meas-")
    assert MeasurementSigner(_SEED_B64, "custom-kid").key_id == "custom-kid"


def test_load_gated_on_flag_and_key():
    assert load_measurement_signer(TrustConfig()) is None  # disabled
    assert load_measurement_signer(TrustConfig(measurement_signing_enabled=True)) is None  # no key
    assert load_measurement_signer(_trust_cfg()) is not None


def test_startup_guard():
    enforce_measurement_key_guard(HyruleConfig())  # off -> no-op
    with pytest.raises(RuntimeError):
        enforce_measurement_key_guard(
            HyruleConfig(trust=TrustConfig(measurement_signing_enabled=True))
        )
    with pytest.raises(RuntimeError):
        enforce_measurement_key_guard(
            HyruleConfig(trust=TrustConfig(measurement_signing_enabled=True, measurement_signing_key="not-b64!"))
        )
    enforce_measurement_key_guard(HyruleConfig(trust=_trust_cfg()))  # valid -> no-op


# --- unified JWKS ------------------------------------------------------------


def test_jwks_includes_measurement_key_when_enabled():
    # No receipt keys, only a measurement signer: JWKS carries the OKP key.
    jwks = build_jwks(None, _trust_cfg(), measurement_signer=_signer())
    okp = [k for k in jwks["keys"] if k.get("kty") == "OKP"]
    assert len(okp) == 1
    assert okp[0]["crv"] == "Ed25519"
    assert okp[0]["alg"] == "EdDSA"
    # And is empty when nothing is configured (byte-identical-off invariant).
    assert build_jwks(None, TrustConfig(), measurement_signer=None)["keys"] == []


def test_agent_registration_advertises_signed_measurements_when_enabled():
    doc_off = build_agent_registration(TrustConfig(agent_card_enabled=True), public_base_url="https://x", api_version="1", keys=None)
    assert "signedMeasurements" not in doc_off
    doc_on = build_agent_registration(_trust_cfg(agent_card_enabled=True), public_base_url="https://x", api_version="1", keys=None)
    assert doc_on["signedMeasurements"]["algorithm"] == "ed25519"
    assert doc_on["signedMeasurements"]["jwks"].endswith("/.well-known/jwks.json")


# --- middleware --------------------------------------------------------------


def _mw_app(signer: MeasurementSigner | None) -> FastAPI:
    app = FastAPI()
    app.add_middleware(ResponseSigningMiddleware)
    app.state._typed_state = SimpleNamespace(trust=SimpleNamespace(measurements=signer))

    @app.post("/v1/dns/lookup")
    async def _paid_json():
        return JSONResponse({"measured": True})

    @app.post("/v1/mx/check")
    async def _paid_402():
        return JSONResponse({"payment_required": True}, status_code=402)

    @app.post("/v1/whois/lookup")
    async def _paid_text():
        return PlainTextResponse("not json")

    @app.get("/health")
    async def _free():
        return JSONResponse({"status": "ok"})

    return app


async def _req(app: FastAPI, path: str, method: str = "post"):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await getattr(client, method)(path)


@pytest.mark.asyncio
async def test_paid_2xx_json_signed_and_verifies():
    signer = _signer()
    res = await _req(_mw_app(signer), "/v1/dns/lookup")
    assert res.status_code == 200
    header = res.headers.get("hyrule-signature")
    assert header and header.startswith("ed25519=")
    assert res.headers.get("hyrule-signature-key") == signer.key_id
    assert verify_measurement_signature(signer.public_key_b64, res.content, header.split("=", 1)[1])
    assert "Hyrule-Signature" in res.headers.get("access-control-expose-headers", "")


@pytest.mark.asyncio
async def test_402_and_nonjson_and_free_not_signed():
    app = _mw_app(_signer())
    assert "hyrule-signature" not in (await _req(app, "/v1/mx/check")).headers
    assert "hyrule-signature" not in (await _req(app, "/v1/whois/lookup")).headers
    assert "hyrule-signature" not in (await _req(app, "/health", method="get")).headers


@pytest.mark.asyncio
async def test_no_signer_is_passthrough():
    res = await _req(_mw_app(None), "/v1/dns/lookup")
    assert res.status_code == 200
    assert "hyrule-signature" not in res.headers
