"""Agent identity surfaces.

M1: JWKS for offline receipt verification (/.well-known/jwks.json).
M3 adds the ERC-8004 agent card built from config — the app runtime never
reads chain state, so a registry outage can never affect service.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

if TYPE_CHECKING:
    from hyrule_cloud.config import TrustConfig
    from hyrule_cloud.trust.receipts import ReceiptSigningKeys

log = structlog.get_logger()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def es256_public_jwk(es256_pem: str, kid: str) -> dict[str, str]:
    """Public JWK (P-256 / ES256) for the given private PEM."""
    private_key = serialization.load_pem_private_key(es256_pem.encode(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("receipt signing key is not an EC key")
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
    }


def _retired_jwks(retired_json: str) -> list[dict[str, Any]]:
    """Parse TRUST_RECEIPT_RETIRED_JWKS_JSON — either a bare JWK list or a
    full {"keys": [...]} document. Malformed input is logged and ignored so
    a bad rotation entry can't take the JWKS endpoint down."""
    if not retired_json:
        return []
    try:
        parsed = json.loads(retired_json)
    except json.JSONDecodeError:
        log.warning("trust_retired_jwks_invalid_json")
        return []
    entries = parsed.get("keys") if isinstance(parsed, dict) else parsed
    if not isinstance(entries, list):
        log.warning("trust_retired_jwks_not_a_list")
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def build_jwks(keys: ReceiptSigningKeys | None, config: TrustConfig) -> dict[str, Any]:
    """Active signing key first, then retired keys (old receipts stay
    verifiable after rotation)."""
    entries: list[dict[str, Any]] = []
    if keys is not None:
        entries.append(es256_public_jwk(keys.es256_pem, keys.kid))
    entries.extend(_retired_jwks(config.receipt_retired_jwks_json))
    return {"keys": entries}
