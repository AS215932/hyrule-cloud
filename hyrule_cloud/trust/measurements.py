"""Signed measurements — ed25519 response-body signatures.

Receipts (``receipts.py``) attest the *transaction*; this attests the
*measurement data*. When ``TRUST_MEASUREMENT_SIGNING_ENABLED`` is set, every
paid 2xx JSON response carries a detached ed25519 signature over its exact body
(``Hyrule-Signature`` header), so a buyer — or any third party — can prove the
result came from Hyrule and was not altered. The public key is published in the
same ``/.well-known/jwks.json`` as the receipt keys.

Flag-gated and soft-fail like the rest of the trust layer: unconfigured or
broken ⇒ no signing, no advertisement, never a broken response.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import TYPE_CHECKING, Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

if TYPE_CHECKING:
    from hyrule_cloud.config import HyruleConfig, TrustConfig

log = structlog.get_logger()


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_seed(value: str) -> bytes:
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        if len(raw) == 32:
            return raw
    raise ValueError("measurement signing key must be a base64-encoded 32-byte ed25519 seed")


class MeasurementSigner:
    """Signs response bodies with a single active ed25519 key."""

    def __init__(self, private_key_b64: str, key_id: str = ""):
        self._sk = Ed25519PrivateKey.from_private_bytes(_decode_seed(private_key_b64))
        self.key_id = key_id.strip() or self._default_kid()

    def _default_kid(self) -> str:
        return "hyr-meas-" + hashlib.sha256(self.public_key_raw).hexdigest()[:16]

    @property
    def public_key_raw(self) -> bytes:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_raw).decode("ascii")

    def sign(self, body: bytes) -> str:
        return base64.b64encode(self._sk.sign(body)).decode("ascii")

    def public_jwk(self) -> dict[str, str]:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_nopad(self.public_key_raw),
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.key_id,
        }


def verify_measurement_signature(public_key_b64: str, body: bytes, signature_b64: str) -> bool:
    """Verify a detached base64 signature against a base64 raw ed25519 pubkey."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), body)
        return True
    except Exception:
        return False


def load_measurement_signer(trust: TrustConfig) -> MeasurementSigner | None:
    """Build the active signer, or None when measurement signing is disabled or
    unconfigured. Soft-fail: a broken key logs and disables (the startup guard,
    not this loader, decides whether a broken key is fatal in production)."""
    if not trust.measurement_signing_enabled or not trust.measurement_signing_key:
        return None
    try:
        return MeasurementSigner(trust.measurement_signing_key, trust.measurement_signing_key_id)
    except Exception as exc:
        log.warning("measurement_signer_load_failed", error=str(exc))
        return None


def enforce_measurement_key_guard(config: HyruleConfig) -> None:
    """Fail fast at startup instead of silently shipping unsigned measurements.

    With TRUST_MEASUREMENT_SIGNING_ENABLED=true, refuse to boot unless the key
    loads — a deployment that advertises signed measurements but cannot sign
    them would break the trust contract quietly."""
    if not config.trust.measurement_signing_enabled:
        return
    if not config.trust.measurement_signing_key:
        raise RuntimeError(
            "TRUST_MEASUREMENT_SIGNING_ENABLED=true but TRUST_MEASUREMENT_SIGNING_KEY is empty"
        )
    try:
        MeasurementSigner(config.trust.measurement_signing_key, config.trust.measurement_signing_key_id)
    except Exception as exc:
        raise RuntimeError(
            f"TRUST_MEASUREMENT_SIGNING_ENABLED=true but the signing key is broken: {exc}"
        ) from exc


def measurement_jwks_entries(
    signer: MeasurementSigner | None, retired_jwks_json: str
) -> list[dict[str, Any]]:
    """Active measurement key first, then retired keys (old measurements stay
    verifiable after rotation). Reuses the trust retired-JWKS parser."""
    from hyrule_cloud.trust.identity import _retired_jwks

    entries: list[dict[str, Any]] = []
    if signer is not None:
        entries.append(signer.public_jwk())
    entries.extend(_retired_jwks(retired_jwks_json))
    return entries
