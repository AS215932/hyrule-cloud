"""ed25519 response signing — the x402 trust layer.

Hyrule Cloud signs the exact bytes of every paid 2xx JSON response so a buyer
(or a third party) can prove a measurement came from Hyrule and was not altered
in transit. The signature is detached (over the raw body) and carried in
response headers; the public key is published at
``/.well-known/hyrule-signing-key.json`` and referenced from the manifest.

Signing is optional: an unconfigured key disables it (no headers, no manifest
advertisement) so the feature ships dark until an operator provisions a key.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

log = structlog.get_logger()


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_seed(value: str) -> bytes:
    """Decode a 32-byte ed25519 seed from base64 (std or url, padded or not)."""
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        if len(raw) == 32:
            return raw
    raise ValueError("response signing key must be a base64-encoded 32-byte ed25519 seed")


class ResponseSigner:
    """Signs response bodies with a single active ed25519 key."""

    def __init__(self, private_key_b64: str, key_id: str):
        if not key_id.strip():
            raise ValueError("response signing key id is required")
        self._sk = Ed25519PrivateKey.from_private_bytes(_decode_seed(private_key_b64))
        self.key_id = key_id.strip()

    @property
    def public_key_raw(self) -> bytes:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_key_b64(self) -> str:
        # Standard base64 (padded) — matches what the signature header consumer
        # gets and what most ed25519 verifiers expect.
        return base64.b64encode(self.public_key_raw).decode("ascii")

    def sign(self, body: bytes) -> str:
        """Return the base64 detached signature over ``body``."""
        return base64.b64encode(self._sk.sign(body)).decode("ascii")


def verify_signature(public_key_b64: str, body: bytes, signature_b64: str) -> bool:
    """Verify a detached base64 signature against a base64 raw ed25519 pubkey."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), body)
        return True
    except Exception:
        return False


def load_signer(config: object) -> ResponseSigner | None:
    """Build the active signer from config, or None when signing is unconfigured."""
    key = getattr(config, "response_signing_key", "") or ""
    key_id = getattr(config, "response_signing_key_id", "") or ""
    if not key or not key_id:
        return None
    try:
        return ResponseSigner(key, key_id)
    except Exception as exc:
        log.warning("response_signer_load_failed", error=str(exc))
        return None


def signing_key_document(signer: ResponseSigner) -> dict[str, Any]:
    """The published key document served at /.well-known/hyrule-signing-key.json.

    Carries both a JWK (OKP/Ed25519) and the raw base64 public key so a verifier
    can use whichever it prefers. Rotation is dual-publish: add the retiring key
    to ``keys`` alongside the new one until all buyers have refreshed.
    """
    return {
        "algorithm": "ed25519",
        "signatureHeader": "Hyrule-Signature",
        "signatureFormat": "ed25519=<base64 detached signature over the exact response body bytes>",
        "keyIdHeader": "Hyrule-Signature-Key",
        "activeKeyId": signer.key_id,
        "keys": [
            {
                "kid": signer.key_id,
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": _b64url_nopad(signer.public_key_raw),
                "publicKeyBase64": signer.public_key_b64,
            }
        ],
    }
