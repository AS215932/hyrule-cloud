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


# ERC-8004 registration document type, pinned to the draft as of 2026-07-10
# (eips.ethereum.org/EIPS/eip-8004, Draft created 2025-08-13). The spec is
# still moving — re-verify the well-known filename and required fields
# against the current draft before flipping TRUST_AGENT_CARD_ENABLED on a
# new deployment.
REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
REGISTRATION_WELL_KNOWN_PATH = "/.well-known/agent-registration.json"


def build_agent_registration(
    config: TrustConfig,
    *,
    public_base_url: str,
    api_version: str,
    keys: ReceiptSigningKeys | None,
) -> dict[str, Any]:
    """ERC-8004 agent registration document for the Hyrule Cloud
    Provisioning Agent.

    Built purely from config — never from chain reads — so a registry or
    RPC outage can never affect this endpoint (soft-fail invariant). The
    same-origin serving location is what proves domain control to registry
    consumers; `registrations` appears only once the on-chain ceremony
    (scripts/erc8004_register.py, human-controlled) has produced an agentId.

    Domain policy (AGENTS.md): this is customer-facing Hyrule Cloud
    identity — it lives under hyrule.host, never servify.network or
    as215932.net.
    """
    base = public_base_url.rstrip("/")
    document: dict[str, Any] = {
        "type": REGISTRATION_TYPE,
        "name": "Hyrule Cloud Provisioning Agent",
        "description": (
            "Full-stack network infrastructure for AI agents on AS215932: "
            "bare IPv6-native VMs with SSH, registered domains and "
            "authoritative DNS, network-intelligence diagnostics, and "
            "proxied egress — every service paid per request via x402 and "
            "attested by dual-signed fulfillment receipts."
        ),
        "image": f"{base}/apple-touch-icon.png",
        "services": [
            {"name": "web", "endpoint": base},
            {"name": "OpenAPI", "endpoint": f"{base}/openapi.json", "version": api_version},
            {"name": "x402", "endpoint": f"{base}/.well-known/x402.json"},
            {"name": "receipts", "endpoint": f"{base}/v1/receipts/{{receipt_id}}"},
            {"name": "jwks", "endpoint": f"{base}/.well-known/jwks.json"},
        ],
        "active": True,
        "x402Support": True,
    }
    if config.erc8004_registry_caip10 and config.erc8004_agent_id is not None:
        document["registrations"] = [
            {
                "agentId": config.erc8004_agent_id,
                "agentRegistry": config.erc8004_registry_caip10,
            }
        ]
    # supportedTrust is deliberately ABSENT until the receipt-backed
    # feedback tooling (roadmap M9) actually implements a trust model —
    # advertise only what is real.
    if config.receipts_enabled:
        document["receipts"] = {
            "profile": "x402-compute-fulfillment-receipt/0.1",
            "jwks": f"{base}/.well-known/jwks.json",
            "receiptSigners": [keys.evm_signer] if keys is not None else [],
        }
    return document
