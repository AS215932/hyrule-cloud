"""Caller-agent binding: RFC 9421 HTTP Message Signatures → did:web.

Observe-only (TRUST_PRINCIPAL_MODE=observe): when a request carries
``Signature-Input``/``Signature`` headers whose keyid is a did:web key, the
resolver verifies the signature against the DID document's published key
and records an ``AgentPrincipal`` on ``request.state`` — flowing into the
payment ledger's ``extra`` and into receipts' ``agent`` field. It NEVER
blocks, NEVER authorizes, and every failure (parse, resolve, verify,
timeout) simply yields no principal.

Supported subset (minimum for agent workloads; extend deliberately):
- covered components: ``@method`` and ``@target-uri`` (exactly);
- signature params: ``created`` (required, ±300s skew), ``expires``
  (optional), ``keyid`` (required, ``did:web:<host>[:<path>...]#<frag>``,
  no ports), ``alg`` (``ed25519`` | ``ecdsa-p256-sha256``);
- DID document keys as ``publicKeyJwk`` (OKP/Ed25519 or EC/P-256).

did:web resolution reuses the repo SSRF guards (services/safety.py): the
DID host must resolve to public addresses only, with a hard timeout, a
body cap, and positive+negative TTL caches.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import time
from typing import TYPE_CHECKING, Any

import httpx
import structlog
from cachetools import TTLCache
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from fastapi import Request

from hyrule_cloud.services.safety import resolve_public_addresses
from hyrule_cloud.trust.models import AgentPrincipal

if TYPE_CHECKING:
    from hyrule_cloud.config import TrustConfig

log = structlog.get_logger()

SIGNATURE_INPUT_HEADER = "Signature-Input"
SIGNATURE_HEADER = "Signature"

_MAX_DID_DOCUMENT_BYTES = 64 * 1024
_CLOCK_SKEW_SECONDS = 300
_HTTP_TIMEOUT_SECONDS = 2.0


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def did_web_document_url(did: str) -> str | None:
    """did:web:<host>[:<segment>...] → HTTPS DID-document URL. Ports
    (percent-encoded colons) are rejected — Hyrule only resolves 443."""
    if not did.startswith("did:web:"):
        return None
    rest = did.removeprefix("did:web:")
    if not rest or "%3a" in rest.lower():
        return None
    parts = rest.split(":")
    host = parts[0].lower()
    if not host or "/" in host or "@" in host:
        return None
    if len(parts) == 1:
        return f"https://{host}/.well-known/did.json"
    path = "/".join(parts[1:])
    if not path or "//" in path:
        return None
    return f"https://{host}/{path}/did.json"


def _parse_structured_params(raw: str) -> dict[str, str]:
    """Parse `;key=value` params of a structured-field inner list (subset)."""
    params: dict[str, str] = {}
    for chunk in raw.split(";")[1:]:
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        params[key.strip()] = value.strip().strip('"')
    return params


def parse_signature_input(header: str) -> tuple[str, list[str], dict[str, str], str] | None:
    """First signature label of a Signature-Input header →
    (label, covered_components, params, inner_list_verbatim)."""
    header = header.strip()
    if "=(" not in header:
        return None
    label, _, remainder = header.partition("=")
    label = label.strip()
    if not label or ")" not in remainder:
        return None
    end = remainder.index(")")
    components_raw = remainder[1:end]
    components = [c.strip().strip('"') for c in components_raw.split() if c.strip()]
    params = _parse_structured_params(remainder[end:])
    inner_list = remainder  # verbatim value after `label=` — the exact bytes signed
    return label, components, params, inner_list


def parse_signature(header: str, label: str) -> bytes | None:
    """`label=:base64:` member of a Signature header."""
    for member in header.split(","):
        member = member.strip()
        if not member.startswith(f"{label}="):
            continue
        value = member[len(label) + 1 :].strip()
        if value.startswith(":") and value.endswith(":") and len(value) > 2:
            try:
                return base64.b64decode(value[1:-1], validate=True)
            except (binascii.Error, ValueError):
                return None
    return None


def build_signature_base(
    components: list[str], values: dict[str, str], inner_list: str
) -> str:
    lines = [f'"{name}": {values[name]}' for name in components]
    lines.append(f'"@signature-params": {inner_list}')
    return "\n".join(lines)


def _verify_with_jwk(jwk: dict[str, Any], base: bytes, signature: bytes, alg: str) -> bool:
    kty = jwk.get("kty")
    try:
        if kty == "OKP" and jwk.get("crv") == "Ed25519" and alg in ("", "ed25519"):
            key = ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(str(jwk["x"])))
            key.verify(signature, base)
            return True
        if kty == "EC" and jwk.get("crv") == "P-256" and alg in ("", "ecdsa-p256-sha256"):
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_b64url_decode(str(jwk["x"])), "big"),
                int.from_bytes(_b64url_decode(str(jwk["y"])), "big"),
                ec.SECP256R1(),
            )
            key_ec = numbers.public_key()
            if len(signature) != 64:
                return False
            der = asym_utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            key_ec.verify(der, base, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, KeyError, ValueError):
        return False
    return False


class AgentPrincipalResolver:
    """Resolves + verifies caller-agent signatures. Every path is soft-fail:
    the only outcomes are AgentPrincipal(...) or None."""

    def __init__(self, config: TrustConfig, *, public_base_url: str) -> None:
        self.config = config
        self.public_base_url = public_base_url.rstrip("/")
        # Positive cache: DID document JSON. Negative cache: resolution
        # failures, so an unreachable DID host can't be used to slow every
        # signed request down.
        self._documents: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=512, ttl=3600)
        self._failures: TTLCache[str, bool] = TTLCache(maxsize=512, ttl=300)

    async def resolve_principal(self, request: Request) -> AgentPrincipal | None:
        try:
            return await self._resolve(request)
        except Exception:
            log.warning("agent_principal_resolution_errored", exc_info=True)
            return None

    async def _resolve(self, request: Request) -> AgentPrincipal | None:
        signature_input = request.headers.get(SIGNATURE_INPUT_HEADER)
        signature_header = request.headers.get(SIGNATURE_HEADER)
        if not signature_input or not signature_header:
            return None
        parsed = parse_signature_input(signature_input)
        if parsed is None:
            return None
        label, components, params, inner_list = parsed
        keyid = params.get("keyid", "")
        if not keyid.startswith("did:web:") or "#" not in keyid:
            return None
        did = keyid.split("#", 1)[0]

        # Anything from here on identifies a did:web caller; a failed
        # verification is still recorded as an UNVERIFIED principal so
        # shadow analytics can see attempted-but-broken bindings.
        unverified = AgentPrincipal(did=did, key_id=keyid, verified=False)

        if set(components) != {"@method", "@target-uri"}:
            return unverified
        created = params.get("created", "")
        if not created.isdigit():
            return unverified
        now = time.time()
        if int(created) > now + _CLOCK_SKEW_SECONDS:
            return unverified
        expires = params.get("expires", "")
        if expires.isdigit() and int(expires) < now - _CLOCK_SKEW_SECONDS:
            return unverified
        signature = parse_signature(signature_header, label)
        if signature is None:
            return unverified

        jwk = await self._key_for(keyid)
        if jwk is None:
            return unverified

        alg = params.get("alg", "")
        # The caller signed the target URI it addressed; behind the TLS
        # proxy the raw request URL differs from the canonical public one,
        # so accept either.
        query = f"?{request.url.query}" if request.url.query else ""
        candidates = [str(request.url)]
        if self.public_base_url:
            candidates.insert(0, f"{self.public_base_url}{request.url.path}{query}")
        for target_uri in candidates:
            base = build_signature_base(
                components,
                {"@method": request.method.upper(), "@target-uri": target_uri},
                inner_list,
            )
            if _verify_with_jwk(jwk, base.encode(), signature, alg):
                return AgentPrincipal(did=did, key_id=keyid, verified=True)
        return unverified

    async def _key_for(self, keyid: str) -> dict[str, Any] | None:
        did = keyid.split("#", 1)[0]
        document = await self._document_for(did)
        if document is None:
            return None
        fragment = keyid.split("#", 1)[1]
        methods = document.get("verificationMethod")
        if not isinstance(methods, list):
            return None
        for method in methods:
            if not isinstance(method, dict):
                continue
            method_id = str(method.get("id", ""))
            if method_id not in (keyid, f"#{fragment}"):
                continue
            jwk = method.get("publicKeyJwk")
            if isinstance(jwk, dict):
                return jwk
        return None

    async def _document_for(self, did: str) -> dict[str, Any] | None:
        cached = self._documents.get(did)
        if cached is not None:
            return cached
        if self._failures.get(did):
            return None
        url = did_web_document_url(did)
        if url is None:
            self._failures[did] = True
            return None
        host = httpx.URL(url).host
        try:
            # SSRF pre-flight: the DID host must resolve publicly. getaddrinfo
            # blocks, so keep it off the event loop and inside the timeout.
            await asyncio.wait_for(
                asyncio.to_thread(resolve_public_addresses, host),
                timeout=_HTTP_TIMEOUT_SECONDS,
            )
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False
            ) as client:
                response = await client.get(url)
            if response.status_code != 200:
                raise ValueError(f"did document HTTP {response.status_code}")
            if len(response.content) > _MAX_DID_DOCUMENT_BYTES:
                raise ValueError("did document too large")
            document = response.json()
            if not isinstance(document, dict):
                raise ValueError("did document is not an object")
        except Exception as exc:  # UnsafeTargetError included — one soft-fail path
            log.info("did_web_resolution_failed", did=did, error=str(exc))
            self._failures[did] = True
            return None
        self._documents[did] = document
        return document
