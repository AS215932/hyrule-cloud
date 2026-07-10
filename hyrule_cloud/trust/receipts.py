"""Dual-signed fulfillment receipts.

Every settled payment — and every asynchronous fulfillment outcome (VM
provisioned/failed, domain registered, job completed, refund owed) — can
mint a receipt carrying two independent signatures over one canonical
payload:

- an ES256 compact JWS (offline-verifiable from /.well-known/jwks.json
  alone), and
- an EIP-712 secp256k1 signature over a ``ReceiptDigest`` struct binding
  the sha256 of the same canonical bytes (verifiable by any EVM tooling and
  usable in ERC-8004 feedback), signed by a dedicated operational key that
  is never the registry-owner key.

Canonicalization contract: receipt payloads contain only strings, booleans,
null, objects, and arrays — amounts and durations are decimal STRINGS — so
compact sorted-key JSON is a faithful RFC 8785 (JCS) subset. ``canonical_
receipt_bytes`` rejects any float member outright.

Receipts are attestations, not the revenue ledger (payment_events remains
the source of truth). Minting is best-effort and bounded: a signing or
persistence failure must never break the payment or provisioning flow —
the receipt header is simply absent.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from eth_account import Account
from eth_account.messages import encode_typed_data
from jwt import api_jws
from sqlalchemy import select

from hyrule_cloud.db import FulfillmentReceiptRow
from hyrule_cloud.services.payments_ledger import service_group_for_path
from hyrule_cloud.trust.models import (
    RECEIPT_PROFILE,
    AgentPrincipal,
    ReceiptAgent,
    ReceiptCorrelation,
    ReceiptIssuer,
    ReceiptKind,
    ReceiptOutcomeInfo,
    ReceiptPayload,
    ReceiptPaymentLeg,
    ReceiptResource,
    ReceiptServiceInfo,
    ReceiptTiming,
    generate_receipt_id,
)

if TYPE_CHECKING:
    from eth_account.signers.local import LocalAccount
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from hyrule_cloud.config import HyruleConfig, TrustConfig

log = structlog.get_logger()

RECEIPT_HEADER = "HYRULE-RECEIPT"
LEGACY_RECEIPT_HEADER = "X-HYRULE-RECEIPT"

EIP712_DOMAIN_NAME = "HyruleCloudReceipt"
EIP712_DOMAIN_VERSION = "0.1"

# Mirrors PaymentGate._LEDGER_WRITE_TIMEOUT_SECONDS: a slow receipts table
# must never hold a settled response hostage.
_PERSIST_TIMEOUT_SECONDS = 2.0

_NATIVE_RAIL_PREFIX = "native-"


def _assert_no_floats(value: object, path: str = "$") -> None:
    if isinstance(value, float):
        raise ValueError(f"receipt payload contains a float at {path} — decimal strings only")
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_no_floats(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_floats(item, f"{path}[{index}]")


def canonical_receipt_bytes(payload: dict[str, Any]) -> bytes:
    """Compact sorted-key UTF-8 JSON — the exact bytes both signatures cover."""
    _assert_no_floats(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def receipt_digest_message(
    receipt_id: str, payload_sha256: bytes, issued_at: str
) -> dict[str, Any]:
    """EIP-712 typed message binding a receipt payload digest.

    Signing a digest struct instead of the full document keeps the typed
    data static while the payload schema evolves; verifiers recompute
    sha256(canonical bytes) and recover the signer.
    """
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
            ],
            "ReceiptDigest": [
                {"name": "receiptId", "type": "string"},
                {"name": "payloadSha256", "type": "bytes32"},
                {"name": "issuedAt", "type": "string"},
            ],
        },
        "primaryType": "ReceiptDigest",
        "domain": {"name": EIP712_DOMAIN_NAME, "version": EIP712_DOMAIN_VERSION},
        "message": {
            "receiptId": receipt_id,
            "payloadSha256": payload_sha256,
            "issuedAt": issued_at,
        },
    }


def _read_key_material(inline: str, path: str) -> str:
    """Key material from an env value (`\\n`-escaped, like CDP_API_KEY_SECRET)
    or from a file path; empty string when neither is configured."""
    if inline:
        return inline.replace("\\n", "\n")
    if path:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    return ""


@dataclass(frozen=True)
class ReceiptSigningKeys:
    es256_pem: str
    kid: str
    evm_account: LocalAccount

    @property
    def evm_signer(self) -> str:
        return str(self.evm_account.address)


def derive_kid(es256_pem: str) -> str:
    """`hyr-rcpt-<16 hex>` from sha256 of the public key's SPKI DER."""
    private_key = serialization.load_pem_private_key(es256_pem.encode(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise ValueError("TRUST receipt signing key must be an EC P-256 (secp256r1) key")
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "hyr-rcpt-" + hashlib.sha256(spki).hexdigest()[:16]


def load_signing_keys(trust: TrustConfig) -> ReceiptSigningKeys:
    """Load + validate both signing keys. Raises ValueError when either is
    missing or malformed — callers decide whether that is fatal (startup
    guard) or a soft disable (tests)."""
    es256_pem = _read_key_material(
        trust.receipt_signing_key_pem, trust.receipt_signing_key_path
    )
    if not es256_pem:
        raise ValueError("TRUST_RECEIPT_SIGNING_KEY_PEM / _PATH is not configured")
    kid = trust.receipt_key_id or derive_kid(es256_pem)

    evm_key = _read_key_material(
        trust.receipt_evm_signing_key, trust.receipt_evm_signing_key_path
    ).strip()
    if not evm_key:
        raise ValueError("TRUST_RECEIPT_EVM_SIGNING_KEY / _PATH is not configured")
    try:
        evm_account = Account.from_key(evm_key)
    except Exception as exc:
        raise ValueError(f"TRUST_RECEIPT_EVM_SIGNING_KEY is not a valid key: {exc}") from exc
    return ReceiptSigningKeys(es256_pem=es256_pem, kid=kid, evm_account=evm_account)


def enforce_trust_key_guard(config: HyruleConfig) -> None:
    """Fail fast at startup instead of silently minting no receipts.

    With TRUST_RECEIPTS_ENABLED=true, refuse to boot unless BOTH signing
    keys load and validate — a deployment that advertises receipts but
    cannot sign them would break the trust contract quietly.
    """
    if not config.trust.receipts_enabled:
        return
    try:
        load_signing_keys(config.trust)
    except ValueError as exc:
        raise RuntimeError(f"TRUST_RECEIPTS_ENABLED=true but receipt signing is broken: {exc}") from exc


@dataclass(frozen=True)
class SignedReceipt:
    receipt_id: str
    payload: dict[str, Any]
    jws: str
    kid: str
    evm_signer: str
    evm_signature: str


def verify_receipt_jws(jws: str, jwk: dict[str, Any]) -> dict[str, Any]:
    """Offline JWS verification from a JWK dict (as served by jwks.json).
    Returns the payload dict; raises on any signature/format problem."""
    import jwt as pyjwt

    key = pyjwt.PyJWK.from_dict(jwk).key
    payload_bytes = api_jws.decode(jws, key=key, algorithms=["ES256"])
    payload = json.loads(payload_bytes)
    if not isinstance(payload, dict):
        raise ValueError("receipt JWS payload is not a JSON object")
    return payload


def recover_receipt_signer(payload: dict[str, Any], evm_signature: str) -> str:
    """Recover the EIP-712 signer address from a receipt payload + signature."""
    digest = hashlib.sha256(canonical_receipt_bytes(payload)).digest()
    receipt_id = str(payload.get("receipt_id", ""))
    timing = payload.get("timing")
    issued_at = str(timing.get("issued_at", "")) if isinstance(timing, dict) else ""
    signable = encode_typed_data(
        full_message=receipt_digest_message(receipt_id, digest, issued_at)
    )
    return str(Account.recover_message(signable, signature=evm_signature))


class ReceiptService:
    """Builds, dual-signs, persists, and serves receipts. Never raises from
    ``mint`` — a broken trust layer must not break paid service."""

    def __init__(
        self,
        config: TrustConfig,
        session_factory: async_sessionmaker[AsyncSession] | None,
        *,
        public_base_url: str,
        api_version: str,
        keys: ReceiptSigningKeys | None,
    ) -> None:
        self.config = config
        self._session_factory = session_factory
        self.public_base_url = public_base_url.rstrip("/")
        self.api_version = api_version
        self.keys = keys
        self.enabled = bool(config.receipts_enabled and keys and session_factory)

    @property
    def jwks_url(self) -> str:
        return f"{self.public_base_url}/.well-known/jwks.json"

    def build_payload(
        self,
        *,
        receipt_id: str,
        kind: ReceiptKind,
        outcome: str,
        resource_path: str,
        method: str,
        rail: str,
        description: str | None = None,
        network: str | None = None,
        asset: str | None = None,
        amount_usd: Decimal | str | None = None,
        payer: str | None = None,
        tx_hash: str | None = None,
        quote_id: str | None = None,
        vm_id: str | None = None,
        intent_id: str | None = None,
        job_id: str | None = None,
        domain_fqdn: str | None = None,
        outcome_detail: str | None = None,
        simulated: bool = False,
        issued_at: datetime | None = None,
        provision_started_at: datetime | None = None,
        provisioned_at: datetime | None = None,
        facilitator_host: str | None = None,
        agent: AgentPrincipal | None = None,
        evidence: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        issued = issued_at or datetime.now(UTC)
        if rail.startswith(_NATIVE_RAIL_PREFIX):
            # Privacy invariant, enforced here regardless of caller input:
            # native-rail receipts never disclose the deposit address or the
            # on-chain transaction — not even hashed.
            payer = None
            tx_hash = None
        provision_seconds: str | None = None
        if provision_started_at is not None and provisioned_at is not None:
            delta = (provisioned_at - provision_started_at).total_seconds()
            provision_seconds = f"{delta:.3f}"
        payload = ReceiptPayload(
            profile=RECEIPT_PROFILE,
            receipt_id=receipt_id,
            kind=kind,
            issuer=ReceiptIssuer(
                name="Hyrule Cloud",
                url=self.public_base_url or "https://cloud.hyrule.host",
                agent_registry=self.config.erc8004_registry_caip10 or None,
                agent_id=self.config.erc8004_agent_id,
            ),
            resource=ReceiptResource(
                path=resource_path[:256],
                method=method[:8],
                service_group=service_group_for_path(resource_path),
                description=description or None,
            ),
            payment=ReceiptPaymentLeg(
                rail=rail,
                network=network,
                asset=asset,
                amount_usd=str(amount_usd) if amount_usd is not None else None,
                payer=payer,
                tx_ref=tx_hash or None,
            ),
            correlation=ReceiptCorrelation(
                quote_id=quote_id,
                vm_id=vm_id,
                intent_id=intent_id,
                job_id=job_id,
                domain=domain_fqdn,
            ),
            outcome=ReceiptOutcomeInfo(
                status=outcome, detail=outcome_detail, simulated=simulated
            ),
            timing=ReceiptTiming(
                issued_at=issued.isoformat(),
                provision_started_at=(
                    provision_started_at.isoformat() if provision_started_at else None
                ),
                provisioned_at=provisioned_at.isoformat() if provisioned_at else None,
                provision_seconds=provision_seconds,
            ),
            service=ReceiptServiceInfo(
                api_version=self.api_version,
                deployment_sha=self.config.deployment_sha or None,
                facilitator_host=facilitator_host,
            ),
            agent=(
                ReceiptAgent(did=agent.did, key_id=agent.key_id, verified=agent.verified)
                if agent
                else None
            ),
            evidence=evidence,
        )
        return payload.model_dump(mode="json")

    def sign(self, payload: dict[str, Any]) -> SignedReceipt:
        if self.keys is None:
            raise RuntimeError("receipt signing keys are not loaded")
        canonical = canonical_receipt_bytes(payload)
        jws = api_jws.encode(
            canonical,
            self.keys.es256_pem,
            algorithm="ES256",
            headers={"kid": self.keys.kid},
        )
        digest = hashlib.sha256(canonical).digest()
        receipt_id = str(payload["receipt_id"])
        timing = payload.get("timing")
        issued_at = str(timing.get("issued_at", "")) if isinstance(timing, dict) else ""
        signable = encode_typed_data(
            full_message=receipt_digest_message(receipt_id, digest, issued_at)
        )
        signed = self.keys.evm_account.sign_message(signable)
        return SignedReceipt(
            receipt_id=receipt_id,
            payload=payload,
            jws=jws,
            kid=self.keys.kid,
            evm_signer=self.keys.evm_signer,
            evm_signature="0x" + bytes(signed.signature).hex(),
        )

    async def mint(
        self,
        *,
        kind: ReceiptKind,
        outcome: str,
        resource_path: str,
        method: str,
        rail: str,
        description: str | None = None,
        network: str | None = None,
        asset: str | None = None,
        amount_usd: Decimal | str | None = None,
        payer: str | None = None,
        tx_hash: str | None = None,
        payment_event_id: str | None = None,
        quote_id: str | None = None,
        vm_id: str | None = None,
        intent_id: str | None = None,
        job_id: str | None = None,
        domain_fqdn: str | None = None,
        outcome_detail: str | None = None,
        simulated: bool = False,
        provision_started_at: datetime | None = None,
        provisioned_at: datetime | None = None,
        facilitator_host: str | None = None,
        agent: AgentPrincipal | None = None,
        evidence: dict[str, str] | None = None,
    ) -> str | None:
        """Build + dual-sign + persist a receipt. Returns the receipt id, or
        None when disabled or when anything fails (logged, never raised)."""
        if not self.enabled or self._session_factory is None:
            return None
        try:
            receipt_id = generate_receipt_id()
            payload = self.build_payload(
                receipt_id=receipt_id,
                kind=kind,
                outcome=outcome,
                resource_path=resource_path,
                method=method,
                rail=rail,
                description=description,
                network=network,
                asset=asset,
                amount_usd=amount_usd,
                payer=payer,
                tx_hash=tx_hash,
                quote_id=quote_id,
                vm_id=vm_id,
                intent_id=intent_id,
                job_id=job_id,
                domain_fqdn=domain_fqdn,
                outcome_detail=outcome_detail,
                simulated=simulated,
                provision_started_at=provision_started_at,
                provisioned_at=provisioned_at,
                facilitator_host=facilitator_host,
                agent=agent,
                evidence=evidence,
            )
            signed = self.sign(payload)
            payment_leg = payload["payment"]
            row = FulfillmentReceiptRow(
                receipt_id=receipt_id,
                kind=str(kind),
                resource_path=resource_path[:256],
                method=method[:8],
                service_group=service_group_for_path(resource_path),
                outcome=outcome[:24],
                rail=rail[:24],
                network=network,
                amount_usd=Decimal(str(amount_usd)) if amount_usd is not None else None,
                payer_wallet=payment_leg.get("payer"),
                tx_hash=payment_leg.get("tx_ref"),
                payment_event_id=payment_event_id,
                quote_id=quote_id,
                vm_id=vm_id,
                intent_id=intent_id,
                job_id=job_id,
                domain_fqdn=domain_fqdn,
                agent_did=agent.did[:256] if agent else None,
                key_id=signed.kid,
                evm_signer=signed.evm_signer,
                evm_signature=signed.evm_signature,
                payload=payload,
                jws=signed.jws,
            )
            await asyncio.wait_for(self._persist(row), timeout=_PERSIST_TIMEOUT_SECONDS)
            log.info(
                "receipt_minted",
                receipt_id=receipt_id,
                kind=str(kind),
                outcome=outcome,
                rail=rail,
                resource=resource_path,
            )
            return receipt_id
        except Exception:
            log.warning("receipt_mint_failed", resource=resource_path, exc_info=True)
            return None

    async def _persist(self, row: FulfillmentReceiptRow) -> None:
        assert self._session_factory is not None
        async with self._session_factory() as session:
            session.add(row)
            await session.commit()

    async def get(self, receipt_id: str) -> FulfillmentReceiptRow | None:
        if not self.enabled or self._session_factory is None:
            return None
        async with self._session_factory() as session:
            result = await session.execute(
                select(FulfillmentReceiptRow).where(
                    FulfillmentReceiptRow.receipt_id == receipt_id
                )
            )
            return result.scalar_one_or_none()

    async def list_for_vm(self, vm_id: str, limit: int = 50) -> list[FulfillmentReceiptRow]:
        if not self.enabled or self._session_factory is None:
            return []
        async with self._session_factory() as session:
            result = await session.execute(
                select(FulfillmentReceiptRow)
                .where(FulfillmentReceiptRow.vm_id == vm_id)
                .order_by(FulfillmentReceiptRow.created_at.asc())
                .limit(limit)
            )
            return list(result.scalars().all())
