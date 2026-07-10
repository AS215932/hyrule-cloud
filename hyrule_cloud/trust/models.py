"""Protocol profile for the agent-trust layer.

Defines the shared vocabulary the trust layer speaks across all x402
services: the dual-signed receipt payload (the open
``x402-compute-fulfillment-receipt`` profile served to customers), the
caller-agent principal, and the x401 proof/read models.

``TransactionIntent`` is deliberately a *derived* read model: the proof,
payment, and fulfillment legs are correlated through the primary keys that
already exist (quote_id / vm_id / intent_id / job_id / domain) — there is no
persisted correlation table, so this model can never drift from the rows
that own the state.
"""

from __future__ import annotations

import enum
import secrets
import string

from pydantic import BaseModel, Field

RECEIPT_PROFILE = "x402-compute-fulfillment-receipt/0.1"

_BASE62_ALPHABET = string.ascii_letters + string.digits


def generate_receipt_id() -> str:
    """Generate a fresh `hyr_rcpt_<22 base62>` receipt id (~131 bits).

    Receipts are fetched by capability id alone (same philosophy as the anon
    VM management token), so the id space must be unguessable.
    """
    return "hyr_rcpt_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(22))


def generate_proof_token() -> str:
    """Generate a fresh `hyr_pf_<32 base62>` x401 proof token (~190 bits).

    Returned in cleartext exactly once by POST /v1/x401/proof; only the
    sha256 lands in x401_proof_tokens (repo-wide token convention).
    """
    return "hyr_pf_" + "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(32))


class ReceiptKind(enum.StrEnum):
    PAYMENT = "payment"
    FULFILLMENT = "fulfillment"
    REFUND = "refund"


class PaymentRail(enum.StrEnum):
    X402_EXACT_EVM = "x402-exact-evm"
    # Reserved for the Circle Gateway additive payment kind (roadmap M8).
    X402_GATEWAY = "x402-gateway"
    NATIVE_BTC = "native-btc"
    NATIVE_XMR = "native-xmr"
    DEV_BYPASS = "dev-bypass"


class ReceiptOutcome(enum.StrEnum):
    SETTLED = "settled"
    DELIVERED = "delivered"
    PROVISIONED = "provisioned"
    EXTENDED = "extended"
    FAILED = "failed"
    REFUND_OWED = "refund_owed"


class ReceiptIssuer(BaseModel):
    name: str
    url: str
    # CAIP-10 registry reference + on-chain agent id, present once the
    # ERC-8004 registration exists (config-sourced; never read from chain).
    agent_registry: str | None = None
    agent_id: int | None = None


class ReceiptResource(BaseModel):
    path: str
    method: str
    service_group: str
    description: str | None = None


class ReceiptPaymentLeg(BaseModel):
    rail: str
    network: str | None = None
    asset: str | None = None
    # Decimal string — receipts never carry JSON floats (see canonicalization
    # contract in trust/receipts.py).
    amount_usd: str | None = None
    # EVM rails only. Native BTC/XMR receipts carry NO payer address and NO
    # transaction reference in any form — a hashed txid is dictionary-
    # attackable against public chain data. Correlation for native rails is
    # the unguessable intent_id.
    payer: str | None = None
    tx_ref: str | None = None


class ReceiptCorrelation(BaseModel):
    quote_id: str | None = None
    vm_id: str | None = None
    intent_id: str | None = None
    job_id: str | None = None
    domain: str | None = None


class ReceiptOutcomeInfo(BaseModel):
    status: str
    detail: str | None = None
    simulated: bool = False


class ReceiptTiming(BaseModel):
    issued_at: str
    provision_started_at: str | None = None
    provisioned_at: str | None = None
    # Decimal string (seconds), not a float — canonicalization contract.
    provision_seconds: str | None = None


class ReceiptServiceInfo(BaseModel):
    api_version: str
    deployment_sha: str | None = None
    facilitator_host: str | None = None


class ReceiptAgent(BaseModel):
    """Caller-agent principal echoed into a receipt (M7 caller binding)."""

    did: str
    key_id: str | None = None
    verified: bool = False


class ReceiptPayload(BaseModel):
    """The exact signed document. `model_dump(mode="json")` of this model is
    what gets canonicalized, JWS-signed, and EIP-712-digest-signed."""

    profile: str = RECEIPT_PROFILE
    receipt_id: str
    kind: ReceiptKind
    issuer: ReceiptIssuer
    resource: ReceiptResource
    payment: ReceiptPaymentLeg
    correlation: ReceiptCorrelation = Field(default_factory=ReceiptCorrelation)
    outcome: ReceiptOutcomeInfo
    timing: ReceiptTiming
    service: ReceiptServiceInfo
    agent: ReceiptAgent | None = None
    # Optional service-specific evidence (e.g. artifact_sha256 for job
    # downloads). Values must obey the no-floats canonicalization contract.
    evidence: dict[str, str] | None = None


class AgentPrincipal(BaseModel):
    """A caller agent identified via RFC 9421 HTTP signature + did:web.

    Observe-only in this tranche: recorded on requests, ledger extras, and
    receipts; never used to allow or deny anything.
    """

    did: str
    key_id: str | None = None
    verified: bool = False


class ProofSatisfaction(BaseModel):
    """Outcome of an x401 proof verification bound to one quoted purchase."""

    policy_tier: str
    decision: str
    quote_hash: str | None = None
    route: str | None = None
    method: str | None = None
    agent_did: str | None = None
    claims: dict[str, str] | None = None
    expires_at: str | None = None


class TransactionIntent(BaseModel):
    """Derived correlation of the proof / payment / fulfillment legs.

    Assembled on demand from existing rows; never persisted (the quote,
    intent, VM, and receipt rows own their own state).
    """

    quote_id: str | None = None
    vm_id: str | None = None
    intent_id: str | None = None
    job_id: str | None = None
    domain: str | None = None
    proof_state: str = "not_required"
    payment_state: str = "unpaid"
    fulfillment_state: str = "pending"
    receipt_ids: list[str] = Field(default_factory=list)
