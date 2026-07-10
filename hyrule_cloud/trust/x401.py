"""x401 identity-proof layer: policy engine, shadow observer, proof tokens.

x401 answers the question payment cannot: who AUTHORIZED an agent to obtain
this resource. Hyrule applies it as risk-triggered step-up on elevated VM
purchases only — discovery, quotes, and ordinary low-value buys stay
identity-free, and native/privacy rails are never singled out.

Spec pin (verified 2026-07-10): x401 v0.2.0 —
- Headers ``PROOF-REQUEST`` / ``PROOF-RESPONSE`` / ``PROOF-RESULT`` carry
  base64url-encoded UTF-8 JSON (RFC 4648 §5, no padding).
- The PROOF-REQUEST header is authoritative; HTTP status codes do not by
  themselves define x401 proof state (401 is the conventional carrier).
- Requested claims ride an OpenID4VP ``dcql_query`` inside
  ``credential_requirements.digital.requests[].data``.
- The retry carries a Result Artifact or an x401 Token Object in the
  ``PROOF-RESPONSE`` REQUEST header. Hyrule issues its short-lived
  verification token as Token Object member ``verification_token``
  (tolerant parse: ``token`` also accepted) — re-verify the exact member
  names against the current spec before flipping TRUST_X401_MODE=enforce.

Modes: ``off`` (no code path runs), ``shadow`` (evaluate + log what
enforcement WOULD require; zero behavior change), ``enforce`` (step-up on
the configured elevated routes only; ships OFF and the flip is a
human-controlled ops event).
"""

from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import select

from hyrule_cloud.db import X401ProofLogRow, X401ProofTokenRow
from hyrule_cloud.trust.models import generate_proof_token

if TYPE_CHECKING:
    from typing import Protocol

    class X401Verifier(Protocol):
        """Credential-verifier adapter. A real implementation (e.g. a Proof
        Digital ID OpenID4VP verifier) validates the Result Artifact against
        the requested DCQL predicates and returns satisfied claims; None
        means not satisfied."""

        async def verify(self, result_artifact: dict[str, Any]) -> dict[str, str] | None: ...

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from hyrule_cloud.config import TrustConfig

log = structlog.get_logger()

X401_VERSION = "0.2.0"
PROOF_REQUEST_HEADER = "PROOF-REQUEST"
PROOF_RESPONSE_HEADER = "PROOF-RESPONSE"
PROOF_RESULT_HEADER = "PROOF-RESULT"

_LOG_WRITE_TIMEOUT_SECONDS = 1.0


class X401Mode(enum.StrEnum):
    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


class PolicyTier(enum.StrEnum):
    NEVER = "never"
    STEP_UP = "step_up"


@dataclass(frozen=True)
class PolicyDecision:
    tier: PolicyTier
    reasons: dict[str, str]

    @property
    def requires_proof(self) -> bool:
        return self.tier == PolicyTier.STEP_UP


def b64url_encode_json(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode_json(value: str) -> dict[str, Any] | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        parsed = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def quote_hash(*, quote_id: str | None, amount: Decimal | str | None, route: str, method: str) -> str:
    """Deterministic binding of a proof to one quoted purchase: the token is
    only valid for the same quote/amount/route/method it was issued for."""
    material = f"{quote_id or ''}|{amount if amount is not None else ''}|{route}|{method}"
    return hashlib.sha256(material.encode()).hexdigest()


def _hash_token(cleartext: str) -> str:
    return hashlib.sha256(cleartext.encode()).hexdigest()


class X401PolicyEngine:
    """Route/attribute → policy tier. v1 policy: only elevated VM purchases
    (long duration or high amount) step up; everything else NEVER requires
    identity. The engine never sees native-rail vs EVM — rails are not a
    risk signal by policy."""

    def __init__(self, config: TrustConfig) -> None:
        self.config = config

    @staticmethod
    def _is_elevated_route(route: str) -> bool:
        if route == "/v1/vm/create":
            return True
        return route.startswith("/v1/vm/") and route.endswith("/extend")

    def evaluate(
        self,
        *,
        route: str,
        method: str,
        amount: Decimal | None,
        duration_days: int | None,
    ) -> PolicyDecision:
        if method.upper() != "POST" or not self._is_elevated_route(route):
            return PolicyDecision(PolicyTier.NEVER, {})
        reasons: dict[str, str] = {}
        max_days = self.config.x401_step_up_vm_duration_days
        if duration_days is not None and duration_days > max_days:
            reasons["duration_days"] = str(duration_days)
            reasons["duration_days_threshold"] = str(max_days)
        max_amount = self.config.x401_step_up_amount_usd
        if amount is not None and amount > max_amount:
            reasons["amount_usd"] = str(amount)
            reasons["amount_usd_threshold"] = str(max_amount)
        if reasons:
            return PolicyDecision(PolicyTier.STEP_UP, reasons)
        return PolicyDecision(PolicyTier.NEVER, {})


def build_proof_request_payload(
    *,
    request_id: str,
    proof_endpoint: str,
    bound_quote_hash: str,
    route: str,
    method: str,
    reasons: dict[str, str],
) -> dict[str, Any]:
    """x401 v0.2 PROOF-REQUEST payload asking for an authorization-assurance
    credential via OpenID4VP DCQL. Predicates, not dossiers: the request
    names an assurance level, never raw identity attributes."""
    return {
        "scheme": "x401",
        "version": X401_VERSION,
        "request_id": request_id,
        "credential_requirements": {
            "digital": {
                "requests": [
                    {
                        "protocol": "openid4vp",
                        "data": {
                            "dcql_query": {
                                "credentials": [
                                    {
                                        "id": "purchase_authorization",
                                        "format": "jwt_vc_json",
                                        "meta": {
                                            "type_values": [
                                                "OrganizationAffiliationCredential",
                                                "PersonhoodCredential",
                                            ]
                                        },
                                        "claims": [
                                            {
                                                "path": ["credentialSubject", "assurance_level"],
                                                "values": ["VC-AL2", "VC-AL3"],
                                            }
                                        ],
                                    }
                                ]
                            }
                        },
                    }
                ]
            }
        },
        # Deployment-specific context (allowed alongside the spec members):
        # where to present the proof and exactly which purchase it unlocks.
        "hyrule": {
            "proof_endpoint": proof_endpoint,
            "quote_hash": bound_quote_hash,
            "route": route,
            "method": method,
            "reasons": reasons,
            "token_ttl_seconds": None,  # filled by the service
        },
    }


def extract_verification_token(header_value: str) -> str | None:
    """Pull the Hyrule verification token out of a PROOF-RESPONSE request
    header carrying an x401 Token Object. Tolerant on the member name
    (``verification_token`` per our issuance; ``token`` accepted) — the
    Token Object member set is re-verified before any enforce flip."""
    parsed = b64url_decode_json(header_value)
    if parsed is None:
        return None
    for key in ("verification_token", "token"):
        value = parsed.get(key)
        if isinstance(value, str) and value.startswith("hyr_pf_"):
            return value
    return None


class StructuralVerifier:
    """v1 verifier: validates the x401 v0.2 Result Artifact SHAPE only
    (``credential_result`` or ``credential_result_uri`` member present) and
    satisfies proofs solely when TRUST_X401_ACCEPT_STRUCTURAL=true — a
    test-only switch. Without it, verification honestly reports that no
    credential verifier is configured. A real OpenID4VP adapter (e.g. Proof
    Digital ID) drops in behind the same interface later."""

    def __init__(self, accept_structural: bool) -> None:
        self.accept_structural = accept_structural

    async def verify(self, result_artifact: dict[str, Any]) -> dict[str, str] | None:
        has_result = isinstance(result_artifact.get("credential_result"), dict) or isinstance(
            result_artifact.get("credential_result_uri"), str
        )
        if not has_result:
            return None
        if not self.accept_structural:
            return None
        return {"assurance": "structural", "verifier": "structural-test-only"}


class X401Service:
    """Policy + shadow logging + proof-token issuance/validation.

    Every DB write is bounded and soft-fail: a broken x401 store must never
    change a payment or provisioning outcome (in shadow mode by definition;
    in enforce mode a log failure still never blocks — only a missing/
    invalid PROOF does)."""

    def __init__(
        self,
        config: TrustConfig,
        session_factory: async_sessionmaker[AsyncSession] | None,
        *,
        public_base_url: str,
        verifier: X401Verifier | None = None,
    ) -> None:
        self.config = config
        self._session_factory = session_factory
        self.public_base_url = public_base_url.rstrip("/")
        self.policy = X401PolicyEngine(config)
        self.verifier: X401Verifier = verifier or StructuralVerifier(
            config.x401_accept_structural
        )

    @property
    def mode(self) -> X401Mode:
        try:
            return X401Mode(self.config.x401_mode)
        except ValueError:
            log.warning("x401_invalid_mode", value=self.config.x401_mode)
            return X401Mode.OFF

    @property
    def enabled(self) -> bool:
        return self.mode != X401Mode.OFF

    @property
    def proof_endpoint(self) -> str:
        return f"{self.public_base_url}/v1/x401/proof"

    def advisory_extension(self) -> dict[str, Any] | None:
        """402-extension block announcing x401 support (attached to every
        challenge while mode != off). Advisory: it changes nothing about
        payment; enforce-mode step-up happens before the gate, per route."""
        if not self.enabled:
            return None
        return {
            "x401": {
                "scheme": "x401",
                "version": X401_VERSION,
                "mode": "required-conditionally" if self.mode == X401Mode.ENFORCE else "advisory",
                "proof_endpoint": self.proof_endpoint,
                "policy": {
                    "step_up_routes": ["/v1/vm/create", "/v1/vm/{vm_id}/extend"],
                    "triggers": {
                        "duration_days_over": self.config.x401_step_up_vm_duration_days,
                        "amount_usd_over": str(self.config.x401_step_up_amount_usd),
                    },
                },
            }
        }

    async def observe(
        self,
        *,
        route: str,
        method: str,
        amount: Decimal | None,
        duration_days: int | None,
        payer: str | None = None,
        agent_did: str | None = None,
    ) -> PolicyDecision:
        """Evaluate policy and (in shadow/enforce) log the decision. The
        caller's behavior must not depend on this in shadow mode."""
        decision = self.policy.evaluate(
            route=route, method=method, amount=amount, duration_days=duration_days
        )
        if self.mode == X401Mode.OFF:
            return decision
        outcome = "would_require" if decision.requires_proof else "would_not_require"
        log.info(
            "x401_policy_decision",
            route=route,
            mode=str(self.mode),
            tier=str(decision.tier),
            decision=outcome,
            **decision.reasons,
        )
        await self._log_decision(
            route=route,
            method=method,
            decision=outcome,
            tier=decision.tier,
            reasons=decision.reasons,
            amount=amount,
            payer=payer,
            agent_did=agent_did,
        )
        return decision

    async def _log_decision(
        self,
        *,
        route: str,
        method: str,
        decision: str,
        tier: PolicyTier,
        reasons: dict[str, str],
        amount: Decimal | None,
        payer: str | None,
        agent_did: str | None,
    ) -> None:
        if self._session_factory is None:
            return
        row = X401ProofLogRow(
            route=route[:256],
            method=method[:8],
            mode=str(self.mode),
            policy_tier=str(tier),
            decision=decision[:24],
            reasons=reasons or None,
            amount_usd=amount,
            payer_wallet=payer,
            agent_did=agent_did[:256] if agent_did else None,
        )
        try:
            await asyncio.wait_for(self._persist_log(row), timeout=_LOG_WRITE_TIMEOUT_SECONDS)
        except Exception:
            log.warning("x401_log_write_dropped", route=route, exc_info=True)

    async def _persist_log(self, row: X401ProofLogRow) -> None:
        assert self._session_factory is not None
        async with self._session_factory() as session:
            session.add(row)
            await session.commit()

    async def record_enforcement(
        self,
        *,
        route: str,
        method: str,
        decision: str,
        reasons: dict[str, str],
        amount: Decimal | None,
    ) -> None:
        """Log an enforce-mode outcome (proof_missing / proof_valid /
        proof_invalid). Bounded + soft-fail like every x401 write."""
        if self.mode == X401Mode.OFF:
            return
        await self._log_decision(
            route=route,
            method=method,
            decision=decision,
            tier=PolicyTier.STEP_UP,
            reasons=reasons,
            amount=amount,
            payer=None,
            agent_did=None,
        )

    # --- Step-up proof tokens (M6; used only when mode=enforce) ---

    async def issue_proof_token(
        self,
        *,
        bound_quote_hash: str,
        route: str,
        method: str,
        claims: dict[str, str] | None = None,
        agent_did: str | None = None,
    ) -> str:
        """Mint a short-lived verification token bound to one quoted
        purchase. Cleartext returned exactly once; sha256 at rest. NOT
        single-use: it must survive the 402→sign→retry round-trip, so it is
        TTL-bounded instead."""
        if self._session_factory is None:
            raise RuntimeError("x401 proof tokens need a session factory")
        cleartext = generate_proof_token()
        row = X401ProofTokenRow(
            token_hash=_hash_token(cleartext),
            quote_hash=bound_quote_hash,
            route=route[:256],
            method=method[:8],
            claims=claims or None,
            agent_did=agent_did[:256] if agent_did else None,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=self.config.x401_proof_token_ttl_seconds),
        )
        async with self._session_factory() as session:
            session.add(row)
            await session.commit()
        return cleartext

    async def check_proof_token(
        self,
        cleartext: str,
        *,
        bound_quote_hash: str,
        route: str,
        method: str,
    ) -> bool:
        """Constant-shape check: token exists, unexpired, and bound to the
        SAME quote_hash + route + method it was issued for."""
        if self._session_factory is None or not cleartext.startswith("hyr_pf_"):
            return False
        try:
            async with self._session_factory() as session:
                row = (
                    await session.execute(
                        select(X401ProofTokenRow).where(
                            X401ProofTokenRow.token_hash == _hash_token(cleartext)
                        )
                    )
                ).scalar_one_or_none()
        except Exception:
            log.warning("x401_token_lookup_failed", exc_info=True)
            return False
        if row is None:
            return False
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires < datetime.now(UTC):
            return False
        return (
            row.quote_hash == bound_quote_hash
            and row.route == route[:256]
            and row.method == method[:8]
        )

    def build_proof_request(
        self,
        *,
        bound_quote_hash: str,
        route: str,
        method: str,
        reasons: dict[str, str],
    ) -> tuple[str, dict[str, Any]]:
        """(header_value, payload) for a 401 PROOF-REQUEST response."""
        payload = build_proof_request_payload(
            request_id=str(uuid.uuid4()),
            proof_endpoint=self.proof_endpoint,
            bound_quote_hash=bound_quote_hash,
            route=route,
            method=method,
            reasons=reasons,
        )
        payload["hyrule"]["token_ttl_seconds"] = self.config.x401_proof_token_ttl_seconds
        return b64url_encode_json(payload), payload
