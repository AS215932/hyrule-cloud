# Agent-trust layer

Extends every x402 service with machine-verifiable trust surfaces while
keeping Hyrule the deterministic execution engine:

> **ERC-8004 identifies the service, x401 proves authority when necessary,
> x402 proves payment, and dual-signed receipts attest outcomes.**

Everything is flag-gated (`TRUST_*`, default off/observe/shadow) and
soft-fail: a broken or disabled trust layer never changes payment,
provisioning, or management behavior.

## Components

| Component | Module | Flag | State |
|---|---|---|---|
| Dual-signed receipts (payment/fulfillment/refund) | `hyrule_cloud/trust/receipts.py` | `TRUST_RECEIPTS_ENABLED` | built (M1/M2) |
| Receipt retrieval + JWKS | `hyrule_cloud/api/trust.py` | same | built |
| ERC-8004 agent registration document | `hyrule_cloud/trust/identity.py` | `TRUST_AGENT_CARD_ENABLED` | built (M3); on-chain registration = ceremony |
| x401 policy + shadow log | `hyrule_cloud/trust/x401.py` | `TRUST_X401_MODE=shadow` | built (M5) |
| x401 step-up enforcement (`/v1/vm/create`) | same + `POST /v1/x401/proof` | `TRUST_X401_MODE=enforce` | scaffolding built (M6), **ships off**; needs a real credential verifier before any flip |
| Caller-agent binding (RFC 9421 → did:web) | `hyrule_cloud/trust/principal.py` | `TRUST_PRINCIPAL_MODE=observe` | built (M7), observe-only |
| Signed measurements (ed25519 response-body signature) | `hyrule_cloud/trust/measurements.py` + `hyrule_cloud/middleware/signing.py` | `TRUST_MEASUREMENT_SIGNING_ENABLED` | built; key in the shared JWKS |

Storage: `fulfillment_receipts` (migration 015, + `ix_payment_events_tx_hash`
duplicate-settle detection), `x401_proof_log` + `x401_proof_tokens`
(migration 016). Metrics: `hyrule_receipts_total{kind,rail}`,
`hyrule_payment_duplicate_settled_tx`, `hyrule_x401_decisions_total`.

How coverage stays universal: every paid route funnels through
`PaymentGate` (`hyrule_cloud/middleware/x402.py`), so payment receipts are
minted at the settle choke points with zero per-route code — including
services that launch later (speedtest, mail). Fulfillment/refund receipts
hook the async outcome transitions (orchestrator, refunds, intents, domain
registration, BGP job completion).

## Invariants (each is test-pinned)

- Zero double-charge / double-provision — unchanged; protection stays at the
  quote-claim / intent-trigger / reservation layer.
- `/.well-known/x402.json` is **byte-identical** to the pre-trust manifest
  while all flags are off (`tests/test_trust_identity.py`).
- Native BTC/XMR receipts disclose no deposit address and no txid, even when
  a caller passes them (`tests/test_trust_receipts.py`, `_fulfillment.py`).
- Payment never substitutes for management authorization; receipts grant
  nothing.
- x401 shadow responses are byte-identical to mode=off; enforce is
  proof-first-then-pay — the gate is never invoked on the 401 path
  (`tests/test_trust_x401.py`).
- Receipt store down / x401 store down / DID resolver down ≠ any change to
  paid behavior (soft-fail suite).
- The app runtime never reads chain state; ERC-8004 registration data is
  config, written by a human ceremony (`scripts/erc8004_register.py`).
- Reputation is never a sovereign policy score; `supportedTrust` stays
  absent from the registration document until a trust model is actually
  implemented.

## Spec pins (verified 2026-07-10 — re-verify before enabling in prod)

- **ERC-8004** (Draft, created 2025-08-13): registration document at
  `/.well-known/agent-registration.json`, type
  `…eip-8004#registration-v1`; IdentityRegistry `register(string)` /
  `setAgentURI(uint256,string)`; events Registered/URIUpdated/MetadataSet.
  Deployments: Base Sepolia `0x8004A818BFB912233c491871b3d84c89A494BD9e`,
  Base mainnet `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` (no tagged
  release upstream). Validation Registry is explicitly unstable — unused.
- **x401 v0.2.0**: `PROOF-REQUEST`/`PROOF-RESPONSE`/`PROOF-RESULT` headers,
  base64url JSON, header-authoritative, OpenID4VP DCQL predicates. The
  Token Object member name is re-verified before any enforce flip.

## Rollout state

Done in-repo (all disabled by default): receipts everywhere, ERC-8004
discovery surfaces, x401 shadow + step-up scaffolding, caller binding.

Remaining (roadmap):

1. **M4-ops** — key ceremony + Vault, Base Sepolia then mainnet
   registration, staging canary (`scripts/x402_canary.py` verifies receipts
   when advertised), flag flips, skills/README updates once live. See
   `docs/runbooks/trust-keys.md`.
2. **M8 — Circle Gateway** (spike first): additive `x402-gateway` payment
   kind for routes ≤ $0.05 only; classic exact-USDC stays first in
   `accepts[]` and exclusive for VM/domain/proxy-POST. Acceptance criteria
   before code: confirm the Gateway scheme kind + facilitator against
   Circle's current x402 seller docs, confirm the x402 SDK server-scheme
   registry accepts a custom scheme, and settle one $0.005 lookup end-to-end
   on testnet. Plus Circle Marketplace listing + an Agent Wallets test buyer.
3. **M9 — external trust**: receipt-backed ERC-8004 `giveFeedback` tooling
   (ops repo), off-chain signed validation reports, publishing this repo's
   receipt profile, ERC-8004↔did:web cross-resolution for caller reputation.
