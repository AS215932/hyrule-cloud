# x402 Compute Fulfillment Receipt — profile `x402-compute-fulfillment-receipt/0.1`

An open, multi-rail receipt profile for machine-verifiable evidence of paid
infrastructure outcomes. Hyrule Cloud mints one for every settled payment
and every asynchronous fulfillment outcome (VM provisioned/failed, domain
registered, job delivered, refund owed) across all of its x402 services —
and for native BTC/XMR purchases, which EVM-only payment evidence cannot
cover.

Receipts are **attestations by the service operator**, dual-signed so third
parties (buyers, ERC-8004 reputation consumers, independent validators) can
verify them offline. They are not the revenue ledger and never grant
management authority — payment never substitutes for authorization.

## Discovery

| Surface | Where |
|---|---|
| Receipt id | `HYRULE-RECEIPT` response header on paid calls (mirror: `X-HYRULE-RECEIPT`) |
| Receipt document | `GET /v1/receipts/{receipt_id}` (public; the unguessable id is the capability) |
| Verification keys | `GET /.well-known/jwks.json` (active key first, then retired keys) |
| EVM signer + profile | `receipts` block of `/.well-known/x402.json` and of `/.well-known/agent-registration.json` |
| Per-VM listing | `GET /v1/vm/{vm_id}/receipts` (management-gated) |

## Payload

The signed document is exactly this JSON object (built by
`hyrule_cloud/trust/models.py:ReceiptPayload`):

```json
{
  "profile": "x402-compute-fulfillment-receipt/0.1",
  "receipt_id": "hyr_rcpt_<22 base62>",
  "kind": "payment | fulfillment | refund",
  "issuer": {"name": "Hyrule Cloud", "url": "https://cloud.hyrule.host",
             "agent_registry": "<CAIP-10 identity registry or null>",
             "agent_id": null},
  "resource": {"path": "/v1/dns/lookup", "method": "POST",
               "service_group": "network_intel", "description": "..."},
  "payment": {"rail": "x402-exact-evm | x402-gateway | native-btc | native-xmr | dev-bypass",
              "network": "eip155:8453 | null", "asset": "USDC | BTC | XMR | null",
              "amount_usd": "0.001", "payer": "<0x…, EVM only>", "tx_ref": "<EVM tx, EVM only>"},
  "correlation": {"quote_id": null, "vm_id": null, "intent_id": null,
                  "job_id": null, "domain": null},
  "outcome": {"status": "settled | delivered | provisioned | extended | failed | refund_owed",
              "detail": null, "simulated": false},
  "timing": {"issued_at": "<RFC 3339>", "provision_started_at": null,
             "provisioned_at": null, "provision_seconds": "12.000"},
  "service": {"api_version": "0.1.0", "deployment_sha": "<git sha or null>",
              "facilitator_host": "<x402 facilitator or null>"},
  "agent": {"did": "did:web:…", "key_id": "…", "verified": true},
  "evidence": {"artifact_sha256": "…"}
}
```

`agent` and `evidence` are `null` unless a caller-agent binding (RFC 9421 →
did:web) or service-specific evidence exists.

### Canonicalization contract

Payloads contain **only strings, booleans, null, objects, and arrays** —
amounts and durations are decimal strings, never JSON numbers with
fractional parts. The canonical bytes are compact sorted-key UTF-8 JSON
(`sort_keys=True`, separators `,`/`:`, non-ASCII preserved), a faithful
RFC 8785 (JCS) subset under that constraint. Implementations MUST reject
payloads containing floats.

### Privacy rules (normative)

- EVM rails include `payer` and `tx_ref` verbatim — both already public
  on-chain.
- **Native rails (BTC/XMR, future Zcash) include no deposit address and no
  transaction id in any form** — hashed values are dictionary-attackable
  against public chain data. Correlation is the unguessable `intent_id`
  known only to the payer; the operator can attest tx linkage out-of-band.
- No customer PII, management tokens, SSH material, or x401 credential
  contents, ever.

## Signatures (dual, over the same canonical bytes)

1. **ES256 compact JWS** (chain-agnostic, offline): the JWS payload IS the
   canonical bytes; the protected header carries `kid`. Verify with any key
   from `/.well-known/jwks.json` (retired keys stay listed after rotation).
2. **EIP-712 secp256k1** (EVM ecosystem / ERC-8004 feedback): a signature
   over the `ReceiptDigest` struct binding `sha256(canonical bytes)`:

   ```
   domain    = { name: "HyruleCloudReceipt", version: "0.1" }
   ReceiptDigest = { receiptId: string, payloadSha256: bytes32, issuedAt: string }
   ```

   Recovering the signer MUST yield an address listed in `receiptSigners`
   (agent registration / manifest). That key is operational and distinct
   from the ERC-8004 registry-owner key.

Reference verifier: `scripts/verify_receipt.py` (also usable as library
functions `hyrule_cloud.trust.receipts.verify_receipt_jws` /
`recover_receipt_signer`).

## Rail semantics

| `payment.rail` | Meaning | `payer`/`tx_ref` |
|---|---|---|
| `x402-exact-evm` | x402 exact scheme, EVM USDC (Base today) | present |
| `x402-gateway` | reserved: Circle Gateway additive payment kind (roadmap) | present |
| `native-btc` / `native-xmr` | native deposit intents (`/v1/intent/*`) | **never** |
| `dev-bypass` | staging bypass; nothing charged (never enabled in production — boot guard) | `payer` sentinel only |

A Zcash rail slot (`native-zec`) is reserved with the same privacy rules as
the other native rails.

## Receipt kinds and when they are minted

| kind | outcome | minted at |
|---|---|---|
| `payment` | `settled` | every x402 settle (gate choke point, all paid routes) and first SETTLED observation of a native intent |
| `fulfillment` | `provisioned` / `extended` / `delivered` / `failed` | VM launch-proof transitions, domain registration outcome, job completion |
| `refund` | `refund_owed` | every refund obligation (`payment_events.refund_owed`), soft-linked via `payment_event_id` |

Fulfillment receipts carry provisioning timings (`provision_seconds`), the
deployment SHA, and — for jobs — the delivered artifact hash, which is what
makes this profile suitable as *evidence* behind ERC-8004 feedback
(`giveFeedback(..., feedbackURI, feedbackHash)`) instead of unverifiable
star ratings.
