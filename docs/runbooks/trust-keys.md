# Runbook: trust-layer keys, registration ceremony, monitoring

Human-controlled operations for the agent-trust layer. Nothing here is
automated on purpose: registry ownership and trust-policy changes stay
human decisions (see docs/trust-layer.md invariants).

## Key inventory

| Key | Purpose | Where | Never |
|---|---|---|---|
| ES256 P-256 receipt key | JWS signature on every receipt | Vault kv/hyrule-cloud → `TRUST_RECEIPT_SIGNING_KEY_PEM` | reuse elsewhere |
| secp256k1 receipt signer | EIP-712 receipt signature | Vault → `TRUST_RECEIPT_EVM_SIGNING_KEY` | fund it, or use as registry owner |
| ed25519 measurement key | detached signature over each paid 2xx JSON body | Vault → `TRUST_MEASUREMENT_SIGNING_KEY` | reuse a receipt/registry key |
| ERC-8004 registry owner | owns the agent NFT (register/setAgentURI) | org-controlled cold key / multisig; only ever exported into `ERC8004_OWNER_KEY` for the ceremony shell | store on the API host |

Generate:

```bash
# ES256 (PEM, PKCS8):
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt
# secp256k1 receipt signer:
python -c "from eth_account import Account; a=Account.create(); print(a.key.hex(), a.address)"
```

With `TRUST_RECEIPTS_ENABLED=true` the app **refuses to boot** unless both
keys load and validate (`enforce_trust_key_guard`) — a deployment that
advertises receipts but cannot sign them would break the trust contract
silently.

## Enabling receipts (staging → prod)

1. Staging: set both keys + `TRUST_RECEIPTS_ENABLED=true` +
   `TRUST_DEPLOYMENT_SHA=$(git rev-parse HEAD)` (deploy pipeline).
2. Run `scripts/x402_canary.py` against staging — it now fails if a paid
   response advertises a receipt that does not verify (both signatures,
   offline).
3. Spot-check `python scripts/verify_receipt.py <receipt-url>`.
4. Prod flip is a normal Vault change + deploy; watch
   `hyrule_receipts_total` and the `receipt_mint_failed` /
   `payment_ledger_write_dropped` log lines.
5. Only after receipts are live in prod: update skills/README to document
   the `HYRULE-RECEIPT` header (same discipline as the 501 rule — never
   document a surface that isn't served).

## Key rotation (receipts stay verifiable forever)

1. Generate the new ES256 key; compute its JWK (see
   `hyrule_cloud/trust/identity.py:es256_public_jwk`).
2. Move the OLD public JWK into `TRUST_RECEIPT_RETIRED_JWKS_JSON` (a JSON
   list; append, never remove).
3. Swap `TRUST_RECEIPT_SIGNING_KEY_PEM` to the new key, deploy. JWKS now
   serves new-active + old-retired; old receipts verify by `kid`.
4. EVM signer rotation: add the new address to `receiptSigners` consumers
   before swapping `TRUST_RECEIPT_EVM_SIGNING_KEY`; old receipts name their
   signer in `evm_signer`, so verifiers compare against the receipt, and
   the registration document should keep listing historical signers.

## Signed measurements (ed25519)

Receipts attest the *transaction*; signed measurements attest the *data*.
When `TRUST_MEASUREMENT_SIGNING_ENABLED=true`, an ed25519 detached signature
over the exact response-body bytes rides on every paid 2xx JSON response as
`Hyrule-Signature: ed25519=<b64>` + `Hyrule-Signature-Key: <kid>`. It is
independent of receipts: enable either, both, or neither.

The public key is published in the SAME `/.well-known/jwks.json` as an
OKP/Ed25519 entry (`build_jwks` appends it), and advertised in the
agent-registration document under `signedMeasurements` — never in the x402
manifest, so `/.well-known/x402.json` stays byte-identical with the flag off.

Like receipts, this fails closed: with the flag on the app **refuses to boot**
unless the seed loads (`enforce_measurement_key_guard`). A signing outage can
never silently drop signatures from an advertised surface.

Generate + enable:

```bash
# 32-byte ed25519 seed, base64 (this is the whole private key):
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

1. Staging: set `TRUST_MEASUREMENT_SIGNING_KEY=<seed-b64>` +
   `TRUST_MEASUREMENT_SIGNING_ENABLED=true`. Leave `TRUST_MEASUREMENT_SIGNING_KEY_ID`
   blank to let the kid derive as `hyr-meas-<sha256(pubkey)[:16]>` (stable per
   key); set it only to pin a human-chosen id.
2. Verify: `python scripts/x402_canary.py <suite> --verify-signature` — it
   re-derives the Ed25519 pubkey from `/.well-known/jwks.json` by `kid` and
   checks the detached signature over the received bytes; a paid 2xx that
   advertises a signature which doesn't verify fails the run.
3. Prod flip is a normal Vault change + deploy.

### Measurement key rotation (old signatures stay verifiable)

1. Generate the new seed; note its derived (or chosen) `kid`.
2. Move the OLD public JWK into `TRUST_MEASUREMENT_RETIRED_JWKS_JSON` (JSON
   list; append, never remove — mirrors the receipt-key discipline). Copy the
   OKP entry the running JWKS currently serves for the active key.
3. Swap `TRUST_MEASUREMENT_SIGNING_KEY` (and `_KEY_ID` if pinned) to the new
   seed and deploy. JWKS now serves new-active + old-retired; signatures made
   before the swap still verify by their `kid`.

## ERC-8004 registration ceremony

Sepolia first, mainnet only after the announcement checklist clears.

1. Re-verify the spec pin (draft is moving): registration filename,
   `register(string)` selector, registry addresses —
   eips.ethereum.org/EIPS/eip-8004 + github.com/erc-8004/erc-8004-contracts.
2. Serve the document first: `TRUST_AGENT_CARD_ENABLED=true` and check
   `https://cloud.hyrule.host/.well-known/agent-registration.json`
   (domain policy: hyrule.host, never servify.network / as215932.net).
3. From an operator shell (never the API host):

   ```bash
   ERC8004_OWNER_KEY=0x... python scripts/erc8004_register.py \
     --rpc-url https://sepolia.base.org \
     --registry 0x8004A818BFB912233c491871b3d84c89A494BD9e
   ```

4. Set the printed `TRUST_ERC8004_*` values in Vault; redeploy; confirm the
   document now carries `registrations[]` and the manifest carries
   `identity`.
5. Two-person sign-off for mainnet (registry
   `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`): owner-key custody
   confirmed, agentURI correct, Sepolia registration observed by a third
   party.

## Monitoring (network-operations repo)

- **Registry events**: poll `eth_getLogs` on the registry address for
  `Registered` / `URIUpdated` / `MetadataSet` / `Transfer` topics (the
  register script prints the exact query). An unexpected `Transfer` or
  `URIUpdated` for our agentId ⇒ treat as compromise: unset
  `TRUST_ERC8004_*` + `TRUST_AGENT_CARD_ENABLED` (trust surfaces degrade
  soft; paid service is unaffected), then investigate.
- **Duplicate settlements**: alert on `hyrule_payment_duplicate_settled_tx
  > 0` — either a double-settle bug or facilitator batching; deliberately
  detected instead of masked by a uniqueness constraint.
- **Receipt lag/drops**: `receipt_mint_failed` warnings; ratio of
  `hyrule_receipts_total{kind="payment"}` to settled
  `hyrule_payment_events_total`.
- **x401 calibration**: `hyrule_x401_decisions_total{decision="would_require"}`
  volume in shadow tells you what an enforce flip would block. The flip
  itself additionally requires a real credential verifier
  (`TRUST_X401_ACCEPT_STRUCTURAL` is test-only and must never be set in
  production).
