# Runbook: trust-layer keys, registration ceremony, monitoring

Human-controlled operations for the agent-trust layer. Nothing here is
automated on purpose: registry ownership and trust-policy changes stay
human decisions (see docs/trust-layer.md invariants).

## Key inventory

| Key | Purpose | Where | Never |
|---|---|---|---|
| ES256 P-256 receipt key | JWS signature on every receipt | Vault kv/hyrule-cloud → `TRUST_RECEIPT_SIGNING_KEY_PEM` | reuse elsewhere |
| secp256k1 receipt signer | EIP-712 receipt signature | Vault → `TRUST_RECEIPT_EVM_SIGNING_KEY` | fund it, or use as registry owner |
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
