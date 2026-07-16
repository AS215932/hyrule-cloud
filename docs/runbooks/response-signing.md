# Runbook: enable ed25519 response signing (x402 trust layer)

Every paid 2xx JSON response can carry a detached ed25519 signature over its
exact body, so a buyer can prove a measurement came from Hyrule and was not
altered. Signing ships **dark**: it does nothing until an operator provisions a
key. This is the ecosystem's most-requested missing piece (verifiable results).

## What buyers get

- Header `Hyrule-Signature: ed25519=<base64 detached signature>` over the raw body.
- Header `Hyrule-Signature-Key: <key id>`.
- Public key at `GET /.well-known/hyrule-signing-key.json` (JWK + raw base64).
- `signingKey` block in `/.well-known/x402.json` and a note in `/llms.txt`.
- Only paid catalog 2xx JSON is signed; 402/501, free endpoints, and non-JSON
  (icons, snapshots) are never signed.

## Enable

1. Generate a key seed and pick a key id:
   ```
   python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
   ```
2. Store in Vault `kv/hyrule-cloud`:
   - `response_signing_key=<base64 seed>`
   - `response_signing_key_id=hyrule-YYYY-MM`
   The Vault Agent template renders `HYRULE_RESPONSE_SIGNING_KEY` /
   `HYRULE_RESPONSE_SIGNING_KEY_ID` into the api `.env`.
3. Restart api. Confirm:
   - `GET /.well-known/hyrule-signing-key.json` returns 200 with the key.
   - `/.well-known/x402.json` now has a `signingKey` block.
   - `python scripts/x402_canary.py dns --verify-signature` (real USDC) prints
     `signature: OK ed25519` and fails if a paid 2xx lacks a valid signature.

## Rotate (dual-publish)

Add the new key, keep serving the old public key in
`/.well-known/hyrule-signing-key.json` `keys[]` until buyers refresh (default
cache window), then drop the old key. The signature always uses the single
active `response_signing_key_id`.

## Disable / rollback

Clear both Vault values and restart api. Signing headers stop, the well-known
route 404s, and the manifest drops `signingKey` — no response is broken.
