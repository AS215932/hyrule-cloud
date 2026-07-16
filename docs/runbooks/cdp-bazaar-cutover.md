# CDP facilitator cutover + Bazaar indexing — operator checklist

Goal: get the catalog indexed by the CDP x402 Bazaar (and its mirrors:
agentic.market, Onyx Bazaar). The Bazaar only catalogs resources **settled
through the CDP facilitator** — on PayAI we appear in PayAI `/list` and
x402scan only. Deeper procedures live in `x402-launch.md`; this is the
ordered cutover.

Distribution model recap:

| Index | How we get in |
|---|---|
| CDP Bazaar / agentic.market / Onyx | first successful **CDP-settled** payment per resource, discovery extension + resource metadata on the 402 (this repo emits both) |
| x402scan | on-chain settlements, facilitator-agnostic — appears once real settles exist |
| PayAI `/list` | facilitator-side listing (current state) |
| x402-list.com / gold-402 / x402station | manual submission / machine-paid badge |

CDP quality score = distinct buyers (30d) + volume (30d) + recency + metadata
completeness, recomputed ~6h; resources idle 30 days are dropped. Judge
traction by **unique payers**, not call counts.

## Steps

1. **Vault**: `vault kv patch kv/hyrule-cloud cdp_api_key_id=<id> cdp_api_key_secret=<pem>`
   (from the CDP key JSON: `.name` → id, `.privateKey` → secret). Confirm
   `dev_bypass_secret` is EMPTY in prod.
2. **Deploy main** (billing-honesty + catalog-streamline + this metadata PR)
   via the network-operations promotion pin. Smoke: `/health` 200, manifest
   resource count matches expectation, `curl -s https://cloud.hyrule.host/llms.txt | head`.
3. **Switch facilitator**:
   `vault kv patch kv/hyrule-cloud payment_facilitator_url=https://api.cdp.coinbase.com/platform/v2/x402`,
   restart, then `scripts/verify_facilitator.py` must print `OK eip155:8453`.
   Rollback = patch back to `https://facilitator.payai.network` + restart.
4. **Per-chain canaries** (real USDC): `scripts/x402_canary.py dns`, then
   `--network eip155:137` and `--network eip155:42161` (canary wallet funded
   with USDC + gas on each chain).
5. **VM gate re-verify**: `scripts/x402_canary.py vm --quote --destroy`.
   If provisioning fails (known risk: XCP-NG/XO routing from the api VM),
   flip `hcp_launch_proof_real_xcpng=0` — the manifest auto-drops
   `/v1/vm/create`. Never leave a non-provisionable VM advertised.
6. **Bazaar seeding**: one paid canary per flagship endpoint so CDP indexes
   at settlement — dns, web, mx, bgp lookup, proxy direct + tor, vm (if step
   5 passed). Verify after ~6h:
   `curl -s 'https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources?limit=1000' | grep -c cloud.hyrule.host`.
7. **Directory submissions**: x402scan (indexes on-chain; reads
   `/openapi.json`), x402-list.com (verifies via live 402 handshake +
   uptime), gold-402, x402station badge (machine-paid; needs ≥95% 7-day
   uptime — Icinga already watches the api VM). agentic.market and Onyx
   mirror CDP automatically — no separate action.

Per house rule, snapshot the Icinga problem list before and after each deploy
step and diff.
