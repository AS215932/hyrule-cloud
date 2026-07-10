---
status: accepted-for-execution
source: claude-plan-mode
created: 2026-07-10
---

# Hyrule Cloud Agent-Trust Layer — ERC-8004 / x401 / receipts across all x402 services

## Context

Hyrule Cloud is live on production (`cloud.hyrule.host`, paid VM canary passed 2026-07-10, announcement pending in hyrule-cloud#53). An accepted architecture recommendation extends it from "an API that accepts x402" into an agent-native compute merchant: **ERC-8004 identifies the service, x401 proves authority when necessary, x402 proves payment, Circle optionally supplies distribution, Hyrule remains the deterministic execution engine.**

This plan implements that recommendation across **every** x402 service — not just VM create. Verified catalog (code + prod manifest cross-check): VM create/extend, domain register, network proxy (two-phase settle), native BTC/XMR intents, and the ~12-family network-intel suite (BGP incl. jobs/snapshots, IP, DNS, RDAP/WHOIS, web/TLS, MX, path, ports, NAT, threat, VoIP; speedtest/mail are 501 today). Repo grep confirms the trust feature-set is **greenfield**: zero existing ERC-8004/x401/Circle/receipt/DID code.

The key structural fact that makes uniform coverage cheap: all paid routes funnel through `PaymentGate` (`hyrule_cloud/middleware/x402.py`) — `check_payment()` for most routes (all 13 intel routers reach it via `api/_contract.py:111-134 require_payment`), `verify_only()`→deliver→`settle_verified()` for the proxy. Receipts minted inside the gate cover the whole catalog with **zero per-route changes**, including speedtest/mail the day they launch.

**User decisions (confirmed):**
- Implementation tranche = **M1–M7 (all code milestones)**. M4-ops (mainnet ceremony/flag flips), M8 (Circle Gateway), M9 (on-chain feedback) stay as roadmap.
- Receipts are **dual-signed from day one**: ES256 compact JWS + EIP-712 secp256k1 signature on every receipt.

**Non-negotiable invariants** (each gets a test): zero double-charge/double-provision; no PII or private payment disclosure in public receipts (BTC/XMR receipts carry no address/txid, not even hashed); payment never substitutes for management authorization; failure of receipts/x401/identity/did-resolution must never break ordinary service (soft-fail everything); all new behavior behind config flags, default off/shadow; the `/.well-known/x402.json` manifest is byte-identical to today when flags are off (protects the pending announcement); registry ownership and trust-policy changes stay human-controlled.

**Frozen contracts** (from accepted plan `docs/plans/2026-07-01T17-12-27Z-fix-hyrule-cloud-x402-server-side-payments.md`): `check_payment(request, amount, description, extra_body) -> Response | str` signature; dual headers `PAYMENT-REQUIRED`/`X-PAYMENT-REQUIRED` and `PAYMENT-RESPONSE`/`X-PAYMENT-RESPONSE`. Do not touch.

---

## Architecture decisions

- **D1 — Module layout:** new `hyrule_cloud/trust/` package (`models.py` protocol profile, `receipts.py` dual signer + service, `identity.py` agent card + JWKS, `x401.py` policy/shadow/proof tokens, `principal.py` RFC 9421 + did:web) plus `hyrule_cloud/api/trust.py` router. Wired via `TrustServices` dataclass on `AppState.trust: TrustServices | None = None` (optional-field pattern, `hyrule_cloud/state.py:17-33`). New modules are **not** added to the mypy-strict override list — they must be strict-clean.
- **D2 — Receipt format:** canonical-JSON payload, dual-signed. Primary: compact JWS (ES256, pyjwt+cryptography — already deps; CDP auth at `middleware/x402.py:68-102` is the in-repo precedent), `kid` header, JWKS at `/.well-known/jwks.json`. Secondary: EIP-712 signature over a `ReceiptDigest` struct (`{receiptId: string, payloadSha256: bytes32, issuedAt: string}`, domain `{name: "HyruleCloudReceipt", version: "0.1"}`) signed by a **dedicated operational secp256k1 key** via `eth_account.Account.sign_typed_data` (already a dep) — never the registry-owner key. Canonical bytes = JCS-style serializer (sorted keys, no whitespace, UTF-8; small in-repo helper, no new dep); JWS payload = those bytes; EIP-712 binds their sha256. Verifiers: JWS via JWKS; EIP-712 via recovered signer == `receiptSigners` address published in the agent card.
- **D3 — DB:** one new table now (`fulfillment_receipts`, migration 015), `x401_proof_log` + `x401_proof_tokens` in migration 016. **No** `agent_principals` table, **no** materialized TransactionIntent — correlation is derived from existing PKs (quote_id/vm_id/intent_id/job_id/fqdn); `TransactionIntent` exists only as a Pydantic read-model. Never create a table named `intents` (collision with `crypto_intents`).
- **D4 — tx_hash gap:** do **not** add a unique constraint to `payment_events` (best-effort ledger; a violation would silently drop a legitimate row, e.g. facilitator batching). Add plain index `ix_payment_events_tx_hash` + a duplicate-settlement gauge in `api/metrics.py`. Double-charge protection already lives at the right layer (atomic quote claim `services/quotes.py:153`, intent trigger `services/intents.py:311-338`).
- **D5 — ERC-8004:** app runtime never talks to a chain (soft-fail by construction). Serve `/.well-known/agent-card.json` from config; one-shot `scripts/erc8004_register.py` (httpx JSON-RPC + eth-account, no web3 dep); continuous event watching belongs to the network-operations repo (document queries in the runbook). ERC-8004 is a moving Draft — pin spec + registry addresses at impl time, don't trust remembered ABIs.
- **D6 — x401:** `TRUST_X401_MODE=off|shadow|enforce`; policy engine in code with config thresholds; shadow = one `observe()` line in the two elevated routes; advertisement rides the existing 402 `extensions` dict; enforcement built for `/v1/vm/create` only and **ships with enforce off**.
- **D7 — Dev-bypass payments** mint receipts with `rail:"dev-bypass"` (launch guard already forbids bypass in prod, `services/launch_proof.py`), keeping one end-to-end-testable path.
- **D8 — Caller binding:** opt-in observe-only middleware (RFC 9421 subset → did:web resolution with existing SSRF guards); principal recorded on `request.state`, ledger `extra`, and receipts; never required, never blocks.

---

## Config additions (`hyrule_cloud/config.py`)

New `TrustConfig(BaseSettings)`, `env_prefix="TRUST_"`, nested as `trust: TrustConfig` in `HyruleConfig` (pattern: `config.py:322-325`):

| Env var | Default | Purpose |
|---|---|---|
| `TRUST_RECEIPTS_ENABLED` | `false` | master receipt switch |
| `TRUST_RECEIPT_SIGNING_KEY_PEM` / `_PATH` | `""` | ES256 P-256 private key (`\n`-escaped env like `CDP_API_KEY_SECRET`) |
| `TRUST_RECEIPT_KEY_ID` | `""` | kid override; else `hyr-rcpt-` + first 16 hex of sha256(SPKI DER) |
| `TRUST_RECEIPT_RETIRED_JWKS_JSON` | `""` | retired public keys kept in JWKS for old receipts |
| `TRUST_RECEIPT_EVM_SIGNING_KEY` / `_PATH` | `""` | secp256k1 hex key for EIP-712 receipt signature |
| `TRUST_DEPLOYMENT_SHA` | `""` | stamped into receipts |
| `TRUST_AGENT_CARD_ENABLED` | `false` | serve agent card + manifest identity block |
| `TRUST_AGENT_DOMAIN` | `cloud.hyrule.host` | identity host (AGENTS.md policy: customer-facing = hyrule.host, never servify.network/as215932.net) |
| `TRUST_ERC8004_REGISTRY_CAIP10` / `_AGENT_ID` / `_OWNER_ADDRESS` | `""`/`None`/`""` | registration data (config, not chain reads) |
| `TRUST_X401_MODE` | `off` | off / shadow / enforce |
| `TRUST_X401_STEP_UP_VM_DURATION_DAYS` | `90` | step-up trigger |
| `TRUST_X401_STEP_UP_AMOUNT_USD` | `25` | step-up trigger |
| `TRUST_X401_PROOF_TOKEN_TTL_SECONDS` | `900` | proof token life |
| `TRUST_X401_ACCEPT_STRUCTURAL` | `false` | test-only structural verifier satisfies proofs |
| `TRUST_PRINCIPAL_MODE` | `off` | off / observe |
| `TRUST_GATEWAY_ENABLED` / `TRUST_GATEWAY_MAX_AMOUNT_USD` | `false` / `0.05` | reserved for M8 (roadmap) |

Startup guard (mirrors `enforce_real_provisioning_guard`): `TRUST_RECEIPTS_ENABLED=true` with a missing/invalid ES256 **or** EVM key → refuse to boot.

## DB migrations

**`alembic/versions/015_trust_receipts.py`** (revises 014; inspector-guard style of 013):

```
fulfillment_receipts
  receipt_id String(40) PK              -- "hyr_rcpt_" + 22 base62 (~131-bit capability id)
  kind String(16) NOT NULL              -- payment | fulfillment | refund
  created_at DateTime(tz) now(), idx
  resource_path String(256); method String(8); service_group String(24) idx
  outcome String(24)                    -- settled|provisioned|extended|delivered|failed|refund_owed
  rail String(24)                       -- x402-exact-evm|native-btc|native-xmr|dev-bypass|x402-gateway
  network String(64) NULL; amount_usd Numeric(12,6) NULL
  payer_wallet String(64) NULL idx      -- EVM only; NULL for native rails
  tx_hash String(128) NULL              -- EVM only; NULL for native rails
  payment_event_id String(36) NULL idx  -- soft link, NO FK (ledger writes are droppable)
  quote_id/vm_id/intent_id/job_id String NULL; domain_fqdn String(256) NULL
  agent_did String(256) NULL            -- populated from M7
  key_id String(64) NOT NULL
  evm_signer String(42) NULL; evm_signature String(178) NULL
  payload JSONB NOT NULL (use db.py _JSONB variant → sqlite-safe); jws Text NOT NULL
  idx: (vm_id, created_at), (intent_id), (service_group, created_at)

payment_events: ADD INDEX ix_payment_events_tx_hash
```

**`alembic/versions/016_x401_shadow.py`**: `x401_proof_log` (BigInt PK autoincrement, created_at idx, route, method, mode, policy_tier, decision, reasons JSONB, amount_usd, payer_wallet, agent_did; idx (route, created_at)) and `x401_proof_tokens` (token_hash sha256 PK, quote_hash, route, method, claims JSONB, agent_did, created_at, expires_at idx — **TTL-bounded, not single-use**, so the token survives the 402→pay→retry round-trip).

ORM rows `FulfillmentReceiptRow`, `X401ProofLogRow`, `X401ProofTokenRow` in `hyrule_cloud/db.py`.

## Receipt payload (the open profile — `docs/x402-compute-fulfillment-receipt.md`)

```json
{
  "profile": "x402-compute-fulfillment-receipt/0.1",
  "receipt_id": "hyr_rcpt_…", "kind": "payment|fulfillment|refund",
  "issuer": {"name": "Hyrule Cloud", "url": "https://cloud.hyrule.host",
             "agent_registry": "<CAIP-10|null>", "agent_id": null},
  "resource": {"path": "/v1/dns/lookup", "method": "POST", "service_group": "network_intel",
               "description": "<402 description>"},
  "payment": {"rail": "…", "network": "eip155:8453|bitcoin|monero|null", "asset": "…",
              "amount_usd": "0.001", "payer": "<0x… EVM only|null>", "tx_ref": "<EVM tx|null>"},
  "correlation": {"quote_id": null, "vm_id": null, "intent_id": null, "job_id": null, "domain": null},
  "outcome": {"status": "…", "detail": null, "simulated": false},
  "timing": {"issued_at": "<iso8601>", "provision_started_at": null, "provisioned_at": null,
             "provision_seconds": null},
  "service": {"api_version": "0.1.0", "deployment_sha": "<or null>", "facilitator_host": "<or null>"},
  "agent": null
}
```

Privacy rule: EVM receipts include `payer`/`tx_ref` verbatim (already public on-chain). **Native BTC/XMR receipts include no address and no txid in any form** — sha256(txid) is dictionary-attackable against public chain data; correlation is the unguessable `intent_id` only.

---

## Wiring per fulfillment shape (file:line anchors verified)

`ReceiptService` (`trust/receipts.py`): own `session_factory`; `build_payload(...)`, `sign(payload) -> (jws, kid, evm_signer, evm_signature)`, `mint(...) -> receipt_id | None` persisting under `asyncio.wait_for(…, 2.0)` mirroring the ledger budget (`x402.py:353-374`); never raises; disabled/absent → returns `None` instantly.

**(a) Every `check_payment` route — gate-internal, zero route edits.**
- `PaymentGate.__init__` (`x402.py:166-186`): add optional kwargs `receipts: ReceiptService | None = None`, `advertised_extensions: dict | None = None`. Existing constructions (`app.py:86-90`, tests) pass no new args; `MockGate` (`tests/test_api.py:65-88`) is a duck type, unaffected.
- Settled block (`x402.py:559-571`): after `_record("settled", …)`, mint `kind=payment, outcome=settled, rail=x402-exact-evm`; merge `settlement_headers["HYRULE-RECEIPT"] = receipt_id` (same dict stored into `request.state.payment_response_headers` at :570). Header carries the id only; the JWS is fetched from `/v1/receipts/{id}`.
- Dev-bypass path (`x402.py:406-414`): sets `payment_tx` but **no headers today** — mint `rail=dev-bypass` and set `request.state.payment_response_headers = {"HYRULE-RECEIPT": …}` explicitly.
- `app.py:223-229`: add `HYRULE-RECEIPT` (and `X-HYRULE-RECEIPT` mirror) to the exposed-headers set; the middleware at `app.py:212-230` already forwards arbitrary dict entries.
- Automatically covers: all 13 intel routers (via `_contract.py:134`), BGP job create + snapshot download, MX jobs, VM extend payment (`routes.py:1091`), domain payment (`routes.py:1215`), proxy POST (`routes.py:1441`), future speedtest/mail.

**(b) Async VM — orchestrator hooks.** `Orchestrator` gains optional `receipts` ctor arg (wired in lifespan `app.py:102`). Mint `kind=fulfillment`:
- `_provision_vm` success commit (`orchestrator.py:439-463`): `outcome=provisioned`, timing incl. `provision_seconds`, correlation vm_id+quote_id (`get_quote_for_vm`, `orchestrator.py:916`).
- `_simulate_provisioning` (`orchestrator.py:760-797`): same mint with `outcome.simulated=true` (tests exercise the path).
- Failure block (`orchestrator.py:465-493`): `outcome=failed`.
- `extend_vm` (`orchestrator.py:923`): `outcome=extended`.
- Refunds: `RefundService` (`services/refunds.py:38-43`) gains optional `receipts`; mint `kind=refund, outcome=refund_owed` inside `record_owed` (`refunds.py:44-101`) and post-commit in `record_native_intent_refund` (`orchestrator.py:685-758`). Covers create-failure and native REFUND_MANUAL automatically.

**(c) Domain** — in `register_domain`: after the ACTIVE flip (`routes.py:1292-1302`) mint `outcome=provisioned` with `domain_fqdn`; in the failure handler (`routes.py:1272-1281`) mint `outcome=failed`.

**(d) Jobs** — payment receipts automatic at create. Fulfillment mint via helper `mint_job_fulfillment(job_row)` at the status→completed flips for `BGPJobRow`/`DiagnosticJobRow`/`MXJobRow` (workers under `services/bgp/`, `services/diagnostics/`, `services/mx/`); include `artifact_sha256` when present. If completion sites exceed ~3 scattered spots, restrict to BGP + diagnostic jobs in M2 and note the rest.

**(e) Native intents** — in `services/intents.py` where SETTLED is first decided (`intents.py:240-242`): mint `kind=payment, rail=native-btc|native-xmr`, correlation `intent_id`, **no address/txid**. VM fulfillment then arrives via (b); no duplicate mint at the PROVISIONED flip.

**(f) Two-phase proxy** — `settle_verified` (`x402.py:706-781`): mint **only in the success branch after :771** (headers are set at :746-749 before the success check — don't attach a receipt to a failed settlement); merge id into `request.state.payment_response_headers`. Dev-bypass branch (:715-724) mints `rail=dev-bypass`.

## New endpoints & surfaces

`hyrule_cloud/api/trust.py` router (registered in `app.py` alongside the others, `app.py:233-253`):
- `GET /v1/receipts/{receipt_id}` — public capability-id lookup (anon-token philosophy); returns `{receipt_id, payload, jws, evm_signer, evm_signature, jwks_url}`; 404 unknown or disabled. Sanitized by construction (nothing beyond stored payload + signatures).
- `GET /v1/vm/{vm_id}/receipts` — management-gated (reuse `_vm_for_management` semantics, `routes.py:662-682`).
- `GET /.well-known/jwks.json` — active + retired ES256 public keys.
- `GET /.well-known/agent-card.json` (flag `TRUST_AGENT_CARD_ENABLED`) — built by `trust/identity.py:build_agent_card(config)`: name/description/url/provider; `endpoints` (openapi, x402Manifest, mcp, jwks, receipts template); `registrations: [{agentId, agentRegistry CAIP-10}]` (omitted while unset); `trustModels: ["feedback"]`; `x402Support: true`; `receiptSigners: [<EVM addr>]`. Verify exact filename/fields against the pinned ERC-8004 draft at impl time; serve an alias if the spec requires a different path.
- `POST /v1/x401/proof` (M6) — see x401 below.

Manifest (`app.py:266-527`): add `identity` / `receipts` / `x401` blocks **each only when its flag is on**; guard test pins byte-identical output when all flags off. `models.py` `ProductCapabilityResponse` gains optional `trust: TrustCapability | None = None` (`receipts: bool`, `receipt_header`, `x401`) — populate opportunistically; platform truth stays in the manifest.

MCP (`mcp_server.py`) + client (`client.py`): `get_receipt`, `list_vm_receipts`, `get_agent_identity` thin passthroughs (verification walkthrough in docstrings). Skills: update only when prod flags flip on (M4-ops) — same discipline as the 501 rule guarded by `tests/test_network_intel_contracts.py`.

Metrics (`api/metrics.py`): `hyrule_receipts_total{kind,rail}`, receipt-persist-drop counter, duplicate-settled-tx gauge, `hyrule_x401_decisions_total{decision}`.

## x401 (M5 shadow, M6 step-up scaffolding — enforce ships OFF)

`trust/x401.py`:
- Pydantic wire models `ProofRequest`/`ProofResponse`/`ProofResult` per **x401 v0.2** (pin the spec commit at impl time; implement the current draft's wire format, not the v0.1 launch-blog headers).
- `X401PolicyEngine.evaluate(route, method, amount, attrs) -> PolicyDecision(tier, reasons)`. v1 policy: `/v1/vm/create` + `/v1/vm/{id}/extend` → `step_up` when `duration_days > TRUST_X401_STEP_UP_VM_DURATION_DAYS` or `amount > TRUST_X401_STEP_UP_AMOUNT_USD`; everything else `never`.
- Shadow: `await trust.x401.observe(request, route, amount, attrs)` — one line before the gate call in `create_vm` (before reservation, ~`routes.py:832`) and `extend_vm` (before `routes.py:1091`). Soft-fail (try/except, ≤1s); writes structlog + `x401_proof_log` row; **no behavior change** (byte-identical off vs shadow is a pinned test).
- Advertisement: gate merges `advertised_extensions` (e.g. `{"x401": {"version": "0.2", "mode": "advisory", "proofEndpoint": "/v1/x401/proof"}}`) into the 402 `extensions` dict (`check_payment` builds extensions at `x402.py:418`; `_payment_required_response` already accepts them, `x402.py:249-265`). Populated from config in `app.py` — no trust import inside `x402.py`.
- Enforcement (`/v1/vm/create` only): when `mode=enforce` and tier=step_up and no valid `X-HYRULE-PROOF`, return **401 + PROOF-REQUEST before** `has_payment_credentials`/reservation/`check_payment` (i.e. before `routes.py:832`) — proof-first-then-pay; a request with a payment header but no proof must never reach verify/settle (test: `MockGate` call count == 0).
- `POST /v1/x401/proof`: verifier adapter (`X401Verifier` Protocol; v1 `StructuralVerifier` satisfies only when `TRUST_X401_ACCEPT_STRUCTURAL=true` — test-only; Proof Digital ID adapter is a later drop-in). Success mints `hyr_pf_<32 base62>` (cleartext once, sha256 at rest per repo convention) bound to quote_hash+route+method+expiry; returns PROOF-RESULT. Token check failure → fresh 401 PROOF-REQUEST.

## Caller-agent binding (M7, observe-only)

`trust/principal.py`: middleware installed only when `TRUST_PRINCIPAL_MODE=observe`. Parse RFC 9421 subset (`Signature-Input`/`Signature`; components `@method`, `@target-uri`, `created`, `expires`, `keyid`; algs `ed25519` + `ecdsa-p256-sha256`). `keyid` = `did:web:…#frag` → resolve did.json via httpx with 2s timeout, 64KB cap, `resolve_public_addresses` SSRF pre-flight (`services/safety.py:92-119`), `cachetools.TTLCache(512, 3600)` + negative cache. Result `AgentPrincipal(did, key_id, verified)` → `request.state.agent_principal`; any failure → absent, request proceeds identically. Recording: one change in `PaymentLedger.record` (`services/payments_ledger.py:54-164`) merging `{"agent": …}` into `extra`; `ReceiptService` reads the same state for receipt `agent` + `agent_did` column. ERC-8004 cross-resolution deferred to M9.

## ERC-8004 registration tooling (M3)

`scripts/erc8004_register.py`: one-shot; `--rpc-url --registry --private-key-env --agent-domain`; eth-account signing + raw JSON-RPC (`eth_call`/`eth_sendRawTransaction`) over httpx — no web3 dep. ABI fragments pinned in-script with the spec commit hash in a comment. Base Sepolia first; mainnet is a human ceremony (M4-ops, runbook checklist). Event watching = network-operations repo; document the `eth_getLogs` queries + event signatures in the runbook.

## Docs deliverables (in-tranche)

- `docs/trust-layer.md` — architecture, flags, invariants matrix, rollout state.
- `docs/x402-compute-fulfillment-receipt.md` — the open profile: payload schema, canonicalization, dual-signature rules (JWS + EIP-712 ReceiptDigest), JWKS discovery, per-rail semantics (incl. reserved Zcash slot + `x402-gateway`), verification walkthrough.
- `docs/runbooks/trust-keys.md` — ES256 + secp256k1 keygen (openssl / eth-account), Vault placement, JWKS rotation via retired list, ERC-8004 registration ceremony w/ human sign-off, monitoring queries (duplicate-settlement, receipt lag).
- Copy this plan to `docs/plans/<ISO-timestamp>-agent-trust-layer.md` with the repo's frontmatter convention (`status: accepted-for-execution`).
- Incidental hygiene (small, optional final PR): CLAUDE.md's endpoint table is badly stale (missing all intel/auth/intent routes, lists nonexistent `/v1/zone/check|buy`) — refresh or point at README.

## Test plan (conventions: AppState swap + `MockGate` duck type `tests/test_api.py:65-133`; real-gate `_FakeServer` harness `tests/test_payment_gate_x402.py`; sqlite via `_JSONB`)

1. `tests/test_trust_receipts.py` — build+dual-sign+**offline verify** roundtrip (JWS from JWKS output alone; EIP-712 recover == published signer); payload golden test; no receipt on required_402/verify_failed/settle_failed; dev-bypass mints `rail=dev-bypass`; `HYRULE-RECEIPT` header present + in `Access-Control-Expose-Headers`; native-rail payload has no address/tx key at all; `/v1/receipts/{id}` 404s; disabled flag → no header, `check_payment` return contract unchanged.
2. `tests/test_trust_fulfillment.py` — VM sim lifecycle receipts (provisioned + timing + simulated flag), failed→refund receipt (reuse `tests/test_refunds.py` fixtures), post-charge create failure, native intent SETTLED + REFUND_MANUAL receipts (reuse `tests/test_intent_engine.py` fixtures), domain ACTIVE/FAILED, extend, proxy two-phase through the real gate.
3. `tests/test_trust_x401.py` — mode=off is a zero-write no-op; **byte-identical off vs shadow**; proof-log rows + reasons; enforce: 401-before-gate with payment header present (gate call count 0), token bind/TTL/reuse-within-TTL, wrong-quote_hash rejection, full proof→402→pay→provision ordering.
4. `tests/test_trust_identity.py` — agent card schema + flag gating; JWKS active+retired; **manifest byte-identical when all flags off** (protects announcement #53).
5. `tests/test_trust_principal.py` — RFC 9421 verify with generated ed25519 key; did:web via respx; RFC1918 did-host refused; resolver down → request still settles (soft-fail); principal lands in ledger extra + receipt.
6. Extensions: `test_payment_gate_x402.py` (mint hooks don't alter Response|str contract or dual headers), migration 015/016 up/down smoke, `scripts/x402_canary.py` gains an assert-receipt step (header present → fetch → verify both signatures) used in staging.
7. Soft-fail suite: receipt store down ≠ payment failure; x401 log down ≠ 402/settle change; did resolver down ≠ anything. Run `mypy` (strict on new modules) + `ruff` before push — CI runs mypy strict on `hyrule_cloud/`.

## Milestones (PR-sized; tranche = M1–M7)

| # | Title | Contents | Blocked by |
|---|---|---|---|
| M1 | Protocol profile + payment receipts at the gate | `trust/` pkg, `TrustConfig`, migration 015, dual signer, gate mints (a)(f), `/v1/receipts/{id}`, JWKS, startup key guard, exposed header | — |
| M2 | Fulfillment + refund receipts | orchestrator/refunds/domain/intents/jobs hooks, `/v1/vm/{id}/receipts`, metrics, MCP/client tools, canary receipt step | M1 |
| M3 | Discovery-only ERC-8004 | agent card + manifest identity block (flag-gated), `scripts/erc8004_register.py`, profile + trust-layer docs | M1; **pin ERC-8004 draft + Sepolia registry addr** |
| M5 | x401 shadow | migration 016, policy engine, `observe()` in create/extend, 402 advisory extension, shadow metrics | M1; **pin x401 v0.2 shapes** |
| M6 | Step-up scaffolding (enforce OFF) | proof tokens, `/v1/x401/proof`, PROOF-REQUEST flow, proof-first-then-pay ordering | M5 |
| M7 | Caller-agent binding | RFC 9421 middleware, did:web resolver, ledger/receipt principal | M1 |
| — | Docs + runbooks + plan copy into docs/plans/ | listed above | alongside M1–M3 |

Order: M1 → M2 → (M3 ∥ M5 ∥ M7) → M6. Everything lands **disabled** (flags off / shadow); nothing changes the announced surface.

**Roadmap (explicitly out of tranche):** M4-ops (mainnet identity ceremony, Vault keys, `TRUST_RECEIPTS_ENABLED=true` canary→prod, skills updates); M8 Circle Gateway (spike w/ acceptance criteria: confirm scheme kind + SDK `server.register` duck-type fit at `x402.py:181-184`, testnet end-to-end on a $0.005 route, `accepts[]` ordering exact-first, threshold + route-class guard so VMs/domains never advertise Gateway; then `GatewayServerScheme` + Marketplace/Agent-Wallets listing); M9 external trust (EIP-712 feedback tooling, receipt-backed ERC-8004 feedback, off-chain signed validation reports, publish profile).

## Verify online at implementation time (WebFetch, before coding M3/M5/M6)

1. ERC-8004: current draft at eips.ethereum.org/EIPS/eip-8004 + github.com/erc-8004/erc-8004-contracts — Identity Registry addresses (Base Sepolia + mainnet), register/update function + event signatures, registration-file/agent-card filename + required fields, CAIP-10 format.
2. x401 v0.2: x401.proof.com/spec/latest + repo CHANGELOG — exact PROOF-REQUEST/RESPONSE/RESULT names, status-code semantics, claim profile.
3. x402 SDK (installed ≥2.9): confirm `create_payment_required_response(extensions=…)` merges arbitrary extension keys (bazaar path proves the mechanism, `x402.py:260-265`) and the server-scheme registry duck type (for M8 later).
4. (M8 only) Circle Gateway x402 seller docs + Marketplace requirements.

## Verification (end-to-end, after implementation)

1. `pytest` (all 323 existing + new must pass), `mypy hyrule_cloud/`, `ruff check`.
2. Alembic: `alembic upgrade head` against the Incus Postgres, then `downgrade -2` / `upgrade head` smoke.
3. Live loop with flags on + dev bypass: `TRUST_RECEIPTS_ENABLED=true` (+ generated test keys) + `PAYMENT_DEV_BYPASS_SECRET` → `uvicorn hyrule_cloud.app:app --port 8402` → `curl -H "X-DEV-BYPASS: …" -X POST :8402/v1/dns/lookup …` → assert `HYRULE-RECEIPT` header → `GET /v1/receipts/{id}` → verify JWS against `/.well-known/jwks.json` and EIP-712 recover with a small script (add as `scripts/verify_receipt.py`, doubles as the customer walkthrough).
4. VM sim lifecycle: quote → create (bypass) → poll status → assert payment receipt + fulfillment receipt (simulated) + `/v1/vm/{id}/receipts`; force a provisioning failure → assert refund receipt.
5. Flags-off regression: default env → diff `/.well-known/x402.json` against a pre-change capture (must be byte-identical); paid route responses carry no new headers.
6. x401: shadow mode → long-duration VM quote/create → `x401_proof_log` row with reasons; enforce mode (local only) → create with payment header but no proof → 401 PROOF-REQUEST and gate never called.
7. Staging canary: `scripts/x402_canary.py` with the new receipt assertion step.

## Risks

- **ERC-8004 / x401 draft drift** — runtime never depends on chain or the x401 spec beyond flag-gated surfaces; pin spec commits; registration data is config.
- **Receipt mint latency on settle-then-respond routes** — sub-ms sign, 2s bounded persist, drop-and-log (header simply absent).
- **Two keys to manage from day one** (dual-sign) — runbook ceremony; EVM signer is operational, separate from registry owner; JWKS retired-list keeps old receipts verifiable after rotation.
- **Ledger/receipt divergence** — accepted: receipts are attestations, ledger is revenue truth; soft `payment_event_id` link + lag metric.
- **Enforce misfire charging before proof** — ordering test-pinned (gate call count 0 on the 401 path); enforce flip documented as human-controlled ops.
- **Announce-surface destabilization** — manifest byte-identical guard test + everything default-off.

---

## Execution progress (2026-07-10)

- [x] M1 — trust core + payment receipts at the gate (commit 0e6abb3)
- [x] M2 — fulfillment + refund receipts across services (9521017)
- [x] M3 — discovery-only ERC-8004 surfaces, spec pinned (156675b)
- [x] M5+M6 — x401 shadow + step-up scaffolding, enforce OFF (a0c6a59)
- [x] M7 — RFC 9421 caller-agent binding, observe-only (094a5e6)
- [x] Docs: trust-layer.md, x402-compute-fulfillment-receipt.md, runbooks/trust-keys.md, scripts/verify_receipt.py
- [ ] M4-ops — key ceremony, Sepolia/mainnet registration, flag flips, skills updates (roadmap; runbook ready)
- [ ] M8 — Circle Gateway spike → additive payment kind (roadmap)
- [ ] M9 — receipt-backed ERC-8004 feedback + off-chain validation reports (roadmap)

Spec-pin notes vs the plan as written: the ERC-8004 registration document
lives at /.well-known/agent-registration.json (not agent-card.json — the
plan's verify-at-impl-time step caught this); registry addresses pinned
(Base Sepolia 0x8004A818…, mainnet 0x8004A169…); x401 v0.2.0 uses
PROOF-RESPONSE as the retry request header, so the planned X-HYRULE-PROOF
header was dropped in favor of the spec's Token Object carriage.
