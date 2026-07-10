---
created: 2026-07-01T17:12:27.331Z
source: pi-plan-mode
status: accepted-for-execution
---

# Fix Hyrule Cloud x402 Server-Side Payments

## Summary
Fix production x402 by updating `PaymentGate` to use the x402 2.10 SDK API, emit standard x402 v2 headers, keep legacy Hyrule header compatibility, and switch production from `https://x402.org/facilitator` to a Base-mainnet-capable facilitator before validation.

## Key Findings
- Production is on `origin/main` / `81e4316`; local `main` is behind by one commit, so hotfix must branch from `origin/main`.
- `hyrule_cloud/middleware/x402.py` calls nonexistent `self.server.verify(...)` / `settle(...)`.
- x402 2.10 exposes `verify_payment(...)` / `settle_payment(...)`.
- Current live dry-run fails standard parsing: `Invalid payment required response`.
- Production manifest advertises `eip155:8453` but reports `https://x402.org/facilitator`; that facilitator currently advertises only `eip155:84532`, so prod config must move to a mainnet-capable facilitator.

## Implementation Steps
1. Branch the hotfix from `origin/main`.
2. Refactor `PaymentGate` to use canonical x402 SDK request/response models and methods.
3. Preserve backward compatibility for existing Hyrule clients while adding standard x402 headers.
4. Add payment response header propagation.
5. Add focused unit tests for x402 2.10 behavior and header compatibility.
6. Update/verify production facilitator configuration for Base mainnet.
7. Run CI and promote the new SHA.
8. Validate production with dry-run only, no spend.

## Code Changes

### `hyrule_cloud/middleware/x402.py`
- Replace manual/nonstandard 402 construction with SDK-backed requirements:
  - Build `ResourceConfig` per enabled network.
  - Use `self.server.build_payment_requirements(...)`.
  - Use `self.server.create_payment_required_response(...)`.
  - Encode with `encode_payment_required_header(...)`.

- Initialize the SDK server before building requirements/verifying:
  - Add lazy async initialization with a lock.
  - Run sync `self.server.initialize()` via `asyncio.to_thread(...)`.
  - If initialization/config is unavailable, return `503 {"error": "Payment facilitator unavailable"}`.

- Accept both payment header names:
  - Standard: `PAYMENT-SIGNATURE`
  - Legacy: `X-PAYMENT`

- Emit both challenge header names:
  - Standard: `PAYMENT-REQUIRED`
  - Legacy: `X-PAYMENT-REQUIRED`

- Replace:
  - `await self.server.verify(...)`
  - `await self.server.settle(...)`

  with:
  - `await self.server.verify_payment(payment_payload, matching_requirements)`
  - `await self.server.settle_payment(payment_payload, matching_requirements)`

- Use SDK response attributes:
  - `verification.is_valid`
  - `verification.invalid_reason`
  - `verification.payer`
  - `settlement.success`
  - `settlement.transaction`
  - `settlement.payer`

- Keep `check_payment(...) -> Response | str` signature unchanged.

- Preserve existing hotfix semantics:
  - Verify and settle before route provisioning, as today.
  - Do not redesign quote/provisioning settlement order in this fix.

### `hyrule_cloud/app.py`
Add a small middleware that attaches settlement headers saved on `request.state` to the final response:
- `PAYMENT-RESPONSE`
- `X-PAYMENT-RESPONSE`
- merge into `Access-Control-Expose-Headers`

## Tests
Add `tests/test_payment_gate_x402.py` covering:
- No payment returns `402` with both `PAYMENT-REQUIRED` and `X-PAYMENT-REQUIRED`.
- Standard `PAYMENT-SIGNATURE` header verifies and settles successfully.
- Legacy `X-PAYMENT` header still verifies and settles successfully.
- Fake server has no `.verify` / `.settle`; test proves only `.verify_payment` / `.settle_payment` are called.
- Invalid payment returns `402`, not `502`.
- Settlement failure returns `402` with payment response headers.
- Facilitator initialization failure returns `503`.

Run:
```bash
uv run ruff check hyrule_cloud/middleware/x402.py hyrule_cloud/app.py tests/test_payment_gate_x402.py
uv run mypy hyrule_cloud/
uv run pytest -q tests/test_payment_gate_x402.py tests/test_vm_quote.py tests/test_payments_networks.py
uv run pytest -q
```

## Production Config
In production/Vault/network-operations config:
- Keep network: `eip155:8453`
- Keep asset: Base USDC
- Replace `PAYMENT_FACILITATOR_URL=https://x402.org/facilitator` with a facilitator whose `/supported` includes:
  - `x402Version: 2`
  - `scheme: exact`
  - `network: eip155:8453`

Do not promote if the configured facilitator only advertises `eip155:84532`.

## Rollout
1. Create hotfix PR from `origin/main`.
2. Merge after CI passes.
3. Trigger/request promotion for the merged SHA.
4. Confirm production manifest now shows the mainnet-capable facilitator.
5. Run dry-run validation only:
   - `POST https://cloud.hyrule.host/v1/vm/create`
   - 1-day `xs` VM payload
   - `dryRun=true`
   - `maxUsdc=0.10`
   - Expected: valid x402 requirements parse successfully.
   - No signing, no settlement, no spend.

## Acceptance Criteria
- Standard x402 clients can parse Hyrule’s 402 challenge.
- Production no longer returns `502 {"error":"Payment processing error"}` due to missing SDK methods.
- Hyrule still accepts legacy `X-PAYMENT` clients.
- Production advertises Base mainnet only with a Base-mainnet-capable facilitator.
- No live paid canary is run; validation stops at dry-run per user choice.

## Explicit Non-Goals
- No paid VM creation during validation.
- No settlement-order redesign.
- No removal of legacy `X-PAYMENT` / `X-PAYMENT-REQUIRED` compatibility.




















<!-- pi-plan-progress:start -->
## Progress

Status legend: `[x]` done, `[~]` in progress, `[-]` skipped, `[>]` deferred, `[!]` blocked, `[ ]` pending.

- [x] 1. Update/verify production facilitator configuration for Base mainnet _(done)_
- [x] 2. Run CI and promote the new SHA _(done)_
- [x] 3. Validate production with dry-run only, no spend _(done)_

<!-- pi-plan-progress:end -->
