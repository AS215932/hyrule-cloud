# VPS Launch-Proof Contract

## Overview

The launch-proof contract is a narrow, customer-visible state machine over the
existing `/v1/vm/quote`, `/v1/vm/create`, and `/v1/vm/{vm_id}/status` endpoints.
It lets an operator or customer follow a VM from quote acceptance through
provisioning, provisioned, failure, or rollback without building a generic
payment system.

This is the AS215932 revenue-wedge proof: a paid VM can be traced end-to-end
from quote to running (or to a safe failure message) with explicit, inspectable
status fields.

## Customer/Operator States

| State            | Meaning                                           | Maps from existing internal state |
|------------------|---------------------------------------------------|-----------------------------------|
| `accepted`       | Quote created; order accepted, awaiting payment   | `QuoteStatus.CREATED`             |
| `payment_required`| Payment not yet settled; 402 returned on create  | `QuoteStatus.CREATED` + 402       |
| `provisioning`   | Payment confirmed; VM build in progress           | `VMStatus.PROVISIONING`           |
| `provisioned`    | VM build completed; ready for SSH                 | `VMStatus.READY` / `RUNNING`      |
| `failed`         | Build failed; rollback may be available           | `VMStatus.FAILED`                 |
| `rolled_back`    | Failed VM was cleaned up / destroyed              | `VMStatus.DESTROYED` after failed |

## Status Endpoint Fields

`GET /v1/vm/{vm_id}/status` returns these launch-proof fields in addition to
the existing public status shape:

- **`launch_proof_status`** — one of the six states above.
- **`payment_status`** — `paid` | `payment_required` | `not_required`.
- **`dns_aaaa_verified`** — `true` when the AAAA record for the VM hostname is
  confirmed (controlled simulation by default; real DNS check only when
  `HCP_LAUNCH_PROOF_REAL_XCPNG=1`).
- **`ssh_smoke_status`** — `not_run` | `passed` | `failed` (controlled simulation
  by default; real SSH smoke only when `HCP_LAUNCH_PROOF_REAL_XCPNG=1`).
- **`rollback_available`** — `true` when the VM is in `failed` and has not yet
  been destroyed.
- **`operator_message`** — Internal detail for operators (raw error, etc.).
- **`customer_message`** — Sanitized, customer-safe message. Never leaks
  provider internals.

## Simulation vs Real Infrastructure

- **Default (simulation)** — Provisioning skips XCP-NG, DNS, and Openprovider.
  SSH smoke and DNS verification are derived from the VM row state.
- **Real mode** — Set `HCP_LAUNCH_PROOF_REAL_XCPNG=1`. The orchestrator
  executes the full real provisioning path and runs actual DNS/SSH checks.

## Failure Contract

When provisioning reaches `failed`:

1. `rollback_available` is `true`.
2. `customer_message` is a safe, generic message (e.g. *"Provisioning could not
   be completed. Our team has been notified and your payment will be refunded."*).
3. `operator_message` contains the internal error detail for operator triage.
4. No provider-internal strings (XCP-NG UUIDs, RPC errors, etc.) leak to the
   customer.

## Example Journey

```
POST /v1/vm/quote          → quote_id, status=created    (launch: accepted)
POST /v1/vm/create 402     → payment required              (launch: payment_required)
POST /v1/vm/create 202     → vm_id, status=provisioning   (launch: provisioning)
GET  /v1/vm/{id}/status    → ssh_smoke=passed, dns=true   (launch: provisioned)
```
