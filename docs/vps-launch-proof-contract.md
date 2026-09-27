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
| `degraded`       | VM provisioned, but the central launch-time resolver probe failed | `VMStatus.READY` + `dns_resolution_status=failed` |
| `failed`         | Build failed; rollback may be available           | `VMStatus.FAILED`                 |
| `rolled_back`    | Failed VM was cleaned up / destroyed              | `VMStatus.DESTROYED` after failed |

## Status Endpoint Fields

`GET /v1/vm/{vm_id}/status` returns these launch-proof fields in addition to
the existing public status shape:

- **`launch_proof_status`** — one of the seven states above.
- **`payment_status`** — `paid` | `payment_required` | `not_required`.
- **`dns_aaaa_verified`** — `true` when the AAAA record for the VM hostname is
  confirmed (controlled simulation by default; real DNS check only when
  `HCP_LAUNCH_PROOF_REAL_XCPNG=1`).
- **`ssh_smoke_status`** — `not_run` | `passed` | `failed` (controlled simulation
  by default; real TCP connection check to the SSH port only when
  `HCP_LAUNCH_PROOF_REAL_XCPNG=1`, not an authenticated guest session).
- **`dns_resolution_status`** — `not_run` | `passed` | `failed`. Whether the
  configured resolver (`HYRULE_CUSTOMER_IPV6_DNS`) answers Hyrule's central
  launch-time query for `HYRULE_CUSTOMER_DNS_PROBE_HOSTNAME`. Guest routes and
  ACLs may differ, so this does not establish DNS success or failure inside
  the guest. Never inferred from the VM being READY — `not_run` means no
  measurement was taken.
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

## Degraded Contract

A provisioned VM whose launch-time resolver probe fails is reported as
`degraded`. This central probe does not prove DNS failure inside the guest,
and the degraded state does not mean that provisioning failed:

1. `launch_proof_status` is `degraded`; `status` stays `ready`.
2. `dns_resolution_status` is `failed` — the machine-readable reason.
3. `customer_message` explains the central probe failure and offers a DNS64
   resolver workaround if DNS also fails inside the guest, plus support.
4. `operator_message` identifies the configured resolver and central launch-time
   probe. This is not a measurement from inside the guest and does not establish
   fleet-wide impact.
5. This formatter does not auto-record a refund. Customers can contact support
   about usability or payment; actual refund status needs separate evidence.

## Failure Contract

When provisioning reaches `failed`:

1. `rollback_available` is `true`.
2. `customer_message` is a safe, generic message (e.g. *"Provisioning could not
   be completed. Contact support for help and to review any payment or refund."*).
3. The fallback does not establish that support was notified or a refund was
   requested/completed; those require separate delivery/payment evidence.
4. `operator_message` contains the internal error detail for operator triage.
5. No provider-internal strings (XCP-NG UUIDs, RPC errors, etc.) leak to the
   customer.

## Example Journey

```
POST /v1/vm/quote          → quote_id, status=created    (launch: accepted)
POST /v1/vm/create 402     → payment required              (launch: payment_required)
POST /v1/vm/create 202     → vm_id, status=provisioning   (launch: provisioning)
GET  /v1/vm/{id}/status    → ssh_smoke=passed, dns=true   (launch: provisioned)
```
