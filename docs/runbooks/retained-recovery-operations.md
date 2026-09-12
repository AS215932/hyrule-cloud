# Retained VM recovery operations

Use this procedure only after the reviewed Cloud release and migrations through 025 are deployed. Keep expiry retention disabled until independent monitoring and disposable provider/data/boot recovery have passed. The API contract exists in source; this runbook does not establish production readiness. See [retention design and rollout prerequisites](vm-disk-retention.md).

## Inspect before changing anything

Use the existing authenticated administrator browser session to read `GET /v1/admin/vms/{vm_id}/retention`. Reads require an enabled administrator. Mutations additionally require CSRF and current step-up authentication; never substitute an API key, database write or provider call for these checks. Keep session credentials, recovery reasons and customer identifiers in the approved private operations record.

Record the VM ID, observation time, `vm_status`, `retention.state`, `retain_until`, verification timestamps/error and `active_recovery`. Read history with `limit` (1–100) and `next_offset` until the relevant operation is found. The active operation is returned separately even when outside the current history page. A missing VM row does not erase historical outcomes.

| Observed state | Operator action |
| --- | --- |
| `retention.state=prepared` | Protection has not been durably confirmed. Preserve evidence and reconcile protection; do not initiate restore or report recoverability. There is no public repair endpoint in this release. |
| `retention.state=retained`, no active recovery | Confirm the intended owner, recovery authorization and verification evidence. An authorized new recovery can be requested. |
| `retention.state=restoring`, active operation `pending` | Request acceptance is durable. Reuse its exact operation ID, days and reason after resolving any stated blocker. |
| `retention.state=restoring`, active operation `authorized` | The fixed future expiry is durable. The provider change or completion commit may still be incomplete. Reuse the exact request; do not assume provider protection is unchanged. |
| History contains the requested operation as `completed` | Recovery completed. Confirm the current VM and any later retention cycle before considering a separate start action. |
| No retention and no matching completed operation, or inconsistent active state | Stop mutation and investigate the identity/evidence mismatch. Do not infer successful recovery from absent active retention alone. |

`retain_until` is a minimum preservation deadline, not permission to purge. Missing or failed verification needs investigation; it is not evidence that disks are gone. This release has no purge or force-complete operation.

## Request or resume one recovery

For a new authorized recovery, generate one UUID and preserve the request before submission. For an existing operation, copy `operation_id`, `days` and `reason` from its active or historical status. Submit only those fields to `POST /v1/admin/vms/{vm_id}/actions/restore` using the existing authenticated admin client:

```json
{
  "operation_id": "<the recorded UUID>",
  "days": 7,
  "reason": "<the recorded authorized recovery reason>"
}
```

The example is a shape, not a ready-to-send request. Days must be 1–365. A retry must preserve the recorded value, including the exact reason. Replacing the UUID after a timeout can conflict with an already accepted recovery. The fixed `new_expiry` is computed once; retries do not grant extra days.

After every ambiguous response, read status before retrying. A timeout or lost connection can occur after a commit or provider action. Avoid unattended retry loops; resume only after the failure has been classified and the relevant prerequisite checked.

| Response or condition | Next step |
| --- | --- |
| Success with `state=completed` | Record the operation ID and fixed expiry, then perform completion checks below. |
| HTTP 503, recovery pending | Read status. Once the provider prerequisite is healthy, retry the exact request with valid step-up/CSRF. The API verifies provider state again. |
| HTTP 401/403 | Reauthenticate through the existing flow, or have an enabled authorized administrator resume. Do not broaden access or bypass revocation. |
| HTTP 409, owner disabled | Account enable is a separate authorized action with consequences for other resources. Resolve that decision first; do not auto-enable an owner merely to retry recovery. |
| HTTP 409, expired or changed authorization | Preserve the pending record and escalate for a separately reviewed reconciliation procedure. This release cannot extend, replace or force-complete that operation. The ordinary expiry-extension endpoint refuses deletion-claimed VMs. |
| HTTP 409, reused ID with different request, changed identity/state, or unavailable request | Compare the private recorded request and fresh status. Do not manufacture a new ID or edit evidence to get past the fence. |
| HTTP 404 | Recheck the exact VM ID and history. Do not reconstruct a VM from partial metadata. |
| Unclassified server error or lost acknowledgement | Read status and retain the same request. Diagnose before another bounded attempt. |

## Confirm completion and preserve rollback evidence

Read status again and locate the matching `completed` operation in history. Confirm its expiry matches the response. For a newly completed recovery with no later lifecycle action, the VM remains suspended, active retention is absent, its network identity is retained, and `power_changed` is false. Recovery does not boot the guest. A replay of an older completed operation is historical evidence, not proof of current VM state.

Correlate private audit events `vm.restore_requested`, `vm.restore_authorized` and `vm.restore_completed` by operation ID. Provider/commit failure must not be papered over by manually deleting the retention row, deletion claim or audit history. Downgrading migration 024 is intentionally refused while active retention or historical recovery evidence exists.

Any start and data/boot verification is a separate explicit action. Before that action, confirm current owner authorization, future expiry, suspension reason and no later retention/deletion claim. Preserve prior operator blocks: recovery restores only retention-owned settings. Do not use a customer's retained VM, retired infrastructure VM or its disks as a disposable test fixture.

Record completed checks and unresolved blockers privately. No owner notification is sent by this procedure. Owner notices, production UI integration, explicit purge policy, deployed-provider compatibility and disposable restoration proof remain separate rollout requirements.
