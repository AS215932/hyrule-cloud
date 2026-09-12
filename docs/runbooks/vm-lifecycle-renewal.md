# VM renewal and deletion claims

Renewal, operator extension and expiry decisions lock the owner account before the PostgreSQL VM row. The extension route acquires it before pricing and payment, rejects a claimed or terminal VM without calling payment, and commits purchased time before attempting to resume a suspended guest. A provider resume failure does not erase the committed extension.

Deletion commits `deletion_started_at` before invoking XO. A retry or a restarted API sees that claim and cannot sell a renewal. The worker resumes claims even when the original expiry is still in the future. An ambiguous XO delete failure counts as success only after a successful inventory query confirms the exact UUID is absent. Failed inventory checks remain failures. Quarantined DNS/prefix cleanup can be retried after the guest is destroyed without deleting the guest again.

## Extension outcomes and operator recovery

A customer extension writes a unique `extend_applied` payment-ledger receipt in the same transaction as the new expiry. The receipt stores the current extension payment transaction, payer, VM, days and old/new dates. Its amount is zero: it records application of purchased time, not additional revenue. Existing settlement events remain the revenue source.

After a commit exception, a fresh lifecycle lock and receipt lookup establish whether the transaction applied. Confirmed absence permits the normal refund-obligation path; a matching receipt retains the purchased time. If reconciliation is unavailable, the API returns 503 and asks the customer to contact support before paying again. A later database failure while recording a resume or reading state returns a distinct 503 saying the extension was applied and must not be purchased again. Provider start failure alone returns the retained expiry with suspended state. Check both provider power and database status when reconciling a resume failure; do not assume they match.

These receipts resolve a particular database commit attempt. They do not provide HTTP retry idempotency, make external payment settlement atomic with the database, or repair a process crash between settlement and starting the extension transaction. Before refunding or retrying, reconcile the original settlement and application receipt by transaction and VM. Never count `extend_applied` as a second charge.

Operators can grant recovery time using `POST /v1/admin/vms/{vm_id}/actions/extend` with integer `days` from 1 through 365 and an explicit reason. The endpoint requires an administrator browser session, CSRF and step-up authentication. Expiry becomes `max(old_expiry, now) + days`, with a `vm.extend` audit committed atomically. It takes no payment and leaves power and suspension reasons unchanged; use the existing explicit start action after resolving suspension restrictions. Missing expiry, provisioning, failed/destroyed VMs and claimed deletion are rejected. A grant cannot undo deletion already claimed by a worker.

## Validation

Run the normal test suite. The opt-in `tests/test_vm_lifecycle_postgres.py` additionally requires `HCP_LIFECYCLE_TEST_DATABASE_URL` pointing to a fresh, disposable PostgreSQL database named `cloud_lifecycle_test`. It creates test tables and fake VM data. Never point it at an application database. It proves blocking between independent connections, both renewal/suspend orderings, rejection before payment after a persisted claim, and migration downgrade protection.

`tests/test_admin_expiry_postgres.py` uses a fresh local `admin_expiry_test` database through `HCP_ADMIN_EXPIRY_TEST_DATABASE_URL`. It applies actual migrations, proves operator/delete blocking with `pg_blocking_pids`, audit rollback, commit-acknowledgment reconciliation, and combined migration rollback/reapply preserving VM dates and application receipts. The admin schema downgrade drops audit history: this test explicitly does not promise audit retention.

## Promotion and rollback

In this integration migration 021 follows 020 and admin migration 023 follows 021. Pending guest migration 022 must be reconciled into one migration chain before combined promotion. Pause the expiry worker during the coordinated rollout, apply the migration, and deploy compatible API and worker code before resuming the worker. Mixed old/new workers do not provide the new locking guarantee. Production versions must still be promoted through network-operations and its normal validated deployment path.

Do not downgrade while an unfinished deletion claim exists. The migration explicitly refuses to remove that fence. Do not clear a claim or manually change expiry as a workaround: first establish whether provider deletion happened and complete or explicitly reconcile the operation. A binary rollback to an older worker also loses claim awareness and requires a coordinated maintenance decision.

This change addresses the renewal/expiry race. Issue 110 still requires owner notices, recoverable disk retention, production rollout of operator recovery tooling, grace-policy review and customer-visible expiry/deletion state. It does not make automatic expiry deletion recoverable. External payment settlement and the database are not one atomic transaction; reconciliation of ambiguous settlement outcomes remains a separate delivery requirement.

### Late provider identity after deletion

A deletion claim can commit while the provider is creating a guest whose UUID is not yet stored. The original attempt preserves the prefix quarantine. Once the provisioner persists that UUID, it checks the claim before network or guest-result waits and attempts cleanup. Failed cleanup remains discoverable by the expiry worker even when the database row already says DESTROYED.

The server-owned VM metadata field `provider_deleted_uuid` records only the exact provider identity whose deletion was confirmed. A later or different UUID is not covered by that evidence. Completion reacquires the owner/VM lifecycle lock before recording evidence or releasing the prefix, and deferred DNS cleanup refuses to release a prefix with an unverified guest. Existing historical destroyed rows without this evidence use the provider's idempotent delete/absence check on retry. This does not discover an unrecorded UUID or authorize removal of ambiguous generation-labelled clones.
