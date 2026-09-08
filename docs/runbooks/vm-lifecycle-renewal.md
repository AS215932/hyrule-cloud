# VM renewal and deletion claims

Renewal and expiry decisions share a PostgreSQL VM row lock. The extension route acquires it before pricing and payment, rejects a claimed or terminal VM without calling payment, and commits purchased time before attempting to resume a suspended guest. A provider resume failure does not erase the committed extension.

Deletion commits `deletion_started_at` before invoking XO. A retry or a restarted API sees that claim and cannot sell a renewal. The worker resumes claims even when the original expiry is still in the future. An ambiguous XO delete failure counts as success only after a successful inventory query confirms the exact UUID is absent. Failed inventory checks remain failures. Quarantined DNS/prefix cleanup can be retried after the guest is destroyed without deleting the guest again.

## Validation

Run the normal test suite. The opt-in `tests/test_vm_lifecycle_postgres.py` additionally requires `HCP_LIFECYCLE_TEST_DATABASE_URL` pointing to a fresh, disposable PostgreSQL database named `cloud_lifecycle_test`. It creates test tables and fake VM data. Never point it at an application database. It proves blocking between independent connections, both renewal/suspend orderings, rejection before payment after a persisted claim, and migration downgrade protection.

## Promotion and rollback

Migration 021 follows 020. Pause the expiry worker during the coordinated rollout, apply the migration, and deploy compatible API and worker code before resuming the worker. Mixed old/new workers do not provide the new locking guarantee. Production versions must still be promoted through network-operations and its normal validated deployment path.

Do not downgrade while an unfinished deletion claim exists. The migration explicitly refuses to remove that fence. Do not clear a claim or manually change expiry as a workaround: first establish whether provider deletion happened and complete or explicitly reconcile the operation. A binary rollback to an older worker also loses claim awareness and requires a coordinated maintenance decision.

This change addresses the renewal/expiry race. Issue 110 still requires owner notices, recoverable disk retention, operator recovery tooling, grace-policy review and customer-visible expiry/deletion state. It does not make automatic expiry deletion recoverable. External payment settlement and the database are not one atomic transaction; reconciliation of ambiguous settlement outcomes remains a separate delivery requirement.
