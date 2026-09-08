# Admin control-plane promotion

This reconciliation preserves the current paid-account checkout, public catalog
readiness gates, domain-registration settlement recovery and provisioning events
alongside the admin PR's audited operations, session CSRF protection and explicit
payment-waiver accounting. Payment waivers remain disabled by default.

The admin migration is revision `023`, currently following `020`. Revision `017`
is already the deployed provisioning-events migration and must not be reused.
Before merging with pending expiry or guest-receipt migrations, reconcile the
parent to produce a single ordered head and rerun the real PostgreSQL checks.
Do not stamp over a conflicting migration history.

Use the infrastructure repository's app promotion workflow and pinned SHA after
required CI and review pass. The API and worker must be quiesced before migration,
using the deployment barriers and provisioning preflight in infrastructure PR547.
Verify the live migration head, API/worker health, session login and CSRF behavior,
and an audited read-only admin view before enabling admin operations.

The optional `tests/test_admin_migration_postgres.py` accepts only an explicitly
configured, empty local `admin_migration_test` database through
`HCP_ADMIN_MIGRATION_TEST_DATABASE_URL`. It runs the real chain through `020`,
seeds fixture rows, upgrades to `023`, checks billing backfills and new fields,
then downgrades to `020` and upgrades again. It preserves the fixture account and
VM rows; it does not establish preservation of admin data across a downgrade.

Downgrading removes admin audit/operation tables and admin-specific columns.
After real admin activity, preserve that history and reconcile pending operations
before considering a schema downgrade. A compatible application rollback that
retains the schema should be evaluated first. Never use the disposable test's
database-reset procedure on production.

This foundation does not implement the operator expiry-extension endpoint from
issue #110. That endpoint still needs explicit authorization, step-up checks,
audit evidence and serialization with expiry/deletion before rollout.
