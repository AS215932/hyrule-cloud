# VM expiry status

Both the public `/v1/vm/{id}/status` and authenticated `/v1/vm/{id}` responses
include `expiry`: a policy assessment alongside the existing runtime `status`.
It contains `state`, `observed_at`, `grace_ends_at`, `deletion_eligible`, and a
customer-safe `message`. Existing response fields remain available.

`active` means the recorded term has not expired. `expired` means the term has
expired and the configured grace period has not elapsed. `deletion_eligible`
means that grace has elapsed; deletion can occur on a subsequent worker sweep.
The grace deadline is computed from the deployment's `vm_grace_period_hours`,
not a hard-coded default. Comparisons match the worker: expiry and grace must
be strictly in the past. This is an eligibility timestamp, not a guarantee of
the exact deletion time or of a retained backup.

A persisted deletion claim, when that schema is present, reports `deleting`.
Destroyed VMs report `destroyed`; failed VMs without a deletion claim report
`not_applicable` because the expiry sweep excludes them. Missing expiry reports
`not_set`. These states do not manufacture a future deletion deadline.

Runtime and expiry remain distinct: a suspended VM may have an active or expired
term. This API does not infer who suspended it or why. Public customer messages
reflect suspension/expiry instead of repeating stale readiness text. Reading status
does not change the VM, extend its term, accept payment, or start a deletion.
The new fields are additive and require no database migration.

This addresses the API visibility part of issue 110. Audited admin recovery,
owner notices, recoverable retained storage, grace-policy changes, and frontend
presentation remain separate work. Promote through the normal reviewed SHA-pinned
workflow and verify the live API before claiming this behavior is deployed.
