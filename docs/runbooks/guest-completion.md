# Guest initialization verification

New Linux VMs stay `provisioning` until their own scoped first-boot report
confirms clean cloud-init completion. SSH reachability and published DNS are
separate checks and cannot make this transition. A failed setup script produces
`failed` in VM status and launch proof, with a fixed message naming the stage.
Detailed logs remain inside the guest. The existing refund-obligation path runs;
recording an obligation does not itself transfer a refund.

A failed or unverified guest is retained for diagnosis, including its disks.
Operators must reconcile recovery, refund and eventual resource retention;
this change does not introduce automatic deletion of failed guests.

The observer is queued without blocking cloud-final and starts after that unit
finishes, including failure. Its private configuration contains only a scoped
report credential, callback URL, deadline and setup requirement. The controller
stores the token hash. A tracked guest retains its report identity across worker
restarts; a fresh clone gets a new identity after existing orphan cleanup.
The database receipt is independent of mutable VM metadata and serialized by a
row lock. Identical retries are accepted, conflicting terminal reports rejected.
A completed receipt can be acknowledged again after its original deadline.

Reports contain only a finite outcome, stage and numeric exit code. No guest
logs or raw cloud-init error output are uploaded. HTTPS verification stays
mandatory and redirects are not followed. A saved result is retried without
reclassification, including after observer restart. Successful acknowledgement
removes the observer's local credential file; the original cloud-init user-data
may still contain the credential, so this is not a promise of secure erasure.
The credential proves possession by that provisioning attempt, not trusted
execution against a guest owner who controls root.

## Promotion prerequisites

- Apply the guest-receipt migration before enabling the new API and worker.
  Reconcile migration parents against current main and verify a single head.
- Use coordinated API/worker quiescence during checkout and migrations. Do not
  permit Vault callbacks to restart mixed code/schema versions.
- Drain or explicitly resolve older in-flight provisioning attempts before
  rollout. A tracked guest created by old code has no report credential; the
  new worker cannot truthfully infer its initialization success. Existing
  delivered VMs are not retrospectively re-probed or recreated by this change.
- Verify the configured `HYRULE_PUBLIC_BASE_URL` is HTTPS and reachable from
  customer guests, with a normally trusted certificate chain. Keep existing
  customer network isolation. The timeout is
  `HYRULE_GUEST_REPORT_TIMEOUT_SECONDS` (default 900, range 60–3600).
- Verify the selected Linux template has Python 3, systemd and cloud-init with
  JSON terminal status. The observer configuration explicitly rejects OpenBSD;
  this change does not establish an OpenBSD completion mechanism.
- Follow normal green CI, review and pinned-SHA promotion. Observe a controlled
  successful guest and a deliberately failing setup script before treating the
  status contract as verified in the production template/network environment.

## Rollback

Keep a compatible receiver available while outstanding guests can report.
Do not remove the receipt table while provisioning is active; its downgrade
explicitly refuses that state. A downgrade must not reintroduce a worker that
marks unresolved guests ready from SSH reachability. Resolve or drain those
attempts first. Preserve failed guest disks and local diagnostics throughout.

## Validation scope

Application tests exercise the orchestrator, scoped HTTP receiver, public
status and launch proof. The optional PostgreSQL test proves actual concurrent
row-lock contention and guarded downgrade/re-upgrade on a fresh disposable
`guest_result_test` database. Run it only with
`HCP_GUEST_RESULT_TEST_DATABASE_URL` explicitly pointing to that local test DB.

A QEMU guest with a verified official Debian image is useful for real cloud-init
and observer execution. A local callback and mocked provider/network probes do
not prove production XCP-NG, customer IPv6 or tenant-isolation behavior. Retain
that distinction in the deployment record.
