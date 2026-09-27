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
At expiry, the waiter locks and refreshes the receipt so an on-time report
transaction that is still committing cannot be mistaken for a missing report.
The server enforces that deadline. Guest retries use a bounded monotonic window
(the configured report timeout, renewed on observer restart), so an incorrect
guest wall clock cannot prevent submission or extend server acceptance.

The worker scans provisioning rows with report identities every 15 seconds,
four rows per page, continuing by VM ID so active earlier rows cannot starve later
ones. This recovers ordinary x402 guests even if only the API restarts. Recovery
rechecks network/DNS and consumes the existing receipt; it never recreates a tracked
guest or rotates its credential. Normal and recovered attempts share a PostgreSQL
transaction advisory lock per VM. Four attempts per process may run concurrently;
ownership connections are separate from the API/receipt pool. Shutdown cancels and
joins tasks before closing providers. A connection heartbeat cancels work on detected
ownership loss; it cannot retract an external provider request already sent. SQLite
only provides single-process development exclusion. Legacy guests without report
identities remain subject to the deployment preflight below.

Before UUID persistence, new guests use an exact label containing both the VM ID
and report generation. A unique running guest with that label is recovered with
the same receipt identity; provider sizing precedes its start. If no matching or
legacy guest exists and no report has arrived, creation can be retried with a new
generation. An old create request finishing after a crash stays halted because
creation uses `bootAfterCreate=False`. Halted guests, multiple matches, legacy
labels, or a completed report with no matching guest require operator recovery:
the attempt becomes failed and enters refund-obligation handling; guests are
preserved, not deleted or blindly started. This does not promise automatic repair
of a partially created guest or automatic removal of a late halted orphan.

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
  customer guests, with a normally trusted certificate chain.
  Configuration loading rejects non-HTTPS, malformed, credential-bearing,
  query-bearing and fragment-bearing callback bases before API/worker startup.
  This syntax check does not establish DNS, TLS trust or guest reachability.
  Keep existing customer network isolation. The timeout is
  `HYRULE_GUEST_REPORT_TIMEOUT_SECONDS` (default 900, range 60–3600).
- Verify the selected Linux template has Python 3, systemd and cloud-init with
  JSON terminal status. The observer configuration explicitly rejects OpenBSD;
  this change does not establish an OpenBSD completion mechanism.
- Follow normal green CI, review and pinned-SHA promotion. Observe a controlled
  successful guest and a deliberately failing setup script before treating the
  status contract as verified in the production template/network environment.

## Rollback

Provisioning dispatch is asynchronous and must be awaited after the caller
links its paid quote or intent. Dispatch commits an initial receipt identity
before creating any in-memory task, including work waiting on the four-task
limit or clone capacity lock. Unpaid reservations cannot be dispatched. New
clones receive a fresh credential and deadline at clone time; waiting in the
queue does not consume their eventual guest-report window. This preserves the
existing link-before-dispatch ordering; it does not make the preceding payment
and quote/intent handoff transactions atomic.

A receipt-backed attempt with no recorded hypervisor UUID keeps its customer
prefix quarantined even after failure, repeated customer deletion, or deferred
DNS cleanup. Retained ambiguous guests may still use that prefix. Operator
reconciliation must account for every candidate and establish cleanup before
releasing the address; DNS success alone is insufficient. The receipt identity
must be preserved until reconciliation, even when no candidate is visible yet.

Observer-local command/read errors are retried within the monotonic report
window without persisting a failed result. If observation never succeeds, the
controller's missing-report deadline determines failure. Explicit terminal
cloud-init or setup-script failure still produces a durable failed receipt.

Keep a compatible receiver available while outstanding guests can report.
The receipt migration also refuses downgrade for any receipt-backed VM without
a recorded hypervisor UUID, including failed or destroyed rows. Those receipts
may be the only durable evidence keeping an ambiguous guest's prefix quarantined.
Complete operator reconciliation before a downgrade; do not erase receipts to
get past the guard.
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

Simulation dispatch does not create guest receipts. A simulation-mode process that finds an existing receipt or provider UUID leaves the real attempt pending for reconciliation; it never replaces that evidence with simulated success. Fresh simulated VMs can release their prefixes on deletion. Receipt-backed UUID-less real attempts remain quarantined, including after a mode change. The queued-dispatch restart fixture verifies re-dispatch of all eight paid attempts with provider execution stubbed; separate provisioning fixtures verify terminal guest completion.
