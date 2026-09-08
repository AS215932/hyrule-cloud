# Expiry disk retention (rollout pending)

`vm_expiry_disk_retention_enabled` defaults off until the deployed XO behavior and a disposable restore have been verified. With the flag enabled, expiry deletion captures a complete disk manifest and commits it with the deletion claim before calling XO. `vm_disk_retention_days` sets the recorded deadline (default 30, range 1–365); no automatic purge is implemented. Existing manifests are honored on retries even if the flag is off or a customer retries deletion directly.

The provider passes `deleteDisks=false`, verifies exact VM absence and every retained VDI's type, storage repository, size and presence, then marks the retention record retained before finalizing the VM's destroyed state. Incomplete or changed inventory fails closed. A lost provider reply requires the same complete verification. The record preserves original owner attribution and basic OS/resource configuration independently of live VM/account rows.

XO recursively deletes child snapshots even with `deleteDisks=false`. This implementation refuses deletion when snapshots exist or snapshot inventory is unknown; an operator must account for those recovery points. Retained disks must be protected from orphan cleanup before activation. Original disk retention is not a separate-storage backup.

Local schema order is 020→021→022→023→024. Validate the full chain against PostgreSQL before combined promotion. The 024 downgrade refuses if any retention record exists; do not delete records to bypass it. Preserve and reconcile recovery evidence through a coordinated rollback.

Outstanding before rollout: full provider boot/firmware restore metadata, audited operator restore with fresh networking, retention/orphan-protection policy, deployed-XO version checks, and disposable data restoration proof. A retained-record state is evidence of disk inventory verification, not proof that the guest can boot or its data can be restored. Production promotion remains controlled by network-operations after CI/review and coordinated API/worker quiescence.
