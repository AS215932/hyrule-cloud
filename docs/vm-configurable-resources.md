# Configurable VM Resources

Hyrule Cloud exposes four technical profile shortcuts. The stable `xs`, `sm`,
`md`, and `lg` identifiers remain in the API and database, while public names
describe the actual base resources.

| ID | Technical name | vCPU | RAM | SSD | USD/day |
|---|---|---:|---:|---:|---:|
| `xs` | `1C-1G-10G` | 1 | 1 GB | 10 GB | $0.20 |
| `sm` | `1C-2G-20G` | 1 | 2 GB | 20 GB | $0.40 |
| `md` | `2C-4G-20G` | 2 | 4 GB | 20 GB | $0.60 |
| `lg` | `4C-4G-40G` | 4 | 4 GB | 40 GB | $0.80 |

An order may request exact final resources in 1-vCPU, 1-GB RAM, and 10-GB SSD
increments. The final ceiling is 4 vCPU, 8 GB RAM, and 40 GB SSD. Add-ons cost
$0.10 per vCPU/day, $0.15 per GB RAM/day, and $0.05 per 10 GB SSD/day.

The API evaluates every base profile that fits under the requested resources
and uses the cheapest result. Exact profile matches win equal-price ties. This
means the same final resources always have the same price regardless of which
shortcut a client initially selected. For example, `1C-2G-20G` resolves to
`sm` at $0.40/day, while `4C-8G-40G` resolves to `lg` plus 4 GB RAM at
$1.40/day.

## Provisioning constraints

Customization is available only while ordering. XCP-ng already supports
setting vCPU and RAM on the halted clone and growing its root VDI before first
boot. Disk shrink is not supported. OpenBSD root growth continues to use the
offline OpenBSD builder VM before the customer guest first starts. No
post-provision resize endpoint is advertised.

Every durable quote stores the canonical exact resources, total, and daily
base/add-on breakdown. VM rows store exact resources plus billing add-on
quantities. Extensions apply current catalog rates to those stored quantities;
they do not reinterpret a legacy machine's physical disk as a new add-on.
Pre-change VMs and in-flight orders retain their original resources, including
retired 80-GB disks, and are never automatically resized.

## Admission control

The production deployment is a RAM-constrained single XCP-ng host. Before a
quote is accepted, the API reads current host/default-SR capacity from Xen
Orchestra and combines it with DB reservations that have not reached XO yet.
The paid EVM path serializes the final check and reservation across workers
with a PostgreSQL advisory lock.

Admission keeps the existing 2:1 vCPU overcommit policy, does not overcommit
RAM, and preserves 2 GB of host RAM plus 20 GB on the default SR. If XO cannot
prove capacity, ordering fails closed before payment. Native payments are
checked before an address is issued and again at settlement; a settled payment
that no longer fits enters the explicit manual-refund path.
