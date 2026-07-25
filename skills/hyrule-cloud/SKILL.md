---
name: hyrule-cloud
description: "Deploy bare VMs with x402 payment and a free auto subdomain. Domain registration is deferred — not yet launched."
---

# Hyrule Cloud — Agentic VPS Hosting

Deploy bare VMs with x402 payment (USDC on Base). Every VM gets a free auto
subdomain under `deploy.hyrule.host`.

## When to Use

Use this skill when:
- You need to deploy an application to the internet (provision a VM, SSH in, set it up)
- You need to check VM pricing or available OS templates
- You need a free auto subdomain for a VM (`<hash>.deploy.hyrule.host`)

Domain registration, renewal, and managed DNS zones are **not yet launched**
— see "Deferred — Not Yet Launched" below.

## API Base

```
https://cloud.hyrule.host
```

Service discovery: `GET /.well-known/x402.json`

## Payment

VMs and network services use the **x402** protocol:
1. Send the request without payment → get a `402` response with pricing + payment instructions
2. Pay via the x402 facilitator (USDC on Base, chain `eip155:8453`)
3. Resend the request with the `X-PAYMENT` header containing the payment proof

The `402` carries an `X-PAYMENT-REQUIRED` header (base64-encoded JSON) plus a
JSON body. Example for `POST /v1/vm/create` (xs, 7 days — values illustrative;
always read the live header):

```
HTTP/1.1 402 Payment Required
X-PAYMENT-REQUIRED: eyJ4NDAyVmVyc2lvbiI6Mn0...   # base64 of the body below
```

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "asset": "USDC",
      "price": "$0.35",
      "payTo": "0xReceiverAddress…"
    }
  ],
  "amount": "0.35",
  "cost_breakdown": {"vm_cost": "$0.35", "domain_cost": "$0.00", "total": "$0.35"},
  "specs": {"vcpu": 1, "memory_mb": 1024, "disk_gb": 10, "ipv6": true, "ipv4": false}
}
```

Sign an EIP-3009 `TransferWithAuthorization` for the `accepts[].price`, base64-
encode the x402 payment payload, and resend the same request with
`X-PAYMENT: <base64>`.

**Durable quotes (recommended):** call `POST /v1/vm/quote` first to lock a price
and get a `quote_id`, then pass `quote_id` to `POST /v1/vm/create`. The server
provisions the quoted spec at the locked price and is idempotent across the
402 → sign → retry round-trip (a replayed paid create returns the same VM).

## Python Client

Install (not on PyPI yet — `pip install hyrule-cloud` 404s today):

```bash
pip install "git+https://github.com/AS215932/hyrule-cloud"
```

### Autonomous payment (recommended)

Hand `HyruleClient` a funded EVM private key and it settles the 402 for you —
sign, retry, return the 2xx body. You never build an EIP-3009 payload by hand.

```python
import os
from hyrule_cloud.client import HyruleClient

async with HyruleClient(
    "https://cloud.hyrule.host",
    private_key=os.environ["HYRULE_AGENT_KEY"],  # USDC-funded wallet on Base
    max_usd_per_call="5.00",                     # hard per-call spend cap
) as hc:
    result = await hc.provision_vm(
        duration_days=7,
        size="sm",
        ssh_pubkey="ssh-ed25519 AAAA...",
        quote_first=True,      # lock the price via POST /v1/vm/quote first
    )

    print(result.ssh)                 # "ssh root@<host>.deploy.hyrule.host"
    print(result.vm_id, result.ipv6)
    print(result.management_token)    # one-time — save it, it is never re-shown
    print(result.settlement.transaction)  # on-chain settlement tx hash
```

`provision_vm()` does quote → paid create → poll `/v1/vm/{id}/status` until the
VM is ready, and raises `ProvisioningError` / `ProvisioningTimeoutError` instead
of returning a half-built VM.

**Safety.** `max_usd_per_call` (default `"10.00"`) is enforced as an x402
`max_amount` policy: a 402 asking for more is dropped *before* anything is
signed and the call raises `HyrulePaymentError`. Payment is also pinned to one
chain (`payment_network`, default `eip155:8453` Base), so the SDK never signs
against whatever chain a challenge advertises first. A paid `2xx` that comes
back without a settlement receipt raises `SettlementMissingError` — the agent
must not treat an uncharged response as paid for.

### Step-by-step

```python
async with HyruleClient("https://cloud.hyrule.host", private_key=KEY) as hc:
    created = await hc.create_vm(duration_days=7, size="sm", ssh_pubkey="ssh-ed25519 ...")
    token = created["management_token"]

    # Public poll endpoint — no credential needed.
    status = await hc.vm_status(created["vm_id"])

    # Management-gated calls take the one-time token per call.
    details = await hc.vm_details(created["vm_id"], management_token=token)
    logs = await hc.vm_logs(created["vm_id"], management_token=token)
    await hc.extend_vm(created["vm_id"], 7, management_token=token)
    await hc.reboot_vm(created["vm_id"], management_token=token)
    await hc.destroy_vm(created["vm_id"], management_token=token)

    print(hc.last_settlement)  # receipt of the most recent paid call
```

The VM `management_token` is **not** the account `api_key`. `api_key=` on the
constructor is the account bearer (Block D); the management token is the
one-time per-VM credential returned by the create `202`.

Read-only calls (`pricing`, `check_domain`, `vm_status`, …) need no key at all:

```python
async with HyruleClient("https://cloud.hyrule.host") as hc:
    pricing = await hc.pricing()
```

## Endpoints

### Free Endpoints

#### GET /v1/pricing
Returns current prices for all resources.

```json
{
  "vm_prices": {
    "xs (1C-1G-10G)": "$0.20/day",
    "sm (1C-2G-20G)": "$0.40/day",
    "md (2C-4G-20G)": "$0.60/day",
    "lg (4C-4G-40G)": "$0.80/day"
  },
  "domain_auto": "$0.00 (subdomain under deploy.hyrule.host)",
  "proxy_prices": {
    "direct": "$0.01/request",
    "tor": "$0.05/request",
    "i2p": "$0.05/request",
    "yggdrasil": "$0.03/request"
  },
  "currency": "USDC",
  "network": "Base (eip155:8453)"
}
```

#### GET /v1/products/vms
Machine-readable VM catalog — specs + daily price per size (no HTML scraping).

```json
{
  "currency": "USD",
  "billing": "prepaid-daily",
  "products": [
    {"size": "xs", "name": "1C-1G-10G", "vcpu": 1, "ram_mb": 1024, "disk_gb": 10, "price_usd_day": "0.20"},
    {"size": "sm", "name": "1C-2G-20G", "vcpu": 1, "ram_mb": 2048, "disk_gb": 20, "price_usd_day": "0.40"},
    {"size": "md", "name": "2C-4G-20G", "vcpu": 2, "ram_mb": 4096, "disk_gb": 20, "price_usd_day": "0.60"},
    {"size": "lg", "name": "4C-4G-40G", "vcpu": 4, "ram_mb": 4096, "disk_gb": 40, "price_usd_day": "0.80"}
  ],
  "customization": {
    "minimum": {"vcpu": 1, "ram_mb": 1024, "disk_gb": 10},
    "maximum": {"vcpu": 4, "ram_mb": 8192, "disk_gb": 40},
    "increments": {"vcpu": 1, "ram_mb": 1024, "disk_gb": 10},
    "addon_prices": {"vcpu_usd_day": "0.10", "ram_gb_usd_day": "0.15", "disk_10gb_usd_day": "0.05"}
  },
  "os_templates_url": "https://cloud.hyrule.host/v1/os/list"
}
```

#### POST /v1/vm/quote
Lock a price and get a durable `quote_id` (free). Pass it to `POST /v1/vm/create`.
Idempotent on `client_order_id` (same key + same spec → same quote; different
spec → 409). Body: `{ "order_payload": { …VM spec… }, "client_order_id": "…" }`.

```json
{
  "quote_id": "q_8sd1f9…",
  "status": "created",
  "resources": {"vcpu": 1, "ram_mb": 1024, "disk_gb": 10},
  "amount_usd": "1.40",
  "pricing": {"base_profile": "xs", "base_label": "1C-1G-10G", "daily_price_usd": "0.20", "duration_days": 7, "total_usd": "1.40"},
  "currency": "USD",
  "accepted_payment_methods": {"evm": [{"key": "base", "caip2": "eip155:8453", "asset": "USDC"}], "native": ["BTC", "XMR"]},
  "expires_at": "2026-05-31T13:00:00Z"
}
```

#### GET /v1/os/list
Lists available OS templates. The template list is dynamic — always read the
live endpoint rather than relying on this example.

```json
{
  "templates": [
    {"name": "debian-13", "description": "Debian 13 (Trixie)", "default": true}
  ]
}
```

#### GET /v1/vm/{vm_id}/status (public)
Sanitized status view — poll this without credentials. Returns status,
hostname, IPv6, expiry, profile/resources, and launch-proof fields
(`launch_proof_status`, `payment_status`, `dns_aaaa_verified`,
`ssh_smoke_status`, `rollback_available`, `customer_message`). It never
includes the SSH command or firewall state.

```json
{
  "vm_id": "vm_a1b2c3d4e5f6",
  "status": "ready",
  "ipv6": "2001:db8::1",
  "hostname": "ab12cd34.deploy.hyrule.host",
  "expires_at": "2026-04-08T00:00:00Z",
  "launch_proof_status": "provisioned",
  "dns_aaaa_verified": true,
  "ssh_smoke_status": "passed"
}
```

Status values: `provisioning` → `ready` → `running` → `suspended` → `destroyed` (or `failed`)

#### GET /v1/vm/{vm_id} (management token required)
Full VM view — adds the SSH command, firewall state, and error detail.
Requires the one-time `management_token` from the create response, presented
as `Authorization: Bearer <management_token>` (or `?token=`). Without valid
management authority the endpoint returns 404, not 403 — deliberately
indistinguishable from "VM not found", so vm_id existence does not leak.

```
GET /v1/vm/vm_a1b2c3d4e5f6
Authorization: Bearer hyr_vm_...
```

```json
{
  "vm_id": "vm_a1b2c3d4e5f6",
  "status": "ready",
  "ipv6": "2001:db8::1",
  "hostname": "ab12cd34.deploy.hyrule.host",
  "ssh": "ssh root@ab12cd34.deploy.hyrule.host",
  "expires_at": "2026-04-08T00:00:00Z",
  "firewall": {"inbound_allow": [22, 80, 443], "policy": "deny"}
}
```

### Paid Endpoints

#### POST /v1/vm/create
Provision a bare VM with SSH access. Returns 202 with a status URL to poll.

**Request:**
```json
{
  "duration_days": 7,
  "size": "sm",
  "resources": {"vcpu": 3, "ram_mb": 6144, "disk_gb": 30},
  "os": "debian-13",
  "ssh_pubkey": "ssh-ed25519 AAAA...",
  "domain_mode": "auto",
  "open_ports": [80, 443],
  "setup_script": "apt-get update && apt-get install -y nginx"
}
```

**Response (202):**
```json
{
  "vm_id": "vm_a1b2c3d4e5f6",
  "status": "provisioning",
  "status_url": "https://cloud.hyrule.host/v1/vm/vm_a1b2c3d4e5f6/status",
  "estimated_ready_seconds": 60,
  "management_token": "hyr_vm_...",
  "management_url": "https://cloud.hyrule.host/v1/vm/vm_a1b2c3d4e5f6?token=hyr_vm_..."
}
```

**`management_token` is shown once — store it now.** Only its sha256 is
stored server-side, and it is not the account API key. It is the only
credential for the full VM view, extend, reboot, logs, and DELETE. A replayed
paid create (idempotent retry) returns the same VM with
`management_token: null`. Poll the public `status_url` (no credentials
needed) while the VM provisions.

**Profiles:** `xs` (`1C-1G-10G`), `sm` (`1C-2G-20G`), `md` (`2C-4G-20G`), `lg` (`4C-4G-40G`). Optional exact `resources` are order-time only, in 1-vCPU/1-GB/10-GB increments up to 4/8/40; the API automatically selects the cheapest compatible profile.

**Domain modes:**
- `auto` — free subdomain `<hash>.deploy.hyrule.host` (default; live)
- `custom` — deferred along with domain registration (see "Deferred — Not
  Yet Launched"); use `auto`

**Workflow:**
1. POST /v1/vm/create → 402 (get price) → pay → POST again with X-PAYMENT → 202
2. Store the one-time `management_token` from the 202 — it is shown once
3. Poll GET /v1/vm/{id}/status until `status` is `ready`
4. SSH in: `ssh root@<hostname>`
5. The VM is yours — install whatever you need

The Python client does all five in one call — see `provision_vm()` above.

#### POST /v1/vm/{vm_id}/extend
Add days to a running VM. Requires `Authorization: Bearer <management_token>`
and is x402-paid (402 → pay → retry, same as create).

```json
{"days": 30}
```

#### POST /v1/network/request
Make one paid HTTP request through the internal Hyrule network proxy sidecar.
Supported modes are `direct`, `tor`, `i2p`, and `yggdrasil`. Residential
proxying is intentionally not offered. If a mode is unavailable, the API returns
`503` before asking for x402 payment.

```json
{
  "url": "https://example.com",
  "method": "GET",
  "headers": {"accept": "text/html"},
  "body": null,
  "proxy_mode": "tor",
  "timeout_seconds": 15
}
```

Response shape:

```json
{
  "status_code": 200,
  "headers": {"content-type": "text/html; charset=utf-8"},
  "body": "<html>...</html>",
  "elapsed_seconds": 0.42,
  "proxy_mode": "tor",
  "error": null
}
```

### VM Management Endpoints (management token required)

All three require `Authorization: Bearer <management_token>` (the one-time
token from the create response; `?token=` also works). Unauthorized calls
return 404.

#### POST /v1/vm/{vm_id}/reboot
Hard reboot a VM.

```
POST /v1/vm/vm_a1b2c3d4e5f6/reboot
Authorization: Bearer hyr_vm_...
```

#### DELETE /v1/vm/{vm_id}
Destroy a VM permanently.

```
DELETE /v1/vm/vm_a1b2c3d4e5f6
Authorization: Bearer hyr_vm_...
```

#### GET /v1/vm/{vm_id}/logs
Provisioning history for a VM, oldest event first. Requires the management
token (same auth as `GET /v1/vm/{id}`).

```json
{
  "vm_id": "vm_...",
  "status": "ready",
  "events": [
    {"ts": "2026-07-24T12:00:01Z", "event": "provisioning_started",
     "message": "Provisioning started."},
    {"ts": "2026-07-24T12:00:31Z", "event": "ready",
     "message": "Your VM is ready.",
     "detail": {"hostname": "abc.deploy.hyrule.host", "ipv6": "2a0c:...",
                "dns_aaaa_verified": true, "ssh_reachable": true}}
  ],
  "error": null
}
```

Event vocabulary (stable; new keys may be added, existing ones never change
meaning). Treat unknown keys as informational.

| `event` | Meaning |
|---|---|
| `provisioning_started` | The background provisioner picked up the order. |
| `provisioning_simulated` | Simulation mode: no real VM/DNS/network was created. Every later event on this VM is simulated. |
| `cloud_init_prepared` | First-boot config rendered (SSH key, firewall defaults). |
| `setup_script_injected` | Your `setup_script` was embedded in first-boot user-data. |
| `vm_created` | The machine was created and powered on. |
| `network_ready` | The VM booted and brought up its IPv6 address. |
| `dns_created` | The AAAA record for your hostname was published. |
| `ssh_reachable` / `ssh_unreachable` | TCP :22 answered / did not answer within the check window. `ssh_unreachable` is not fatal — the VM is still delivered. |
| `custom_domain_attached` / `custom_domain_attach_failed` | Custom domain pointed at the VM, or attachment deferred to retry. |
| `ready` | Terminal success. `detail` carries hostname, ipv6, `dns_aaaa_verified`, `ssh_reachable`. |
| `provisioning_failed` | Terminal failure. `message` is the customer-facing reason; a paid VM is refunded. |

What this endpoint **cannot** tell you:

- **It is not a log stream from inside your VM.** These are control-plane
  events observed by Hyrule while building the machine — no console output, no
  syslog, no application logs.
- **`setup_script` outcome is not observable.** Hyrule sees the script injected
  into user-data (`setup_script_injected`) and nothing after that: there is no
  agent channel into the guest, so a script that ran, failed, or never started
  looks identical from here. To check it, SSH in and read
  `/var/log/hyrule-setup.log` (the script runs as root at first boot; a
  non-zero exit does not fail the VM).
- **Failure messages are deliberately generic** (capacity / boot timeout / DNS /
  internal). Infrastructure detail is not exposed; the operator has it.
- VMs created before provisioning events existed return a single
  `provisioning_started` entry derived from their creation time.

```
GET /v1/vm/vm_a1b2c3d4e5f6/logs
Authorization: Bearer hyr_vm_...
```

## Deferred — Not Yet Launched

> **NOT YET LAUNCHED.** Domain registration is deferred from the current
> launch catalog: `GET /v1/domains/tlds` returns 503 and the domain endpoints
> are absent from the live manifest. Do not call them.

This covers everything domain-shaped: availability checks (`/v1/domains/check`),
quotes (`/v1/domains/quotes`), registration/renewal orders
(`/v1/domains/orders`), managed DNS zones (changesets, nameservers, DNSSEC),
and signed transfer-out. Free auto subdomains for VMs
(`domain_mode: "auto"` → `<hash>.deploy.hyrule.host`) **are** live and are
not affected. When domain registration launches, these endpoints will appear
in `/.well-known/x402.json` and this skill will document them again.

## Typical Agent Workflow

```
1. GET /v1/pricing                          # check prices
2. POST /v1/vm/create                       # → 402 with price
3. Pay via x402 facilitator                 # USDC on Base
4. POST /v1/vm/create + X-PAYMENT header    # → 202 + status_url + one-time management_token (store it!)
5. Poll GET /v1/vm/{id}/status              # wait for "ready" (public, no auth)
6. ssh root@<hostname>                      # deploy your app
7. (optional) POST /v1/network/request      # paid Direct/Tor/I2P/Yggdrasil request
```

## Infrastructure Details

- **Network:** IPv6-only (NAT64/DNS64 for IPv4 destinations). All VMs get a public IPv6 address.
- **DNS:** Auto subdomains under `deploy.hyrule.host`. Custom domain registration is deferred (not yet launched).
- **Firewall:** Cloud-init sets UFW defaults (deny all inbound except 22/80/443, block outbound SMTP). Modify via SSH after boot.
- **Expiry:** Prepaid model. VMs suspended at expiry, destroyed after 48h grace period. Extend with `/v1/vm/{id}/extend`.
- **Network proxy:** `POST /v1/network/request` is x402-gated in Hyrule Cloud and executed by the internal `hyrule-network-proxy` Go sidecar.
- **ASN:** AS215932 (RIPE)

### DNS on your VM (IPv6-only + NAT64)

Your VM has no IPv4 address. It reaches IPv4-only hosts through NAT64, which
only works when its resolver is **DNS64-capable** — DNS64 answers an IPv4-only
name with a synthetic AAAA in `64:ff9b::/96` that NAT64 then translates. A
resolver without DNS64 (or one that does not answer at all) leaves the VM
unable to reach — or even resolve — most of the internet, including package
mirrors.

Hyrule writes the resolver into the VM's netplan at build time (currently
`2a0c:b641:b51::1` on the customer network). Check what your VM actually got:

```bash
resolvectl status || cat /etc/resolv.conf
getent ahosts deb.debian.org        # must return addresses
```

`GET /v1/vm/{vm_id}/status` reports this as `dns_resolution_status`
(`passed` | `failed` | `not_run`). A VM whose resolver does not answer is
returned as `launch_proof_status: degraded` rather than `provisioned` — it is
reachable over SSH but cannot resolve names.

To override with your own DNS64 resolver (e.g. Google's public DNS64):

```bash
# quick fix, until reboot
printf 'nameserver 2001:4860:4860::6464\n' > /etc/resolv.conf
# persistent: edit nameservers.addresses in /etc/netplan/*.yaml, then
netplan apply
```

Any resolver you pick must be reachable over IPv6 and DNS64-capable; a plain
IPv6 resolver without DNS64 resolves names but still cannot reach IPv4-only
destinations.
