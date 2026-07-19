---
name: hyrule-cloud
description: "Deploy bare VMs and register, renew, or manage account-owned domains and DNS."
---

# Hyrule Cloud — Agentic VPS Hosting

Deploy bare VMs and register, renew, or manage account-owned domains and DNS.

## When to Use

Use this skill when:
- You need to deploy an application to the internet (provision a VM, SSH in, set it up)
- You need to register a domain name
- You need managed authoritative DNS records (AAAA, A, CNAME, TXT, MX, etc.)
- You need to check pricing or domain availability

## API Base

```
https://cloud.hyrule.host
```

Service discovery: `GET /.well-known/x402.json`

## Payment

VMs, network services, and USDC domain orders use the **x402** protocol:
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

Domain orders also support native BTC and XMR payment intents. Account-owned
purchase, renewal, and management use a session or scoped API key. Autonomous
agents can use the separately gated USDC-only `/v1/domains/agent/orders` flow;
it returns a one-time capability token and requires no human signup.

**Durable quotes (recommended):** call `POST /v1/vm/quote` first to lock a price
and get a `quote_id`, then pass `quote_id` to `POST /v1/vm/create`. The server
provisions the quoted spec at the locked price and is idempotent across the
402 → sign → retry round-trip (a replayed paid create returns the same VM).

## Python Client

```python
from hyrule_cloud.client import HyruleClient

async with HyruleClient("https://cloud.hyrule.host") as hc:
    result = await hc.create_vm(duration_days=7, size="sm", ssh_pubkey="ssh-ed25519 ...")
```

Install: `pip install hyrule-cloud`

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
Lists available OS templates.

```json
{
  "templates": [
    {"name": "debian-13", "description": "Debian 13 (Trixie)", "default": true},
    {"name": "alpine-3.21", "description": "Alpine Linux 3.21"},
    {"name": "freebsd-14", "description": "FreeBSD 14.2"}
  ]
}
```

#### GET /v1/vm/{vm_id}
Get VM status, IP, hostname, SSH command, and expiry.

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

Status values: `provisioning` → `ready` → `running` → `suspended` → `destroyed` (or `failed`)

#### GET /v1/domains/check?domain=example.dev
Check strict ASCII, single-label domain eligibility, live availability, and
separate registration/renewal prices. Premium and non-generic TLDs fail closed.

```json
{
  "domain": "example.dev",
  "eligible": true,
  "available": true,
  "premium": false,
  "registration": {"provider_cost_usd":"10.00","hyrule_fee_usd":"3.00","tax_usd":"0.00","total_usd":"13.00","currency":"USD"},
  "renewal": {"provider_cost_usd":"10.00","hyrule_fee_usd":"3.00","tax_usd":"0.00","total_usd":"13.00","currency":"USD"}
}
```

#### POST /v1/domains/quotes
Create a durable 15-minute registration or renewal quote.

```json
{"domain":"example.dev","action":"register"}
```

The response includes `quote_id`, `terms_version`, `expires_at`, and an exact
USD price breakdown. Registration is always one year; renewal is manual and
registrar auto-renew is disabled.

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
  "status_url": "https://cloud.hyrule.host/v1/vm/vm_a1b2c3d4e5f6",
  "estimated_ready_seconds": 60
}
```

**Profiles:** `xs` (`1C-1G-10G`), `sm` (`1C-2G-20G`), `md` (`2C-4G-20G`), `lg` (`4C-4G-40G`). Optional exact `resources` are order-time only, in 1-vCPU/1-GB/10-GB increments up to 4/8/40; the API automatically selects the cheapest compatible profile.

**Domain modes:**
- `auto` — free subdomain `<hash>.deploy.hyrule.host` (default)
- `custom` — requires `domain` field, registers via Openprovider (extra cost)

**Workflow:**
1. POST /v1/vm/create → 402 (get price) → pay → POST again with X-PAYMENT → 202
2. Poll GET /v1/vm/{id} until `status` is `ready`
3. SSH in: `ssh root@<hostname>`
4. The VM is yours — install whatever you need

#### POST /v1/vm/{vm_id}/extend
Add days to a running VM.

```json
{"days": 30}
```

#### POST /v1/domains/orders
Place an idempotent account-owned registration or renewal order. Send
`Authorization: Bearer <api-key>` and a stable `Idempotency-Key`. USDC orders
use the normal 402/sign/retry flow; BTC/XMR return a 60-minute deposit intent.

```json
{
  "quote_id": "dq_...",
  "payment_method": "usdc",
  "terms_version": "2026-07-15"
}
```

Poll `GET /v1/domains/orders/{order_id}` until `active`, `provider_pending`,
`refund_due`, or `failed`. A provider timeout remains pending for reconciliation;
do not submit a second purchase with a new idempotency key.

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

### Domain Management Endpoints (Account Required)

#### POST /v1/domains/{domain}/dns/changesets
Atomically upsert/delete managed RRsets. Send the current numeric zone revision
in `If-Match` and a stable `Idempotency-Key`; stale revisions return 412.

```json
{
  "changes": [{
    "action": "upsert",
    "rrset": {"name":"www","type":"AAAA","ttl":300,"values":["2001:db8::1"]}
  }]
}
```

Use `GET /v1/domains/{domain}/dns` to read the current records and revision.
`PUT /v1/domains/{domain}/nameservers` switches between Hyrule-managed and
external delegation. `PUT /v1/domains/{domain}/dnssec` manages DNSSEC. Signed
transfer-out uses `/v1/domains/{domain}/transfer-out/challenge` followed by
`/v1/domains/{domain}/transfer-out`; the registrar auth code is reveal-once.

### Management Endpoints (Free)

#### POST /v1/vm/{vm_id}/reboot
Hard reboot a VM.

#### DELETE /v1/vm/{vm_id}
Destroy a VM permanently.

#### GET /v1/vm/{vm_id}/logs
Get provisioning log for a VM.

## Typical Agent Workflow

```
1. GET /v1/pricing                          # check prices
2. POST /v1/vm/create                       # → 402 with price
3. Pay via x402 facilitator                 # USDC on Base
4. POST /v1/vm/create + X-PAYMENT header    # → 202 + status_url
5. Poll GET /v1/vm/{id}                     # wait for "ready"
6. ssh root@<hostname>                      # deploy your app
7. (optional) POST /v1/domains/quotes       # lock registration price
8. (optional) POST /v1/domains/orders       # idempotent account-owned purchase
9. (optional) POST /v1/domains/{domain}/dns/changesets  # point domain at VM
10. (optional) POST /v1/network/request     # paid Direct/Tor/I2P/Yggdrasil request
```

## Infrastructure Details

- **Network:** IPv6-only (NAT64/DNS64 for IPv4 destinations). All VMs get a public IPv6 address.
- **DNS:** Auto subdomains under `deploy.hyrule.host`. Custom domains via Openprovider with Hyrule Cloud nameservers.
- **Firewall:** Cloud-init sets UFW defaults (deny all inbound except 22/80/443, block outbound SMTP). Modify via SSH after boot.
- **Expiry:** Prepaid model. VMs suspended at expiry, destroyed after 48h grace period. Extend with `/v1/vm/{id}/extend`.
- **Network proxy:** `POST /v1/network/request` is x402-gated in Hyrule Cloud and executed by the internal `hyrule-network-proxy` Go sidecar.
- **ASN:** AS215932 (RIPE)
