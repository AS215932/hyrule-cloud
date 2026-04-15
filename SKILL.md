# Hyrule Cloud — Agentic VPS Hosting

Deploy bare VMs, register domains, and manage DNS zones — all paid via x402 (USDC on Base).

## When to Use

Use this skill when:
- You need to deploy an application to the internet (provision a VM, SSH in, set it up)
- You need to register a domain name
- You need to buy a DNS zone and manage records (AAAA, A, CNAME, TXT, MX, etc.)
- You need to check pricing or domain availability

## API Base

```
https://cloud.servify.network
```

Service discovery: `GET /.well-known/x402.json`

## Payment

All paid endpoints use the **x402** protocol:
1. Send the request without payment → get a `402` response with pricing + payment instructions
2. Pay via the x402 facilitator (USDC on Base, chain `eip155:8453`)
3. Resend the request with the `X-PAYMENT` header containing the payment proof

The 402 response body includes `cost_breakdown`, `specs`, and the facilitator URL.

## Python Client

```python
from hyrule_cloud.client import HyruleClient

async with HyruleClient("https://cloud.servify.network") as hc:
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
    "xs (1vCPU/512MB/10GB)": "$0.05/day",
    "sm (1vCPU/1GB/20GB)": "$0.10/day",
    "md (2vCPU/2GB/40GB)": "$0.20/day",
    "lg (4vCPU/4GB/80GB)": "$0.40/day"
  },
  "domain_auto": "$0.00 (subdomain under deploy.servify.network)",
  "vpn_per_day": "$0.02/day",
  "currency": "USDC",
  "network": "Base (eip155:8453)"
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
  "hostname": "ab12cd34.deploy.servify.network",
  "ssh": "ssh root@ab12cd34.deploy.servify.network",
  "expires_at": "2026-04-08T00:00:00Z",
  "firewall": {"inbound_allow": [22, 80, 443], "policy": "deny"}
}
```

Status values: `provisioning` → `ready` → `running` → `suspended` → `destroyed` (or `failed`)

#### GET /v1/domain/check?name=example&extension=com
Check domain availability.

```json
{"status": "free", "is_premium": false, "price": "9.99", "currency": "USD"}
```

#### GET /v1/zone/check?name=example&extension=dev
Check DNS zone availability and price.

### Paid Endpoints

#### POST /v1/vm/create
Provision a bare VM with SSH access. Returns 202 with a status URL to poll.

**Request:**
```json
{
  "duration_days": 7,
  "size": "sm",
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
  "status_url": "https://cloud.servify.network/v1/vm/vm_a1b2c3d4e5f6",
  "estimated_ready_seconds": 60
}
```

**Sizes:** `xs` (1vCPU/512MB/10GB), `sm` (1vCPU/1GB/20GB), `md` (2vCPU/2GB/40GB), `lg` (4vCPU/4GB/80GB)

**Domain modes:**
- `auto` — free subdomain `<hash>.deploy.servify.network` (default)
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

#### POST /v1/domain/register
Register a domain via Openprovider.

```json
{"name": "mysite", "extension": "dev", "ipv6": "2001:db8::1"}
```

#### POST /v1/zone/buy
Buy a DNS zone — registers the domain and sets up Hyrule Cloud's authoritative DNS.

```json
{"name": "mysite", "extension": "dev"}
```

Response includes the nameservers to use. After buying, manage records via:

#### POST /v1/zone/record
Create a DNS record in a zone you own.

```json
{"zone": "mysite.dev", "name": "www", "type": "AAAA", "value": "2001:db8::1", "ttl": 300}
```

#### DELETE /v1/zone/record?zone=mysite.dev&name=www&type=AAAA
Delete a DNS record.

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
7. (optional) POST /v1/zone/buy             # buy a DNS zone
8. (optional) POST /v1/zone/record          # point domain at VM
```

## Infrastructure Details

- **Network:** IPv6-only (NAT64/DNS64 for IPv4 destinations). All VMs get a public IPv6 address.
- **DNS:** Auto subdomains under `deploy.servify.network`. Custom domains via Openprovider with Hyrule Cloud nameservers.
- **Firewall:** Cloud-init sets UFW defaults (deny all inbound except 22/80/443, block outbound SMTP). Modify via SSH after boot.
- **Expiry:** Prepaid model. VMs suspended at expiry, destroyed after 48h grace period. Extend with `/v1/vm/{id}/extend`.
- **ASN:** AS215932 (RIPE)
