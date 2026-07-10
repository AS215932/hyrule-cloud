# Hyrule Cloud

Full-stack network infrastructure for AI agents on Hyrule Networks (AS215932), paid per request via x402.

Agents discover the service via the x402 Bazaar or `/.well-known/x402.json` and pay with USDC on Base. Four service groups:

- **Compute** — bare IPv6-native VMs with SSH, automatic HTTPS subdomains, and optional custom domains.
- **Domains & DNS** — domain registration and DNS management.
- **Network intelligence** — BGP/routing over AS215932's own tables plus RouteViews/RIPE RIS, IP geolocation/ASN/reputation, DNS (lookup, propagation, DNSSEC, record recommendations), RDAP/WHOIS, web reachability and deep TLS grading, MXToolbox-compatible mail deliverability (MX/SPF/DKIM/DMARC/blacklist/bounce), port and NAT/CGNAT reachability, and VoIP/SIP diagnostics.
- **Network proxy** — outbound requests over Direct, Tor, I2P, or Yggdrasil.

## Architecture

```
Agent (OpenClaw, Claude MCP, x402-aware client)
  |
  |-- discovers via /.well-known/x402.json or Bazaar
  |
  |-- POST /v1/vm/create  (no payment) --> 402 + pricing + specs
  |-- pays via x402 facilitator (USDC on Base)
  |-- POST /v1/vm/create  (with X-PAYMENT header) --> 202 + status_url
  |-- GET  /v1/vm/{id}    (poll) --> { ipv6, hostname, ssh }
  |
  |-- ssh root@<hostname>  --> agent owns the VM from here
```

```
Hyrule Cloud API (FastAPI + x402 SDK)
  |-- XCP-NG XAPI       VM lifecycle (clone, start, stop, destroy)
  |-- cloud-init         SSH key, default UFW rules, optional setup script
  |-- DNS (RFC 2136)     AAAA records on authoritative NS
  |-- Openprovider       Domain registration (custom domain mode)
  |-- PostgreSQL         Persistent state (VMs, domains, tunnels)
  |-- x402 facilitator   Payment verification and settlement (official SDK)
  |-- network proxy      Internal Go sidecar for paid Direct/Tor/I2P/Yggdrasil requests
```

## Endpoints

| Endpoint              | Method | Paid | Description                  |
|-----------------------|--------|------|------------------------------|
| `/v1/vm/create`       | POST   | Yes  | Provision a bare VM          |
| `/v1/vm/{id}`         | GET    | No   | Status, IP, expiry           |
| `/v1/vm/{id}/extend`  | POST   | Yes  | Add days to VM               |
| `/v1/vm/{id}/reboot`  | POST   | No   | Hard reboot                  |
| `/v1/vm/{id}`         | DELETE | No   | Destroy VM                   |
| `/v1/vm/{id}/logs`    | GET    | No   | Provisioning log             |
| `/v1/domain/check`    | GET    | No   | Domain availability          |
| `/v1/domain/register` | POST   | Yes  | Register via Openprovider    |
| `/v1/pricing`         | GET    | No   | Current pricing              |
| `/v1/os/list`         | GET    | No   | Available OS templates       |
| `/v1/network/request` | POST   | Yes  | One paid network request     |

## Quick Start

```bash
# Start Postgres
docker compose up -d postgres

# Configure
cp .env.example .env
# Fill in XCP-NG, Openprovider, and wallet details

# Install
pip install -e .

# Run migrations
alembic upgrade head

# Start
uvicorn hyrule_cloud.app:app --host :: --port 8402
```

Or with Docker Compose (runs migrations automatically):

```bash
docker compose up
```

## XCP-NG Template Preparation

Templates are managed via Xen Orchestra. Each template needs cloud-init
and guest tooling pre-installed:

```bash
# On a Debian 12 VM that will become a template:
apt-get install cloud-init xe-guest-utilities
systemctl enable cloud-init
# Clean up, then convert to template in Xen Orchestra
```

Add the template UUID to your `.env`:

```
XCPNG_TEMPLATES={"debian-13": "<uuid>", "openbsd-7.8": "<uuid>"}
```

### OpenBSD root disk sizing

Linux templates grow their root filesystem on first boot after the root VDI is
resized. OpenBSD cannot safely grow a mounted root filesystem, so Hyrule Cloud
does an offline native prep step before first boot:

1. clone the OpenBSD template;
2. resize the clone's root VDI to the selected size tier;
3. attach that VDI to a dedicated halted OpenBSD builder VM;
4. boot the builder and run native `fdisk`, `disklabel`, `growfs`, and
   `fsck_ffs` against the unmounted secondary disk;
5. detach the VDI and boot the customer VM normally.

Configure the builder with `XCPNG_OPENBSD_BUILDER_*` variables. The default SSH
user is `svag`; it must be in `wheel` with passwordless `doas` for the resize
command. The customer API still exposes the same size tiers as Debian; the
OpenBSD-specific work is hidden inside provisioning.

## Network

All VMs are IPv6-native on AS215932. NAT64/DNS64 available for IPv4-only
destinations. VMs get a global IPv6 address via SLAAC.

Default firewall (set via cloud-init): deny all inbound except SSH (22),
HTTP (80), HTTPS (443). The agent manages its own firewall after boot
via SSH -- the API does not interfere with in-VM configuration.

Outbound SMTP (25, 465, 587) is blocked at provisioning time.

## Domain Policy

`AGENTS.md` is the canonical domain-policy reference for this repo. In short:
`hyrule.host` is customer-facing Hyrule Cloud identity, `servify.network` is
infrastructure identity, and `as215932.net` is AS215932 overlay/routing identity
only.

## Payment

x402 exact scheme, USDC on Base (eip155:8453). Uses the official Coinbase
x402 Python SDK for verification and settlement.

VM/domain pricing is per-day or per-operation, paid upfront. Extend via `/v1/vm/{id}/extend`.
VMs are suspended at expiry, destroyed after a 48h grace period.

`POST /v1/network/request` is a per-request x402 resource. The API verifies
payment, checks sidecar mode availability, and then delegates execution to the
internal `hyrule-network-proxy` Go sidecar. Supported modes are `direct`, `tor`,
`i2p`, and `yggdrasil`; residential proxying is intentionally not offered.

## Database

PostgreSQL with SQLAlchemy 2.0 async (asyncpg). Migrations via Alembic.

```bash
# Create a new migration after model changes
alembic revision --autogenerate -m "description"

# Apply
alembic upgrade head
```

## Project Structure

```
hyrule_cloud/
  app.py                 FastAPI entrypoint, lifespan, x402 manifest
  config.py              pydantic-settings configuration
  models.py              API request/response models
  db.py                  SQLAlchemy ORM models, engine setup
  orchestrator.py        VM lifecycle coordinator
  api/
    routes.py            All HTTP endpoints
  middleware/
    x402.py              PaymentGate (official SDK wrapper for dynamic pricing)
  providers/
    xcpng.py             XCP-NG XAPI client (async XML-RPC)
    cloudinit.py         cloud-config renderer
    dns.py               RFC 2136 dynamic DNS updates
    openprovider.py      Domain registration REST client
alembic/
  env.py                 Async migration environment
  versions/
    001_initial_schema.py
```

---

*Part of [Hyrule Networks (AS215932)](https://github.com/AS215932).*
