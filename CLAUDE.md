# Hyrule Cloud

Agentic VPS hosting API on AS215932, paid via x402 (USDC on Base). Agents discover the service via x402 Bazaar or `/.well-known/x402.json`, pay per-request, and receive bare VMs with SSH access, automatic DNS subdomains, and IPv6-native networking.

## Business Context

Target market: AI agents (especially OpenClaw) that "vibe code" apps and need to deploy them. The API is the first full-stack infrastructure offering in the x402 Bazaar (VPS + domain + DNS). Revenue model is prepaid compute-time in USDC via the x402 exact scheme.

The operator holds AS215932 (RIPE), runs XCP-NG hypervisors, uses Openprovider as domain registrar, and runs authoritative DNS (BIND/Knot with TSIG for RFC 2136 dynamic updates). All VMs are IPv6-only with NAT64/DNS64 for IPv4-only destinations. If IPv6-only proves insufficient for agent workloads, an IPv4 subnet lease is possible but not preferred.

TODO: Hosted OpenClaw instances, with a custom web interface for management

## Stack

- Python 3.12, FastAPI, Pydantic v2
- Official Coinbase x402 Python SDK (`x402[fastapi,evm]>=2.0`) for payment gating
- SQLAlchemy 2.0 async + asyncpg (Postgres 17) for persistence
- Alembic for migrations
- XCP-NG XAPI (XML-RPC over HTTPS) for VM lifecycle
- Openprovider REST API for domain registration
- RFC 2136 (`nsupdate` + TSIG) for dynamic DNS (AAAA records)
- cloud-init for VM bootstrapping (SSH key, UFW defaults, optional setup script)
- APScheduler for periodic VM expiry checks
- structlog for structured logging
- Ruff for linting (line-length=100, target py312)

## Architecture

```
Agent --> POST /v1/vm/create (no payment) --> 402 + pricing
      --> pays via x402 facilitator
      --> POST /v1/vm/create (with X-PAYMENT header) --> 202 + status_url
      --> GET /v1/vm/{id} (poll) --> { ipv6, hostname, ssh }
      --> ssh root@<hostname> --> agent owns the VM
```

The API server coordinates: XCP-NG XAPI (clone template, set CPU/RAM/disk, inject cloud-init, start VM), DNS (create AAAA record under deploy.servify.network), and optionally Openprovider (register custom domain).

## Key Design Decisions

- **Bare VM, not PaaS.** No runtime detection, no buildpacks. The agent SSHes in and sets up its own environment. This eliminates support headaches from broken deployments.
- **Agent manages its own firewall.** Cloud-init sets defaults (deny inbound except 22/80/443, block outbound SMTP 25/465/587). After boot, the agent modifies UFW via SSH. There is no firewall management API endpoint.
- **Dynamic pricing.** The x402 SDK's `PaymentMiddlewareASGI` only supports static per-route prices. Our `PaymentGate` class wraps the SDK's lower-level primitives (`x402ResourceServer`, `ExactEvmServerScheme`, `HTTPFacilitatorClient`) to compute prices dynamically based on VM size * duration.
- **Async provisioning.** VM creation returns 202 immediately. A background task clones the template, waits for IPv6 via XAPI guest metrics, creates DNS, and updates DB. The agent polls `GET /v1/vm/{id}` until status is `ready`.
- **Auto subdomains for short-lived deployments.** `<sha256prefix>.deploy.servify.network` with AAAA pointing to VM IPv6. Custom domains via Openprovider for persistent deployments.
- **Prepaid model.** x402 exact scheme charges upfront for N days. `POST /v1/vm/{id}/extend` adds time. Expired VMs are suspended, destroyed after 48h grace period.
- **XCP-NG templates managed via Xen Orchestra.** Templates need cloud-init + xe-guest-utilities pre-installed. Template UUIDs are configured via env vars.

## Endpoints

| Endpoint              | Method | Paid | Description               |
|-----------------------|--------|------|---------------------------|
| `/v1/vm/create`       | POST   | Yes  | Provision a bare VM       |
| `/v1/vm/{id}`         | GET    | No   | Status, IP, expiry        |
| `/v1/vm/{id}/extend`  | POST   | Yes  | Add days                  |
| `/v1/vm/{id}/reboot`  | POST   | No   | Hard reboot               |
| `/v1/vm/{id}`         | DELETE | No   | Destroy                   |
| `/v1/vm/{id}/logs`    | GET    | No   | Provisioning log          |
| `/v1/domain/check`    | GET    | No   | Availability check        |
| `/v1/domain/register` | POST   | Yes  | Register via Openprovider |
| `/v1/pricing`         | GET    | No   | Price list                |
| `/v1/os/list`         | GET    | No   | Available templates       |
| `/v1/zone/check`      | GET    | No   | DNS zone availability     |
| `/v1/zone/buy`        | POST   | Yes  | Buy DNS zone (domain+DNS) |
| `/v1/zone/record`     | POST   | No   | Create DNS record in zone |
| `/v1/zone/record`     | DELETE | No   | Delete DNS record         |

Management endpoints are free. Wallet-based auth on management endpoints is not yet implemented (deferred until payment integration is tested end-to-end).

## File Structure

```
hyrule_cloud/
  app.py                 FastAPI entrypoint, lifespan, x402 manifest
  config.py              pydantic-settings (env vars / .env)
  models.py              API request/response Pydantic models
  db.py                  SQLAlchemy ORM models (VMRow, DomainRow, VPNTunnelRow)
  orchestrator.py        VM lifecycle coordinator (provisions, extends, destroys)
  client.py              Thin async Python client wrapping the HTTP API
  mcp_server.py          MCP server for Claude/Cursor (tools + resources)
  api/
    routes.py            All HTTP endpoints (VM, domain, zone)
  middleware/
    x402.py              PaymentGate wrapping official x402 SDK
  providers/
    xcpng.py             Async XAPI XML-RPC client
    cloudinit.py         cloud-config YAML renderer
    dns.py               RFC 2136 dynamic DNS via nsupdate
    openprovider.py      Domain registration + DNS zone management REST client
SKILL.md                 OpenClaw skill definition (agent-readable API reference)
alembic/
  env.py                 Async migration env for Postgres
  versions/
    001_initial_schema.py
```

## Development

```bash
# Postgres runs in an Incus container (not Docker)
# If not already running:
#   incus launch images:debian/13 hyrule-postgres
#   incus exec hyrule-postgres -- apt install -y postgresql
#   incus exec hyrule-postgres -- sudo -u postgres createuser -s hyrule
#   incus exec hyrule-postgres -- sudo -u postgres createdb -O hyrule hyrule
#   incus exec hyrule-postgres -- sudo -u postgres psql -c "ALTER USER hyrule PASSWORD 'hyrule';"
#   # Edit pg_hba.conf to allow md5 auth from host network

cp .env.example .env  # fill in credentials
# Set HYRULE_DATABASE_URL=postgresql+asyncpg://hyrule:hyrule@<incus-ip>/hyrule

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
alembic upgrade head
uvicorn hyrule_cloud.app:app --host :: --port 8402 --reload

# Dev payment bypass: set PAYMENT_DEV_BYPASS_SECRET in .env, then pass
# X-DEV-BYPASS: <secret> header to skip x402 payment verification.
```

## MCP Server

The MCP server (`hyrule_cloud/mcp_server.py`) exposes all Hyrule Cloud operations as MCP tools for Claude, Cursor, and other MCP-compatible clients. Run with `python -m hyrule_cloud.mcp_server` or use the `hyrule-mcp` console script.

MCP server config for Claude/Cursor:
```json
{
    "mcpServers": {
        "hyrule-cloud": {
            "command": "hyrule-mcp",
            "env": {
                "HYRULE_API_URL": "https://cloud.servify.network"
            }
        }
    }
}
```

## What's Not Yet Built

- VPN endpoints (`/v1/vpn/*`) - WireGuard tunnel provisioning (DB model exists, no routes/provider yet)
- Wallet-based auth on management endpoints (need x402 V2 session/identity)
- Wallet-based auth on zone record management (currently open)
- Bazaar extension registration (discoverable: true in route config)
- Automated abuse detection / VM content scanning
- Refunds on provisioning failure
- Real log streaming from VMs (current `/logs` is a placeholder)
- Production deployment config (systemd, TLS termination, rate limiting)

## Conventions

- Python 3.12+, type hints on everything
- `StrEnum` for enums (not `str, Enum`)
- Ruff for linting, ruff format for formatting
- No JavaScript/TypeScript unless absolutely unavoidable
- Postgres for all persistence, no SQLite in production
- Keep the API boundary clean: we provide compute + networking + DNS. What runs inside the VM is the agent's responsibility.
