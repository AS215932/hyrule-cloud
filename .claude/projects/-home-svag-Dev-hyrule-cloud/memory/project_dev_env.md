---
name: project_dev_env
description: Local development environment setup details for hyrule-cloud
type: project
---

Local dev environment as of 2026-03-23:

- **Postgres**: Runs in Incus container `hyrule-postgres` (Debian 13, PG 17) at `10.187.9.183`
- **XCP-NG**: At `192.168.122.226`, Xen Orchestra at `192.168.122.222`
- **Python venv**: `.venv/` with Python 3.14.3 and all deps installed editable
- **nsupdate (bind)**: Not yet installed — deferred, only needed for DNS provider at runtime
- **sg incus-admin**: Required prefix for incus commands (user not yet in incus-admin group persistently)

**Why:** XCP-NG login is made optional in orchestrator startup so the API can run for development without XAPI credentials.

**How to apply:** Use `sg incus-admin -c '...'` for all incus commands. Postgres IP may change if container is recreated.
