# Runbook: deploy hyrule-prober and go live on /v1/path/*

The `/v1/path/ping` and `/v1/path/report` endpoints are gated OFF until a prober
is configured (`HYRULE_PROBER_TOKEN` set). Hyrule Cloud verifies/settles the
x402 payment and delegates the actual ping/traceroute to the internal
`hyrule-prober` sidecar (AS215932/hyrule-prober), which runs from AS215932
vantage points. This is deliver-then-settle: a probe the prober can't produce
returns 502 and is never charged.

## Integration contract (must hold)

- The prober MUST advertise vantages **named** `as215932` and/or `extmon` — these
  strings must match the `DiagnosticVantage` values Hyrule Cloud sends. A vantage
  the prober names differently is simply never probed.
- The prober binds internal-only and requires a bearer token on every request.
  It is NOT hyrule-mcp: it exposes only bounded probe/health verbs, so a path
  route can never reach ssh_run_command or a service restart.
- `/v1/path/ping` and `/v1/path/report` default to the `as215932` vantage, so
  they auto-list in the manifest/OpenAPI/Bazaar the moment the token is set.

## Operator sequence

1. **Deploy the prober on `noc`** via network-operations (systemd unit, internal
   bind on `:8460`, node_exporter already present). Configure its vantage list so
   at least `as215932` (and optionally `extmon`) resolve to real AS215932 hosts:
   `HYRULE_PROBER_VANTAGES` is a JSON array of `{name,address,os,user,key,tools}`.
   FreeBSD core routers: set `os=freebsd` and drop `dig` from `tools`.
2. **Seed the prober's bearer token in Vault** and render it into the prober
   unit's `HYRULE_PROBER_AUTH_TOKEN` (fail-closed: an empty token refuses all).
3. **Open the firewall** api → noc `:8460` only (internal overlay); the prober is
   never Internet-reachable.
4. **Icinga**: register a `GET /v1/health` (bearer) check on the prober; page on
   `status != ok`. Snapshot Icinga problem state before/after per house rule.
5. **Flip Hyrule Cloud on**: `vault kv patch kv/hyrule-cloud prober_token=<same
   token>` and set `prober_url=http://[noc-internal]:8460`; restart api.
   `path_active_probe_enabled` now returns True and both endpoints re-list.
6. **Verify**:
   - `curl -s https://cloud.hyrule.host/.well-known/x402.json | jq '.resources[].path'`
     now includes `/v1/path/ping` and `/v1/path/report`.
   - `curl -s https://cloud.hyrule.host/v1/path/vantages` shows `as215932`/`extmon`
     as `supported`.
   - `python scripts/x402_canary.py path` and `path-report` (real USDC) return
     real RTT/hop findings and a settlement header — they flip from SKIPPED(501)
     to live.
7. **Bazaar**: the paid path canary settle seeds CDP indexing (~6h recompute);
   confirm `cloud.hyrule.host` appears in the CDP discovery API.

## Rollback

`vault kv patch kv/hyrule-cloud prober_token=""` and restart api. Both path
endpoints immediately return to 501-before-charge and drop from the manifest;
no in-flight measurement is charged.
