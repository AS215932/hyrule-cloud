# Agentic ISP Support Diagnostics Rollout

This runbook covers the `/v1/web`, `/v1/mx`, `/v1/dns`, `/v1/path`,
`/v1/ports`, `/v1/nat`, `/v1/threat`, `/v1/voip`, and `/v1/speedtest` surfaces.

## Scope

Hyrule exposes low-overhead x402-paid diagnostics for AI agents and ISP support
workflows. Product namespaces wrap existing primitives rather than replacing
UNIX-style API boundaries:

- `/v1/web` combines the external monitor with Globalping HTTP probes and
  returns DNS/HTTP/TLS/header/CDN, latency, redirect, and outage-cause evidence.
- `/v1/mx` remains canonical for mail deliverability diagnostics.
- `/v1/dns`, `/v1/rdap`, `/v1/whois` remain registry/DNS primitives.
- `/v1/path` combines active path, BGP/RPKI, AS215932, and optional multi-vantage evidence.
- `/v1/ports` performs one declared service reachability check only.
- `/v1/nat` is server-only NAT/CGNAT hints in MVP.
- `/v1/threat` is open-source-first reputation with licensed adapters disabled until configured.
- `/v1/voip` is SIP diagnostics plus pluggable number-provider adapters.
- `/v1/speedtest` measures to Hyrule/AS215932 endpoints only.

## Deployment requirements

1. Apply migrations through `011_diagnostic_job_primitives.py`.
2. Ensure runtime env contains the new `PAYMENT_PRICE_*` knobs or relies on defaults.
3. Keep `EXTMON` operationally independent and outside AS215932.
4. Leave `GLOBALPING_ENABLED=true` and configure `GLOBALPING_TOKEN` from the
   deployment secret store when authenticated capacity is required.
5. Configure provider tokens only when provider terms permit commercial/API use.
6. Do not enable private-target scanning in the public API.

## Abuse controls

Active probes must call shared safety helpers that block:

- private/RFC1918 targets
- loopback
- link-local
- multicast
- reserved/unspecified addresses
- domain names resolving to any of the above

Port checks are one target + one port per request. Broad scans and arbitrary
port ranges are intentionally unsupported.

## Observability

Every diagnostic endpoint is a normal FastAPI route and is covered by existing
request-latency metrics middleware. Source-specific health is returned in each
response via `sources` fields, including `source_not_configured` for disabled
third-party adapters.

Watch during rollout:

- HTTP status distribution, especially `402`, `4xx`, and `5xx`
- request latency by route
- source status fields in responses
- extmon agent health
- Globalping quota/availability and the ratio of partial web checks
- BGP/RPKI source freshness
- abuse-control rejects from active probes

## Acceptance checks

Free discovery:

```bash
curl https://cloud.hyrule.host/.well-known/x402.json
curl https://cloud.hyrule.host/v1/web/capabilities
curl https://cloud.hyrule.host/v1/path/vantages
curl https://cloud.hyrule.host/v1/ports/allowed
curl https://cloud.hyrule.host/v1/nat/ip
curl https://cloud.hyrule.host/v1/threat/sources
curl https://cloud.hyrule.host/v1/voip/sources
```

Paid fail-closed without payment:

```bash
curl -i -X POST https://cloud.hyrule.host/v1/web/check \
  -H 'Content-Type: application/json' -d '{"target":"https://example.com"}'

curl -i -X POST https://cloud.hyrule.host/v1/path/report \
  -H 'Content-Type: application/json' -d '{"target":"example.com"}'

curl -i -X POST https://cloud.hyrule.host/v1/ports/check \
  -H 'Content-Type: application/json' -d '{"target":"example.com","port":443}'
```

Expected result: `402 Payment Required` with x402 payment instructions.

Safety rejection after payment/dev bypass:

```bash
curl -i -X POST https://cloud.hyrule.host/v1/ports/check \
  -H 'Content-Type: application/json' \
  -H 'X-DEV-BYPASS: <staging-only-secret>' \
  -d '{"target":"127.0.0.1","port":443}'
```

Expected result: request is rejected; private/loopback targets are not probed.

## Rollback

The new routes are additive. If any provider integration misbehaves, disable the
provider token/config first. If route code must be rolled back, deploy the prior
`hyrule-cloud` SHA; migrations are additive and can remain in place.
