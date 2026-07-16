---
name: hyrule-web-reachability
description: "Use Hyrule Cloud when an AI agent needs live, paid multi-point evidence for public website reachability, latency, redirects, TLS/certificate failures, server headers, and outage root-cause analysis."
---

# Hyrule Web Reachability Skill

Use Hyrule Cloud when an AI agent needs live, paid evidence from Hyrule's
external monitor and distributed Globalping probes. The quick check reports
availability, latency/timings, redirects, TLS, selected server and security
headers, and a deterministic root-cause assessment.

## When to use

- Customer says a site is down from the public internet.
- HTTPS works in one place but fails elsewhere.
- Certificate expiry, hostname mismatch, or chain issues are suspected.
- Security headers need an agent-readable report.
- CDN/WAF behavior may explain blocked or different responses.

## API boundaries

- `/v1/web` diagnoses public web endpoints.
- `/v1/dns` diagnoses read-only DNS details.
- `/v1/ports` checks one declared service port from outside.
- `/v1/domains/{domain}/dns/changesets` mutates authoritative DNS and is not
  used by this Skill.

## Discovery

```bash
curl https://cloud.hyrule.host/v1/web/capabilities
curl https://cloud.hyrule.host/v1/web/pricing
```

## Paid quick check

```bash
curl -X POST https://cloud.hyrule.host/v1/web/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{
    "target":"https://example.com",
    "checks":["dns","http","tls","cert","headers","cdn_waf"],
    "vantages":["extmon","globalping"],
    "locations":["Western Europe","Northern America","Eastern Asia"],
    "max_redirects":5
  }'
```

The default request uses those two vantages and three distributed locations,
so callers normally only need to send `target`. Inspect:

- `availability.status` and `availability.is_down` for the headline answer;
- `vantage_results` for per-location status, latency, DNS/TCP/TLS/first-byte
  timings, redirect evidence, TLS details, and selected headers;
- `root_cause` for the inferred failure scope, confidence, evidence, and
  recommended next action;
- `partial` and `sources` before treating the conclusion as global. A provider
  outage is reported as incomplete evidence, not as proof that the target is
  down.

## Paid deep TLS scan

Hyrule implements an SSL Labs-style scanner internally. Do not describe it as
SSL Labs output and do not imply affiliation.

```bash
curl -X POST https://cloud.hyrule.host/v1/web/tls/deep \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"host":"example.com","port":443,"scan_profile":"ssl_labs_style"}'
```

## Agent guidance

Prefer `/v1/web/check` for normal support triage. Use `/v1/web/tls/deep` only
when the customer specifically needs protocol/certificate grading evidence.
Active probes are abuse-controlled: private, reserved, loopback, link-local,
and multicast targets are blocked. Root-cause output is evidence-based
classification, not a substitute for the target operator's origin logs.
