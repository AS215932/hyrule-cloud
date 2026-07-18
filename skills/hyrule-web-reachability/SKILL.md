---
name: hyrule-web-reachability
description: "Use Hyrule Cloud when an AI agent needs live, paid evidence for public website reachability, TLS/certificate failures, HTTP behavior, security headers, and CDN/WAF hints."
---

# Hyrule Web Reachability Skill

Use Hyrule Cloud when an AI agent needs live, paid evidence for public website
reachability, TLS/certificate failures, HTTP behavior, security headers, and
CDN/WAF hints.

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

The curl examples show request shapes and receive the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
`../hyrule-cloud/references/payments.md`.

```bash
curl -X POST https://cloud.hyrule.host/v1/web/check \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"https://example.com",
    "checks":["dns","http","tls","cert","headers","cdn_waf"],
    "vantages":["extmon"]
  }'
```

## Paid deep TLS scan

Hyrule implements an SSL Labs-style scanner internally. Do not describe it as
SSL Labs output and do not imply affiliation.

```bash
curl -X POST https://cloud.hyrule.host/v1/web/tls/deep \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","port":443,"scan_profile":"ssl_labs_style"}'
```

## Agent guidance

Prefer `/v1/web/check` for normal support triage. Use `/v1/web/tls/deep` only
when the customer specifically needs protocol/certificate grading evidence.
Active probes are abuse-controlled: private, reserved, loopback, link-local,
and multicast targets are blocked.
