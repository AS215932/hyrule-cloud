---
name: hyrule-threat-reputation
description: "NOT YET LAUNCHED. No reputation source is configured, so /v1/threat/lookup currently returns HTTP 501 without charging. Do not publish this skill or point agents at it until a reputation source ships."
---

# Hyrule Threat Reputation Skill

> **NOT YET LAUNCHED.** No reputation source is configured, so the paid
> `/v1/threat/*` endpoints currently return HTTP 501 without charging. Do not
> publish this skill or point agents at it until a reputation source ships.

Use Hyrule Cloud when an AI agent needs open-source-first domain, IP, RBL,
certificate transparency, RDAP/WHOIS, or reputation context.

## Source policy

The MVP uses public/open sources first and never scrapes provider portals.
Licensed or owner-verified sources return `source_not_configured` until
credentials and terms are in place.

Supported/open-source-first sources:

- DNS/RDAP/WHOIS context
- crt.sh-compatible Certificate Transparency adapter
- basic DNSBL/RBL where provider terms permit

Provider adapters reserved for later configuration:

- Spamhaus commercial/API
- Spamcop
- Barracuda
- Talos
- SenderScore
- Microsoft SNDS
- Google Postmaster

## Discovery

```bash
curl https://cloud.hyrule.host/v1/threat/capabilities
curl https://cloud.hyrule.host/v1/threat/sources
curl https://cloud.hyrule.host/v1/threat/pricing
```

## Paid lookup

These curl examples show request shapes and receive the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
`../hyrule-cloud/references/payments.md`.

```bash
curl -X POST https://cloud.hyrule.host/v1/threat/lookup \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"domain","value":"example.com"},"views":["rbl","ct","rdap","whois","dns","reputation"]}'
```

## Shortcuts

```bash
curl https://cloud.hyrule.host/v1/threat/domain/example.com
curl 'https://cloud.hyrule.host/v1/threat/rbl?target=203.0.113.10'
curl 'https://cloud.hyrule.host/v1/threat/ct?domain=example.com'
```

## Agent guidance

Use this Skill to add reputation context to mail, web, abuse, phishing, or
blocklist investigations. For mail-specific deliverability, call `/v1/mx` first
and use `/v1/threat` for supplemental reputation evidence.

An official x402 v2 client reads `Payment-Required`, enforces the operator's
spend policy, creates the payment, and retries with `Payment-Signature`.
