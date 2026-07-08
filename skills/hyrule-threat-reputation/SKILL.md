---
name: hyrule-threat-reputation
description: Use Hyrule Cloud when an AI agent needs open-source-first domain, IP, RBL, certificate transparency, RDAP/WHOIS, or reputation context.
---

# Hyrule Threat Reputation Skill

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

```bash
curl -X POST https://cloud.hyrule.host/v1/threat/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"subject":{"type":"domain","value":"example.com"},"views":["rbl","ct","rdap","whois","dns","reputation"]}'
```

## Shortcuts

```bash
curl -H 'X-PAYMENT: <x402-payment>' https://cloud.hyrule.host/v1/threat/domain/example.com
curl -H 'X-PAYMENT: <x402-payment>' https://cloud.hyrule.host/v1/threat/rbl?target=203.0.113.10
curl -H 'X-PAYMENT: <x402-payment>' https://cloud.hyrule.host/v1/threat/ct?domain=example.com
```

## Agent guidance

Use this Skill to add reputation context to mail, web, abuse, phishing, or
blocklist investigations. For mail-specific deliverability, call `/v1/mx` first
and use `/v1/threat` for supplemental reputation evidence.
