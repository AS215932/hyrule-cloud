---
name: hyrule-voip-sip
description: "Use Hyrule Cloud when an AI agent needs SIP DNS, SIP TLS, SIP OPTIONS, STUN/TURN, number carrier, CNAM, number spam reputation, or E911 diagnostic context."
---

# Hyrule VoIP/SIP Skill

Use Hyrule Cloud when an AI agent needs SIP DNS, SIP TLS, SIP OPTIONS,
STUN/TURN, number carrier, CNAM, number spam reputation, or E911 diagnostic
context.

## Source policy

SIP DNS and SIP TLS can run from Hyrule's public diagnostic surface. Number
carrier/CNAM/spam/E911 providers are pluggable adapters and return
`source_not_configured` until API keys and compliance requirements are in place.

## Discovery

```bash
curl https://cloud.hyrule.host/v1/voip/capabilities
curl https://cloud.hyrule.host/v1/voip/sources
curl https://cloud.hyrule.host/v1/voip/pricing
```

## Paid SIP check

```bash
curl -X POST https://cloud.hyrule.host/v1/voip/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"target":"example.com","checks":["sip_dns","sip_tls"],"sip_port":5061}'
```

## Paid number lookup contract

> **NOT YET AVAILABLE.** No carrier/CNAM/spam/E911 provider is configured, so
> `/v1/voip/number/lookup` (and its quote) currently return HTTP 501 without
> charging. The rest of this skill — SIP DNS/TLS via `/v1/voip/check` — is live.
> Strip this section when publishing until a number-intelligence provider ships.

```bash
curl -X POST https://cloud.hyrule.host/v1/voip/number/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"number":"+15551234567","country":"US","checks":["number_intel","cnam","spam_reputation","e911"]}'
```

## Agent guidance

Use this Skill for hosted PBX/SIP trunk, softphone, SIP TLS certificate, SRV
record, or number-reputation tickets. If the issue is general packet loss or
routing, use `/v1/path`. If it is a single SIP port reachability question, use
`/v1/ports/check` with `5060` or `5061`.
