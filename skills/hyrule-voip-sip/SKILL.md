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

## Agent guidance

Use this Skill for hosted PBX/SIP trunk, softphone, SIP TLS certificate, or SRV
record tickets. If the issue is general packet loss or routing, use `/v1/path`.
If it is a single SIP port reachability question, use `/v1/ports/check` with
`5060` or `5061`.

Number intelligence (carrier/CNAM/spam/E911 via `/v1/voip/number/lookup`) is not
launched yet — the route returns HTTP 501 until a provider is configured, so
this skill does not document it.
