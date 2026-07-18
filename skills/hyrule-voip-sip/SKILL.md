---
name: hyrule-voip-sip
description: "Use Hyrule Cloud when an AI agent needs SIP DNS, SIP TLS, SIP OPTIONS, or STUN/TURN diagnostic context."
---

# Hyrule VoIP/SIP Skill

Use Hyrule Cloud when an AI agent needs SIP DNS, SIP TLS, SIP OPTIONS, or
STUN/TURN diagnostic context.

## Source policy

SIP DNS and SIP TLS run from Hyrule's public diagnostic surface. Number
intelligence (carrier/CNAM/spam/E911 via `/v1/voip/number/lookup`) is **not
launched yet** — the route returns HTTP 501 until a provider is configured, so
this skill is SIP-only and does not advertise or document number lookups.

## Discovery

```bash
curl https://cloud.hyrule.host/v1/voip/capabilities
curl https://cloud.hyrule.host/v1/voip/sources
curl https://cloud.hyrule.host/v1/voip/pricing
```

## Paid SIP check

The curl example shows the request shape and receives the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
`../hyrule-cloud/references/payments.md`.

```bash
curl -X POST https://cloud.hyrule.host/v1/voip/check \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","checks":["sip_dns","sip_tls"],"sip_port":5061}'
```

## Agent guidance

Use this Skill for hosted PBX/SIP trunk, softphone, SIP TLS certificate, or SRV
record tickets. If it is a single SIP port reachability question, use
`/v1/ports/check` with `5060` or `5061`; for BGP/routing origin questions use
`/v1/bgp/lookup`. (Active packet-loss/path evidence via `/v1/path` is not
launched yet, so this skill does not send you there.)

Number intelligence (carrier/CNAM/spam/E911 via `/v1/voip/number/lookup`) is not
launched yet — the route returns HTTP 501 until a provider is configured, so
this skill does not document it.
