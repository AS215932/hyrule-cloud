---
name: hyrule-port-reachability
description: Use Hyrule Cloud when an AI agent needs to answer whether one declared public service is reachable from outside.
---

# Hyrule Port Reachability Skill

Use Hyrule Cloud when an AI agent needs to answer whether one declared public
service is reachable from outside.

This Skill is not a general port scanner.

## API

```bash
curl https://cloud.hyrule.host/v1/ports/capabilities
curl https://cloud.hyrule.host/v1/ports/allowed
curl https://cloud.hyrule.host/v1/ports/pricing
```

## Paid check

```bash
curl -X POST https://cloud.hyrule.host/v1/ports/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"target":"example.com","port":443,"protocol":"tcp","profile":"https","vantage":"extmon"}'
```

## Safety rules

- One target and one service port per request.
- No broad scans or port ranges.
- Private, reserved, loopback, link-local, multicast, and unsafe resolved
  targets are blocked.
- Only public diagnostic allowlist ports are accepted.

## Agent guidance

Use this Skill for “my web/mail/SIP port is closed from outside” tickets. Use
`/v1/web` for HTTP/TLS details, `/v1/mx` for SMTP/mail delivery details, and
`/v1/path` for packet loss or routing evidence.
