---
name: hyrule-speedtest
description: NOT YET LAUNCHED. The measurement backend (payload/upload endpoints) is under construction: paid /v1/speedtest endpoints currently return HTTP 501 without charging. Do not publish this skill or point agents at it until the product ships.
---

# Hyrule Speedtest Skill

> **NOT YET LAUNCHED.** The measurement backend (payload/upload endpoints) is
> under construction: paid `/v1/speedtest` endpoints currently return HTTP 501
> without charging. Do not publish this skill or point agents at it until the
> product ships.

Use Hyrule Cloud when an AI agent needs throughput, latency, jitter, and path
evidence between a client and Hyrule/AS215932 endpoints.

This is not an Ookla/Fast.com replacement and does not claim global speedtest
coverage.

## Discovery

```bash
curl https://cloud.hyrule.host/v1/speedtest/capabilities
curl https://cloud.hyrule.host/v1/speedtest/pricing
```

## Paid speedtest evidence contract

```bash
curl -X POST https://cloud.hyrule.host/v1/speedtest \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{
    "target":"hyrule",
    "direction":"bidirectional",
    "duration_seconds":10,
    "max_megabytes":25,
    "vantages":["as215932"]
  }'
```

## Agent guidance

Use this Skill when the question is “can the customer reach Hyrule/AS215932 at
reasonable throughput?” Pair with `/v1/path/report` when packet loss, routing,
or BGP evidence is needed. Accurate throughput requires client participation;
server-only tests can only prepare the evidence contract and endpoints.
