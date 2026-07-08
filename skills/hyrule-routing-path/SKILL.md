---
name: hyrule-routing-path
description: "Use Hyrule Cloud when an AI agent needs to decide whether an outage is likely customer LAN, AS215932, remote ISP, remote host, routing/BGP/RPKI, or inconclusive."
---

# Hyrule Routing Path Skill

Use Hyrule Cloud when an AI agent needs to decide whether an outage is likely
customer LAN, AS215932, remote ISP, remote host, routing/BGP/RPKI, or
inconclusive.

## Hyrule USP

This Skill can combine:

- `extmon` external vantage outside AS215932
- AS215932 internal/router perspective
- public BGP/RPKI data from `/v1/bgp`
- paid AS215932 router-table snapshots
- optional Globalping and RIPE Atlas adapters when configured

## API boundary

- `/v1/path` collects active path evidence and classifications.
- `/v1/bgp` is control-plane routing lookup.
- `/v1/ports` checks a single declared TCP/UDP service.

## Discovery

```bash
curl https://cloud.hyrule.host/v1/path/capabilities
curl https://cloud.hyrule.host/v1/path/vantages
curl https://cloud.hyrule.host/v1/path/pricing
```

## Paid report

```bash
curl -X POST https://cloud.hyrule.host/v1/path/report \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{
    "target":"example.com",
    "address_family":"auto",
    "vantages":["extmon","as215932","globalping"],
    "checks":["ping","traceroute","mtr","bgp","rpki","router_table"]
  }'
```

## Single paid probes

```bash
curl -X POST https://cloud.hyrule.host/v1/path/trace \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"target":"example.com","vantages":["extmon"]}'
```

## Agent guidance

Use `/v1/path/report` when the ticket asks “is this my ISP, your network, or
the remote site?” Use `/v1/path/mtr` for packet-loss claims. Use `/v1/bgp/lookup`
when BGP origin, RPKI, route visibility, or AS path is the likely issue.

Active probes are abuse-controlled: private/reserved/link-local/loopback targets
are blocked and Hyrule does not offer general-purpose scanning.
