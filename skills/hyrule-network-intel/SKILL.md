---
name: hyrule-network-intel
description: "Use Hyrule Cloud for paid, agent-friendly network intelligence primitives."
---

# Hyrule Network Intelligence Skill

Use Hyrule Cloud for paid, agent-friendly network intelligence primitives.

## Separation of concerns

- `/v1/domains` buys, renews, and manages account-owned domains and DNS.
- `/v1/dns` is read-only DNS lookup/diagnostics only.
- `/v1/ip` is IP intelligence.
- `/v1/rdap` and `/v1/whois` are registry lookups.
- `/v1/mx` is mail/domain troubleshooting.

## Capabilities

- IP geolocation (activates once a provider is configured; requests 501 before charging until then)
- IP-to-ASN/ISP lookup
- Licensed IP-quality reports combining MaxMind Insights, IPQS, current
  routing/RPKI, bounded routing history, and RIPE-only registration history
  (dark-launched until both provider resale approvals and credentials are live)
- Reverse DNS
- RDAP for domains, IPs, prefixes, ASNs, entities
- Legacy WHOIS for domains, IPs, prefixes/network blocks, ASNs
- Read-only DNS A/AAAA/CNAME/MX/NS/PTR/SOA/TXT/etc lookup
- DNSSEC and trace-oriented response fields

## Examples

```bash
curl https://cloud.hyrule.host/v1/dns/capabilities
```

```bash
curl -X POST https://cloud.hyrule.host/v1/dns/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"name":"example.com","type":"MX","dnssec":true}'
```

```bash
curl -X POST https://cloud.hyrule.host/v1/ip/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"address":"8.8.8.8","views":["asn","rdns","rdap","whois"]}'
```

Check `/v1/ip/capabilities` or the curated `/openapi.json` before offering the
quality report. When enabled, quote and call it with explicit context only:

```bash
curl -X POST https://cloud.hyrule.host/v1/ip/quality \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"address":"8.8.8.8","expected_country_code":"US","client_context":{"timezone":"America/Los_Angeles"},"history_days":90}'
```

Treat `verdict.level` as a screening outcome, not proof that a person is
fraudulent. Hyrule intentionally does not invent a universal numeric score:
IPQS scores at least 90 and confirmed high-risk abuse are `high_risk`; scores
75–89, anonymity/hosting signals, consistency mismatches, RPKI invalidity, or
origin changes are `review`; `low_risk` requires both licensed sources and no
review reasons. Open-source enrichment can be `partial` without hiding the
licensed evidence. Only send user-agent or language values the user explicitly
provided.

## x402

Call a paid endpoint without `X-PAYMENT` to receive a `402 Payment Required`
challenge. Pay through an x402 facilitator and retry with the `X-PAYMENT`
header.
