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
- Reverse DNS
- RDAP for domains, IPs, prefixes, ASNs, entities
- Legacy WHOIS for domains, IPs, prefixes/network blocks, ASNs
- Read-only DNS A/AAAA/CNAME/MX/NS/PTR/SOA/TXT/etc lookup
- DNSSEC and trace-oriented response fields

## Examples

The curl examples show request shapes and receive the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
<https://github.com/AS215932/hyrule-cloud/blob/main/skills/hyrule-cloud/references/payments.md>.

```bash
curl https://cloud.hyrule.host/v1/dns/capabilities
```

```bash
curl -X POST https://cloud.hyrule.host/v1/dns/lookup \
  -H 'Content-Type: application/json' \
  -d '{"name":"example.com","type":"MX","dnssec":true}'
```

```bash
curl -X POST https://cloud.hyrule.host/v1/ip/lookup \
  -H 'Content-Type: application/json' \
  -d '{"address":"8.8.8.8","views":["asn","rdns","rdap","whois"]}'
```

## x402

An official x402 v2 client reads `Payment-Required`, enforces the operator's
spend policy, creates the payment, and retries with `Payment-Signature`.
