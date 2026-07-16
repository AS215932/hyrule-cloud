---
name: hyrule-network-intel
description: "Use Hyrule Cloud for paid, agent-friendly network intelligence primitives."
---

# Hyrule Network Intelligence Skill

Use Hyrule Cloud for paid, agent-friendly network intelligence primitives.

## Separation of concerns

- `/v1/domain` buys/registers domains.
- `/v1/zone` manages authoritative DNS records for owned zones.
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

## x402

Call a paid endpoint without `X-PAYMENT` to receive a `402 Payment Required`
challenge. Pay through an x402 facilitator and retry with the `X-PAYMENT`
header.
