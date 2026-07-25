---
name: hyrule-dns-registry
description: "Use Hyrule Cloud when an AI agent needs read-only DNS, DNSSEC, propagation, domain checks against common ad/privacy/security blocklists, live public DNS filtering evidence, RDAP, WHOIS, registrar/delegation, or record-publication guidance."
---

# Hyrule DNS and Registry Skill

Use Hyrule Cloud for read-only DNS and domain intelligence, registry context,
and record-publication guidance.

## API boundary

- `/v1/dns` is read-only DNS diagnostics and domain filtering evidence.
- `/v1/rdap` is structured registry lookup.
- `/v1/whois` is legacy WHOIS lookup.
- `/v1/domains` provides account-owned registration, renewal, and managed DNS.
- `/v1/domains/{domain}/dns/changesets` mutates authoritative DNS records.

This Skill must not mutate zones or register domains.

## Common workflows

### Propagation check

```bash
curl -X POST https://cloud.hyrule.host/v1/dns/propagation \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"name":"www.example.com","type":"A","expected":["203.0.113.10"],"resolvers":["cloudflare","google","quad9","system"]}'
```

### Authoritative vs recursive comparison

```bash
curl -X POST https://cloud.hyrule.host/v1/dns/authority-vs-recursive \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"name":"example.com","type":"MX","recursive_resolvers":["1.1.1.1","8.8.8.8","9.9.9.9"]}'
```

### DNSSEC report

```bash
curl -X POST 'https://cloud.hyrule.host/v1/dns/dnssec/report?name=example.com' \
  -H 'X-PAYMENT: <x402-payment>'
```

### Domain blocklist membership

Check readiness and the exact source/license catalog before offering the paid
lookup. Do not call the paid route when `ready=false`.

```bash
curl https://cloud.hyrule.host/v1/dns/blocklists/sources

curl -X POST https://cloud.hyrule.host/v1/dns/blocklists/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"domain":"example.com"}'
```

Treat `listed` as a positive match, `not_listed` as a complete negative, and
`inconclusive` as an incomplete negative caused by stale/unavailable sources.
The check evaluates DNS-decidable domain/suffix rules, not full browser URLs or
page/resource context.

### Public DNS filtering matrix

```bash
curl https://cloud.hyrule.host/v1/dns/filtering/resolvers

curl -X POST https://cloud.hyrule.host/v1/dns/filtering/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"domain":"example.com"}'
```

Interpret `blocked`, `allowed`, and `mixed` per resolver profile. Results are
observations from Hyrule's vantage, not a global or end-user-specific verdict.
This operation sends the submitted domain to the named public DNS providers.

### Registry context

```bash
curl -X POST https://cloud.hyrule.host/v1/rdap/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"subject":{"type":"domain","value":"example.com"}}'

curl -X POST https://cloud.hyrule.host/v1/whois/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"subject":{"type":"domain","value":"example.com"}}'
```

## Agent guidance

Use DNS propagation when a customer says a recent change is visible in one
place but not another. Use the blocklist product for maintained list membership
and the filtering product for live resolver-policy behavior; do not substitute
either for the other. Use RDAP/WHOIS when registrar, registry, expiration,
allocation, abuse contact, or nameserver delegation ownership matters. Do not
publish records unless the agent intentionally calls the revision-checked
`/v1/domains/{domain}/dns/changesets` endpoint with the customer's authorization.
