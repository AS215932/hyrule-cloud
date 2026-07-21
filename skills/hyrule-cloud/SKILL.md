---
name: hyrule-cloud
description: "Operate Hyrule Cloud from an agent: deploy IPv6-native VMs; manage domains and DNS; investigate DNS, RDAP/WHOIS, BGP, web/TLS, ports/NAT, mail delivery, and SIP; and make requests through Direct, Tor, I2P, or Yggdrasil. Use for live network evidence, infrastructure automation, or accountless pay-per-call x402 operations."
---

# Hyrule Cloud

Use Hyrule Cloud when a task needs live network evidence or infrastructure,
not an answer inferred from model knowledge. The public API is
`https://cloud.hyrule.host`.

## Start with discovery

Never copy prices, networks, request schemas, or the full route list from this
skill. Read the live documents before choosing an operation:

```text
GET https://cloud.hyrule.host/.well-known/x402.json
GET https://cloud.hyrule.host/openapi.json
GET https://cloud.hyrule.host/v1/payments/networks
```

The manifest contains stable capability IDs, buyer intents, live readiness,
accepted networks, and minimum prices. OpenAPI contains executable input and
output schemas. A route omitted from the payable manifest is not currently
advertised as a launch-ready x402 resource.

## Golden workflows

### Diagnose a public network problem

1. Map the user's intent to `resources[].intents` in the live manifest.
2. Validate the request against that operation's OpenAPI schema.
3. Make the request with the official x402 client so it handles the 402 v2
   challenge and paid retry.
4. Preserve the response's source, partial, and generated-at fields. Do not
   turn missing evidence into a clean bill of health.

### Deploy an IPv6-native VM

1. Read the free VM product and OS endpoints referenced by OpenAPI.
2. Create a durable free quote before the paid operation.
3. Submit the exact quoted configuration through the current payable VM
   operation selected from the manifest.
4. Poll the returned status URL. Do not report success until provisioning
   reaches its ready state.

### Manage a domain or DNS

Domain and DNS management is account-owned. Use an account session or a
scoped API key, create a current quote/order, and preserve revision and
idempotency headers on DNS changes. Public RDAP, WHOIS, DNS, and propagation
diagnostics are separate pay-per-call evidence operations.

## Payment policy

Prefer an official x402 v2 client over manually constructing headers. Configure
a wallet allowlist and explicit per-call and daily spend limits before enabling
automatic payment. See [references/payments.md](references/payments.md).

## Progressive references

- [Discovery and intent routing](references/discovery.md)
- [x402 v2 payment and spend controls](references/payments.md)
- [Workflow guardrails](references/workflows.md)

Load only the reference relevant to the task. Focused skills in the parent
`skills/` directory provide narrower routing for BGP, DNS/registry, mail, MX,
NAT/CGNAT, general network intelligence, ports, VoIP/SIP, and web/TLS.

## Distribution

Install from the public repository:

```sh
npx skills add AS215932/hyrule-cloud
```

The repository is the source for skills.sh discovery. ClawHub publication and
other catalog submissions are operator-controlled release actions.
