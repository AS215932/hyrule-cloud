---
name: hyrule-bgp
description: "Hyrule BGP Data provides free AS215932 status plus paid public/global BGP intelligence for agents."
---

# Hyrule BGP Data Skill

Hyrule BGP Data provides free AS215932 status plus paid public/global BGP
intelligence for agents.

## Free

```bash
curl https://cloud.hyrule.host/v1/bgp/status
curl https://cloud.hyrule.host/v1/bgp/sources
curl https://cloud.hyrule.host/v1/bgp/capabilities
```

`/v1/bgp/status` is Hyrule/AS215932 status only. It is not an arbitrary ASN
status endpoint.

## Paid lookup

Use `/v1/bgp/lookup` for arbitrary prefix, IP, or ASN investigation. Prefix and
IP lookups do not require the caller to know the ASN.

The curl example shows the request shape and receives the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
<https://github.com/AS215932/hyrule-cloud/blob/main/skills/hyrule-cloud/references/payments.md>.

```bash
curl -X POST https://cloud.hyrule.host/v1/bgp/lookup \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"prefix","value":"2a0c:b641:b50::/44"},"views":["origins","rpki","visibility"]}'
```

ASN assertion example:

```json
{
  "subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"},
  "assertions": {"expected_origin_asns": [215932], "expected_rpki": "valid"}
}
```

## Sources

Current synchronous lookup uses RIPEstat/RPKI and PeeringDB where applicable.
The extmon rollout adds Cloudflare Radar, bgp.tools, Routinator-local,
BGPalerter, BGPStream jobs over RouteViews/RIS, and paid AS215932 router table
snapshots.

## x402

An official x402 v2 client reads `Payment-Required`, enforces the operator's
spend policy, creates the payment, and retries with `Payment-Signature`.
