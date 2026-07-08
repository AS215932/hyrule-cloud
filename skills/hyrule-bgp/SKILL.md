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

```bash
curl -X POST https://cloud.hyrule.host/v1/bgp/lookup \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
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

Call a paid endpoint without `X-PAYMENT` to receive a `402 Payment Required`
challenge. Pay through an x402 facilitator and retry with `X-PAYMENT`.
