---
name: hyrule-nat-cgnat
description: "Use Hyrule Cloud when an AI agent needs server-observed NAT/CGNAT hints or an outside-in port-forward check. This MVP does not require browser/WebRTC/STUN participation."
---

# Hyrule NAT/CGNAT Skill

Use Hyrule Cloud when an AI agent needs server-observed NAT or CGNAT hints for
a customer. This MVP does not require browser/WebRTC/STUN participation.

## Free caller IP with CGNAT/scope classification

```bash
curl https://cloud.hyrule.host/v1/nat/ip
```

Returns the IP Hyrule sees, its classification (`cgnat`, `private`, `global`,
or `non_global`), a `cgnat_likely` flag, and selected proxy headers. Run it
from the customer's network to learn how their egress address is classified —
Hyrule only classifies addresses it actually observes.

## Paid port-forward check

The curl example shows the request shape and receives the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
`../hyrule-cloud/references/payments.md`.

```bash
curl -X POST https://cloud.hyrule.host/v1/nat/port-forward/check \
  -H 'Content-Type: application/json' \
  -d '{"target":"customer.example.net","port":443,"protocol":"tcp","profile":"https"}'
```

## Agent guidance

CGNAT is likely when the observed egress IP is inside `100.64.0.0/10`, or when
the address the customer reports for their WAN differs from what `/v1/nat/ip`
observes. For precise NAT type, a future client-assisted STUN/WebRTC test is
required.
