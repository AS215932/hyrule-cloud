---
name: hyrule-nat-cgnat
description: "Use Hyrule Cloud when an AI agent needs server-observed IP/DNS/STUN evidence, short-lived agent or browser fingerprints, NAT/CGNAT hints, or an outside-in port-forward check."
---

# Hyrule NAT/CGNAT Skill

Use Hyrule Cloud when an AI agent needs server-observed NAT or CGNAT evidence.
The agent-first flow runs from the environment under test; a browser is only an
optional WebRTC and browser-fingerprint adapter.

## Free caller IP with CGNAT/scope classification

```bash
curl https://cloud.hyrule.host/v1/nat/ip
```

Returns the IP Hyrule sees, its classification (`cgnat`, `private`, `global`,
or `non_global`), a `cgnat_likely` flag, and selected proxy headers. Run it
from the customer's network to learn how their egress address is classified —
Hyrule only classifies addresses it actually observes.

## Agent-first environment check

Prefer the `network_environment_check` MCP tool or the Python client method of
the same name. It creates a 15-minute session, performs dual-stack HTTPS, DNS,
and RFC 5389 STUN probes from the process hosting the client, records a declared
agent runtime profile, and returns one correlated report.

For an agent with its own probe engine, call `network_probe_manifest`. Execute
every manifest target from the environment being measured, then call
`network_check_report`. Never claim that a hosted/remote MCP gateway measured a
user's local network: it measured the gateway.

Evidence has explicit provenance:

- `server_observed`: Hyrule directly saw the HTTPS source or DNS resolver.
- `client_declared`: the client submitted runtime, model claims, WebRTC, or STUN output.
- `signed`: an EVM wallet signature verified against the per-session challenge.
- `attested`: reserved for a verified workload/TEE attestation; never infer it.

Browser fingerprints are session-scoped and expire with the session. WebGL,
canvas, and audio hashes require explicit high-entropy consent. Model/vendor
names are claims, not verified identity.

## Paid port-forward check

```bash
curl -X POST https://cloud.hyrule.host/v1/nat/port-forward/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"target":"customer.example.net","port":443,"protocol":"tcp","profile":"https"}'
```

## Agent guidance

CGNAT is likely when the observed egress IP is inside `100.64.0.0/10`, or when
the address the customer reports for their WAN differs from what `/v1/nat/ip`
observes. Treat absent IPv6, blocked WebRTC, failed STUN, or an unconfigured DNS
expectation as inconclusive—not as proof of a leak.
