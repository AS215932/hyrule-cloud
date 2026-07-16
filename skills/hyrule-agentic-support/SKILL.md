---
name: hyrule-agentic-support
description: "NOT YET LAUNCHED. Umbrella skill that cross-references not-yet-launched flows (/v1/path/report and /v1/threat/lookup) which return HTTP 501; do not publish until those subskills ship. Hyrule Agentic ISP Support covers x402-paid network facts that LLMs cannot infer: live reachability, DNS, BGP, mail deliverability, routing/path evidence, TLS, reputation, VoIP, NAT hints, and AS215932-backed vantage data."
---

# Hyrule Agentic ISP Support Skill

> **NOT YET LAUNCHED.** This umbrella cross-references flows that are still
> gated: `/v1/path/report` and `/v1/threat/lookup` return HTTP 501 until their
> backends ship. Do not publish this skill until those subskills launch, so it
> never points agents at a 501 route.

Hyrule Agentic ISP Support is the umbrella Skill for x402-paid network facts
that LLMs cannot infer: live reachability, DNS, BGP, mail deliverability,
routing/path evidence, TLS, reputation, VoIP, NAT hints, and
AS215932-backed external vantage data.

## Focused subskills

- `hyrule-web-reachability` → `/v1/web`
- `hyrule-mail-deliverability` → `/v1/mx`
- `hyrule-dns-registry` → `/v1/dns`, `/v1/rdap`, `/v1/whois`
- `hyrule-routing-path` → `/v1/path`, `/v1/bgp`
- `hyrule-port-reachability` → `/v1/ports`
- `hyrule-nat-cgnat` → `/v1/nat`
- `hyrule-threat-reputation` → `/v1/threat`
- `hyrule-voip-sip` → `/v1/voip`

## Typical ISP support flow

1. Identify caller domain, IP, URL, mailbox, phone number, or service port.
2. For website outages, run `/v1/web/check`; use `/v1/web/tls/deep` for deep TLS.
3. For mail delivery, run `/v1/mx/reports/mail-delivery`; parse bounces with
   `/v1/mx/bounce/parse`.
4. For DNS/registry, use `/v1/dns/propagation`, `/v1/rdap/lookup`, and
   `/v1/whois/lookup`.
5. For routing/path claims, use `/v1/path/report` and `/v1/bgp/lookup`.
6. For outside-in reachability, use `/v1/ports/check` or
   `/v1/nat/port-forward/check`.
7. For NAT/CGNAT, use free `/v1/nat/ip` (includes CGNAT/scope classification).
8. For reputation, use `/v1/threat/lookup`; for VoIP, use `/v1/voip/check`.

## Discovery

- `/.well-known/x402.json` lists paid resources and prices.
- `/v1/*/capabilities` describes each product boundary.
- `/v1/mx/tools` lists SuperTool-compatible mail diagnostics.
- `/v1/path/vantages`, `/v1/threat/sources`, and `/v1/voip/sources` expose
  external/provider source status.

## Product boundaries

- Domain sales and authoritative DNS mutation: `/v1/domains`
- Recursive/read-only DNS diagnostics: `/v1/dns`
- Mail deliverability diagnostics: `/v1/mx`
- BGP/routing intelligence: `/v1/bgp`
- Path/packet-loss evidence: `/v1/path`
- Web/TLS/header/CDN diagnostics: `/v1/web`
- Single-service reachability: `/v1/ports`
- NAT/CGNAT hints: `/v1/nat`
- Threat/reputation context: `/v1/threat`
- VoIP/SIP diagnostics: `/v1/voip`
- IP/registry intelligence: `/v1/ip`, `/v1/rdap`, `/v1/whois`

## Abuse and source policy

Active probes block private, reserved, loopback, link-local, and multicast
targets by default. Port reachability is single-service only, not broad
scanning. Licensed threat/VoIP/mail reputation providers are represented as
pluggable sources and return `source_not_configured` until credentials and terms
are in place.
