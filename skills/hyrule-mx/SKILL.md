---
name: hyrule-mx
description: "Hyrule MX Diagnostics is a paid, MXToolbox-compatible troubleshooting API for AI agents and ISP support automation. Hyrule implements the checks internally; it is not affiliated with MXToolbox and does not scrape MXToolbox."
---

# Hyrule MX Diagnostics Skill

Hyrule MX Diagnostics is a paid, MXToolbox-compatible troubleshooting API for
AI agents and ISP support automation. Hyrule implements the checks internally;
it is not affiliated with MXToolbox and does not scrape MXToolbox.

## Tools

Supported SuperTool-style tools:

`a`, `aaaa`, `arin`, `asn`, `bimi`, `blacklist`, `cname`, `dkim`, `dmarc`,
`dns`, `http`, `https`, `mta-sts`, `mx`, `ping`, `ptr`, `smtp`, `soa`, `spf`,
`tcp`, `tlsrpt`, `trace`, `txt`, `whois`.

## Use cases

- Missing inbound mail
- Rejected outbound mail
- Spam-folder placement
- DNS/MX/SPF/DKIM/DMARC alignment issues
- SMTP reachability and STARTTLS/TLS issues
- IP/domain reputation listings
- ISP first/second/third-line support automation

## Examples

The curl examples show request shapes and receive the initial 402. Use an
official x402 v2 client for `Payment-Required` handling and the paid retry; see
<https://github.com/AS215932/hyrule-cloud/blob/main/skills/hyrule-cloud/references/payments.md>.

```bash
curl https://cloud.hyrule.host/v1/mx/tools
```

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/check \
  -H 'Content-Type: application/json' \
  -d '{"tool":"spf","target":"example.com"}'
```

SuperTool-compatible command form:

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/check \
  -H 'Content-Type: application/json' \
  -d '{"command":"mx:example.com"}'
```

Full mail-delivery report:

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/jobs \
  -H 'Content-Type: application/json' \
  -d '{"profile":"mail_delivery","target":"example.com"}'
```

## Safety

Active probes reject private, loopback, link-local, multicast, unspecified, and
reserved targets by default.
