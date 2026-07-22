# Exact customer-journey prompts

## 1. Explain why this website or TLS deployment is broken

> Diagnose `<URL>` from the public internet. Use Hyrule's web check first and
> deep TLS evidence only if needed. Test DNS, address reachability, HTTP
> redirects/status, certificate chain/hostname/expiry, protocol support, and
> relevant IPv4/IPv6 differences. Do not change the target. Return the primary
> cause, ranked supporting findings, exact redacted commands, source evidence,
> exact settled cost, UTC start/end, and elapsed seconds. Keep total spend at or
> below `$0.25`; ask once before exceeding it.

Generic entry command:

```bash
curl -sS -X POST https://cloud.hyrule.host/v1/web/check \
  -H 'Content-Type: application/json' \
  -d '{"url":"<URL>"}'
```

## 2. Buy and prove an agent email identity; diagnose rejection or spam

> From these candidate domains, choose the first available non-premium name:
> `<CANDIDATES>`. Obtain a live one-year domain quote and combine it atomically
> with a 30-day `agent@<domain>` Agent Mail activation. Show the exact combined
> amount and continue without another question only when it is at or below
> `$26.10`; otherwise ask once. Save the returned identity token securely.
> Poll until active, then verify authoritative MX, SPF, DKIM, DMARC, TLS-RPT,
> MTA-STS, A/AAAA, and PTR/FCrDNS evidence. Send exactly one controlled message
> to `<CONTROLLED_RECIPIENT>` and prove one controlled inbound reply. If the
> message is rejected or spam-filtered, preserve and parse the full bounce and
> remote MX, run the full mail-delivery report, and distinguish observed DNS,
> SMTP, IP/ASN reputation, and content inferences. Return redacted commands and
> identifiers, exact settled costs, UTC start/end, elapsed time per phase, and
> the 30-day/7-day deletion timeline. Never send to any other recipient.

Generic entry command:

```bash
curl -sS https://cloud.hyrule.host/v1/mail/products
```

For fully autonomous operation, replace placeholders with an explicit ordered
candidate list, a controlled recipient, and the same hard cap. This grants
selection within that list; it does not grant uncapped purchasing or bulk mail.

## 3. Deploy a fresh VM and return connection details

> Provision an `xs` Debian 13 VM for `<WORKLOAD>` for 45 days. Use Hyrule's
> automatically assigned hostname, open only the workload ports plus SSH, and
> keep new spend at or below `$12.00`; ask once before exceeding it. Poll to
> ready, then verify the returned DNS name, public IPv6 reachability, service
> TLS/HTTP where applicable, and SSH
> connection details without exposing private keys. Return the redacted exact
> command, resource ids, connection details, evidence, exact settled cost, UTC
> start/end, elapsed time per phase, and expiry/cleanup date.

Generic entry command:

```bash
curl -sS -X POST https://cloud.hyrule.host/v1/vm/quote \
  -H 'Content-Type: application/json' \
  -d '{"order_payload":{"duration_days":45,"size":"xs","os":"debian-13","ssh_pubkey":"<SSH_PUBLIC_KEY>","domain_mode":"auto","open_ports":[80,443]},"client_order_id":"<HIGH_ENTROPY_ID>"}'
```

## Client adaptation

- Coinbase/Bazaar MCP: discover the resource in Bazaar, let the x402-capable
  client handle the 402 retry, and preserve the exact quoted request body.
- OpenClaw: install the matching Hyrule Skill and use its API workflow; do not
  bypass readiness checks embedded in the Skill.
- Generic Agent Skills client: load the Skill directory, use the generic curl
  entry command for discovery, and delegate payment signing only to an x402 v2
  wallet tool that supports an advertised network.
