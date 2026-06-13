# Hyrule Agentic Support Skill

Hyrule Agentic Support combines Network Intelligence, MX Diagnostics, BGP Data,
and Agent Mail into an API surface designed for AI agents replacing ISP support
workflows.

## Typical ISP support flow

1. Identify caller domain/IP/mailbox.
2. Run `/v1/mx/jobs` with `profile=mail_delivery`.
3. Use `/v1/dns/lookup`, `/v1/ip/lookup`, `/v1/rdap/lookup`, and
   `/v1/whois/lookup` for deeper evidence.
4. Use `/v1/bgp/lookup` when route visibility, RPKI, prefix origin, or ASN
   ownership matters.
5. Use `/v1/mail` for Hyrule-hosted agent mailboxes, sending updates, receiving
   replies, webhooks, delivery logs, and quarantine actions.

## Discovery

- `/.well-known/x402.json` lists paid resources and prices.
- `/v1/mx/tools` lists SuperTool-compatible mail diagnostics.
- `/v1/dns/capabilities`, `/v1/ip/capabilities`, `/v1/bgp/capabilities`, and
  `/v1/mail/capabilities` describe each product boundary.

## Product boundaries

- Domain sales: `/v1/domain`
- Authoritative DNS mutation: `/v1/zone`
- Recursive DNS diagnostics: `/v1/dns`
- Mail deliverability diagnostics: `/v1/mx`
- Paid mailboxes: `/v1/mail`
- Routing intelligence: `/v1/bgp`
- IP/registry intelligence: `/v1/ip`, `/v1/rdap`, `/v1/whois`
