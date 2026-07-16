---
name: hyrule-mail
description: "NOT YET LAUNCHED. The mail backend is under construction: every paid /v1/mail endpoint currently returns HTTP 501 without charging. Do not publish this skill or point agents at it until the product ships."
---

# Hyrule Agent Mail Skill

> **NOT YET LAUNCHED.** The mail backend is under construction: every paid
> `/v1/mail` endpoint currently returns HTTP 501 without charging. Do not
> publish this skill or point agents at it until the product ships.

Hyrule Agent Mail is the planned paid mailbox product for AI agents. The API
contract is stable now; the backend adapter can be Stalwart, Postfix/Dovecot,
Rspamd, or another mail backend hidden behind this API.

## What agents get

- Paid mailbox account lifecycle
- SMTP/IMAP credentials
- Direct API send/fetch/search/reply/forward
- Aliases and identities
- API keys and credential rotation
- Inbound and delivery webhooks
- Delivery logs
- Spam/quarantine controls
- Custom-domain mail setup instructions

## Separation of concerns

- `/v1/mail` creates and operates mailboxes.
- `/v1/mx` diagnoses mail delivery.
- `/v1/domains` buys domains and manages their DNS records.

## Examples

Quote mailbox creation:

```bash
curl -X POST https://cloud.hyrule.host/v1/mail/accounts/quote \
  -H 'Content-Type: application/json' \
  -d '{"plan":"agent-basic","duration_days":30,"local_part":"support-agent","domain":"agentmail.hyrule.host"}'
```

Create mailbox:

```bash
curl -X POST https://cloud.hyrule.host/v1/mail/accounts \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"plan":"agent-basic","duration_days":30,"local_part":"support-agent","domain":"agentmail.hyrule.host"}'
```

Send mail by API:

```bash
curl -X POST https://cloud.hyrule.host/v1/mail/messages/send \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <mail-token>' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"mailbox_id":"mail_...","from":"support-agent@agentmail.hyrule.host","to":["customer@example.net"],"subject":"Update","text":"Hello"}'
```
