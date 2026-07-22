---
name: hyrule-agent-mail
description: "Buy or activate an API-only email account for an autonomous agent, send single-recipient conversational mail with x402, receive mail and signed webhooks, or pair mailbox evidence with Hyrule deliverability diagnostics. Use for hosted agent addresses, custom managed domains, or an atomic domain-plus-mailbox purchase."
---

# Hyrule Agent Mail

Use `https://cloud.hyrule.host` to give an agent a durable email identity without
a human signup. Keep every returned capability token secret.

## Start with live discovery

1. Read `GET /v1/mail/products`, `/v1/mail/pricing`, and `/v1/mail/capabilities`.
2. Stop if `available` is false. Do not infer readiness from this Skill.
3. Read `GET /.well-known/x402.json` before paying. Use only advertised routes.
4. Set a total USD cap before requesting any registrar quote.

## Activate an address

Choose exactly one mode:

- `hosted`: `local_part@agentmail.hyrule.host`; activation is $1 for 30 days.
- `custom`: mailbox on an active Hyrule-managed domain; supply its capability
  token only to the quote call.
- `domain_and_mailbox`: a live one-year domain quote plus the $1 activation in
  one x402 payment. The returned `hyr_identity_…` token manages both resources.

Create the immutable quote with `POST /v1/mail/accounts/quote`. Show the user
the exact total and expiry. Pay `POST /v1/mail/accounts` with the `quote_id` and
a high-entropy `Idempotency-Key`; retry the same body and key after the 402.
Save `management_token` immediately. Poll `status_url` until `active`, `failed`,
or `refund_due`.

For field-level examples and status semantics, read [references/api.md](references/api.md).

## Send conversational mail

1. Create a locked quote with `POST /v1/mail/messages/send/quote` and the
   mailbox bearer token.
2. Pay `POST /v1/mail/messages/send` using only that `quote_id`.
3. Treat `accepted` as local submission, not final remote delivery. Watch
   `/events` or a signed webhook for delivery evidence.

Never add CC, BCC, multiple recipients, or outbound attachments. Respect the
published limits: five new recipients/day, twenty outbound/day, and replies to
known inbound correspondents. Do not use this product for marketing or bulk mail.

## Receive and diagnose

Read message summaries and bodies through `/accounts/{mailbox_id}/messages`.
Download inbound attachments only after checking their content type and the
live `inbound_attachment_max_bytes` capability (25 MiB at launch).
Verify `X-Hyrule-Signature` before acting on a webhook.

When mail is rejected or spam-filtered, first preserve the full bounce, remote
MX, SMTP enhanced status, message id, and timestamps. Then use the
`hyrule-mail-deliverability` Skill for `/v1/mx/bounce/parse` and the full sender
domain report. Separate DNS/authentication evidence from remote reputation or
content inferences.

## Lifecycle and safety

Activation lasts 30 days and never auto-renews. Outbound access stops at
expiry; reads and inbound delivery remain available for seven days. After that,
mailbox data and Agent Mail-owned DNS records are deleted while a purchased
domain remains registered. A complaint or malware event can suspend outbound
access immediately.
