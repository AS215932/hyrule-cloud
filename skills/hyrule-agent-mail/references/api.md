# Agent Mail API reference

Base URL: `https://cloud.hyrule.host`

## Hosted quote

```bash
curl -sS https://cloud.hyrule.host/v1/mail/accounts/quote \
  -H 'Content-Type: application/json' \
  -d '{"local_part":"journey-agent","mode":"hosted","terms_version":"2026-08-04"}'
```

## Atomic domain and mailbox quote

```bash
curl -sS https://cloud.hyrule.host/v1/mail/accounts/quote \
  -H 'Content-Type: application/json' \
  -d '{"local_part":"agent","mode":"domain_and_mailbox","domain":"prompttoproof.dev","terms_version":"2026-08-04","domain_terms_version":"2026-07-15"}'
```

Always copy the live `terms_version` values from product/quote discovery. The
example dates are contract examples, not an instruction to accept stale terms.

## Pay activation

```bash
curl -sS https://cloud.hyrule.host/v1/mail/accounts \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: <32-or-more-random-characters>' \
  -d '{"quote_id":"<mailq_...>"}'
```

The first call returns an x402 402 challenge. Have the client sign the exact
live requirement, then repeat the identical URL, body, and idempotency key with
its x402 payment header. Save the returned `hyr_identity_…` token once.

## Pay one send

```bash
curl -sS https://cloud.hyrule.host/v1/mail/messages/send/quote \
  -H 'Authorization: Bearer <hyr_identity_...>' \
  -H 'Content-Type: application/json' \
  -d '{"mailbox_id":"<mbx_...>","to":"proof-recipient@example.net","subject":"Agent Mail canary","text":"This is a controlled one-recipient canary."}'

curl -sS https://cloud.hyrule.host/v1/mail/messages/send \
  -H 'Authorization: Bearer <hyr_identity_...>' \
  -H 'Content-Type: application/json' \
  -d '{"quote_id":"<mailq_...>"}'
```

Pay the second call through the client's x402 handler. Hyrule verifies before
submission and settles only after Stalwart accepts the message.

## Statuses

- `awaiting_payment`: quote reserved; no funds accepted yet.
- `pending_domain`: combined purchase is waiting on the registrar.
- `provisioning`: dedicated mail backend and DNS are being configured.
- `active`: send/read/webhook APIs are available.
- `suspended`: reads remain, outbound is blocked by abuse controls.
- `grace`: outbound expired; reads/inbound remain temporarily available.
- `refund_due`: paid activation failed; operator refund work is durable.
- `deleted`: mailbox data and credentials are gone; the domain is retained.
