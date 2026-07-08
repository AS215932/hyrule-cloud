# Hyrule Mail Deliverability Skill

Use Hyrule Cloud when an AI agent needs to diagnose missing, rejected,
delayed, or spam-filtered email for any public domain. This Skill is a
marketing/support wrapper over the canonical `/v1/mx` API.

## API boundary

- `/v1/mx` diagnoses mail delivery, DNS authentication, SMTP reachability,
  blacklists, bounce messages, and record recommendations.
- `/v1/dns` performs lower-level read-only DNS lookups.

## Discovery

```bash
curl https://cloud.hyrule.host/v1/mx/tools
curl https://cloud.hyrule.host/v1/mx/capabilities
curl https://cloud.hyrule.host/v1/mx/pricing
```

## Single paid check

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/check \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"tool":"dmarc","target":"example.com"}'
```

## Full paid mail-delivery report

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/reports/mail-delivery \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{"target":"example.com","profile":"mail_delivery"}'
```

## Bounce parser

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/bounce/parse \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{
    "message":"550 5.7.26 Unauthenticated email from example.com is not accepted",
    "context":{"sender_domain":"example.com","recipient_domain":"gmail.com"}
  }'
```

## DNS record recommendations

```bash
curl -X POST https://cloud.hyrule.host/v1/mx/recommend-records \
  -H 'Content-Type: application/json' \
  -H 'X-PAYMENT: <x402-payment>' \
  -d '{
    "domain":"example.com",
    "provider":"custom",
    "sending_ips":["203.0.113.10"],
    "policy":{"dmarc":"quarantine","tls_reporting":true,"mta_sts":true,"bimi":false}
  }'
```

## Agent guidance

For rejected mail, parse the bounce first, then run `/v1/mx/reports/mail-delivery`
for the sender domain and any mentioned remote MX. For spam placement, prioritize
SPF, DKIM, DMARC alignment, reverse DNS/FCrDNS, blacklist, ASN/IP reputation,
and SMTP TLS evidence.

Hyrule implements MXToolbox-compatible behavior internally and is not affiliated
with MXToolbox.
