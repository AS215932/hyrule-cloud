# Licensed IP quality launch

`POST /v1/ip/quality` is dark by default. It must remain absent from the
curated OpenAPI document, x402 manifest, Bazaar challenges, capabilities, and
the customer MCP catalog until every launch guard below is satisfied.

## Contract and cost gate

Record written approval to return normalized provider-derived fields to paying
Hyrule customers. A normal API subscription is not enough evidence of resale
rights.

- MaxMind GeoIP Insights web-service credentials are present.
- `IP_QUALITY_MAXMIND_RESALE_APPROVED=true` reflects written approval.
- IPQS credentials are present and are sent only in the `IPQS-KEY` header.
- `IP_QUALITY_IPQS_RESALE_APPROVED=true` reflects written approval.
- Declared per-report unit costs sum to at most 40% of
  `PAYMENT_PRICE_IP_QUALITY` (default price: `$0.02`).
- `IP_QUALITY_ENABLED=true` is the final API launch switch.
- `HYRULE_IP_QUALITY_TOOL_ENABLED=true` is set for customer MCP only after the
  hosted API entitlement is confirmed live.

The implementation uses the MaxMind Insights web service rather than shipping
an MMDB. Provider payloads are normalized into Hyrule-owned response models;
raw payloads are never returned. Caching remains off unless both contracts
explicitly permit it and `IP_QUALITY_CACHE_RIGHTS_APPROVED=true` is recorded.

Provider references:

- <https://dev.maxmind.com/geoip/docs/web-services/requests/>
- <https://dev.maxmind.com/geoip/docs/web-services/responses/>
- <https://www.ipqualityscore.com/documentation/about-ipqs-apis/submitting-data-to-ipqs-apis>
- <https://www.ipqualityscore.com/documentation/proxy-detection-api/response-parameters>

## Billing invariant

The route verifies an x402 authorization first, queries MaxMind and IPQS
concurrently with a five-second timeout and no automatic retry, and settles
only after both return usable evidence. A required-provider failure returns
`503 ip_quality_sources_unavailable` and does not settle. RIPEstat, Team Cymru,
RPKI, routing history, and RIPE historical WHOIS may degrade to `partial`
without blocking settlement after the two paid sources delivered.

## Canary

Before enabling discovery:

1. Confirm `/v1/ip/pricing` returns `quality_report_usd: null` and the quality
   route returns 501 without a payment challenge.
2. Add credentials, approvals, unit costs, and the API switch in Vault.
3. Restart the API and confirm `/v1/ip/sources` reports both licensed sources
   configured, approved, and enabled.
4. Confirm `/openapi.json` and `/.well-known/x402.json` contain exactly one new
   paid resource: `POST /v1/ip/quality` at `$0.02`.
5. Run an unpaid request and validate its 402/Bazaar metadata.
6. Run a paid report for one IPv4 and one IPv6 address. Confirm the payment
   ledger records one settlement per successful report.
7. Simulate each provider failing independently and confirm a 503 with no new
   settlement.
8. Enable the customer MCP tool only after these checks pass.

The verdict is a screening result, not a determination about a person. Do not
market it as a universal "clean IP" score.
