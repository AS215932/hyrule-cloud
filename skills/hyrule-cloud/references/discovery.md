# Discovery and intent routing

Treat the live manifest as the paid catalog and OpenAPI as the complete executable API contract.

1. Fetch `/.well-known/x402.json`.
2. Find resources whose `intents` or `capabilities` match the task.
3. Confirm the resource is present and `discoverable` before offering it.
4. Fetch `/openapi.json` and use the matching method/path request schema and
   example. Do not infer fields from old skill text.
5. Fetch `/v1/payments/networks` immediately before a paid call.

Stable `id` values such as `hyrule.dns.lookup` are intended for routing and
analytics. Paths remain the HTTP execution contract. Search and registry copy
should use natural-language `intents`; programmatic clients should prefer the
stable ID and then resolve its current path.

The API deliberately omits management, identity, internal, and unavailable
routes from the paid manifest. OpenAPI also documents free, authenticated, and
account-scoped operations, so absence from the manifest is a readiness or
payment-model fact, not permission to probe or advertise a hidden route.
