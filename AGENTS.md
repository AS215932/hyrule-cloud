# Hyrule Cloud Agent Guide

## Domain Policy

- `hyrule.host` is customer-facing Hyrule Cloud/product identity. Public API clients use `https://cloud.hyrule.host`; automatic VM hostnames live under `deploy.hyrule.host`.
- `servify.network` is infrastructure identity for nameservers, underlay and management references, provider relationships, internal UIs, and partner-facing hostnames.
- `as215932.net` is AS215932 overlay/routing identity only. DNS records in this zone must point only at prefixes owned by AS215932.

Do not blindly replace `servify.network`: nameservers such as `ns1.servify.network` and `ns2.servify.network` are intentionally infrastructure identity.
