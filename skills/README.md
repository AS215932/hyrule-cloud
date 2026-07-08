# Hyrule Cloud OpenClaw Skills

One directory per ClawHub slug, each containing a `SKILL.md` with
`name`/`description` frontmatter. These are the agent-facing API references
published to the [ClawHub](https://clawhub.ai) skill registry.

## Publishing

```bash
npm i -g clawhub
clawhub login   # GitHub account must be ≥ 1 week old

# Dry-run one skill, then publish it
clawhub skill publish ./skills/hyrule-cloud --slug hyrule-cloud --version 1.0.0 --dry-run
clawhub skill publish ./skills/hyrule-cloud --slug hyrule-cloud --version 1.0.0

# Later bulk updates
clawhub sync --dry-run
clawhub sync --all
```

**Do not publish anything until the live paid VM canary has passed**
(docs/runbooks/x402-launch.md). Publishing order — umbrella first so
cross-references resolve:

1. `hyrule-cloud` (VM + domain + DNS umbrella)
2. `hyrule-network-intel`
3. `hyrule-bgp`
4. `hyrule-dns-registry`
5. `hyrule-mx`
6. `hyrule-web-reachability`
7. `hyrule-routing-path`
8. `hyrule-port-reachability`
9. `hyrule-nat-cgnat`
10. `hyrule-voip-sip`
11. `hyrule-agentic-support`
12. `hyrule-mail-deliverability`
13. `hyrule-threat-reputation` — only after its output quality passes the
    Phase 3a canary (the lookup service currently makes no external calls)

## Withheld — do NOT publish

- `hyrule-mail` — every paid `/v1/mail` endpoint returns 501; contract preview only
- `hyrule-speedtest` — measurement backend (payload/upload endpoints) not routed

Both carry a NOT YET LAUNCHED banner. Publish only once the backends ship and
the endpoints are re-advertised in `/.well-known/x402.json`.

## Keeping skills honest

A skill must never document an endpoint that 501s or is absent from the
manifest. When an endpoint changes, update the skill in the same PR —
`tests/test_network_intel_contracts.py` guards the manifest side.
