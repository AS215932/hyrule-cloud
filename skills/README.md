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
7. `hyrule-port-reachability`
8. `hyrule-nat-cgnat`
9. `hyrule-voip-sip` — SIP/`/v1/voip/check` only (the number-lookup section is
   already stripped from the source SKILL.md until a number-intel provider ships)
10. `hyrule-mail-deliverability`
11. `hyrule-agent-mail` — only after the dedicated Stalwart canary and legal/
    abuse launch gates pass
12. `hyrule-customer-journeys` — only after all three redacted production
    canaries have been captured

## Withheld — do NOT publish

- `hyrule-routing-path` — `/v1/path/*` returns 501 until an active-probe vantage
  (Globalping/RIPE Atlas) is configured; only a "probe accepted" contract today
- `hyrule-threat-reputation` — `/v1/threat/lookup` returns 501 until a licensed
  reputation source is configured; the lookup service makes no external calls today
- `hyrule-agentic-support` — the umbrella cross-references not-yet-launched flows
  (`/v1/path/report`, `/v1/threat/lookup`, `/v1/mx` reports); publish it only once
  those subskills ship, so it never points agents at a 501 route

These carry a NOT YET LAUNCHED banner. Publish only once the backends ship and
the endpoints are re-advertised in `/.well-known/x402.json`.

Agent Mail and the customer-journey umbrella are likewise withheld until their
explicit readiness conditions above pass; checked-in Skills are launch assets,
not evidence that a gated service is already live.

## Keeping skills honest

A skill must never document an endpoint that 501s or is absent from the
manifest. When an endpoint changes, update the skill in the same PR —
`tests/test_network_intel_contracts.py` guards the manifest side.
