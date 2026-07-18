# Hyrule Cloud OpenClaw Skills

One directory per ClawHub slug, each containing a `SKILL.md` with
`name`/`description` frontmatter. These are the agent-facing API references
published to the [ClawHub](https://clawhub.ai) skill registry.

## Publishing

```bash
npm i -g clawhub
clawhub login   # GitHub account must be ≥ 1 week old

# Dry-run one skill, then publish it
clawhub skill publish ./skills/hyrule-cloud \
  --slug hyrule-cloud \
  --name "Hyrule Cloud" \
  --changelog "Initial public release" \
  --dry-run
clawhub skill publish ./skills/hyrule-cloud \
  --slug hyrule-cloud \
  --name "Hyrule Cloud" \
  --changelog "Initial public release"
```

The CLI starts a new skill at `1.0.0` and increments later releases unless an
explicit `--version` is supplied. Publishing is an operator action: always use
`--dry-run`, verify the referenced routes are present in the live paid
manifest, and then publish the umbrella before focused skills so references
resolve.

1. `hyrule-cloud` (compute, domains/DNS, network evidence, proxy umbrella)
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

The same public repository is the skills.sh distribution source; there is no
separate upload workflow:

```bash
npx skills add AS215932/hyrule-cloud --list
npx skills add AS215932/hyrule-cloud --skill hyrule-cloud
```

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

## Keeping skills honest

A skill must never document an endpoint that 501s or is absent from the
manifest. When an endpoint changes, update the skill in the same PR —
`tests/test_network_intel_contracts.py` guards the manifest side and
`tests/test_skills_distribution.py` guards portable metadata and x402 v2
terminology.
