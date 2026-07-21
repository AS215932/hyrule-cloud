# Hyrule Cloud buyer MCP

<!-- mcp-name: io.github.AS215932/hyrule-cloud -->

This stdio MCP server lets an agent discover Hyrule Cloud's live x402 catalog
and buy launch-ready diagnostic operations. It uses the official x402 v2
client while keeping authorization outside the model:

- exact `https://cloud.hyrule.host` origin and live-manifest path checks;
- diagnostic capabilities only by default;
- a hard per-payment maximum;
- a durable SQLite daily reservation ledger;
- an optional exact capability allowlist;
- private keys read only from the process environment.

VM creation and generic network proxying are denied by default. Enabling an
infrastructure purchase requires both
`HYRULE_MCP_ALLOW_INFRASTRUCTURE=1` and an exact entry in
`HYRULE_MCP_CAPABILITIES`.

## Run

After the package is published:

```bash
EVM_PRIVATE_KEY='0x...' \
HYRULE_MCP_MAX_PAYMENT_USD=0.10 \
HYRULE_MCP_DAILY_BUDGET_USD=1.00 \
uvx hyrule-cloud-mcp
```

For local repository development:

```bash
uv run --project packages/hyrule-cloud-mcp hyrule-cloud-mcp
```

The server exposes:

- `discover_hyrule` — reads and filters the live paid manifest, including each
  request schema and example, without paying;
- `call_hyrule` — resolves a stable capability ID from that manifest, then
  automatically handles the x402 v2 challenge and paid retry;
- `follow_hyrule` — polls a same-origin job/VM status URL or retrieves a job
  artifact through a narrow, non-paying allowlist.

Never place the private key in MCP arguments, prompts, checked-in config, or
logs. Use the MCP client's secret environment configuration.

## Operator configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `EVM_PRIVATE_KEY` | unset | Required only for a paid call. |
| `HYRULE_MCP_BASE_URL` | `https://cloud.hyrule.host` | Exact allowed API origin. |
| `HYRULE_MCP_MAX_PAYMENT_USD` | `0.10` | Maximum one x402 payment. |
| `HYRULE_MCP_DAILY_BUDGET_USD` | `1.00` | UTC-day aggregate reservation cap. |
| `HYRULE_MCP_LEDGER_PATH` | platform state directory | Durable SQLite spend ledger. |
| `HYRULE_MCP_CAPABILITIES` | safe diagnostics | Optional comma-separated exact capability IDs. |
| `HYRULE_MCP_ALLOW_INFRASTRUCTURE` | `0` | Second opt-in required for VM/proxy purchases. |
| `HYRULE_MCP_PREFERRED_NETWORK` | `eip155:8453` | Preferred x402 EVM network. |
| `HYRULE_MCP_MAX_RESPONSE_BYTES` | `524288` | Maximum streamed result size; snapshot purchases are preflighted against it. |

Reservations are intentionally conservative: a payment amount is counted
before signing, so a failed retry can reduce the remaining daily budget but
can never cause an over-spend.
