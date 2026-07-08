# x402 Launch Runbook

Operator steps to take Hyrule Cloud's paid services live and announce them to
agents. Code phases live in PRs #34 (customer IPv6), #35 (hygiene), #36
(payment-stack prep), #37 (payments ledger + /metrics), #38 (launch proof +
Bazaar discovery); infra in network-operations#371.

**The one rule: nothing is announced (Phase 5) until the live paid VM canary
(Phase 3d) has passed on production.**

Production state at time of writing (2026-07-08):
- `cloud.hyrule.host` pinned to `0f041d8` (current main before this stack)
- Facilitator: Vault-kv `payment_facilitator_url`, default payai
- `HCP_LAUNCH_PROOF_REAL_XCPNG` defaults to `1` in the env template
- No live paid canary has ever run — the 2026-07-01 validation stopped at
  dry-run

---

## Phase 1 — Deploy the stack, then switch facilitator to CDP

### Operator-only prerequisites

1. **CDP API key**: create an ES256 secret API key in the Coinbase Developer
   Platform (KYB'd account). Then:
   ```
   vault kv patch kv/hyrule-cloud cdp_api_key_id=<id> cdp_api_key_secret=<pem>
   ```
2. **Confirm no dev bypass in prod kv** (template defaults empty — check the
   kv, not the template):
   ```
   vault kv get -field=dev_bypass_secret kv/hyrule-cloud   # must be absent/empty
   ```
3. **Fund the canary wallet**: ~$5 USDC + gas on Base mainnet, operator-held.
4. **Metrics token** (for Phase 2):
   ```
   vault kv patch kv/hyrule-cloud metrics_token=$(openssl rand -hex 32)
   ```
   Write the same token to `/etc/prometheus/hyrule-cloud-metrics.token` on mon
   (mode 0600, owner prometheus).

### Deploy (still on payai)

1. Merge the hyrule-cloud PR stack (#34→#38) and network-operations#371.
2. **Snapshot Postgres on the api VM** — `ExecStartPre` applies migration 013:
   ```
   sudo -u postgres pg_dump hyrule > /var/backups/hyrule-pre-013.sql
   ```
3. Promote: bump `hyrule_cloud_version` in
   `network-operations/ansible/inventory/host_vars/api.yml` to the new main
   SHA (the promotion PR flow does this), run
   `ansible-playbook playbooks/cloud.yml --tags apply -e hyrule_cloud_apply=true --limit api`.
4. Smoke: `curl -s https://cloud.hyrule.host/health`;
   `curl -s https://cloud.hyrule.host/.well-known/x402.json | jq '.resources | length'`
   (mail/speedtest/web-reports gone, `discoverable` flags present).

### Live canary #1 — payai (first-ever real spend)

Cheapest endpoint, $0.001:

```bash
# 1. Expect 402 with PAYMENT-REQUIRED + X-PAYMENT-REQUIRED headers
curl -si -X POST https://cloud.hyrule.host/v1/dns/lookup \
  -H 'Content-Type: application/json' -d '{"name":"example.com","type":"AAAA"}'

# 2. Pay with any x402 v2 client (or hyrule_cloud.client) using the canary
#    wallet; expect 200 + PAYMENT-RESPONSE header.
```

Verify: tx hash on basescan paying `payment_wallet`; `payment_settled` event
in Loki (Grafana Explore, `{service="hyrule-cloud"}`); a `settled` row in
`payment_events`.

### Switch to CDP

1. `vault kv patch kv/hyrule-cloud payment_facilitator_url=https://api.cdp.coinbase.com/platform/v2/x402`
   (confirm the exact base path first with the authed probe below).
2. Pre-flight from the api VM (uses the same JWT path as the server):
   ```
   PYTHONPATH=/opt/hyrule-cloud .venv/bin/python scripts/verify_facilitator.py
   ```
   Must print `OK eip155:8453` (mainnet alias allowed, testnet not).
3. Restart `hyrule-cloud` (vault-agent re-renders `.env` first).
4. **Live canary #2** — repeat the dns/lookup canary through CDP.

**Rollback**: `vault kv patch kv/hyrule-cloud payment_facilitator_url=https://facilitator.payai.network`
+ restart. No Ansible run needed. (Losing CDP loses Bazaar indexing, not
revenue.)

## Phase 2 — Observability online

1. Deploy network-operations#371 to mon (prometheus.yml job + rules;
   `promtool check rules /etc/prometheus/rules.d/hyrule-payments.yml`).
2. Import `configs/mon/grafana-dashboards/hyrule-payments.json` in Grafana
   (map the Prometheus + Loki datasources).
3. Gate: the Phase 1 canaries are visible — settlements panel shows 2 events,
   revenue shows ~$0.002, unique payers = 1, `up{job="hyrule-cloud"} == 1`.

## Phase 3 — Service-by-service live canaries (paid, small)

### 3a Network-intel (no code changes)

One paid call each; response must contain substantive real data:
`/v1/dns/lookup`, `/v1/ip/lookup`, `/v1/bgp/lookup`, `/v1/rdap/lookup`,
`/v1/whois/lookup`, `/v1/web/check`, `/v1/web/tls/deep`, `/v1/mx/check`,
`/v1/path/ping`, `/v1/path/report`, `/v1/ports/check`, `/v1/nat/lookup`,
`/v1/voip/check`, **`/v1/threat/lookup`** (inspect quality — its service
makes no external calls; if stub-grade, pull it from the manifest +
discovery.py and skip its skill).

### 3b Network proxy

1. On netproxy: `systemctl status hyrule-network-proxy`; token match between
   Vault kv `network_proxy_token` and the sidecar env.
2. Gate: paid `POST /v1/network/request` with `proxy_mode=direct` ($0.01) and
   `proxy_mode=tor` ($0.05) both return real fetched content.

### 3c Domains + DNS zones

1. Vault kv: `openprovider_username/password/*_handle` non-empty; Openprovider
   account has balance.
2. Gate: live paid registration of one cheap real TLD via
   `POST /v1/domain/register` → `POST /v1/zone/record` (AAAA) → public
   `dig AAAA <name>` resolves → `payment_events` row + Grafana movement.

### 3d VM hosting — the big gate

1. Verify Vault kv against live XO: `sr_uuid`, `vm_network_uuid`,
   `xcpng_templates` (debian-13 UUID); customer L2 exists and
   `2a0c:b641:b51::/48` routes to it.
2. Confirm env: `HCP_LAUNCH_PROOF_REAL_XCPNG=1`,
   `HYRULE_REQUIRE_REAL_PROVISIONING=1` (app refuses to boot otherwise),
   `HYRULE_MAX_PAID_ACTIVE_VMS=10` (soft-launch cap; raise stepwise
   10→25→… while provisioning success stays >95%).
3. **Gate**:
   - `POST /v1/vm/quote` (xs, 1 day = $0.05) → pay via x402/CDP
   - poll `GET /v1/vm/{id}/status` until `launch_proof_status=provisioned`
     with `ssh_smoke_status=passed` and `dns_aaaa_verified=true` (now
     measured, not inferred)
   - **manually `ssh root@<hostname>` over IPv6**
   - `DELETE /v1/vm/{id}` and confirm destroy
   - ledger + Grafana provisioning panels moved
4. **Failure drill**: provision one VM against a deliberately broken template
   size; confirm `launch_proof_status=failed`, sanitized `customer_message`,
   and alert `HyruleVMProvisionFailureRatio` behavior.

### Refunds (manual until automated)

The FAILED customer message promises a refund. Keep it:
`payment_events` gives payer wallet + amount + tx hash — send USDC back from
the receiver wallet the same day. The Grafana provisioning panel and the
`HyrulePaymentSettlementFailures` / provision-failure alerts are the worklist.

## Phase 4 — Bazaar indexing

1. After the CDP switch + PR #38 deploy: run one paid canary per flagship
   endpoint (`/v1/vm/create` via quote flow, `/v1/domain/register`,
   `/v1/network/request`, `/v1/dns/lookup`, `/v1/web/check`, `/v1/mx/check`)
   so CDP indexes them at settlement.
2. Verify after ~6h (ranking recomputes on that cadence):
   ```
   curl -s -H "Authorization: Bearer <cdp-jwt>" \
     "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources?limit=100" \
     | grep cloud.hyrule.host
   ```
3. Known flake: x402-foundation/x402#2112 (CDP occasionally fails to index).
   If absent after 24h and two re-seeds, comment on that issue and proceed —
   Phase 5 does not depend on Bazaar.

## Phase 5 — Announce (only after 3d passed)

1. **x402scan**: submit `https://cloud.hyrule.host/.well-known/x402.json` at
   <https://www.x402scan.com/resources/register>; verify the listing.
2. **x402-list.com** submit flow; then Agentic.Market and
   app.ampersend.ai/discover.
3. **ClawHub skills**: follow `skills/README.md` (13 publishable slugs in
   order; `hyrule-mail` + `hyrule-speedtest` withheld; dry-run first).
4. **GitHub org README** (github.com/AS215932 profile — the manifest
   `contact` target): add service list, manifest URL, golden-path curl,
   ClawHub links, pricing table.
5. **llms.txt** on hyrule.host: network-intel + proxy golden paths and skill
   links (hyrule-web change), deployed via its own promotion pin.

## Success criteria

Watch the Grafana "Hyrule Cloud — x402 Payments" dashboard: settlements from
wallets that are not the canary wallet, unique payers climbing, revenue by
service group, provisioning success >95%, zero `dev_bypass` events (the
tripwire alert must never fire in production).
