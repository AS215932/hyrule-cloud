# Hyrule Cloud — Agentic VPS Hosting

Deploy bare VMs, register domains, and manage DNS zones — all paid via x402 (USDC on Base).

## When to Use

Use this skill when:
- You need to deploy an application to the internet (provision a VM, SSH in, set it up)
- You need to register a domain name
- You need to buy a DNS zone and manage records (AAAA, A, CNAME, TXT, MX, etc.)
- You need to check pricing or domain availability

## API Base

```
https://cloud.hyrule.host
```

Service discovery: `GET /.well-known/x402.json`

## Payment

All paid endpoints use the **x402** protocol (v2):
1. Send the request without payment → get a `402` response with pricing + payment instructions
2. Pay via the x402 facilitator on a verified chain — see `GET /v1/payments/networks`
3. Resend the request with the `X-PAYMENT` header containing the payment proof

Supported chains (mainnet, USDC):
- **EVM** — Base, Polygon, Arbitrum (always on). Sign EIP-3009 `TransferWithAuthorization`.
- **Solana** — opt-in via `PAYMENT_ENABLE_SVM=true`. Sign an SPL `transferChecked` transaction.

Each `accepts` entry in the 402 body carries `family` (`evm` or `svm`) so the client can pick the right signing flow without parsing CAIP-2 by hand. The 402 response body also includes `cost_breakdown`, `specs`, and the facilitator URL.

### Solana payment flow (Block H)

1. Detect a Solana wallet (Phantom / Solflare / Backpack via `window.solana.isPhantom`, `window.solflare`, `window.backpack`).
2. POST the order → receive 402. The matching `accepts` entry has `family: "svm"`, `token_address` (USDC mint), and `pay_to` (recipient pubkey).
3. Build an SPL `transferChecked` instruction (payer ATA → recipient ATA, mint = USDC, amount = `price * 10**token_decimals`). Use `getAssociatedTokenAddress` for both sides.
4. Wallet signs the transaction (`wallet.signTransaction(tx)` — NOT `signAndSendTransaction`; the facilitator submits).
5. POST again with `X-PAYMENT: base64(json({x402Version:2, scheme:"exact", network:caip2, payload:{transaction:<base64-signed-tx>}, accepted:<requirements>}))`.

The browser dispatcher (`payment.js`) lazy-loads `@solana/web3.js` + `@solana/spl-token` from a CDN only when the Solana tab is selected, so EVM-only checkouts pay zero bundle cost. Python agents using the x402 SDK can drive Solana via `x402.mechanisms.svm.exact.client.ExactSvmScheme` directly.

## Authentication

There are three authentication paths. Pick the one that matches your context:

1. **Anonymous + management token** — anyone can `POST /v1/vm/create` with no account. The response includes a one-time `management_token` (`hyr_vm_<...>`). Save it; it is the **only** way to reboot/extend/destroy that VM later. Present as `Authorization: Bearer hyr_vm_<...>` or `?token=hyr_vm_<...>`.
2. **Browser session** — `POST /v1/auth/register` returns an `account_id` (`H<10 hex>`) and a recovery code. Save the recovery code; it is the only way to reset the password. Subsequent calls use the `hyr_sess` cookie.
3. **Scoped API key (Block D, for agents)** — `POST /v1/me/api-keys` (from a logged-in session) mints a `hyr_sk_<32 base62>` bearer revealed exactly **once**. Present as `Authorization: Bearer hyr_sk_<...>`. For MCP-only agents who can't run a browser: `POST /v1/auth/register` accepts `{"with_api_key": true, "api_key_name": "..."}` and returns a starter key with `DEFAULT_API_KEY_SCOPES` alongside the account_id + recovery_code — the agent-bootstrap path.

### Scope vocabulary

Keys carry an explicit, non-wildcard scope set:

| Scope             | Permits                                          |
|-------------------|--------------------------------------------------|
| `vm:read`         | list / status / details on owned VMs             |
| `vm:power`        | reboot                                           |
| `vm:extend`       | pay-to-extend (still requires x402)              |
| `vm:destroy`      | delete                                           |
| `vm:logs`         | provisioning + system logs                       |
| `vm:create`       | create new VMs (still requires x402)             |
| `api_keys:read`   | list own keys                                    |
| `api_keys:write`  | create / revoke keys (subject to no-escalation)  |
| `account:read`    | `GET /v1/me`                                     |

Default at creation if `scopes` is omitted: `vm:read`, `vm:power`, `vm:extend`, `vm:logs`, `account:read`. Anything else is opt-in.

### x402 + API key interaction model

- **Sessions are unrestricted.** A logged-in browser can do anything the account can do — scopes apply only to API keys.
- **An API key proves "this VM is yours."** It does NOT pay for anything.
- **x402 proves "you paid for this action."** It does NOT prove identity.
- Free actions over an API key (read, reboot, logs) need ONLY the key.
- Paid actions over an API key (`vm:create`, `vm:extend`) need BOTH the key (for the scope check) AND an `X-PAYMENT` header (for settlement).

### Forbidden via API key (browser session only)

A leaked agent key must never destroy the account it belongs to. These endpoints reject API keys with `403` regardless of scope:

- `POST /v1/me/password`
- `POST /v1/me/recovery-code`
- `DELETE /v1/me?vm_policy=...`

### No-escalation rule

A key holding `api_keys:write` cannot mint a child key with scopes the parent does not itself hold. (Browser sessions bypass this.) An agent that needs `vm:destroy` must be issued a key with `vm:destroy` by a session-authenticated user — it cannot self-elevate.

## Python Client

```python
from hyrule_cloud.client import HyruleClient

async with HyruleClient("https://cloud.hyrule.host") as hc:
    result = await hc.create_vm(duration_days=7, size="sm", ssh_pubkey="ssh-ed25519 ...")
```

Install: `pip install hyrule-cloud`

## Endpoints

### Free Endpoints

#### GET /v1/pricing
Returns current prices for all resources.

```json
{
  "vm_prices": {
    "xs (1vCPU/512MB/10GB)": "$0.05/day",
    "sm (1vCPU/1GB/20GB)": "$0.10/day",
    "md (2vCPU/2GB/40GB)": "$0.20/day",
    "lg (4vCPU/4GB/80GB)": "$0.40/day"
  },
  "domain_auto": "$0.00 (subdomain under deploy.hyrule.host)",
  "vpn_per_day": "$0.02/day",
  "currency": "USDC",
  "network": "Base (eip155:8453)"
}
```

#### GET /v1/os/list
Lists available OS templates.

```json
{
  "templates": [
    {"name": "debian-13", "description": "Debian 13 (Trixie)", "default": true},
    {"name": "alpine-3.21", "description": "Alpine Linux 3.21"},
    {"name": "freebsd-14", "description": "FreeBSD 14.2"}
  ]
}
```

#### GET /v1/vm/{vm_id}/status
**Public sanitized status.** Anon-owned VMs are visible by `vm_id` alone (preserves the one-shot anon checkout UX). Account-owned VMs require the owning account or admin — to a non-owner the response is indistinguishable from a missing VM (404).

```json
{
  "vm_id": "vm_a1b2c3d4e5f6...",
  "status": "ready",
  "os": "debian-13",
  "ipv6": "2001:db8::1",
  "hostname": "ab12cd34.deploy.hyrule.host",
  "ssh": "ssh root@ab12cd34.deploy.hyrule.host",
  "expires_at": "2026-04-08T00:00:00Z"
}
```

#### GET /v1/vm/{vm_id}
**Full detail, management-gated.** Anon VMs require the `hyr_vm_<...>` token; account-owned VMs require the matching session or API key (scope `vm:read`). Returns the same fields as `/status` plus `ssh_pubkey`, `firewall`, `cost_total`, `owner_wallet`, and `payment_tx`. Legacy short `vm_<12 hex>` VMs without a token are management-disabled until claimed.

Status values: `provisioning` → `ready` → `running` → `suspended` → `destroyed` (or `failed`)

#### GET /v1/domain/check?name=example&extension=com
Check domain availability.

```json
{"status": "free", "is_premium": false, "price": "9.99", "currency": "USD"}
```

#### GET /v1/zone/check?name=example&extension=dev
Check DNS zone availability and price.

### Paid Endpoints

#### POST /v1/vm/create
Provision a bare VM with SSH access. Returns 202 with a status URL to poll.

**Request:**
```json
{
  "duration_days": 7,
  "size": "sm",
  "os": "debian-13",
  "ssh_pubkey": "ssh-ed25519 AAAA...",
  "domain_mode": "auto",
  "open_ports": [80, 443],
  "setup_script": "apt-get update && apt-get install -y nginx"
}
```

**Response (202):**
```json
{
  "vm_id": "vm_a1b2c3d4e5f6",
  "status": "provisioning",
  "status_url": "https://cloud.hyrule.host/v1/vm/vm_a1b2c3d4e5f6",
  "estimated_ready_seconds": 60
}
```

**Sizes:** `xs` (1vCPU/512MB/10GB), `sm` (1vCPU/1GB/20GB), `md` (2vCPU/2GB/40GB), `lg` (4vCPU/4GB/80GB)

**Domain modes:**
- `auto` — free subdomain `<hash>.deploy.hyrule.host` (default)
- `custom` — requires `domain` field, registers via Openprovider (extra cost)

**Workflow:**
1. POST /v1/vm/create → 402 (get price) → pay → POST again with X-PAYMENT → 202
2. Poll GET /v1/vm/{id} until `status` is `ready`
3. SSH in: `ssh root@<hostname>`
4. The VM is yours — install whatever you need

#### POST /v1/vm/{vm_id}/extend
Add days to a running VM.

```json
{"days": 30}
```

#### POST /v1/domain/register
Register a domain via Openprovider.

```json
{"name": "mysite", "extension": "dev", "ipv6": "2001:db8::1"}
```

#### POST /v1/zone/buy
Buy a DNS zone — registers the domain and sets up Hyrule Cloud's authoritative DNS.

```json
{"name": "mysite", "extension": "dev"}
```

Response includes the nameservers to use. After buying, manage records via:

#### POST /v1/zone/record
Create a DNS record in a zone you own.

```json
{"zone": "mysite.dev", "name": "www", "type": "AAAA", "value": "2001:db8::1", "ttl": 300}
```

#### DELETE /v1/zone/record?zone=mysite.dev&name=www&type=AAAA
Delete a DNS record.

### Management Endpoints (Free)

All require either the anon management token, a session cookie, OR an API key with the corresponding scope (`vm:power`, `vm:destroy`, `vm:logs`).

#### POST /v1/vm/{vm_id}/reboot
Hard reboot a VM. Scope: `vm:power`.

#### DELETE /v1/vm/{vm_id}
Destroy a VM permanently. Scope: `vm:destroy`.

#### GET /v1/vm/{vm_id}/logs
Get provisioning log for a VM. Scope: `vm:logs`.

### Account & API Key Endpoints (Block D)

#### GET /v1/me
Profile. Scope: `account:read` (or any session).

#### GET /v1/me/vms
List VMs owned by the calling account. Scope: `vm:read`.

#### GET /v1/me/api-keys
List the caller's keys. Cleartext bearers are never returned. Scope: `api_keys:read`.

#### POST /v1/me/api-keys
Mint a new key. Scope: `api_keys:write`. The response contains `key` — **save it**, it is the only chance.

```json
{"name": "deploy-agent", "scopes": ["vm:read", "vm:power", "vm:logs"], "expires_at": null}
```

```json
{
  "key_id": "uuid",
  "key": "hyr_sk_<32 base62>",
  "name": "deploy-agent",
  "scopes": ["vm:read", "vm:power", "vm:logs"],
  "created_at": "...",
  "expires_at": null,
  "message": "This is the only time the key will be shown..."
}
```

#### DELETE /v1/me/api-keys/{key_id}
Hard-delete a key. Scope: `api_keys:write`. A key cannot revoke itself (returns 403) — use a session or another key.

#### POST /v1/me/vms/{vm_id}/claim
Attach an anon VM to the calling account. Body is one of:

- `{"proof": "management_token", "token": "hyr_vm_..."}` — the token from the original order response
- `{"proof": "wallet_signature", "challenge": "...vm_id...", "signature": "0x..."}` — EIP-191 sig from the wallet that paid (challenge MUST contain the `vm_id`)
- `{"proof": "ssh_signature", "challenge": "...vm_id...", "signature_armor": "..."}` — output of `ssh-keygen -Y sign -n hyrule-claim -f key < challenge`. Public-key match alone is NOT accepted.

After claim, the anon token is burned; account auth supersedes.

### Password Recovery (Block A1 + F)

Two paths, both reset the password and revoke all live sessions on success.

#### POST /v1/auth/recover/code
Reset using the recovery code shown at registration.

```json
{"account_id": "H...", "recovery_code": "...", "new_password": "..."}
```

Single-use; a fresh code is auto-issued and returned in the response.

#### POST /v1/auth/recover/wallet/challenge
Issue a single-use, time-bound (5 min) challenge bound to the calling account.

```json
{"account_id": "H..."}
```

Response:

```json
{
  "nonce": "...",
  "challenge_text": "Recover Hyrule account H...\nOrigin: https://hyrule.host\nNonce: ...\nIssued: ...\nExpires: ...",
  "expires_at": "..."
}
```

The endpoint always returns a challenge — even for unknown account IDs — so it cannot be used to enumerate accounts.

#### POST /v1/auth/recover/wallet/verify
Sign `challenge_text` verbatim with `personal_sign` / EIP-191 from a wallet that paid for at least one VM owned by this account. Submit the signature to reset the password.

```json
{"nonce": "...", "signature": "0x...", "new_password": "..."}
```

The signer must match `owner_wallet` on some VM whose `owner_account_id` is this account. Accounts with no payment history (no VMs paid via x402 EVM) **cannot** use this path — they must use the recovery code. On success, all live sessions are revoked.

## MCP Crypto Payment Tools (Block H)

For BTC / XMR — agents that prefer paying with native crypto over x402 USDC:

- **`list_payment_networks()`** — lists currently-enabled x402 networks with `family` (`evm`/`svm`), CAIP-2, USDC mint, decimals. The agent uses `family` to pick the right signing flow; don't hardcode the network list.
- **`create_crypto_intent(asset, amount_usd, order_payload, client_order_id=None)`** — opens a BTC or XMR intent. Returns the deposit address, exact crypto amount, rate snapshot expiry, and a wallet URI (`bitcoin:...` / `monero:...`). Pass a stable `client_order_id` for idempotent retries.
- **`get_intent_status(intent_id)`** — polls a crypto intent. Status walk: `CREATED → WAITING_PAYMENT → SETTLED → PROVISIONING → PROVISIONED`. Off-amount edge cases land in `UNDERPAID` / `OVERPAID` / `LATE_PAID` / `REFUND_MANUAL` per the LENIENT policy. On `PROVISIONED` the response includes `vm_id` + `management_token` (save the token once — it's the only way to manage the VM later unless the intent was placed by a logged-in account).

Canonical agent loop:
```
nets   = list_payment_networks()                # discover surface, pick asset
intent = create_crypto_intent(asset="BTC", amount_usd="0.40",
                              order_payload={"size":"xs","duration_days":7,"ssh_pubkey":"..."},
                              client_order_id="<your-uuid>")
# … customer pays the deposit address …
loop:
  s = get_intent_status(intent.intent_id)
  if s.status == "PROVISIONED":
      vm = vm_status(s.vm_id)                   # use the existing VM tool
      break
  sleep(15)
```

## Typical Agent Workflow

**Anonymous (one-shot):**
```
1. GET /v1/pricing                          # check prices
2. POST /v1/vm/create                       # → 402 with price
3. Pay via x402 facilitator                 # USDC on Base/Polygon/Arbitrum/Solana (if SVM enabled)
4. POST /v1/vm/create + X-PAYMENT header    # → 202 + status_url + management_token (SAVE IT)
5. Poll GET /v1/vm/{id}/status              # wait for "ready" (public, no token)
6. ssh root@<hostname>                      # deploy your app
7. For reboot/extend/destroy: present       # Authorization: Bearer hyr_vm_<...>
   the saved management_token
```

**With a scoped API key (persistent agent — MCP bootstrap):**
```
1. register_account(password=..., with_api_key=True)
   → returns account_id, recovery_code, api_key (DEFAULT_API_KEY_SCOPES:
     account:read, vm:read, vm:power, vm:extend, vm:logs)
   → SAVE recovery_code AND api_key — neither is recoverable
2. Configure HYRULE_API_KEY=<api_key> in your MCP client env
   (or send Authorization: Bearer hyr_sk_<...> on HTTP calls)
3. All subsequent requests are authenticated as your account.
4. Paid actions also include X-PAYMENT (the key proves identity,
   x402 settles payment).
5. Need broader scopes (vm:create / vm:destroy / api_keys:*)? Mint a
   second key from a browser session — `with_api_key` only issues the
   default scope set, and key holders cannot escalate beyond their own
   scopes (see No-escalation rule).
```

**With a scoped API key (persistent agent — browser bootstrap):**
```
1. (one-time, via browser) POST /v1/auth/register, then POST /v1/me/api-keys
   with scopes=["vm:read","vm:power","vm:extend","vm:logs","vm:create","account:read"]
   → save the cleartext bearer ONCE
2. All subsequent requests: Authorization: Bearer hyr_sk_<...>
3. Paid actions also include X-PAYMENT (scope proves identity, x402 settles payment)
4. GET /v1/me/vms                           # list your fleet
5. POST /v1/vm/create + Authorization + X-PAYMENT → VM auto-attached to your account
```

## Infrastructure Details

- **Network:** IPv6-only (NAT64/DNS64 for IPv4 destinations). All VMs get a public IPv6 address.
- **DNS:** Auto subdomains under `deploy.hyrule.host`. Custom domains via Openprovider with Hyrule Cloud nameservers.
- **Firewall:** Cloud-init sets UFW defaults (deny all inbound except 22/80/443, block outbound SMTP). Modify via SSH after boot.
- **Expiry:** Prepaid model. VMs suspended at expiry, destroyed after 48h grace period. Extend with `/v1/vm/{id}/extend`.
- **ASN:** AS215932 (RIPE)
