"""
MCP server for Hyrule Cloud.

Exposes Hyrule Cloud operations as MCP tools for Claude, Cursor, and other
MCP-compatible clients.

Run standalone:
    python -m hyrule_cloud.mcp_server

Or use as an MCP server config:
    {
        "mcpServers": {
            "hyrule-cloud": {
                "command": "python",
                "args": ["-m", "hyrule_cloud.mcp_server"],
                "env": {
                    "HYRULE_API_URL": "https://cloud.hyrule.host",
                    "HYRULE_DEV_BYPASS": ""
                }
            }
        }
    }
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from hyrule_cloud.client import HyruleClient, HyruleError

mcp = FastMCP(
    "Hyrule Cloud",
    instructions=(
        "Agentic VPS hosting on AS215932. Deploy bare VMs with SSH access, "
        "register domains, and manage DNS zones. Payment via x402 (USDC on Base)."
    ),
)

_api_url = os.environ.get("HYRULE_API_URL", "https://cloud.hyrule.host")
_dev_bypass = os.environ.get("HYRULE_DEV_BYPASS", "")
# Block D: a scoped bearer (hyr_sk_<...>). If set, every request authenticates
# as the owning account. Free reads are auth-only; paid actions still require
# an x402 payment header on top.
_api_key = os.environ.get("HYRULE_API_KEY", "")


def _client() -> HyruleClient:
    return HyruleClient(
        _api_url,
        dev_bypass=_dev_bypass or None,
        api_key=_api_key or None,
    )


def _err(e: HyruleError) -> str:
    if e.status_code == 402:
        return (
            f"Payment required. The API returned a 402 response with payment instructions:\n"
            f"{e.detail}\n\n"
            f"To complete this action, pay via the x402 facilitator (USDC on Base) "
            f"and retry with the payment proof."
        )
    return f"Error {e.status_code}: {e.detail}"


# --- Resource: Service Info ---


@mcp.resource("hyrule://pricing")
async def pricing_resource() -> str:
    """Current Hyrule Cloud pricing for VMs, domains, and VPN."""
    async with _client() as hc:
        data = await hc.pricing()
    lines = ["# Hyrule Cloud Pricing", ""]
    for size, price in data.get("vm_prices", {}).items():
        lines.append(f"- **{size}**: {price}")
    lines.append(f"- **Auto subdomain**: {data.get('domain_auto', 'free')}")
    lines.append(f"- **VPN**: {data.get('vpn_per_day', 'N/A')}")
    lines.append(f"\nCurrency: {data.get('currency', 'USDC')} on {data.get('network', 'Base')}")
    return "\n".join(lines)


@mcp.resource("hyrule://os-templates")
async def os_templates_resource() -> str:
    """Available OS templates for VM provisioning."""
    async with _client() as hc:
        data = await hc.os_list()
    lines = ["# Available OS Templates", ""]
    for t in data.get("templates", []):
        default = " (default)" if t.get("default") else ""
        lines.append(f"- **{t['name']}**: {t['description']}{default}")
    return "\n".join(lines)


# --- Tools: VM Lifecycle ---


@mcp.tool()
async def get_pricing() -> str:
    """Get current Hyrule Cloud pricing for VMs, domains, and DNS zones."""
    try:
        async with _client() as hc:
            return str(await hc.pricing())
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def list_os_templates() -> str:
    """List available OS templates (Debian, Alpine, FreeBSD, etc.)."""
    try:
        async with _client() as hc:
            return str(await hc.os_list())
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def create_vm(
    duration_days: int,
    ssh_pubkey: str,
    size: str = "xs",
    os: str = "debian-13",
    domain_mode: str = "auto",
    domain: str | None = None,
    open_ports: str = "80,443",
    setup_script: str | None = None,
) -> str:
    """
    Provision a bare VM with SSH access.

    Sizes: xs (1vCPU/512MB/10GB), sm (1vCPU/1GB/20GB), md (2vCPU/2GB/40GB), lg (4vCPU/4GB/80GB).
    Domain modes: 'auto' (free subdomain), 'custom' (register domain, extra cost).
    Returns 402 with payment instructions if no payment is attached.
    """
    ports = [int(p.strip()) for p in open_ports.split(",") if p.strip()]
    try:
        async with _client() as hc:
            result = await hc.create_vm(
                duration_days=duration_days,
                ssh_pubkey=ssh_pubkey,
                size=size,
                os=os,
                domain_mode=domain_mode,
                domain=domain,
                open_ports=ports,
                setup_script=setup_script,
            )
            return (
                f"VM created!\n"
                f"  ID: {result['vm_id']}\n"
                f"  Status: {result['status']}\n"
                f"  Poll: {result['status_url']}\n"
                f"  ETA: ~{result.get('estimated_ready_seconds', 60)}s"
            )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def vm_status(vm_id: str) -> str:
    """Get VM status: IP address, hostname, SSH command, expiry, firewall state."""
    try:
        async with _client() as hc:
            s = await hc.vm_status(vm_id)
            lines = [
                f"VM: {s['vm_id']}",
                f"Status: {s['status']}",
            ]
            if s.get("ipv6"):
                lines.append(f"IPv6: {s['ipv6']}")
            if s.get("hostname"):
                lines.append(f"Hostname: {s['hostname']}")
            if s.get("ssh"):
                lines.append(f"SSH: {s['ssh']}")
            if s.get("expires_at"):
                lines.append(f"Expires: {s['expires_at']}")
            if s.get("firewall"):
                fw = s["firewall"]
                lines.append(f"Firewall: allow {fw['inbound_allow']}, policy={fw['policy']}")
            if s.get("error"):
                lines.append(f"Error: {s['error']}")
            return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def extend_vm(vm_id: str, days: int) -> str:
    """Add more days to a running VM. Payment required via x402."""
    try:
        async with _client() as hc:
            result = await hc.extend_vm(vm_id, days)
            return (
                f"VM {vm_id} extended.\n"
                f"  New expiry: {result.get('new_expiry', 'unknown')}\n"
                f"  Status: {result.get('status', 'unknown')}"
            )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def reboot_vm(vm_id: str) -> str:
    """Hard reboot a VM."""
    try:
        async with _client() as hc:
            await hc.reboot_vm(vm_id)
            return f"VM {vm_id} is rebooting."
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def destroy_vm(vm_id: str) -> str:
    """Destroy a VM permanently. This cannot be undone."""
    try:
        async with _client() as hc:
            await hc.destroy_vm(vm_id)
            return f"VM {vm_id} destroyed."
    except HyruleError as e:
        return _err(e)


# --- Tools: Domains ---


@mcp.tool()
async def check_domain(name: str, extension: str) -> str:
    """Check if a domain is available for registration and get the price."""
    try:
        async with _client() as hc:
            result = await hc.check_domain(name, extension)
            status = result.get("status", "unknown")
            price = result.get("price", "N/A")
            premium = " (premium)" if result.get("is_premium") else ""
            return f"{name}.{extension}: {status}{premium}, price: ${price}"
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def register_domain(
    name: str,
    extension: str,
    ipv6: str | None = None,
) -> str:
    """
    Register a domain via Openprovider. Payment required via x402.

    Optionally point it at an IPv6 address immediately.
    """
    try:
        async with _client() as hc:
            result = await hc.register_domain(name, extension, ipv6)
            ns = ", ".join(result.get("nameservers", []))
            return (
                f"Domain {result.get('domain', f'{name}.{extension}')} registered!\n"
                f"  Status: {result.get('status', 'registered')}\n"
                f"  Nameservers: {ns}"
            )
    except HyruleError as e:
        return _err(e)


# --- Tools: DNS Zones ---


@mcp.tool()
async def check_zone(name: str, extension: str) -> str:
    """Check DNS zone availability and price before buying."""
    try:
        async with _client() as hc:
            result = await hc.check_zone(name, extension)
            return str(result)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def buy_zone(name: str, extension: str) -> str:
    """
    Buy a DNS zone — registers the domain and sets up authoritative DNS.

    After buying, use create_dns_record to add records to the zone.
    Payment required via x402.
    """
    try:
        async with _client() as hc:
            result = await hc.buy_zone(name, extension)
            ns = ", ".join(result.get("nameservers", []))
            return (
                f"Zone {result.get('zone', f'{name}.{extension}')} created!\n"
                f"  Nameservers: {ns}\n"
                f"  Status: {result.get('status', 'active')}"
            )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def create_dns_record(
    zone: str,
    name: str,
    record_type: str,
    value: str,
    ttl: int = 300,
) -> str:
    """
    Create a DNS record in a zone you own.

    Supported types: AAAA, A, CNAME, TXT, MX, NS, SRV, CAA.
    Example: zone="mysite.dev", name="www", record_type="AAAA", value="2001:db8::1"
    """
    try:
        async with _client() as hc:
            await hc.create_record(zone, name, record_type, value, ttl)
            fqdn = f"{name}.{zone}" if name != "@" else zone
            return f"Record created: {fqdn} {record_type} → {value} (TTL {ttl})"
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def delete_dns_record(zone: str, name: str, record_type: str) -> str:
    """Delete a DNS record from a zone you own."""
    try:
        async with _client() as hc:
            await hc.delete_record(zone, name, record_type)
            fqdn = f"{name}.{zone}" if name != "@" else zone
            return f"Record deleted: {fqdn} {record_type}"
    except HyruleError as e:
        return _err(e)


# --- Tools: Payment surface + crypto intents (Block H) ---


@mcp.tool()
async def list_payment_networks() -> str:
    """List the currently-enabled x402 payment networks.

    Returns one line per network: key, display_name, family ("evm" or "svm"),
    CAIP-2, USDC token address, and decimals. The dispatcher / agent uses
    `family` to pick the right signing flow (EIP-3009 for EVM, signed SPL
    transaction for SVM). Reads the live catalog — never hardcode the chain
    list (feedback_verified_payment_chains.md).
    """
    try:
        async with _client() as hc:
            data = await hc.payment_networks()
        nets = data.get("networks", [])
        if not nets:
            return "No payment networks enabled."
        lines = [f"Receiver: {data.get('receiver_address', '')}"]
        lines.append(f"Facilitator: {data.get('facilitator_url', '')}")
        for n in nets:
            lines.append(
                f"  {n['key']:>12s} ({n.get('family', '?')}) {n['display_name']:<18s} "
                f"caip2={n['caip2']} mint={n['token_address']} dec={n['token_decimals']}"
            )
        return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def create_crypto_intent(
    asset: str,
    amount_usd: str,
    order_payload: dict,
    client_order_id: str | None = None,
) -> str:
    """
    Open a BTC or XMR crypto intent for a VM order.

    asset: "BTC" or "XMR".
    amount_usd: USD price as a decimal string (e.g. "0.40").
    order_payload: the full VM spec the intent will provision when paid (same
        shape as create_vm: {"os", "size", "duration_days", "ssh_pubkey", ...}).
    client_order_id: an opaque idempotency key — sending the same value twice
        returns the existing intent without creating a second deposit address.

    Returns the deposit address, exact crypto amount, rate snapshot expiry,
    and a wallet-compatible URI for QR rendering. Poll with get_intent_status.
    """
    try:
        async with _client() as hc:
            result = await hc.create_crypto_intent(
                asset=asset,
                amount_usd=amount_usd,
                order_payload=order_payload,
                client_order_id=client_order_id,
            )
        lines = [
            f"Intent: {result['intent_id']}",
            f"Asset:  {result['asset']}",
            f"Status: {result['status']}",
            f"Pay:    {result['amount_crypto']} {result['asset']} "
            f"(~${result.get('amount_usd', amount_usd)}) to {result['address']}",
        ]
        if result.get("rate_valid_until"):
            lines.append(f"Rate valid until: {result['rate_valid_until']}")
        if result.get("qr_code_uri"):
            lines.append(f"Wallet URI: {result['qr_code_uri']}")
        return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def get_intent_status(intent_id: str) -> str:
    """
    Poll a previously-created crypto intent.

    Status transitions: CREATED → WAITING_PAYMENT → SETTLED → PROVISIONING →
    PROVISIONED. Off-amount edge cases land in UNDERPAID / OVERPAID / LATE_PAID
    / REFUND_MANUAL per the LENIENT policy (Block E). Once PROVISIONED the
    response carries the resulting `vm_id` + management token.
    """
    try:
        async with _client() as hc:
            s = await hc.get_crypto_intent(intent_id)
        lines = [
            f"Intent: {s['intent_id']}",
            f"Status: {s['status']}",
        ]
        if s.get("confirmations") is not None:
            lines.append(f"Confirmations: {s['confirmations']}")
        if s.get("amount_received_crypto"):
            lines.append(f"Received: {s['amount_received_crypto']} {s.get('asset', '')}")
        if s.get("vm_id"):
            lines.append(f"VM: {s['vm_id']} (use vm_status to poll readiness)")
        if s.get("management_token"):
            lines.append(f"Management token: {s['management_token']} (save once!)")
        return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


# --- Tools: Account & API keys (Block D) ---


@mcp.tool()
async def register_account(
    password: str,
    with_api_key: bool = True,
    api_key_name: str | None = None,
) -> str:
    """Create a Hyrule account. Returns account_id, recovery_code, and (by
    default) a cleartext API key the agent should immediately wire into
    HYRULE_API_KEY for subsequent calls.

    Sessions are HttpOnly browser cookies and intentionally unavailable to
    MCP agents — `with_api_key=True` is the agent bootstrap path. Both the
    recovery_code AND the api_key are revealed exactly ONCE; save them.
    """
    try:
        async with _client() as hc:
            r = await hc.register(
                password,
                with_api_key=with_api_key,
                api_key_name=api_key_name,
            )
            lines = [
                f"Account created: {r['account_id']}",
                "",
                f"Recovery code (save now, one-time reveal): {r['recovery_code']}",
            ]
            if r.get("api_key"):
                lines.extend([
                    "",
                    f"API key (save now, one-time reveal): {r['api_key']}",
                    f"  key_id: {r['api_key_id']}",
                    f"  scopes: {', '.join(r.get('api_key_scopes') or [])}",
                    "",
                    "Set HYRULE_API_KEY=<api_key> in your MCP client env to use it.",
                ])
            else:
                lines.extend([
                    "",
                    "No API key was issued (with_api_key=False). You'll need a",
                    "browser session to mint one via /v1/me/api-keys.",
                ])
            return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def whoami() -> str:
    """Return the calling account's profile (requires HYRULE_API_KEY with account:read)."""
    try:
        async with _client() as hc:
            me = await hc.me()
            return (
                f"Account: {me['account_id']}\n"
                f"  Created: {me['created_at']}\n"
                f"  Last login: {me.get('last_login_at') or 'never'}\n"
                f"  VMs: {me['vm_count']}\n"
                f"  Admin: {me['is_admin']}"
            )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def list_my_vms() -> str:
    """List VMs owned by the calling account (requires HYRULE_API_KEY with vm:read)."""
    try:
        async with _client() as hc:
            data = await hc.my_vms()
            vms = data.get("vms", [])
            if not vms:
                return "No VMs."
            lines = [f"{len(vms)} VM(s):"]
            for v in vms:
                lines.append(
                    f"  - {v['vm_id']} [{v['status']}] {v.get('os', '?')} "
                    f"{v.get('hostname') or ''} expires={v.get('expires_at') or '—'}"
                )
            return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def claim_vm(vm_id: str, management_token: str) -> str:
    """Attach an anon VM to your account using the one-time management token
    from the order response. Requires HYRULE_API_KEY or session login.
    """
    try:
        async with _client() as hc:
            result = await hc.claim_vm_by_token(vm_id, management_token)
            return f"VM {result['vm_id']} claimed by account {result['owner_account_id']}."
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def list_api_keys() -> str:
    """List API keys on the calling account (requires api_keys:read)."""
    try:
        async with _client() as hc:
            data = await hc.list_api_keys()
            keys = data.get("keys", [])
            if not keys:
                return "No API keys."
            lines = [f"{len(keys)} key(s):"]
            for k in keys:
                lines.append(
                    f"  - {k['key_id']} [{k['name']}] scopes={k['scopes']} "
                    f"last_used={k.get('last_used_at') or 'never'} "
                    f"expires={k.get('expires_at') or '—'}"
                )
            return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def create_api_key(
    name: str,
    scopes: str = "vm:read,vm:power,vm:extend,vm:logs,account:read",
    expires_at: str | None = None,
) -> str:
    """Mint a new API key. The cleartext bearer is returned ONCE — save it.

    Scopes are comma-separated. Vocabulary: vm:read, vm:power, vm:extend,
    vm:destroy, vm:logs, vm:create, api_keys:read, api_keys:write, account:read.
    Requires api_keys:write. Cannot grant scopes the calling key does not hold.
    """
    scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
    try:
        async with _client() as hc:
            result = await hc.create_api_key(
                name=name, scopes=scope_list, expires_at=expires_at
            )
            return (
                f"API key created (SAVE THIS — it cannot be shown again):\n"
                f"  key_id: {result['key_id']}\n"
                f"  bearer: {result['key']}\n"
                f"  scopes: {result['scopes']}\n"
                f"  expires_at: {result.get('expires_at') or 'never'}\n"
                f"\nUse as: Authorization: Bearer {result['key']}"
            )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def revoke_api_key(key_id: str) -> str:
    """Revoke an API key by id. Cannot revoke the calling key itself."""
    try:
        async with _client() as hc:
            await hc.revoke_api_key(key_id)
            return f"Key {key_id} revoked."
    except HyruleError as e:
        return _err(e)


# --- Entrypoint ---


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
