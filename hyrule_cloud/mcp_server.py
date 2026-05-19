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
# Wave 3 (Block D): agents bootstrap their first key via `register_account`
# and persist it as HYRULE_API_KEY. Once set, every subsequent MCP call is
# authenticated via that bearer (no x402 payment needed for free endpoints,
# scope-gated for paid ones).
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


# --- Block C + D (Wave 3): payments + accounts + API keys ---


@mcp.tool()
async def list_payment_networks() -> str:
    """List the payment chains the backend currently accepts (Block C).

    Use this BEFORE picking a chain for create_vm or any paid call —
    operators flip chains on/off via Vault and the backend is the source
    of truth. Returns the CAIP-2 identifier + EIP-712 domain shape per
    chain so an agent's wallet adapter has everything it needs.
    """
    try:
        async with _client() as hc:
            data = await hc.payment_networks()
        if not data.get("networks"):
            return "No payment networks are currently enabled."
        lines = ["Accepted payment chains:"]
        for n in data["networks"]:
            tag = " (testnet)" if n.get("testnet") else ""
            lines.append(
                f"- {n['display_name']}{tag}: {n['caip2']} · {n['asset']} · "
                f"token={n['token_address']}"
            )
        lines.append(f"\nFacilitator: {data.get('facilitator_url')}")
        return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def register_account(
    password: str,
    *,
    with_api_key: bool = True,
    api_key_name: str | None = None,
) -> str:
    """Bootstrap a new Hyrule Cloud account from MCP (Block D).

    `with_api_key=True` (the default for agents) returns a cleartext
    `hyr_sk_...` bearer alongside the recovery code. Save BOTH — the
    recovery code is the only way to reset the password if it's lost, and
    the API key is the only way to authenticate subsequent calls without
    a browser. Set the returned key into HYRULE_API_KEY in this MCP
    server's env to authenticate further tool calls.

    The starter key carries the narrow DEFAULT_BOOTSTRAP_SCOPES
    (vm:read, vm:create, intent:read, intent:create) — destructive
    actions (vm:destroy, password change, account deletion) require
    minting a wider key from the dashboard or a session.
    """
    try:
        async with _client() as hc:
            data = await hc.register(
                password,
                with_api_key=with_api_key,
                api_key_name=api_key_name,
            )
        lines = [
            "Account created — save the following SECRETS now (will not be re-shown):",
            f"  account_id      = {data['account_id']}",
            f"  recovery_code   = {data['recovery_code']}",
        ]
        if data.get("api_key"):
            lines.append(f"  api_key         = {data['api_key']}")
            lines.append(f"  api_key_id      = {data['api_key_id']}")
            lines.append(f"  api_key_scopes  = {data['api_key_scopes']}")
            lines.append(
                "\nSet HYRULE_API_KEY={api_key} in this MCP server's env "
                "to authenticate further calls.".format(api_key=data["api_key"])
            )
        return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def whoami() -> str:
    """Return the currently-authenticated account ID (Block D).

    Requires HYRULE_API_KEY or a cookie session. Use this to confirm
    which account a key belongs to before running destructive tools.
    """
    try:
        async with _client() as hc:
            data = await hc._request("GET", "/v1/me")
        return (
            f"account_id  = {data['account_id']}\n"
            f"vm_count    = {data.get('vm_count', '?')}\n"
            f"created_at  = {data.get('created_at', '?')}"
        )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def list_api_keys() -> str:
    """List active API keys for the authenticated account (Block D).

    Requires an API key with `api_keys:read` OR a cookie session. The
    cleartext bearer is never returned here — only summaries (key_id,
    name, scopes, created_at, last_used_at).
    """
    try:
        async with _client() as hc:
            data = await hc.list_api_keys()
        if not data.get("keys"):
            return "No active API keys."
        lines = []
        for k in data["keys"]:
            lines.append(
                f"- {k['key_id']} · '{k['name']}' · scopes={k['scopes']} · "
                f"created={k['created_at']}"
            )
        return "\n".join(lines)
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def create_api_key(
    name: str,
    scopes: list[str],
    *,
    expires_in_days: int | None = None,
) -> str:
    """Mint a fresh API key (Block D).

    Requires `api_keys:write` for an API-key-authed caller. The cleartext
    bearer is in the response — save it now, no second chance. When
    minted via an API key (not a session), the requested scopes must be
    a subset of the issuing key's scopes (no escalation).

    Valid scopes: vm:read, vm:create, vm:reboot, vm:extend, vm:destroy,
    intent:create, intent:read, domain:register, api_keys:read, api_keys:write.
    """
    try:
        async with _client() as hc:
            data = await hc.create_api_key(name, scopes, expires_in_days=expires_in_days)
        return (
            f"api_key     = {data['api_key']}  (SAVE NOW — not shown again)\n"
            f"key_id      = {data['key']['key_id']}\n"
            f"name        = {data['key']['name']}\n"
            f"scopes      = {data['key']['scopes']}\n"
            f"expires_at  = {data['key'].get('expires_at')}"
        )
    except HyruleError as e:
        return _err(e)


@mcp.tool()
async def revoke_api_key(key_id: str) -> str:
    """Revoke an API key by id (Block D). Idempotent — revoking an
    already-revoked key returns success. A key cannot revoke itself."""
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
