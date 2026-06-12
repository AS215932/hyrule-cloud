"""
Thin async Python client for the Hyrule Cloud API.

Usage:
    from hyrule_cloud.client import HyruleClient

    async with HyruleClient("https://cloud.hyrule.host") as hc:
        # Check pricing
        pricing = await hc.pricing()

        # Create a VM (will return 402 without payment header)
        vm = await hc.create_vm(
            duration_days=7,
            size="sm",
            ssh_pubkey="ssh-ed25519 AAAA...",
        )

        # Poll until ready
        status = await hc.vm_status(vm["vm_id"])

        # Check domain availability
        avail = await hc.check_domain("example", "com")

        # Register a domain
        reg = await hc.register_domain("mysite", "dev", ipv6="2001:db8::1")
"""

from __future__ import annotations

from typing import Any

import httpx


class HyruleError(Exception):
    """Raised when the Hyrule Cloud API returns an error."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class HyruleClient:
    """Async client for the Hyrule Cloud API."""

    def __init__(
        self,
        base_url: str = "https://cloud.hyrule.host",
        *,
        payment_header: str | None = None,
        dev_bypass: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        """If `api_key` is set (Wave 3 / Block D) the bearer is sent on every
        request, taking the place of session-cookie auth. Keys are minted via
        `register(with_api_key=True)` or `/v1/me/api-keys` on the dashboard."""
        headers: dict[str, str] = {}
        if payment_header:
            headers["X-PAYMENT"] = payment_header
        if dev_bypass:
            headers["X-DEV-BYPASS"] = dev_bypass
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    async def __aenter__(self) -> HyruleClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    # -- internal --

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        resp = await self._http.request(method, path, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise HyruleError(resp.status_code, detail)
        return resp.json()

    # -- Free endpoints --

    async def pricing(self) -> dict[str, Any]:
        """Get current pricing for all resources."""
        return await self._request("GET", "/v1/pricing")

    async def os_list(self) -> dict[str, Any]:
        """List available OS templates."""
        return await self._request("GET", "/v1/os/list")

    async def vm_status(self, vm_id: str) -> dict[str, Any]:
        """Get VM status, IP, hostname, expiry."""
        return await self._request("GET", f"/v1/vm/{vm_id}")

    async def vm_logs(self, vm_id: str) -> dict[str, Any]:
        """Get VM provisioning logs."""
        return await self._request("GET", f"/v1/vm/{vm_id}/logs")

    async def check_domain(self, name: str, extension: str) -> dict[str, Any]:
        """Check domain availability and price."""
        return await self._request(
            "GET", "/v1/domain/check", params={"domain": f"{name}.{extension}"}
        )

    async def check_zone(self, name: str, extension: str) -> dict[str, Any]:
        """Check DNS zone availability and price."""
        return await self._request(
            "GET", "/v1/zone/check", params={"name": name, "extension": extension}
        )

    # -- Paid endpoints --

    async def create_vm(
        self,
        *,
        duration_days: int,
        ssh_pubkey: str,
        size: str = "xs",
        os: str = "debian-13",
        domain_mode: str = "auto",
        domain: str | None = None,
        open_ports: list[int] | None = None,
        setup_script: str | None = None,
    ) -> dict[str, Any]:
        """
        Provision a bare VM.

        Returns 402 if no payment header is set — the response body contains
        pricing info and x402 payment instructions.
        """
        body: dict[str, Any] = {
            "duration_days": duration_days,
            "size": size,
            "os": os,
            "ssh_pubkey": ssh_pubkey,
            "domain_mode": domain_mode,
        }
        if domain:
            body["domain"] = domain
        if open_ports is not None:
            body["open_ports"] = open_ports
        if setup_script is not None:
            body["setup_script"] = setup_script

        return await self._request("POST", "/v1/vm/create", json=body)

    async def extend_vm(self, vm_id: str, days: int) -> dict[str, Any]:
        """Add days to a running VM. Paid via x402."""
        return await self._request("POST", f"/v1/vm/{vm_id}/extend", json={"days": days})

    async def reboot_vm(self, vm_id: str) -> dict[str, Any]:
        """Hard reboot a VM."""
        return await self._request("POST", f"/v1/vm/{vm_id}/reboot")

    async def destroy_vm(self, vm_id: str) -> dict[str, Any]:
        """Destroy a VM permanently."""
        return await self._request("DELETE", f"/v1/vm/{vm_id}")

    async def register_domain(
        self,
        name: str,
        extension: str,
        ipv6: str | None = None,
    ) -> dict[str, Any]:
        """Register a domain via Openprovider. Paid via x402."""
        body: dict[str, Any] = {"domain": f"{name}.{extension}"}
        if ipv6:
            body["ipv6"] = ipv6
        return await self._request("POST", "/v1/domain/register", json=body)

    async def buy_zone(
        self,
        name: str,
        extension: str,
    ) -> dict[str, Any]:
        """
        Buy a DNS zone (register the domain + configure our nameservers).

        The zone will be managed by Hyrule Cloud's authoritative DNS.
        Agents can then create records in the zone via the records API.
        """
        return await self._request(
            "POST", "/v1/zone/buy", json={"name": name, "extension": extension}
        )

    async def create_record(
        self,
        zone: str,
        name: str,
        rtype: str,
        value: str,
        ttl: int = 300,
    ) -> dict[str, Any]:
        """Create a DNS record in a zone owned by the caller."""
        return await self._request(
            "POST",
            "/v1/zone/record",
            json={"zone": zone, "name": name, "type": rtype, "value": value, "ttl": ttl},
        )

    async def delete_record(
        self,
        zone: str,
        name: str,
        rtype: str,
    ) -> dict[str, Any]:
        """Delete a DNS record from a zone owned by the caller."""
        return await self._request(
            "DELETE",
            "/v1/zone/record",
            params={"zone": zone, "name": name, "type": rtype},
        )

    # -- Discovery --

    async def x402_manifest(self) -> dict[str, Any]:
        """Fetch the x402 service manifest for agent discovery."""
        return await self._request("GET", "/.well-known/x402.json")

    async def health(self) -> dict[str, Any]:
        """Health check."""
        return await self._request("GET", "/health")

    # -- Block A1 (Wave 2) + D (Wave 3): account-level operations --

    async def payment_networks(self) -> dict[str, Any]:
        """Block C: list the chains the backend currently accepts.

        Frontends and agent SDKs SHOULD call this rather than hardcoding a
        chain list — operators flip individual chains on/off in Vault and
        the wire format is the single source of truth."""
        return await self._request("GET", "/v1/payments/networks")

    async def create_crypto_intent(
        self,
        *,
        asset: str,
        amount_usd: str,
        order_payload: dict[str, Any],
        client_order_id: str | None = None,
    ) -> dict[str, Any]:
        """Block E/H: open a BTC or XMR payment intent. Returns deposit address
        + QR + rate snapshot. Use client_order_id for idempotent retries."""
        body: dict[str, Any] = {
            "asset": asset,
            "amount_usd": amount_usd,
            "order_payload": order_payload,
        }
        if client_order_id:
            body["client_order_id"] = client_order_id
        return await self._request("POST", "/v1/intent/create", json=body)

    async def get_crypto_intent(self, intent_id: str) -> dict[str, Any]:
        """Block E/H: poll a crypto intent. Returns status, confirmations, and
        once PROVISIONED the resulting vm_id + one-shot management token."""
        return await self._request("GET", f"/v1/intent/{intent_id}")

    async def register(
        self,
        password: str,
        *,
        with_api_key: bool = False,
        api_key_name: str | None = None,
    ) -> dict[str, Any]:
        """Register a fresh account. Returns `{account_id, recovery_code, ...}`.

        If `with_api_key=True` the response also carries a cleartext
        `api_key` (Block D agent bootstrap) with the narrow
        DEFAULT_BOOTSTRAP_SCOPES — save it; we never re-show it."""
        payload: dict[str, Any] = {"password": password}
        if with_api_key:
            payload["with_api_key"] = True
            if api_key_name:
                payload["api_key_name"] = api_key_name
        return await self._request("POST", "/v1/auth/register", json=payload)

    async def list_api_keys(self) -> dict[str, Any]:
        """Block D: list active (non-revoked) API keys for the current
        account. Authenticate via `api_key=` on the client constructor."""
        return await self._request("GET", "/v1/me/api-keys")

    async def create_api_key(
        self, name: str, scopes: list[str], *, expires_in_days: int | None = None,
    ) -> dict[str, Any]:
        """Block D: mint a new API key. Response carries the cleartext
        bearer exactly once."""
        payload: dict[str, Any] = {"name": name, "scopes": scopes}
        if expires_in_days is not None:
            payload["expires_in_days"] = expires_in_days
        return await self._request("POST", "/v1/me/api-keys", json=payload)

    async def revoke_api_key(self, key_id: str) -> dict[str, Any]:
        """Block D: idempotent revocation."""
        return await self._request("DELETE", f"/v1/me/api-keys/{key_id}")
