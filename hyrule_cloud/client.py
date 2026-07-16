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
        reg = await hc.register_domain("mysite", "dev")
"""

from __future__ import annotations

import asyncio
import platform
import secrets
from typing import Any

import httpx

from hyrule_cloud.agent_probe import stun_binding_address, trigger_dns_observation


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
            "GET", "/v1/domains/check", params={"domain": f"{name}.{extension}"}
        )

    async def check_zone(self, name: str, extension: str) -> dict[str, Any]:
        """Check DNS zone availability and price (same as domain availability)."""
        return await self._request(
            "GET", "/v1/domains/check", params={"domain": f"{name}.{extension}"}
        )

    async def domain_tlds(self) -> dict[str, Any]:
        """List the current eligible generic TLD catalog."""
        return await self._request("GET", "/v1/domains/tlds")

    async def quote_domain(self, domain: str, action: str = "register") -> dict[str, Any]:
        """Create a 15-minute registration or renewal quote."""
        return await self._request(
            "POST", "/v1/domains/quotes", json={"domain": domain, "action": action}
        )

    async def domain_order(self, order_id: str) -> dict[str, Any]:
        """Fetch a durable domain order and its fulfillment state."""
        return await self._request("GET", f"/v1/domains/orders/{order_id}")

    async def domains(self) -> dict[str, Any]:
        """List domains owned by the authenticated account."""
        return await self._request("GET", "/v1/domains")

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
        *,
        payment_method: str = "usdc",
        refund_address: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Quote and create an account-owned registrar order."""
        quote = await self.quote_domain(f"{name}.{extension}")
        body: dict[str, Any] = {
            "quote_id": quote["quote_id"],
            "payment_method": payment_method,
            "terms_version": quote["terms_version"],
        }
        if refund_address:
            body["refund_address"] = refund_address
        return await self._request(
            "POST",
            "/v1/domains/orders",
            json=body,
            headers={"Idempotency-Key": idempotency_key or secrets.token_urlsafe(24)},
        )

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
        return await self.register_domain(name, extension)

    async def create_record(
        self,
        zone: str,
        name: str,
        rtype: str,
        value: str,
        ttl: int = 300,
    ) -> dict[str, Any]:
        """Create a DNS record in a zone owned by the caller."""
        current = await self._request("GET", f"/v1/domains/{zone}/dns")
        return await self._request(
            "POST",
            f"/v1/domains/{zone}/dns/changesets",
            json={
                "changes": [
                    {
                        "action": "upsert",
                        "rrset": {
                            "name": name,
                            "type": rtype,
                            "ttl": ttl,
                            "values": [value],
                        },
                    }
                ]
            },
            headers={
                "If-Match": str(current["revision"]),
                "Idempotency-Key": secrets.token_urlsafe(24),
            },
        )

    async def delete_record(
        self,
        zone: str,
        name: str,
        rtype: str,
    ) -> dict[str, Any]:
        """Delete a DNS record from a zone owned by the caller."""
        current = await self._request("GET", f"/v1/domains/{zone}/dns")
        existing = next(
            (
                record
                for record in current.get("records", [])
                if record.get("name") == name and record.get("type") == rtype.upper()
            ),
            None,
        )
        if existing is None:
            return current
        return await self._request(
            "POST",
            f"/v1/domains/{zone}/dns/changesets",
            json={"changes": [{"action": "delete", "rrset": existing}]},
            headers={
                "If-Match": str(current["revision"]),
                "Idempotency-Key": secrets.token_urlsafe(24),
            },
        )

    # -- Network intelligence / agentic support --

    async def bgp_status(self) -> dict[str, Any]:
        """Free AS215932 BGP/routing status."""
        return await self._request("GET", "/v1/bgp/status")

    async def bgp_lookup(self, subject: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Paid BGP lookup by prefix, IP, or ASN. Prefix/IP do not require ASN."""
        payload: dict[str, Any] = {"subject": subject, **kwargs}
        return await self._request("POST", "/v1/bgp/lookup", json=payload)

    async def ip_lookup(self, address: str, views: list[str] | None = None) -> dict[str, Any]:
        """Paid IP geolocation/ASN/rDNS/RDAP/WHOIS/reputation lookup."""
        payload: dict[str, Any] = {"address": address}
        if views:
            payload["views"] = views
        return await self._request("POST", "/v1/ip/lookup", json=payload)

    async def ip_sources(self) -> dict[str, Any]:
        """Free inventory of IP-intelligence sources and launch readiness."""
        return await self._request("GET", "/v1/ip/sources")

    async def ip_check_session(
        self, expected_dns_resolvers: list[str] | None = None
    ) -> dict[str, Any]:
        """Create a free, short-lived machine-readable network probe session."""
        return await self._request(
            "POST",
            "/v1/ip-check/sessions",
            json={"expected_dns_resolvers": expected_dns_resolvers or []},
        )

    async def ip_check_report(self, session_id: str, token: str) -> dict[str, Any]:
        """Fetch a network observation report with its session bearer."""
        return await self._request(
            "GET",
            f"/v1/ip-check/sessions/{session_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    async def ip_check_agent_fingerprint(
        self,
        session_id: str,
        token: str,
        fingerprint: dict[str, object],
    ) -> dict[str, Any]:
        """Submit declared agent provenance and an optional signed identity proof."""
        return await self._request(
            "POST",
            f"/v1/ip-check/sessions/{session_id}/fingerprints/agent",
            headers={"Authorization": f"Bearer {token}"},
            json=fingerprint,
        )

    async def ip_check_browser_fingerprint(
        self,
        session_id: str,
        token: str,
        fingerprint: dict[str, object],
    ) -> dict[str, Any]:
        """Submit explicit browser traits to the session-scoped fingerprint endpoint."""
        return await self._request(
            "POST",
            f"/v1/ip-check/sessions/{session_id}/fingerprints/browser",
            headers={"Authorization": f"Bearer {token}"},
            json=fingerprint,
        )

    async def network_environment_check(
        self,
        *,
        expected_dns_resolvers: list[str] | None = None,
        protocol: str = "sdk",
        model_vendor_claim: str | None = None,
        model_name_claim: str | None = None,
    ) -> dict[str, Any]:
        """Run HTTP, DNS, and STUN probes from this client process.

        This measures the environment where the Python client/MCP process runs,
        not the Hyrule API host and not a different browser or remote gateway.
        """
        created = await self.ip_check_session(expected_dns_resolvers)
        session_id = str(created["session_id"])
        token = str(created["token"])
        auth = {"Authorization": f"Bearer {token}"}
        outcomes: dict[str, object] = {}

        async def http_probe(name: str, url: str) -> None:
            try:
                observed = await self._request("POST", url, headers=auth)
                outcomes[name] = {
                    "status": "observed",
                    "address": observed.get("address"),
                }
            except (HyruleError, httpx.HTTPError) as exc:
                outcomes[name] = {"status": "unavailable", "reason": str(exc)[:256]}

        await asyncio.gather(
            http_probe("https_ipv4", str(created["ipv4_probe_url"])),
            http_probe("https_ipv6", str(created["ipv6_probe_url"])),
        )

        dns_hostname = str(created["dns_probe_hostname"])
        outcomes["dns"] = {
            "status": (
                "query_sent" if await trigger_dns_observation(dns_hostname) else "unavailable"
            ),
            "hostname": dns_hostname,
        }

        stun_addresses: list[str] = []
        stun_errors: list[str] = []
        for url in created.get("stun_urls", []):
            try:
                address = await stun_binding_address(str(url))
            except (OSError, ValueError) as exc:
                stun_errors.append(f"{url}: {str(exc)[:160]}")
                continue
            if address is not None and address not in stun_addresses:
                stun_addresses.append(address)
        stun_status = "collected" if stun_addresses else "failed"
        outcomes["stun"] = {
            "status": stun_status,
            "public_addresses": stun_addresses,
            "errors": stun_errors,
        }
        try:
            await self._request(
                "POST",
                f"/v1/ip-check/sessions/{session_id}/observe/network",
                headers=auth,
                json={
                    "adapter": "stun",
                    "status": stun_status,
                    "public_addresses": stun_addresses,
                },
            )
        except (HyruleError, httpx.HTTPError) as exc:
            outcomes["stun_submission"] = {
                "status": "unavailable",
                "reason": str(exc)[:256],
            }

        agent_payload: dict[str, object] = {
            "runtime": f"{platform.python_implementation()} HyruleClient",
            "runtime_version": platform.python_version(),
            "operating_system": platform.system(),
            "architecture": platform.machine(),
            "protocol": protocol,
            "capabilities": ["https-ipv4", "https-ipv6", "dns", "stun-rfc5389"],
        }
        if model_vendor_claim is not None:
            agent_payload["model_vendor_claim"] = model_vendor_claim
        if model_name_claim is not None:
            agent_payload["model_name_claim"] = model_name_claim
        try:
            await self._request(
                "POST",
                f"/v1/ip-check/sessions/{session_id}/fingerprints/agent",
                headers=auth,
                json=agent_payload,
            )
            outcomes["agent_fingerprint"] = {"status": "recorded"}
        except (HyruleError, httpx.HTTPError) as exc:
            outcomes["agent_fingerprint"] = {
                "status": "unavailable",
                "reason": str(exc)[:256],
            }

        report = await self.ip_check_report(session_id, token)
        for _ in range(4):
            if report.get("dns_resolver_addresses"):
                break
            await asyncio.sleep(0.25)
            report = await self.ip_check_report(session_id, token)

        manifest = dict(created.get("probe_manifest") or {})
        manifest["probes"] = [
            {
                **dict(probe),
                "headers": {
                    name: "Bearer <redacted>" if name.lower() == "authorization" else value
                    for name, value in dict(probe.get("headers") or {}).items()
                },
            }
            for probe in manifest.get("probes", [])
            if isinstance(probe, dict)
        ]
        return {
            "measurement_scope": "process_running_hyrule_client",
            "session_id": session_id,
            "expires_at": created.get("expires_at"),
            "probe_manifest": manifest,
            "probe_outcomes": outcomes,
            "report": report,
        }

    async def ip_quality(
        self,
        address: str,
        *,
        expected_country_code: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
        timezone: str | None = None,
        history_days: int = 90,
    ) -> dict[str, Any]:
        """Paid licensed IP quality, risk, routing, and consistency report."""
        payload: dict[str, Any] = {"address": address, "history_days": history_days}
        if expected_country_code is not None:
            payload["expected_country_code"] = expected_country_code
        context = {
            key: value
            for key, value in {
                "user_agent": user_agent,
                "accept_language": accept_language,
                "timezone": timezone,
            }.items()
            if value is not None
        }
        if context:
            payload["client_context"] = context
        return await self._request("POST", "/v1/ip/quality", json=payload)

    async def dns_lookup(
        self,
        name: str,
        record_type: str = "A",
        *,
        dnssec: bool = False,
        trace: bool = False,
    ) -> dict[str, Any]:
        """Paid read-only DNS lookup."""
        return await self._request(
            "POST",
            "/v1/dns/lookup",
            json={"name": name, "type": record_type, "dnssec": dnssec, "trace": trace},
        )

    async def dns_propagation(
        self,
        name: str,
        record_type: str = "A",
        *,
        expected: list[str] | None = None,
        resolvers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Paid DNS propagation comparison across recursive resolvers."""
        payload: dict[str, Any] = {"name": name, "type": record_type}
        if expected is not None:
            payload["expected"] = expected
        if resolvers is not None:
            payload["resolvers"] = resolvers
        return await self._request("POST", "/v1/dns/propagation", json=payload)

    async def rdap_lookup(self, subject_type: str, value: str | int, *, include_raw: bool = False) -> dict[str, Any]:
        """Paid RDAP lookup for domain/IP/prefix/ASN/entity."""
        return await self._request(
            "POST",
            "/v1/rdap/lookup",
            json={"subject": {"type": subject_type, "value": value}, "include_raw": include_raw},
        )

    async def whois_lookup(self, subject_type: str, value: str | int, *, include_raw: bool = False) -> dict[str, Any]:
        """Paid WHOIS lookup for domain/IP/prefix/ASN."""
        return await self._request(
            "POST",
            "/v1/whois/lookup",
            json={"subject": {"type": subject_type, "value": value}, "include_raw": include_raw},
        )

    async def web_check(self, target: str, checks: list[str] | None = None) -> dict[str, Any]:
        """Paid web reachability/TLS/header/CDN check."""
        payload: dict[str, Any] = {"target": target}
        if checks:
            payload["checks"] = checks
        return await self._request("POST", "/v1/web/check", json=payload)

    async def web_tls_deep(self, host: str, port: int = 443) -> dict[str, Any]:
        """Paid deep TLS protocol/certificate/cipher scan with grade."""
        return await self._request("POST", "/v1/web/tls/deep", json={"host": host, "port": port})

    async def mx_tools(self) -> dict[str, Any]:
        """Free list of MXToolbox-compatible diagnostic tools."""
        return await self._request("GET", "/v1/mx/tools")

    async def mx_check(
        self,
        tool: str,
        target: str,
        *,
        dkim_selectors: list[str] | None = None,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        """Paid MXToolbox-compatible single diagnostic check."""
        options: dict[str, Any] = {"include_raw": include_raw}
        if dkim_selectors:
            options["dkim_selectors"] = dkim_selectors
        return await self._request(
            "POST",
            "/v1/mx/check",
            json={"tool": tool, "target": target, "options": options},
        )

    async def mx_report(self, target: str, checks: list[str] | None = None) -> dict[str, Any]:
        """Paid full mail-delivery diagnostic report."""
        payload: dict[str, Any] = {"profile": "mail_delivery", "target": target}
        if checks:
            payload["checks"] = checks
        return await self._request("POST", "/v1/mx/jobs", json=payload)

    async def mx_parse_bounce(self, message: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Paid bounce/rejection parser."""
        return await self._request("POST", "/v1/mx/bounce/parse", json={"message": message, "context": context or {}})

    async def path_report(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Paid routing/path evidence pack."""
        return await self._request("POST", "/v1/path/report", json={"target": target, **kwargs})

    async def port_check(self, target: str, port: int, protocol: str = "tcp", profile: str = "custom") -> dict[str, Any]:
        """Paid outside-in single-service reachability check."""
        return await self._request("POST", "/v1/ports/check", json={"target": target, "port": port, "protocol": protocol, "profile": profile})

    async def nat_ip(self) -> dict[str, Any]:
        """Free caller-observed IP."""
        return await self._request("GET", "/v1/nat/ip")

    async def nat_port_forward_check(self, target: str, port: int, protocol: str = "tcp", profile: str = "custom") -> dict[str, Any]:
        """Paid NAT port-forward outside-in check."""
        return await self._request("POST", "/v1/nat/port-forward/check", json={"target": target, "port": port, "protocol": protocol, "profile": profile})

    async def threat_lookup(self, subject_type: str, value: str, views: list[str] | None = None) -> dict[str, Any]:
        """Paid threat/reputation lookup."""
        payload: dict[str, Any] = {"subject": {"type": subject_type, "value": value}}
        if views:
            payload["views"] = views
        return await self._request("POST", "/v1/threat/lookup", json=payload)

    async def voip_check(self, target: str, checks: list[str] | None = None) -> dict[str, Any]:
        """Paid SIP/VoIP diagnostic check."""
        payload: dict[str, Any] = {"target": target}
        if checks:
            payload["checks"] = checks
        return await self._request("POST", "/v1/voip/check", json=payload)

    async def voip_number_lookup(self, number: str, country: str | None = None) -> dict[str, Any]:
        """Paid VoIP number-provider lookup contract."""
        payload: dict[str, Any] = {"number": number}
        if country:
            payload["country"] = country
        return await self._request("POST", "/v1/voip/number/lookup", json=payload)

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
