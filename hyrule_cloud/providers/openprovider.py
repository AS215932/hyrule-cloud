"""
Openprovider REST API client.

Handles domain availability checks, registration, and nameserver configuration.
API docs: https://docs.openprovider.com/
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import structlog

from hyrule_cloud.config import OpenproviderConfig

log = structlog.get_logger()


from hyrule_cloud.providers.base import Provider, ProviderError

class OpenproviderError(ProviderError):
    def __init__(self, code: int, desc: str) -> None:
        self.openprovider_code = code
        self.desc = desc
        super().__init__("Openprovider", str(code), desc, retryable=(code == 401))

class OpenproviderClient(Provider):
    """Async client for the Openprovider REST API."""

    def __init__(self, config: OpenproviderConfig) -> None:
        self.config = config
        self._http = httpx.AsyncClient(
            base_url=config.api_url,
            timeout=30.0,
        )
        self._token: str | None = None

    async def _authenticate(self) -> None:
        """Obtain a bearer token."""
        resp = await self._http.post(
            "/auth/login",
            json={
                "username": self.config.username,
                "password": self.config.password,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["data"]["token"]
        log.info("openprovider_auth_success")

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make an authenticated request, refreshing token if needed."""
        if not self._token:
            await self._authenticate()

        headers = {"Authorization": f"Bearer {self._token}"}
        resp = await self._http.request(method, path, headers=headers, **kwargs)

        # Token might be expired
        if resp.status_code == 401:
            await self._authenticate()
            headers = {"Authorization": f"Bearer {self._token}"}
            resp = await self._http.request(method, path, headers=headers, **kwargs)

        resp.raise_for_status()
        body = resp.json()

        if body.get("code") != 0:
            raise OpenproviderError(body.get("code", -1), body.get("desc", "Unknown"))

        return body.get("data", {})

    async def check_domain(self, name: str, extension: str) -> dict:
        """
        Check domain availability.

        Returns {"status": "free"|"active"|..., "price": Decimal|None}
        """
        data = await self._request(
            "POST",
            "/domains/check",
            json={
                "domains": [{"name": name, "extension": extension}],
            },
        )

        results = data.get("results", [])
        if not results:
            return {"status": "unknown", "price": None}

        result = results[0]
        price = None
        if result.get("price", {}).get("product", {}).get("price"):
            price = Decimal(str(result["price"]["product"]["price"]))

        return {
            "status": result.get("status", "unknown"),
            "is_premium": result.get("is_premium", False),
            "price": price,
            "currency": result.get("price", {}).get("product", {}).get("currency", "USD"),
        }

    async def register_domain(
        self,
        name: str,
        extension: str,
        period: int = 1,
    ) -> dict:
        """
        Register a domain.

        Uses the contact handles from config. Sets nameservers to our
        authoritative NS.
        """
        nameservers = [{"name": ns} for ns in self.config.nameservers]

        data = await self._request(
            "POST",
            "/domains",
            json={
                "domain": {"name": name, "extension": extension},
                "period": period,
                "owner_handle": self.config.owner_handle,
                "admin_handle": self.config.admin_handle,
                "tech_handle": self.config.tech_handle,
                "billing_handle": self.config.billing_handle,
                "name_servers": nameservers,
                "is_private_whois_enabled": True,
                "is_dnssec_enabled": False,  # we manage DNSSEC separately if needed
                "autorenew": "off",
            },
        )

        log.info("domain_registered", name=name, extension=extension)
        return data

    async def update_nameservers(self, domain_id: int, nameservers: list[str]) -> dict:
        """Update nameservers for a registered domain."""
        ns_list = [{"name": ns} for ns in nameservers]
        return await self._request(
            "PUT",
            f"/domains/{domain_id}",
            json={"name_servers": ns_list},
        )

    # --- DNS Zone Management ---

    async def create_zone(self, name: str) -> dict:
        """
        Create a DNS zone on Openprovider's nameservers.

        The zone must correspond to a domain registered with Openprovider,
        or the domain must have its nameservers pointed to Openprovider.
        """
        data = await self._request(
            "POST",
            "/dns/zones",
            json={
                "domain": {"name": name},
                "type": "master",
                "is_active": True,
            },
        )
        log.info("dns_zone_created", zone=name)
        return data

    async def get_zone(self, name: str) -> dict | None:
        """Get a DNS zone by domain name. Returns None if not found."""
        try:
            return await self._request("GET", f"/dns/zones/{name}")
        except (httpx.HTTPStatusError, OpenproviderError):
            return None

    async def list_zone_records(self, zone_name: str) -> list[dict]:
        """List all DNS records in a zone."""
        data = await self._request("GET", f"/dns/zones/{zone_name}/records")
        return data.get("results", [])

    async def create_zone_record(
        self,
        zone_name: str,
        name: str,
        rtype: str,
        value: str,
        ttl: int = 300,
        prio: int | None = None,
    ) -> dict:
        """
        Create a DNS record in an Openprovider-managed zone.

        For records at the zone apex, use name="".
        """
        record: dict = {
            "name": name,
            "type": rtype,
            "value": value,
            "ttl": ttl,
        }
        if prio is not None:
            record["prio"] = prio

        # Openprovider zone record API: PUT replaces all records.
        # We fetch existing records, append the new one, and PUT the full set.
        existing = await self.list_zone_records(zone_name)
        records = [
            {k: r[k] for k in ("name", "type", "value", "ttl", "prio") if k in r} for r in existing
        ]
        records.append(record)

        data = await self._request(
            "PUT",
            f"/dns/zones/{zone_name}",
            json={"records": records},
        )
        log.info("zone_record_created", zone=zone_name, name=name, type=rtype, value=value)
        return data

    async def delete_zone_record(
        self,
        zone_name: str,
        name: str,
        rtype: str,
    ) -> dict:
        """
        Delete a DNS record from an Openprovider-managed zone.

        Removes all records matching the given name and type.
        """
        existing = await self.list_zone_records(zone_name)
        records = [
            {k: r[k] for k in ("name", "type", "value", "ttl", "prio") if k in r}
            for r in existing
            if not (r.get("name") == name and r.get("type") == rtype)
        ]

        data = await self._request(
            "PUT",
            f"/dns/zones/{zone_name}",
            json={"records": records},
        )
        log.info("zone_record_deleted", zone=zone_name, name=name, type=rtype)
        return data

    async def health_check(self) -> bool:
        try:
            # Simple check if api is responding
            resp = await self._http.get("/auth/login")
            return resp.status_code in [400, 401, 405]
        except httpx.RequestError:
            return False

    async def close(self) -> None:
        await self._http.aclose()
