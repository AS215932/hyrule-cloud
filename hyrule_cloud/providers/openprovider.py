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


class OpenproviderError(Exception):
    def __init__(self, code: int, desc: str) -> None:
        self.code = code
        self.desc = desc
        super().__init__(f"Openprovider error {code}: {desc}")


class OpenproviderClient:
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
        nameservers = [
            {"name": ns} for ns in self.config.nameservers
        ]

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

    async def close(self) -> None:
        await self._http.aclose()
