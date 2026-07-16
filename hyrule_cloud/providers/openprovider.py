"""Typed, fail-closed OpenProvider registrar client.

Only registrar operations live here. Authoritative DNS is intentionally
handled by Hyrule's Knot control plane, never by OpenProvider's DNS product.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any

import httpx
import structlog

from hyrule_cloud.config import OpenproviderConfig
from hyrule_cloud.providers.base import Provider, ProviderError

log = structlog.get_logger()


class OpenproviderError(ProviderError):
    def __init__(
        self,
        code: int | str,
        desc: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
    ) -> None:
        self.openprovider_code = code
        self.desc = desc
        self.http_status = http_status
        super().__init__("OpenProvider", str(code), desc, retryable=retryable)


class OpenproviderUnavailableError(OpenproviderError):
    pass


class OpenproviderAuthError(OpenproviderError):
    pass


class OpenproviderClient(Provider):
    """Async client for OpenProvider v1beta with safe retry boundaries."""

    def __init__(self, config: OpenproviderConfig) -> None:
        self.config = config
        self._http = httpx.AsyncClient(
            base_url=config.api_url.rstrip("/"),
            timeout=httpx.Timeout(20.0, connect=5.0),
            headers={"Accept": "application/json", "User-Agent": "hyrule-cloud/1 domains"},
        )
        self._token: str | None = None
        self._auth_lock = asyncio.Lock()

    async def _authenticate(self, *, force: bool = False) -> None:
        async with self._auth_lock:
            if self._token and not force:
                return
            if not self.config.username or not self.config.password:
                raise OpenproviderAuthError(
                    "credentials_missing",
                    "OpenProvider credentials are not configured",
                    retryable=False,
                    http_status=503,
                )
            try:
                response = await self._http.post(
                    "/auth/login",
                    json={"username": self.config.username, "password": self.config.password},
                )
            except httpx.RequestError as exc:
                raise OpenproviderUnavailableError(
                    "auth_network_error",
                    "OpenProvider authentication is unavailable",
                    retryable=True,
                ) from exc

            body = _json_body(response)
            api_code = body.get("code")
            if response.status_code >= 400 or api_code not in (None, 0):
                # OpenProvider can return HTTP 500 with API code 196 for bad
                # credentials. Parse the body before raise_for_status so this
                # becomes a controlled launch blocker instead of an uncaught
                # HTTPStatusError.
                raise OpenproviderAuthError(
                    api_code if api_code is not None else response.status_code,
                    "OpenProvider authentication was rejected",
                    retryable=response.status_code >= 500 and api_code != 196,
                    http_status=response.status_code,
                )
            token = (body.get("data") or {}).get("token")
            if not token:
                raise OpenproviderAuthError(
                    "token_missing",
                    "OpenProvider authentication returned no token",
                    retryable=True,
                    http_status=response.status_code,
                )
            self._token = str(token)
            log.info("openprovider_auth_success")

    async def _request(
        self,
        method: str,
        path: str,
        *,
        safe_retry: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        await self._authenticate()
        # A rejected bearer means OpenProvider did not execute the operation,
        # so one authentication refresh is safe even for non-idempotent calls.
        # Transport/5xx retries remain limited to explicitly safe operations.
        attempts = 2
        for attempt in range(attempts):
            try:
                response = await self._http.request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {self._token}"},
                    **kwargs,
                )
            except httpx.RequestError as exc:
                if safe_retry and attempt + 1 < attempts:
                    continue
                raise OpenproviderUnavailableError(
                    "network_error",
                    "OpenProvider is temporarily unavailable",
                    retryable=True,
                ) from exc

            if response.status_code == 401 and attempt == 0:
                self._token = None
                await self._authenticate(force=True)
                continue

            body = _json_body(response)
            api_code = body.get("code")
            if response.status_code == 429 or response.status_code >= 500:
                if safe_retry and attempt + 1 < attempts:
                    continue
                raise OpenproviderUnavailableError(
                    api_code if api_code is not None else response.status_code,
                    "OpenProvider is temporarily unavailable",
                    retryable=True,
                    http_status=response.status_code,
                )
            if response.status_code >= 400:
                raise OpenproviderError(
                    api_code if api_code is not None else response.status_code,
                    _safe_description(body),
                    retryable=False,
                    http_status=response.status_code,
                )
            if api_code not in (None, 0):
                raise OpenproviderError(
                    api_code,
                    _safe_description(body),
                    retryable=_retryable_api_code(api_code),
                    http_status=response.status_code,
                )
            data = body.get("data", {})
            return data if isinstance(data, dict) else {"result": data}
        raise AssertionError("unreachable")

    async def check_domain(self, name: str, extension: str) -> dict[str, Any]:
        data = await self._request(
            "POST",
            "/domains/check",
            safe_retry=True,
            json={
                "domains": [{"name": name, "extension": extension}],
                "with_price": True,
            },
        )
        results = data.get("results") or []
        if not results:
            raise OpenproviderUnavailableError(
                "empty_check",
                "OpenProvider returned no availability result",
                retryable=True,
            )
        result = dict(results[0])
        result["price_amount"], result["price_currency"] = _extract_product_price(result)
        return result

    async def list_tlds(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        offset = 0
        limit = 100
        while True:
            data = await self._request(
                "GET",
                "/tlds",
                safe_retry=True,
                params={
                    "limit": limit,
                    "offset": offset,
                    "with_price": "true",
                    "with_restrictions": "true",
                    "with_description": "false",
                },
            )
            batch = data.get("results") or []
            results.extend(dict(item) for item in batch)
            if len(batch) < limit:
                break
            offset += limit
        return results

    async def get_tld(self, extension: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/tlds/{extension}",
            safe_retry=True,
            params={"with_price": "true", "with_restrictions": "true"},
        )

    async def register_domain(
        self,
        name: str,
        extension: str,
        period: int = 1,
        *,
        nameservers: list[str] | None = None,
    ) -> dict[str, Any]:
        configured_nameservers = nameservers or self.config.nameservers
        nameservers = [
            {"name": nameserver, "seq_nr": index + 1}
            for index, nameserver in enumerate(configured_nameservers)
        ]
        data = await self._request(
            "POST",
            "/domains",
            # Registration is intentionally never retried blindly. A timeout
            # is reconciled through search_domain before another submission.
            safe_retry=False,
            json={
                "domain": {"name": name, "extension": extension},
                "period": period,
                "unit": "y",
                "owner_handle": self.config.owner_handle,
                "admin_handle": self.config.admin_handle,
                "tech_handle": self.config.tech_handle,
                "billing_handle": self.config.billing_handle,
                "name_servers": nameservers,
                "is_private_whois_enabled": True,
                "is_dnssec_enabled": False,
                "autorenew": "off",
                "application_mode": "GA",
            },
        )
        log.info(
            "openprovider_registration_submitted",
            domain=f"{name}.{extension}",
            status=data.get("status"),
        )
        return data

    async def search_domain(self, name: str, extension: str) -> dict[str, Any] | None:
        data = await self._request(
            "GET",
            "/domains",
            safe_retry=True,
            params={
                "domain_name_pattern": name,
                "extension": extension,
                "limit": 100,
                "offset": 0,
            },
        )
        for item in data.get("results") or []:
            domain = item.get("domain") or {}
            if (
                str(domain.get("name", "")).lower() == name.lower()
                and str(domain.get("extension", "")).lower() == extension.lower()
            ):
                return dict(item)
        return None

    async def get_domain(self, domain_id: int) -> dict[str, Any]:
        return await self._request("GET", f"/domains/{domain_id}", safe_retry=True)

    async def renew_domain(
        self,
        domain_id: int,
        *,
        name: str,
        extension: str,
        period: int = 1,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/domains/{domain_id}/renew",
            json={
                "domain": {"name": name, "extension": extension},
                "period": period,
            },
        )

    async def update_domain(self, domain_id: int, **values: Any) -> dict[str, Any]:
        return await self._request("PUT", f"/domains/{domain_id}", json=values)

    async def update_nameservers(self, domain_id: int, nameservers: list[str]) -> dict[str, Any]:
        return await self.update_domain(
            domain_id,
            name_servers=[
                {"name": nameserver, "seq_nr": index + 1}
                for index, nameserver in enumerate(nameservers)
            ],
        )

    async def set_dnssec_keys(
        self,
        domain_id: int,
        keys: list[dict[str, Any]],
    ) -> dict[str, Any]:
        normalized = [
            {
                "flags": int(key["flags"]),
                "alg": int(key.get("alg", key.get("algorithm"))),
                "protocol": int(key.get("protocol", 3)),
                "pub_key": str(key.get("pub_key", key.get("public_key"))),
            }
            for key in keys
        ]
        return await self.update_domain(
            domain_id,
            is_dnssec_enabled=bool(normalized),
            dnssec_keys=normalized,
        )

    async def unlock_domain(self, domain_id: int) -> dict[str, Any]:
        return await self.update_domain(domain_id, is_locked=False)

    async def get_authcode(self, domain_id: int) -> str:
        data = await self._request(
            "GET",
            f"/domains/{domain_id}/authcode",
            safe_retry=True,
            params={"auth_code_type": "external"},
        )
        code = data.get("auth_code")
        if not code:
            reset = await self._request(
                "POST",
                f"/domains/{domain_id}/authcode/reset",
                json={"id": domain_id, "auth_code_type": "external"},
            )
            code = reset.get("auth_code")
        if not code:
            raise OpenproviderError(
                "authcode_unavailable",
                "OpenProvider did not return a transfer authorization code",
                retryable=True,
            )
        return str(code)

    async def health_check(self) -> bool:
        try:
            await self._authenticate(force=True)
            return True
        except OpenproviderError:
            return False

    async def close(self) -> None:
        await self._http.aclose()


def _json_body(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except (TypeError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def _safe_description(body: dict[str, Any]) -> str:
    description = str(body.get("desc") or "OpenProvider rejected the request")
    # Avoid reflecting provider payloads or contact data through public errors.
    return description[:300]


def _retryable_api_code(code: object) -> bool:
    try:
        numeric = int(str(code))
    except ValueError:
        return False
    return numeric in {1000, 1001, 1002, 2000, 2001}


def _extract_product_price(result: dict[str, Any]) -> tuple[Decimal | None, str | None]:
    """Support both the established v1beta and newer compact price shapes."""
    price = result.get("price")
    if price is not None and not isinstance(price, dict):
        try:
            return Decimal(str(price)), str(result.get("currency") or "USD").upper()
        except Exception:
            return None, str(result.get("currency") or "").upper() or None
    price = price or {}
    # OpenProvider's customer charge is the reseller price. ``product`` is the
    # wholesale component and must not be surfaced as our firm sell price.
    reseller = price.get("reseller") or {}
    product = price.get("product") or {}
    if isinstance(reseller, dict):
        raw = reseller.get("price")
        currency = reseller.get("currency")
    else:
        raw = reseller
        currency = None
    if raw is None and isinstance(product, dict):
        raw = product.get("price")
        currency = currency or product.get("currency")
    if raw is None:
        raw = price.get("price")
        currency = currency or price.get("currency")
    if raw is None:
        return None, str(currency).upper() if currency else None
    try:
        amount = Decimal(str(raw))
    except Exception:
        return None, str(currency).upper() if currency else None
    return amount, str(currency or "USD").upper()
