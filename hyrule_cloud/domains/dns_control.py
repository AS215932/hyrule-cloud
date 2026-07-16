"""Authenticated client for Hyrule's Knot authoritative-DNS control plane."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import quote

import httpx

from hyrule_cloud.config import DomainConfig


class DNSControlError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = True) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(message)


class DNSControlClient:
    def __init__(self, config: DomainConfig) -> None:
        self.config = config
        self._http = httpx.AsyncClient(
            base_url=config.dns_control_url.rstrip("/") or "http://127.0.0.1",
            timeout=config.dns_control_timeout_seconds,
            headers={"Accept": "application/json", "User-Agent": "hyrule-cloud/1 dns-control"},
        )

    @property
    def configured(self) -> bool:
        return bool(self.config.dns_control_url and self.config.dns_control_secret)

    async def apply_zone(
        self,
        zone: str,
        *,
        revision: int,
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return await self._request(
            "PUT",
            f"/v1/zones/{quote(zone, safe='')}",
            {
                "revision": revision,
                "nameservers": self.config.managed_nameservers,
                "soa_mname": self.config.soa_mname,
                "soa_rname": self.config.soa_rname,
                "records": records,
                "dnssec": True,
            },
        )

    async def delete_zone(self, zone: str) -> dict[str, Any]:
        return await self._request("DELETE", f"/v1/zones/{quote(zone, safe='')}", None)

    async def dnssec_keys(self, zone: str) -> list[dict[str, Any]]:
        result = await self._request("GET", f"/v1/zones/{quote(zone, safe='')}/dnssec", None)
        keys = result.get("dnskey") or result.get("keys") or []
        if not isinstance(keys, list) or not keys:
            raise DNSControlError("dnskey_missing", "DNS control returned no DNSKEY records")
        return [dict(key) for key in keys]

    async def health_check(self) -> bool:
        if not self.configured:
            return False
        try:
            await self._request("GET", "/health", None)
            return True
        except DNSControlError:
            return False

    async def close(self) -> None:
        await self._http.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if not self.configured:
            raise DNSControlError("not_configured", "Managed DNS is not configured", retryable=False)
        body = b"" if payload is None else json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        timestamp = str(int(time.time()))
        signing_input = b"\n".join(
            [timestamp.encode(), method.upper().encode(), path.encode(), hashlib.sha256(body).hexdigest().encode()]
        )
        signature = hmac.new(
            self.config.dns_control_secret.encode(), signing_input, hashlib.sha256
        ).hexdigest()
        try:
            response = await self._http.request(
                method,
                path,
                content=body or None,
                headers={
                    "Content-Type": "application/json",
                    "X-Hyrule-Timestamp": timestamp,
                    "X-Hyrule-Signature": f"sha256={signature}",
                },
            )
        except httpx.RequestError as exc:
            raise DNSControlError("network_error", "Managed DNS is temporarily unavailable") from exc
        try:
            result = response.json()
        except ValueError:
            result = {}
        if response.status_code >= 400:
            retryable = response.status_code >= 500 or response.status_code == 429
            code = str(result.get("code") or f"http_{response.status_code}")
            detail = str(result.get("detail") or "Managed DNS rejected the change")
            raise DNSControlError(code, detail[:300], retryable=retryable)
        return result if isinstance(result, dict) else {}
