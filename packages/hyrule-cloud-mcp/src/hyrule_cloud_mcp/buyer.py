"""Buyer orchestration independent from the MCP transport."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from x402.http.clients import wrapHttpxWithPayment

from hyrule_cloud_mcp.catalog import CatalogResource, build_request, fetch_catalog
from hyrule_cloud_mcp.config import Settings
from hyrule_cloud_mcp.payments import SpendLedger, build_x402_client

CatalogLoader = Callable[[str], Awaitable[list[CatalogResource]]]


class Buyer:
    def __init__(
        self,
        settings: Settings,
        *,
        catalog_loader: CatalogLoader | None = None,
    ) -> None:
        self.settings = settings
        self.ledger = SpendLedger(settings.ledger_path)
        self._catalog_loader = catalog_loader

    async def _catalog(self) -> list[CatalogResource]:
        if self._catalog_loader is not None:
            return await self._catalog_loader(self.settings.base_url)
        return await fetch_catalog(self.settings.base_url, timeout=self.settings.timeout_seconds)

    async def discover(self, query: str = "") -> list[dict[str, Any]]:
        resources = await self._catalog()
        needle = query.strip().lower()
        result: list[dict[str, Any]] = []
        for resource in resources:
            haystack = " ".join(
                (
                    resource.capability_id,
                    resource.description,
                    *resource.intents,
                    *resource.capabilities,
                )
            ).lower()
            if needle and needle not in haystack:
                continue
            result.append(
                {
                    "id": resource.capability_id,
                    "method": resource.method,
                    "path": resource.path,
                    "description": resource.description,
                    "intents": list(resource.intents),
                    "capabilities": list(resource.capabilities),
                    "price": resource.price,
                    "automaticPaymentAllowed": self.settings.allows(resource.capability_id),
                }
            )
        return result

    async def call(self, capability_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        resources = await self._catalog()
        resource = next(
            (item for item in resources if item.capability_id == capability_id),
            None,
        )
        if resource is None:
            raise ValueError("capability is not present in the live paid manifest")
        if not self.settings.allows(capability_id):
            raise PermissionError(
                "capability is outside the operator-owned automatic payment allowlist"
            )
        path, request_kwargs = build_request(resource, arguments)
        x402_client = build_x402_client(
            self.settings,
            allowed_path=path,
            ledger=self.ledger,
        )
        async with wrapHttpxWithPayment(
            x402_client,
            base_url=self.settings.base_url,
            timeout=self.settings.timeout_seconds,
            follow_redirects=False,
        ) as client:
            response = await client.request(resource.method, path, **request_kwargs)
            body = await response.aread()
        if len(body) > self.settings.max_response_bytes:
            raise ValueError("Hyrule response exceeded the configured MCP response limit")
        response.raise_for_status()
        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            payload: object = response.json()
        else:
            payload = body.decode("utf-8", errors="replace")
        return {
            "capabilityId": capability_id,
            "status": response.status_code,
            "result": payload,
        }


def render(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)
