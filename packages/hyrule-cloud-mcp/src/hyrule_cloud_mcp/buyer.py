"""Buyer orchestration independent from the MCP transport."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
from x402.http.clients import wrapHttpxWithPayment

from hyrule_cloud_mcp.catalog import CatalogResource, build_request, fetch_catalog
from hyrule_cloud_mcp.config import Settings
from hyrule_cloud_mcp.payments import SpendLedger, build_x402_client

CatalogLoader = Callable[[str], Awaitable[list[CatalogResource]]]
_FOLLOWUP_PATH = re.compile(
    r"^/v1/(?:(?:bgp|mx|path|voip|web)/jobs/[A-Za-z0-9_-]+(?:/download)?|"
    r"vm/[A-Za-z0-9_-]+/status)$"
)


async def _read_limited(response: httpx.Response, maximum: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > maximum:
            raise ValueError("Hyrule response exceeded the configured MCP response limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_body(response: httpx.Response, body: bytes) -> object:
    media_type = response.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type == "application/json" or media_type.endswith("+json"):
        return json.loads(body)
    if media_type.startswith("text/") or media_type in {
        "application/javascript",
        "application/xml",
        "application/yaml",
    }:
        return body.decode(response.encoding or "utf-8", errors="replace")
    return {
        "encoding": "base64",
        "mediaType": media_type or "application/octet-stream",
        "bytes": len(body),
        "data": base64.b64encode(body).decode("ascii"),
    }


def _followup_path(base_url: str, value: str) -> str:
    parsed = urlsplit(value)
    base = urlsplit(base_url)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("follow-up URL must not contain credentials, a query, or a fragment")
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != base.scheme or parsed.netloc != base.netloc:
            raise ValueError("follow-up URL must use the configured Hyrule origin")
    elif not parsed.path.startswith("/") or value.startswith("//"):
        raise ValueError("follow-up URL must be absolute-path or use the Hyrule origin")
    if not _FOLLOWUP_PATH.fullmatch(parsed.path):
        raise ValueError("follow-up URL is not an allowed Hyrule status or artifact path")
    return parsed.path


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
                    "inputSchema": resource.input_schema,
                    "inputExample": resource.input_example,
                    "automaticPaymentAllowed": self.settings.allows_resource(
                        resource.capability_id, resource.path
                    ),
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
        if not self.settings.allows_resource(capability_id, resource.path):
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
            async with client.stream(resource.method, path, **request_kwargs) as response:
                body = await _read_limited(response, self.settings.max_response_bytes)
        response.raise_for_status()
        return {
            "capabilityId": capability_id,
            "status": response.status_code,
            "result": _decode_body(response, body),
        }

    async def follow(
        self, followup_url: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Fetch a returned status/artifact URL without enabling arbitrary GETs or payment."""

        path = _followup_path(self.settings.base_url, followup_url)
        supplied = arguments or {}
        if set(supplied) - {"token"}:
            raise ValueError("only a returned job access token may accompany a follow-up URL")
        token = supplied.get("token")
        if token is not None and not isinstance(token, str):
            raise ValueError("follow-up token must be a string")
        params = {"token": token} if token else None
        async with httpx.AsyncClient(
            base_url=self.settings.base_url,
            timeout=self.settings.timeout_seconds,
            follow_redirects=False,
        ) as client:
            async with client.stream("GET", path, params=params) as response:
                body = await _read_limited(response, self.settings.max_response_bytes)
        response.raise_for_status()
        return {
            "followUpUrl": path,
            "status": response.status_code,
            "result": _decode_body(response, body),
        }


def render(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)
