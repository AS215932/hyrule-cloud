"""Live-manifest discovery and safe request construction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote

import httpx

from hyrule_cloud_mcp.config import USDC_ATOMIC_UNITS

_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")


class CatalogError(ValueError):
    """The live catalog or requested capability is not safe to execute."""


@dataclass(frozen=True, slots=True)
class CatalogResource:
    capability_id: str
    method: str
    path: str
    description: str
    intents: tuple[str, ...]
    capabilities: tuple[str, ...]
    price: dict[str, Any]
    input_schema: dict[str, Any] = field(default_factory=dict)
    input_example: dict[str, Any] = field(default_factory=dict)

    def payment_bounds_atomic(self) -> tuple[int, int | None]:
        if self.price.get("currency") != "USD":
            raise CatalogError("catalog price currency must be USD")
        mode = self.price.get("mode")
        if mode == "fixed":
            amount = _price_atomic(self.price.get("amount"), "amount")
            return amount, amount
        if mode != "dynamic":
            raise CatalogError("catalog price mode must be fixed or dynamic")
        minimum = _price_atomic(self.price.get("min"), "min")
        raw_maximum = self.price.get("max")
        maximum = _price_atomic(raw_maximum, "max") if raw_maximum is not None else None
        if maximum is not None and maximum < minimum:
            raise CatalogError("catalog dynamic price max must be at least min")
        return minimum, maximum

    @classmethod
    def from_json(cls, value: object) -> CatalogResource:
        if not isinstance(value, dict):
            raise CatalogError("catalog resource must be an object")
        capability_id = value.get("id")
        method = value.get("method")
        path = value.get("path")
        if not isinstance(capability_id, str) or not capability_id.startswith("hyrule."):
            raise CatalogError("catalog resource has no stable Hyrule capability ID")
        if method not in {"GET", "POST"}:
            raise CatalogError("buyer MCP only supports GET and POST resources")
        if not isinstance(path, str) or not path.startswith("/v1/") or "//" in path:
            raise CatalogError("catalog resource has an unsafe path")
        area = path.removeprefix("/v1/").split("/", 1)[0]
        if not capability_id.startswith(f"hyrule.{area}."):
            raise CatalogError("catalog capability ID does not match its path")
        intents = value.get("intents") or []
        capabilities = value.get("capabilities") or []
        if not isinstance(intents, list) or not all(isinstance(item, str) for item in intents):
            raise CatalogError("catalog resource intents must be strings")
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) for item in capabilities
        ):
            raise CatalogError("catalog resource capabilities must be strings")
        price = value.get("price")
        input_schema = value.get("inputSchema")
        input_example = value.get("inputExample")
        resource = cls(
            capability_id=capability_id,
            method=method,
            path=path,
            description=str(value.get("description") or ""),
            intents=tuple(intents),
            capabilities=tuple(capabilities),
            price=price if isinstance(price, dict) else {},
            input_schema=input_schema if isinstance(input_schema, dict) else {},
            input_example=input_example if isinstance(input_example, dict) else {},
        )
        resource.payment_bounds_atomic()
        return resource


def _price_atomic(value: object, field_name: str) -> int:
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise CatalogError(f"catalog price {field_name} must be decimal USD") from exc
    scaled = decimal * USDC_ATOMIC_UNITS
    if decimal <= 0 or scaled != scaled.to_integral_value():
        raise CatalogError(
            f"catalog price {field_name} must be positive with at most six decimal places"
        )
    return int(scaled)


def parse_manifest(value: object) -> list[CatalogResource]:
    if not isinstance(value, dict) or str(value.get("x402Version")) != "2":
        raise CatalogError("Hyrule manifest is missing x402Version 2")
    resources = value.get("resources")
    if not isinstance(resources, list):
        raise CatalogError("Hyrule manifest has no resources array")
    parsed = [CatalogResource.from_json(item) for item in resources]
    ids = [resource.capability_id for resource in parsed]
    if len(ids) != len(set(ids)):
        raise CatalogError("Hyrule manifest contains duplicate capability IDs")
    return parsed


def build_request(
    resource: CatalogResource,
    arguments: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    remaining = dict(arguments)

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = remaining.pop(name, None)
        if value is None or isinstance(value, (dict, list)):
            raise CatalogError(f"path parameter {name!r} must be a scalar")
        return quote(str(value), safe="")

    path = _PATH_PARAMETER.sub(replace, resource.path)
    if "{" in path or "}" in path:
        raise CatalogError("unresolved path parameter")
    if resource.method == "GET":
        return path, {"params": remaining}
    return path, {"json": remaining}


async def fetch_catalog(base_url: str, *, timeout: float = 30.0) -> list[CatalogResource]:
    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=False,
    ) as client:
        response = await client.get("/.well-known/x402.json")
        response.raise_for_status()
        return parse_manifest(response.json())
