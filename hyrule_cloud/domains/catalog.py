"""Fail-closed IANA/OpenProvider TLD catalog synchronization."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import DomainConfig
from hyrule_cloud.db import DomainTLDRow
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.providers.openprovider import OpenproviderClient

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class _IanaTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_cell = False
        self.cells: list[str] = []
        self.cell_parts: list[str] = []
        self.types: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"td", "th"}:
            self.in_cell = True
            self.cell_parts = []

    def handle_data(self, data: str) -> None:
        if self.in_cell:
            self.cell_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self.in_cell:
            self.cells.append(" ".join("".join(self.cell_parts).split()))
            self.in_cell = False
        if tag == "tr":
            self._finish_row()

    def close(self) -> None:
        super().close()
        self._finish_row()

    def _finish_row(self) -> None:
        if len(self.cells) >= 2:
            tld = self.cells[0].strip().lower().lstrip(".")
            kind = self.cells[1].strip().lower()
            if tld and kind in {
                "generic",
                "generic-restricted",
                "sponsored",
                "country-code",
                "infrastructure",
                "test",
            }:
                self.types[tld] = kind
        self.cells = []


def parse_iana_root_db(html: str) -> dict[str, str]:
    parser = _IanaTableParser()
    parser.feed(html)
    parser.close()
    if not parser.types:
        raise ValueError("IANA root database contained no recognizable TLD rows")
    return parser.types


class DomainCatalog:
    def __init__(
        self,
        config: DomainConfig,
        session_factory: async_sessionmaker[AsyncSession],
        provider: OpenproviderClient,
    ) -> None:
        self.config = config
        self.db = session_factory
        self.provider = provider

    async def sync(self) -> int:
        """Refresh the provider/IANA intersection; old data survives a failed refresh."""
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            response = await client.get(self.config.iana_root_db_url)
            response.raise_for_status()
            iana = parse_iana_root_db(response.text)
        provider_tlds = await self.provider.list_tlds()
        refreshed_at = _now()
        rows: list[DomainTLDRow] = []
        for raw in provider_tlds:
            tld = _tld_name(raw)
            if not tld:
                continue
            iana_type = iana.get(tld)
            registration, reg_currency = _operation_price(raw, {"create", "register", "registration"})
            renewal, renewal_currency = _operation_price(raw, {"renew", "renewal"})
            # A single cached currency is used for both operation prices. Fail
            # closed if the provider ever reports different currencies rather
            # than silently converting one price with the other's FX rate.
            currency = (
                reg_currency
                if reg_currency and renewal_currency and reg_currency == renewal_currency
                else None
            )
            reason = _ineligible_reason(
                tld=tld,
                iana_type=iana_type,
                raw=raw,
                registration=registration,
                renewal=renewal,
                currency=currency,
                allowlist={item.lower().lstrip(".") for item in self.config.tld_allowlist},
            )
            rows.append(
                DomainTLDRow(
                    tld=tld,
                    iana_type=iana_type,
                    provider_status=str(raw.get("status") or "")[:32] or None,
                    eligible=reason is None,
                    ineligible_reason=reason,
                    registration_cost=registration,
                    renewal_cost=renewal,
                    currency=currency,
                    metadata_=raw,
                    refreshed_at=refreshed_at,
                )
            )
        if not rows:
            raise RuntimeError("OpenProvider returned no usable TLD metadata")
        async with self.db() as session:
            for row in rows:
                existing = await session.get(DomainTLDRow, row.tld)
                if existing is None:
                    session.add(row)
                    continue
                for field in (
                    "iana_type",
                    "provider_status",
                    "eligible",
                    "ineligible_reason",
                    "registration_cost",
                    "renewal_cost",
                    "currency",
                    "metadata_",
                    "refreshed_at",
                ):
                    setattr(existing, field, getattr(row, field))
            await session.commit()
        log.info("domain_catalog_refreshed", tlds=len(rows), eligible=sum(row.eligible for row in rows))
        return len(rows)

    async def get(self, tld: str, *, require_eligible: bool = True) -> DomainTLDRow:
        async with self.db() as session:
            row = await session.get(DomainTLDRow, tld.lower().lstrip("."))
        if row is None:
            raise DomainProblem(422, "unsupported_tld", "That top-level domain is not supported.")
        if _aware(row.refreshed_at) < _now() - timedelta(seconds=self.config.catalog_max_age_seconds):
            raise DomainProblem(
                503,
                "catalog_stale",
                "Domain pricing is temporarily unavailable while the registrar catalog refreshes.",
                headers={"Retry-After": "300"},
            )
        if require_eligible and not row.eligible:
            raise DomainProblem(
                422,
                "unsupported_tld",
                "That top-level domain is not eligible for Hyrule registration.",
            )
        return row

    async def list_eligible(self) -> list[DomainTLDRow]:
        async with self.db() as session:
            result = await session.scalars(
                select(DomainTLDRow).where(DomainTLDRow.eligible.is_(True)).order_by(DomainTLDRow.tld)
            )
            rows = list(result)
        if rows and any(
            _aware(row.refreshed_at) < _now() - timedelta(seconds=self.config.catalog_max_age_seconds)
            for row in rows
        ):
            raise DomainProblem(503, "catalog_stale", "Domain pricing is temporarily unavailable.")
        return rows


def _tld_name(raw: dict[str, Any]) -> str | None:
    value: Any = raw.get("name") or raw.get("extension") or raw.get("tld")
    if isinstance(value, dict):
        value = value.get("name") or value.get("extension")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().lstrip(".")
    if not normalized or "." in normalized or normalized.startswith("xn--"):
        return None
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError:
        return None
    return normalized


def _operation_price(
    raw: dict[str, Any], operations: set[str]
) -> tuple[Decimal | None, str | None]:
    matches: list[tuple[Decimal, str | None]] = []

    def walk(node: Any, context: str = "") -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, context)
            return
        if not isinstance(node, dict):
            return
        operation = " ".join(
            str(node.get(key) or "") for key in ("operation", "action", "type", "name")
        ).lower()
        new_context = f"{context} {operation}".strip()
        if any(term in new_context for term in operations):
            amount, currency = _price_from_node(node)
            if amount is not None:
                matches.append((amount, currency))
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                walk(value, f"{new_context} {key.lower()}")

    walk(raw)
    if matches:
        return matches[0]
    # Compact OpenProvider responses can expose the registration price at the
    # top level without an operation label. Only use that fallback for create.
    if "create" in operations or "register" in operations:
        return _price_from_node(raw)
    return None, None


def _price_from_node(node: dict[str, Any]) -> tuple[Decimal | None, str | None]:
    candidates: list[tuple[Any, Any]] = []
    reseller = node.get("reseller")
    product = node.get("product")
    if isinstance(reseller, dict):
        candidates.append((reseller.get("price") or reseller.get("amount"), reseller.get("currency")))
    if isinstance(product, dict):
        candidates.append((product.get("price") or product.get("amount"), product.get("currency")))
    price = node.get("price")
    if isinstance(price, dict):
        candidates.append((price.get("price") or price.get("amount"), price.get("currency")))
    else:
        candidates.append((price or node.get("amount") or node.get("price_amount"), node.get("currency") or node.get("price_currency")))
    for raw_amount, raw_currency in candidates:
        if raw_amount is None:
            continue
        try:
            amount = Decimal(str(raw_amount))
        except (InvalidOperation, TypeError, ValueError):
            continue
        if amount >= 0:
            return amount, str(raw_currency or "USD").upper()
    return None, None


def _ineligible_reason(
    *,
    tld: str,
    iana_type: str | None,
    raw: dict[str, Any],
    registration: Decimal | None,
    renewal: Decimal | None,
    currency: str | None,
    allowlist: set[str],
) -> str | None:
    if allowlist and tld not in allowlist:
        return "not_allowlisted"
    if iana_type != "generic":
        return f"iana_{iana_type or 'unknown'}"
    status = str(raw.get("status") or "").lower()
    if status and status not in {"act", "active", "available", "enabled", "ok"}:
        return "provider_inactive"
    for key in ("is_restricted", "requires_additional_data"):
        if raw.get(key) is True:
            return key
    for key in ("registration_allowed", "is_available", "is_active"):
        if raw.get(key) is False:
            return key
    application_mode = str(raw.get("application_mode") or "").lower()
    if application_mode and application_mode not in {"ga", "general_availability"}:
        return "not_general_availability"
    if registration is None or renewal is None or not currency:
        return "price_unavailable"
    if registration <= 0 or renewal <= 0:
        return "invalid_price"
    return None
