"""Deterministic domain pricing in USD."""

from __future__ import annotations

from decimal import ROUND_CEILING, Decimal

from hyrule_cloud.config import DomainConfig
from hyrule_cloud.domains.models import MoneyBreakdown

_CENT = Decimal("0.01")


def ceil_cent(value: Decimal) -> Decimal:
    return value.quantize(_CENT, rounding=ROUND_CEILING)


def price_domain(provider_cost: Decimal, fx_rate: Decimal, config: DomainConfig) -> tuple[
    Decimal, Decimal, Decimal, Decimal
]:
    """Return provider USD cost, fee, tax, total; every payable amount rounds up."""
    provider_usd = ceil_cent(provider_cost * fx_rate)
    fee = ceil_cent(max(provider_usd * config.markup_percent, config.markup_min_usd))
    tax = Decimal("0.00")
    total = ceil_cent(provider_usd + fee + tax)
    return provider_usd, fee, tax, total


def money_breakdown(
    provider_usd: Decimal,
    fee: Decimal,
    tax: Decimal,
    total: Decimal,
) -> MoneyBreakdown:
    return MoneyBreakdown(
        provider_cost_usd=f"{provider_usd:.2f}",
        hyrule_fee_usd=f"{fee:.2f}",
        tax_usd=f"{tax:.2f}",
        total_usd=f"{total:.2f}",
    )
