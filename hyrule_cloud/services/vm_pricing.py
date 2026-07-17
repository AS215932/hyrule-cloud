"""Canonical VM resource selection and pricing.

Profiles are shortcuts, not hard provisioning limits. A requested final
configuration is priced from every compatible profile and rebound to the
cheapest one so identical resources always have one price.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from hyrule_cloud.models import (
    VM_PROFILE_LABELS,
    VM_SPECS,
    VMAddonPrices,
    VMCreateRequest,
    VMCustomization,
    VMOrderResources,
    VMPriceBreakdown,
    VMResourceLimits,
    VMResourceSpec,
    VMSize,
)

MIN_RESOURCES = VMResourceLimits(vcpu=1, ram_mb=1024, disk_gb=10)
MAX_RESOURCES = VMResourceLimits(vcpu=4, ram_mb=8192, disk_gb=40)
RESOURCE_INCREMENTS = VMResourceLimits(vcpu=1, ram_mb=1024, disk_gb=10)

DEFAULT_BASE_PRICES: dict[VMSize, Decimal] = {
    VMSize.XS: Decimal("0.20"),
    VMSize.SM: Decimal("0.40"),
    VMSize.MD: Decimal("0.60"),
    VMSize.LG: Decimal("0.80"),
}
DEFAULT_ADDON_VCPU = Decimal("0.10")
DEFAULT_ADDON_RAM_GB = Decimal("0.15")
DEFAULT_ADDON_DISK_10GB = Decimal("0.05")


class VMResourceValidationError(ValueError):
    """The requested final configuration is outside the order contract."""


def _money(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01')):.2f}"


def resources_for_profile(size: VMSize) -> VMOrderResources:
    spec = VM_SPECS[size]
    return VMOrderResources(
        vcpu=spec["vcpu"],
        ram_mb=spec["memory_mb"],
        disk_gb=spec["disk_gb"],
    )


def requested_resources(order: VMCreateRequest) -> VMOrderResources:
    return order.resources or resources_for_profile(order.size)


def base_prices(payment: Any) -> dict[VMSize, Decimal]:
    return {
        size: Decimal(str(getattr(payment, f"price_vm_{size.value}", fallback)))
        for size, fallback in DEFAULT_BASE_PRICES.items()
    }


def addon_prices(payment: Any) -> tuple[Decimal, Decimal, Decimal]:
    return (
        Decimal(str(getattr(payment, "price_vm_addon_vcpu", DEFAULT_ADDON_VCPU))),
        Decimal(str(getattr(payment, "price_vm_addon_ram_gb", DEFAULT_ADDON_RAM_GB))),
        Decimal(
            str(getattr(payment, "price_vm_addon_disk_10gb", DEFAULT_ADDON_DISK_10GB))
        ),
    )


def customization_contract(payment: Any) -> VMCustomization:
    cpu, ram, disk = addon_prices(payment)
    return VMCustomization(
        minimum=MIN_RESOURCES,
        maximum=MAX_RESOURCES,
        increments=RESOURCE_INCREMENTS,
        addon_prices=VMAddonPrices(
            vcpu_usd_day=_money(cpu),
            ram_gb_usd_day=_money(ram),
            disk_10gb_usd_day=_money(disk),
        ),
    )


def validate_new_order_resources(resources: VMResourceSpec) -> None:
    if not MIN_RESOURCES.vcpu <= resources.vcpu <= MAX_RESOURCES.vcpu:
        raise VMResourceValidationError("vcpu must be between 1 and 4")
    if not MIN_RESOURCES.ram_mb <= resources.ram_mb <= MAX_RESOURCES.ram_mb:
        raise VMResourceValidationError("ram_mb must be between 1024 and 8192")
    if not MIN_RESOURCES.disk_gb <= resources.disk_gb <= MAX_RESOURCES.disk_gb:
        raise VMResourceValidationError("disk_gb must be between 10 and 40")
    if resources.ram_mb % RESOURCE_INCREMENTS.ram_mb:
        raise VMResourceValidationError("ram_mb must be a whole number of GiB")
    if resources.disk_gb % RESOURCE_INCREMENTS.disk_gb:
        raise VMResourceValidationError("disk_gb must be in 10-GB increments")


@dataclass(frozen=True)
class PricedVMOrder:
    order: VMCreateRequest
    resources: VMOrderResources
    daily_price: Decimal
    total: Decimal
    breakdown: VMPriceBreakdown

    @property
    def pricing_snapshot(self) -> dict[str, Any]:
        return self.breakdown.model_dump(mode="json")


def price_vm_order(order: VMCreateRequest, payment: Any) -> PricedVMOrder:
    resources = requested_resources(order)
    validate_new_order_resources(resources)
    prices = base_prices(payment)
    cpu_rate, ram_rate, disk_rate = addon_prices(payment)

    candidates: list[tuple[tuple[Decimal, int, int, int], VMSize, tuple[int, int, int]]] = []
    for position, size in enumerate(VMSize):
        base = resources_for_profile(size)
        if (
            base.vcpu > resources.vcpu
            or base.ram_mb > resources.ram_mb
            or base.disk_gb > resources.disk_gb
        ):
            continue
        addon_vcpu = resources.vcpu - base.vcpu
        addon_ram_mb = resources.ram_mb - base.ram_mb
        addon_disk_gb = resources.disk_gb - base.disk_gb
        daily = (
            prices[size]
            + Decimal(addon_vcpu) * cpu_rate
            + Decimal(addon_ram_mb // 1024) * ram_rate
            + Decimal(addon_disk_gb // 10) * disk_rate
        )
        exact = int(bool(addon_vcpu or addon_ram_mb or addon_disk_gb))
        addon_units = addon_vcpu + addon_ram_mb // 1024 + addon_disk_gb // 10
        candidates.append(
            ((daily, exact, addon_units, position), size, (addon_vcpu, addon_ram_mb, addon_disk_gb))
        )

    if not candidates:  # XS is the global minimum, so validation should make this unreachable.
        raise VMResourceValidationError("no compatible VM profile")

    (daily, _, _, _), size, addons = min(candidates, key=lambda candidate: candidate[0])
    addon_vcpu, addon_ram_mb, addon_disk_gb = addons
    duration = order.duration_days
    total = daily * duration
    canonical = order.model_copy(update={"size": size, "resources": resources})
    breakdown = VMPriceBreakdown(
        base_profile=size,
        base_label=VM_PROFILE_LABELS[size],
        base_price_usd_day=_money(prices[size]),
        addon_vcpu=addon_vcpu,
        addon_ram_mb=addon_ram_mb,
        addon_disk_gb=addon_disk_gb,
        addon_vcpu_usd_day=_money(Decimal(addon_vcpu) * cpu_rate),
        addon_ram_usd_day=_money(Decimal(addon_ram_mb // 1024) * ram_rate),
        addon_disk_usd_day=_money(Decimal(addon_disk_gb // 10) * disk_rate),
        daily_price_usd=_money(daily),
        duration_days=duration,
        total_usd=_money(total),
    )
    return PricedVMOrder(
        order=canonical,
        resources=resources,
        daily_price=daily,
        total=total,
        breakdown=breakdown,
    )


def legacy_pricing_snapshot(order: VMCreateRequest, amount: Decimal) -> VMPriceBreakdown:
    """Render a migrated pre-customization quote without changing its economics."""
    daily = amount / order.duration_days
    return VMPriceBreakdown(
        base_profile=order.size,
        base_label=VM_PROFILE_LABELS[order.size],
        base_price_usd_day=_money(daily),
        daily_price_usd=_money(daily),
        duration_days=order.duration_days,
        total_usd=_money(amount),
    )


def billing_addons_from_snapshot(snapshot: dict[str, Any] | None) -> tuple[int, int, int]:
    """Legacy rows/snapshots intentionally carry zero historical add-ons."""
    if not snapshot:
        return 0, 0, 0
    return (
        int(snapshot.get("addon_vcpu", 0)),
        int(snapshot.get("addon_ram_mb", 0)),
        int(snapshot.get("addon_disk_gb", 0)),
    )


def current_daily_price_for_vm(row: Any, payment: Any) -> Decimal:
    prices = base_prices(payment)
    cpu_rate, ram_rate, disk_rate = addon_prices(payment)
    return (
        prices[VMSize(row.size)]
        + Decimal(int(getattr(row, "billing_addon_vcpu", 0) or 0)) * cpu_rate
        + Decimal(int(getattr(row, "billing_addon_ram_mb", 0) or 0) // 1024) * ram_rate
        + Decimal(int(getattr(row, "billing_addon_disk_gb", 0) or 0) // 10) * disk_rate
    )
