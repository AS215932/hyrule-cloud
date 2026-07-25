from decimal import Decimal

import pytest

from hyrule_cloud.models import VMCreateRequest, VMSize
from hyrule_cloud.services.vm_pricing import (
    VMResourceValidationError,
    current_daily_price_for_vm,
    price_vm_order,
)


class _Payment:
    price_vm_xs = Decimal("0.20")
    price_vm_sm = Decimal("0.40")
    price_vm_md = Decimal("0.60")
    price_vm_lg = Decimal("0.80")
    price_vm_addon_vcpu = Decimal("0.10")
    price_vm_addon_ram_gb = Decimal("0.15")
    price_vm_addon_disk_10gb = Decimal("0.05")


def _order(size: VMSize, resources: dict[str, int]) -> VMCreateRequest:
    return VMCreateRequest(
        duration_days=1,
        size=size,
        resources=resources,
        ssh_pubkey="ssh-ed25519 AAAA test",
    )


def test_exact_profile_wins_equal_price_tie() -> None:
    priced = price_vm_order(
        _order(VMSize.XS, {"vcpu": 1, "ram_mb": 2048, "disk_gb": 20}),
        _Payment(),
    )
    assert priced.order.size == VMSize.SM
    assert priced.daily_price == Decimal("0.40")
    assert priced.breakdown.addon_vcpu == 0
    assert priced.breakdown.addon_ram_mb == 0
    assert priced.breakdown.addon_disk_gb == 0


def test_maximum_configuration_is_lg_plus_four_gb_ram() -> None:
    priced = price_vm_order(
        _order(VMSize.XS, {"vcpu": 4, "ram_mb": 8192, "disk_gb": 40}),
        _Payment(),
    )
    assert priced.order.size == VMSize.LG
    assert priced.daily_price == Decimal("1.40")
    assert priced.breakdown.addon_ram_mb == 4096
    assert priced.breakdown.addon_ram_usd_day == "0.60"


def test_original_profile_does_not_change_price_or_canonical_result() -> None:
    resources = {"vcpu": 3, "ram_mb": 6144, "disk_gb": 30}
    results = [price_vm_order(_order(size, resources), _Payment()) for size in VMSize]
    assert {result.order.size for result in results} == {VMSize.MD}
    assert {result.daily_price for result in results} == {Decimal("1.05")}


def test_pricing_snapshot_preserves_sub_cent_configured_amounts() -> None:
    payment = _Payment()
    payment.price_vm_xs = Decimal("0.005")

    priced = price_vm_order(
        _order(VMSize.XS, {"vcpu": 1, "ram_mb": 1024, "disk_gb": 10}),
        payment,
    )

    assert priced.total == Decimal("0.005")
    assert priced.breakdown.base_price_usd_day == "0.005"
    assert priced.breakdown.daily_price_usd == "0.005"
    assert priced.breakdown.total_usd == "0.005"
    assert Decimal(priced.pricing_snapshot["total_usd"]) == priced.total


@pytest.mark.parametrize(
    "resources",
    [
        {"vcpu": 5, "ram_mb": 4096, "disk_gb": 20},
        {"vcpu": 2, "ram_mb": 9216, "disk_gb": 20},
        {"vcpu": 2, "ram_mb": 4096, "disk_gb": 50},
    ],
)
def test_order_caps_are_enforced(resources: dict[str, int]) -> None:
    with pytest.raises(VMResourceValidationError):
        price_vm_order(_order(VMSize.XS, resources), _Payment())


def test_extensions_use_current_base_and_stored_addon_quantities() -> None:
    row = type(
        "VM",
        (),
        {
            "size": VMSize.LG,
            "billing_addon_vcpu": 0,
            "billing_addon_ram_mb": 4096,
            "billing_addon_disk_gb": 0,
        },
    )()
    assert current_daily_price_for_vm(row, _Payment()) == Decimal("1.40")


def test_legacy_extensions_do_not_reinterpret_retired_disk_as_addon() -> None:
    row = type(
        "VM",
        (),
        {
            "size": VMSize.LG,
            "disk_gb": 80,
            "billing_addon_vcpu": 0,
            "billing_addon_ram_mb": 0,
            "billing_addon_disk_gb": 0,
        },
    )()
    assert current_daily_price_for_vm(row, _Payment()) == Decimal("0.80")
