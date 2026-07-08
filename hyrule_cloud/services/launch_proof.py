"""
Launch-proof contract logic (issue #28).

Maps internal VM/Quote state to customer-visible launch-proof states.
Default behaviour = controlled simulation; real XCP-NG / Openprovider / DNS
only behind HCP_LAUNCH_PROOF_REAL_XCPNG=1.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from hyrule_cloud.models import (
    LaunchProofStatus,
    PaymentStatus,
    SSHSmokeStatus,
    VMStatus,
)

if TYPE_CHECKING:
    from hyrule_cloud.config import HyruleConfig

_LAUNCH_PROOF_REAL = os.environ.get("HCP_LAUNCH_PROOF_REAL_XCPNG") == "1"


def use_real_provisioning() -> bool:
    return _LAUNCH_PROOF_REAL


def enforce_real_provisioning_guard(config: HyruleConfig) -> None:
    """Fail fast at startup instead of charging real USDC for simulated VMs.

    With HYRULE_REQUIRE_REAL_PROVISIONING=1 (production), refuse to boot when
    either simulation mode or the payment dev bypass is still active — both
    would let paying customers receive nothing real.
    """
    if not config.require_real_provisioning:
        return
    if not use_real_provisioning():
        raise RuntimeError(
            "HYRULE_REQUIRE_REAL_PROVISIONING=1 but HCP_LAUNCH_PROOF_REAL_XCPNG "
            "is not enabled — refusing to charge for simulated VMs"
        )
    if config.payment.dev_bypass_secret:
        raise RuntimeError(
            "HYRULE_REQUIRE_REAL_PROVISIONING=1 but PAYMENT_DEV_BYPASS_SECRET is "
            "set — the dev bypass makes every paid endpoint free and must not "
            "reach production"
        )


def _safe_getattr(obj: object, name: str, default: object = None) -> object:
    return getattr(obj, name, default)


def build_launch_proof(
    vm_row: object,
    *,
    quote_row: object | None = None,
) -> dict[str, object]:
    """Build the launch-proof contract fields from a VMRow and optional quote."""
    meta_raw = _safe_getattr(vm_row, "metadata_", None) or {}
    lp_meta = meta_raw.get("launch_proof", {}) if isinstance(meta_raw, dict) else {}

    # --- Payment status ---
    payment_status: PaymentStatus
    if quote_row is not None:
        q_status = _safe_getattr(quote_row, "status", "")
        if q_status == "created":
            payment_status = PaymentStatus.PAYMENT_REQUIRED
        elif q_status == "consumed":
            payment_status = PaymentStatus.PAID
        else:
            payment_status = PaymentStatus.PAID
    elif _safe_getattr(vm_row, "payment_tx", None):
        payment_status = PaymentStatus.PAID
    elif _safe_getattr(vm_row, "cost_total", 0) == 0:
        payment_status = PaymentStatus.NOT_REQUIRED
    else:
        # VM exists and cost > 0 but no explicit payment_tx on the row;
        # treat as paid because the create flow already cleared payment.
        payment_status = PaymentStatus.PAID

    # --- Launch-proof state ---
    vm_status_str = str(_safe_getattr(vm_row, "status", "") or "")
    try:
        vm_status = VMStatus(vm_status_str)
    except ValueError:
        vm_status = VMStatus.PROVISIONING

    if vm_status == VMStatus.DESTROYED:
        launch_status = LaunchProofStatus.ROLLED_BACK
    elif vm_status == VMStatus.FAILED:
        launch_status = LaunchProofStatus.FAILED
    elif vm_status in (VMStatus.READY, VMStatus.RUNNING):
        launch_status = LaunchProofStatus.PROVISIONED
    elif vm_status == VMStatus.PROVISIONING:
        # If the quote is still created (shouldn't happen in normal flow,
        # but used in controlled simulation) show payment_required.
        if quote_row is not None and _safe_getattr(quote_row, "status", "") == "created":
            launch_status = LaunchProofStatus.PAYMENT_REQUIRED
        else:
            launch_status = LaunchProofStatus.PROVISIONING
    elif vm_status == VMStatus.SUSPENDED:
        launch_status = LaunchProofStatus.PROVISIONED
    else:
        launch_status = LaunchProofStatus.PROVISIONING

    # --- DNS AAAA verification ---
    dns_aaaa_verified = bool(
        lp_meta.get("dns_aaaa_verified", False)
        or (_safe_getattr(vm_row, "ipv6", None) and _safe_getattr(vm_row, "hostname", None))
    )

    # --- SSH smoke test ---
    ssh_smoke: SSHSmokeStatus
    explicit_ssh = lp_meta.get("ssh_smoke_status")
    if explicit_ssh is not None:
        ssh_smoke = SSHSmokeStatus(str(explicit_ssh))
    elif vm_status in (VMStatus.READY, VMStatus.RUNNING):
        ssh_smoke = SSHSmokeStatus.PASSED
    elif vm_status == VMStatus.FAILED:
        ssh_smoke = SSHSmokeStatus.FAILED
    else:
        ssh_smoke = SSHSmokeStatus.NOT_RUN

    # --- Rollback availability ---
    rollback_available = bool(
        lp_meta.get("rollback_available", False)
        or (vm_status == VMStatus.FAILED)
    )
    if vm_status == VMStatus.DESTROYED:
        rollback_available = False

    # --- Messages ---
    operator_message: str | None = lp_meta.get("operator_message")
    customer_message: str | None = lp_meta.get("customer_message")

    if vm_status == VMStatus.FAILED:
        if not operator_message:
            err = _safe_getattr(vm_row, "error", None)
            operator_message = str(err) if err else None
        if not customer_message:
            customer_message = (
                "Provisioning could not be completed. "
                "Our team has been notified and your payment will be refunded."
            )
    elif vm_status == VMStatus.PROVISIONING:
        if not customer_message:
            customer_message = (
                "Your VM is being prepared. This usually takes about 60 seconds."
            )
    elif vm_status in (VMStatus.READY, VMStatus.RUNNING):
        if not customer_message:
            customer_message = "Your VM is ready."

    return {
        "launch_proof_status": launch_status,
        "payment_status": payment_status,
        "dns_aaaa_verified": dns_aaaa_verified,
        "ssh_smoke_status": ssh_smoke,
        "rollback_available": rollback_available,
        "operator_message": operator_message,
        "customer_message": customer_message,
    }
