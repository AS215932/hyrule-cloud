"""Prometheus exposition for "can Hyrule actually sell right now".

The gap these metrics close: an expired `XCPNG_XO_TOKEN` took every VM sale
down from 2026-08-01 to 2026-08-05. `/v1/vm/create` returned 503 the whole
time, but the only compute alert blackbox-probes `/health`, which stayed 200,
so nothing ever fired. Nothing measured whether a customer could buy anything.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hyrule_cloud.api import status as status_module
from hyrule_cloud.api.metrics import _render_commerce_readiness
from hyrule_cloud.api.status import ServiceState, probe_live_readiness


class _XOError(Exception):
    """Stands in for the XOError the provider raises on a rejected token."""


def _state(*, capacity=None, domains_ready=None) -> SimpleNamespace:
    orchestrator = SimpleNamespace()
    if capacity is not None:
        orchestrator.ensure_vm_capacity = capacity
    service = SimpleNamespace()
    if domains_ready is not None:
        service.public_discovery_ready = domains_ready
    return SimpleNamespace(orchestrator=orchestrator, domains=service)


async def _ok_capacity(_order: object) -> None:
    return None


async def _dead_xo_token(_order: object) -> None:
    raise _XOError("session.signInWithToken: {'message': 'invalid credentials', 'code': 3}")


async def _ready_domains() -> bool:
    return True


async def _unlaunched_domains() -> bool:
    return False


async def _broken_domains() -> bool:
    raise RuntimeError("catalog unreachable")


@pytest.fixture(autouse=True)
def _real_provisioning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default to production semantics; individual tests opt out."""
    monkeypatch.setattr(status_module, "use_real_provisioning", lambda: True)


async def _render(state: object) -> list[str]:
    lines: list[str] = []
    await _render_commerce_readiness(lines, state)
    return lines


@pytest.mark.asyncio
async def test_both_products_sellable_export_one() -> None:
    lines = await _render(_state(capacity=_ok_capacity, domains_ready=_ready_domains))
    assert "hyrule_vm_admission_ready 1" in lines
    assert "hyrule_domains_discovery_ready 1" in lines


@pytest.mark.asyncio
async def test_rejected_xo_token_exports_admission_zero() -> None:
    """The exact 2026-08 outage: XO auth dies, /health stays green."""
    lines = await _render(_state(capacity=_dead_xo_token, domains_ready=_ready_domains))
    assert "hyrule_vm_admission_ready 0" in lines
    # The registrar is a separate credential and must not be implicated.
    assert "hyrule_domains_discovery_ready 1" in lines


@pytest.mark.asyncio
async def test_unlaunched_domains_export_zero() -> None:
    lines = await _render(_state(capacity=_ok_capacity, domains_ready=_unlaunched_domains))
    assert "hyrule_domains_discovery_ready 0" in lines


@pytest.mark.asyncio
async def test_domains_probe_failure_omits_the_series() -> None:
    """A probe that could not run is not evidence the product is down."""
    lines = await _render(_state(capacity=_ok_capacity, domains_ready=_broken_domains))
    assert not any(line.startswith("hyrule_domains_discovery_ready") for line in lines)
    assert "hyrule_vm_admission_ready 1" in lines


@pytest.mark.asyncio
async def test_missing_capacity_hook_exports_zero() -> None:
    """No admission control wired up is a fail-closed condition, not silence."""
    lines = await _render(_state(domains_ready=_ready_domains))
    assert "hyrule_vm_admission_ready 0" in lines


@pytest.mark.asyncio
async def test_simulation_mode_omits_the_admission_series(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(status_module, "use_real_provisioning", lambda: False)
    lines = await _render(_state(capacity=_ok_capacity, domains_ready=_ready_domains))
    assert not any(line.startswith("hyrule_vm_admission_ready") for line in lines)
    assert "hyrule_domains_discovery_ready 1" in lines


@pytest.mark.asyncio
async def test_no_app_state_exports_nothing() -> None:
    assert await _render(None) == []


@pytest.mark.asyncio
async def test_help_and_type_precede_every_sample() -> None:
    """Exposition must stay parseable, not just contain the right numbers."""
    lines = await _render(_state(capacity=_dead_xo_token, domains_ready=_unlaunched_domains))
    for name in ("hyrule_vm_admission_ready", "hyrule_domains_discovery_ready"):
        assert f"# HELP {name} " in "\n".join(lines)
        assert f"# TYPE {name} gauge" in lines
        sample = next(i for i, line in enumerate(lines) if line.startswith(f"{name} "))
        assert lines[sample - 1] == f"# TYPE {name} gauge"


@pytest.mark.asyncio
async def test_probe_live_readiness_reports_both_probes() -> None:
    readiness = await probe_live_readiness(
        _state(capacity=_dead_xo_token, domains_ready=_ready_domains)
    )
    assert readiness.vm_admission is False
    assert readiness.domains is ServiceState.OPERATIONAL
