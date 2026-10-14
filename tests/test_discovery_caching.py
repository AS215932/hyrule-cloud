from __future__ import annotations

from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.services import discovery


def test_gate_results_are_memoised_per_config(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_evaluate(gate: str, config=None) -> bool:
        calls.append(gate)
        return True

    monkeypatch.setattr(discovery, "_evaluate_gate", fake_evaluate)
    config = HyruleConfig()
    for _ in range(5):
        assert discovery._gate_enabled("real_vm", config)
    assert calls == ["real_vm"]

    # A different live config object is evaluated independently.
    assert discovery._gate_enabled("real_vm", HyruleConfig())
    assert calls == ["real_vm", "real_vm"]

    # No config means no memoisation (import-time tooling, ad-hoc callers).
    discovery._gate_enabled("real_vm")
    discovery._gate_enabled("real_vm")
    assert len(calls) == 4


def test_gate_cache_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter([False, True])
    monkeypatch.setattr(discovery, "_evaluate_gate", lambda gate, config=None: next(results))
    monkeypatch.setattr(discovery, "GATE_CACHE_TTL_SECONDS", 0.0)
    config = HyruleConfig()
    assert discovery._gate_enabled("tunnel", config) is False
    assert discovery._gate_enabled("tunnel", config) is True


@pytest.mark.asyncio
async def test_openapi_is_built_once_and_well_known_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    builds: list[int] = []
    real_build = discovery.build_curated_openapi

    def counting_build(application, config):
        builds.append(1)
        return real_build(application, config)

    monkeypatch.setattr(discovery, "build_curated_openapi", counting_build)
    # Keep the test hermetic: readiness gates may stat host paths.
    monkeypatch.setattr(discovery, "_evaluate_gate", lambda gate, config=None: True)
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig())
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            first = await client.get("/openapi.json")
            second = await client.get("/openapi.json")
            manifest = await client.get("/.well-known/x402.json")
            alias = await client.get("/.well-known/x402")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            del app.state._typed_state

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert len(builds) == 1
    assert manifest.status_code == alias.status_code == 200
    assert alias.json() == manifest.json()
    assert "/.well-known/x402" not in first.json()["paths"]
