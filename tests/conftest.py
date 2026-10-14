from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_discovery_caches():
    """Readiness gates and the curated OpenAPI are memoised per process.

    Tests flip gates with monkeypatch, so every test starts and ends cold.
    """
    import hyrule_cloud.app as app_module
    from hyrule_cloud.services.discovery import clear_gate_cache

    clear_gate_cache()
    app_module._openapi_cache = None
    yield
    clear_gate_cache()
    app_module._openapi_cache = None
