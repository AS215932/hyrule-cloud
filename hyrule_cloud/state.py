from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi import Request

if TYPE_CHECKING:
    from hyrule_cloud.config import HyruleConfig
    from hyrule_cloud.middleware.x402 import PaymentGate
    from hyrule_cloud.orchestrator import Orchestrator
    from hyrule_cloud.providers.native_crypto import NativeCryptoProvider
    from hyrule_cloud.providers.network_client import NetworkProvider
    from hyrule_cloud.providers.prober_client import ProberProvider
    from hyrule_cloud.providers.rates import RateProvider


@dataclass
class AppState:
    config: HyruleConfig
    orchestrator: Orchestrator
    payment_gate: PaymentGate
    network_provider: NetworkProvider
    # Internal prober sidecar for /v1/path/* active measurements. Optional so
    # tests can construct AppState without it; path routes treat None as
    # "prober not configured" and refuse before charging.
    prober_provider: ProberProvider | None = field(default=None)
    # Block E: native crypto path. Optional so existing tests can wire only
    # what they need; routes that require them check for None.
    native_crypto: NativeCryptoProvider | None = field(default=None)
    rate_provider: RateProvider | None = field(default=None)
    native_payment_assets: list[str] = field(default_factory=list)
    # Block B: session factory for direct read-only metric queries from
    # /v1/stats/runtime — avoids routing every metric query through the
    # orchestrator. Typed Any so we don't need to import async_sessionmaker
    # at runtime when AppState is constructed in test fixtures.
    session_factory: Any | None = field(default=None)


def get_app_state(request: Request) -> AppState:
    return request.app.state._typed_state
