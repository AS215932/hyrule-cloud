from __future__ import annotations

from dataclasses import dataclass
from fastapi import Request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hyrule_cloud.config import HyruleConfig
    from hyrule_cloud.orchestrator import Orchestrator
    from hyrule_cloud.middleware.x402 import PaymentGate
    from hyrule_cloud.providers.network_client import NetworkProvider

@dataclass
class AppState:
    config: HyruleConfig
    orchestrator: Orchestrator
    payment_gate: PaymentGate
    network_provider: NetworkProvider

def get_app_state(request: Request) -> AppState:
    return request.app.state._typed_state
