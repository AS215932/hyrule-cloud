"""Agent-trust layer: dual-signed receipts, agent identity, x401, caller
binding. Everything here is flag-gated (TRUST_* env vars, default off) and
soft-fail — a broken or disabled trust layer must never break paid service.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from hyrule_cloud.trust.receipts import ReceiptService, load_signing_keys
from hyrule_cloud.trust.x401 import X401Service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from hyrule_cloud.config import HyruleConfig

log = structlog.get_logger()


@dataclass
class TrustServices:
    """DI container for trust-layer services, carried on AppState.trust."""

    receipts: ReceiptService
    # Optional so test fixtures that only exercise receipts stay small.
    x401: X401Service | None = None


def _api_version() -> str:
    try:
        from importlib.metadata import version

        return version("hyrule-cloud")
    except Exception:
        return "0.1.0"


def build_trust_services(
    config: HyruleConfig,
    session_factory: async_sessionmaker[AsyncSession] | None,
) -> TrustServices:
    """Construct trust services from config. With TRUST_RECEIPTS_ENABLED
    unset this returns disabled services (mint is a no-op returning None);
    the startup key guard — not this builder — decides whether a broken key
    is fatal."""
    keys = None
    if config.trust.receipts_enabled:
        try:
            keys = load_signing_keys(config.trust)
        except ValueError:
            # enforce_trust_key_guard already refused to boot in production;
            # reaching here means a test/dev context — run disabled.
            log.warning("trust_receipt_keys_unavailable", exc_info=True)
    receipts = ReceiptService(
        config.trust,
        session_factory,
        public_base_url=config.public_base_url,
        api_version=_api_version(),
        keys=keys,
    )
    x401 = X401Service(
        config.trust, session_factory, public_base_url=config.public_base_url
    )
    return TrustServices(receipts=receipts, x401=x401)
