"""
Hyrule Cloud API server.

Agentic VPS hosting on AS215932 with x402 payments.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from hyrule_cloud.api.auth import router as auth_router
from hyrule_cloud.api.routes import router
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import create_db_engine, create_session_factory, init_db
from hyrule_cloud.middleware.metrics import install_metrics
from hyrule_cloud.middleware.x402 import PaymentGate
from hyrule_cloud.orchestrator import Orchestrator

# Newline-delimited JSON to stdout per AS215932's application logging
# contract (hyrule-infra/docs/application-logging.md). systemd-journald
# captures it; the host's Vector agent ships to Loki.
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        structlog.contextvars.merge_contextvars,
        structlog.processors.dict_tracebacks,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger().bind(service="hyrule-cloud")


from hyrule_cloud.state import AppState


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = HyruleConfig()

    # Database
    engine = create_db_engine(config.database_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)

    # Payment gate (official x402 SDK)
    payment_gate = PaymentGate(config.payment)

    # Network client
    from hyrule_cloud.providers.network_client import NetworkProvider
    network_provider = NetworkProvider()

    # Orchestrator
    orchestrator = Orchestrator(config, session_factory)
    await orchestrator.startup()

    # Wire up app state
    app.state._typed_state = AppState(
        config=config,
        orchestrator=orchestrator,
        payment_gate=payment_gate,
        network_provider=network_provider,
    )

    # Expiry scheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(orchestrator.check_expiries, "interval", minutes=5)
    scheduler.start()

    log.info(
        "hyrule_cloud_started",
        deploy_domain=config.deploy_domain,
        database=config.database_url.split("@")[-1] if "@" in config.database_url else "local",
    )

    yield

    scheduler.shutdown()
    await orchestrator.shutdown()
    await network_provider.close()
    await engine.dispose()
    log.info("hyrule_cloud_stopped")


app = FastAPI(
    title="Hyrule Cloud",
    description=(
        "Agentic VPS hosting with x402 payments. "
        "Deploy bare VMs with SSH access, automatic DNS, and "
        "IPv6-native networking on AS215932. "
        "Payment via USDC across EVM, Solana, Hyperliquid, or native crypto (BTC, XMR)."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)
# Block A1 (Wave 2): /v1/auth/* and /v1/me/* live in api/auth.py.
app.include_router(auth_router)

# Block B (Wave 2): per-process request-latency middleware feeds
# `/v1/stats/runtime`. Cheap (one perf_counter per request + O(1) deque
# append) and bounded in memory.
install_metrics(app)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "hyrule-cloud"}


@app.get("/.well-known/x402.json")
async def x402_manifest():
    """x402 service manifest for agent discovery."""
    config: HyruleConfig = app.state._typed_state.config
    return {
        "x402Version": 2,
        "name": "Hyrule Cloud",
        "description": (
            "Bare VM hosting for AI agents. Deploy VMs with SSH access, "
            "automatic HTTPS subdomains, and IPv6-native networking. "
            "Pay with multi-chain USDC or native un-smart contracts."
        ),
        "resources": [
            {
                "path": "/v1/vm/create",
                "method": "POST",
                "description": "Provision a bare VM with SSH access",
                "minPrice": str(config.payment.price_vm_xs),
                "networks": config.payment.networks,
            },
            {
                "path": "/v1/domain/register",
                "method": "POST",
                "description": "Register a domain via Openprovider",
                "minPrice": str(config.payment.price_domain_markup + 5),
                "networks": config.payment.networks,
            },
            {
                "path": "/v1/network/request",
                "method": "POST",
                "description": "Make a micro-proxy network request (Clearnet/Tor)",
                "minPrice": str(config.payment.price_proxy_direct),
                "networks": config.payment.networks,
            },
        ],
        "facilitator": config.payment.facilitator_url,
        "contact": "https://github.com/as215932",
    }
