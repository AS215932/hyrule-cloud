"""
Hyrule Cloud API server.

Agentic VPS hosting on AS215932 with x402 payments.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from hyrule_cloud.api.routes import router
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import create_db_engine, create_session_factory, init_db
from hyrule_cloud.middleware.x402 import PaymentGate
from hyrule_cloud.orchestrator import Orchestrator

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
)

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = HyruleConfig()

    # Database
    engine = create_db_engine(config.database_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)

    # Payment gate (official x402 SDK)
    payment_gate = PaymentGate(config.payment)

    # Orchestrator
    orchestrator = Orchestrator(config, session_factory)
    await orchestrator.startup()

    # Wire up app state
    app.state.config = config
    app.state.orchestrator = orchestrator
    app.state.payment_gate = payment_gate

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
    await engine.dispose()
    log.info("hyrule_cloud_stopped")


app = FastAPI(
    title="Hyrule Cloud",
    description=(
        "Agentic VPS hosting with x402 payments. "
        "Deploy bare VMs with SSH access, automatic DNS, and "
        "IPv6-native networking on AS215932. "
        "Payment via USDC on Base."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "hyrule-cloud"}


@app.get("/.well-known/x402.json")
async def x402_manifest():
    """x402 service manifest for agent discovery."""
    config: HyruleConfig = app.state.config
    return {
        "x402Version": 2,
        "name": "Hyrule Cloud",
        "description": (
            "Bare VM hosting for AI agents. Deploy VMs with SSH access, "
            "automatic HTTPS subdomains, and IPv6-native networking. "
            "Pay with USDC on Base."
        ),
        "resources": [
            {
                "path": "/v1/vm/create",
                "method": "POST",
                "description": "Provision a bare VM with SSH access",
                "minPrice": str(config.payment.price_vm_xs),
                "asset": config.payment.asset,
                "network": config.payment.network,
            },
            {
                "path": "/v1/domain/register",
                "method": "POST",
                "description": "Register a domain via Openprovider",
                "minPrice": str(config.payment.price_domain_markup + 5),
                "asset": config.payment.asset,
                "network": config.payment.network,
            },
            {
                "path": "/v1/zone/buy",
                "method": "POST",
                "description": "Buy a DNS zone (domain + authoritative DNS)",
                "minPrice": str(config.payment.price_domain_markup + 5),
                "asset": config.payment.asset,
                "network": config.payment.network,
            },
        ],
        "facilitator": config.payment.facilitator_url,
        "contact": "https://github.com/as215932",
    }
