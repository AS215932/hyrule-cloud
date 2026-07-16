"""
Hyrule Cloud API server.

Agentic VPS hosting on AS215932 with x402 payments.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from x402.http import PAYMENT_RESPONSE_HEADER, X_PAYMENT_RESPONSE_HEADER

from hyrule_cloud.api.auth import router as auth_router
from hyrule_cloud.api.bgp import router as bgp_router
from hyrule_cloud.api.dns import router as dns_router
from hyrule_cloud.api.internal_bgp import router as internal_bgp_router
from hyrule_cloud.api.ip import router as ip_router
from hyrule_cloud.api.metrics import router as metrics_router
from hyrule_cloud.api.mx import router as mx_router
from hyrule_cloud.api.nat import router as nat_router
from hyrule_cloud.api.path import router as path_router
from hyrule_cloud.api.ports import router as ports_router
from hyrule_cloud.api.registry import router as registry_router
from hyrule_cloud.api.routes import router
from hyrule_cloud.api.status import router as status_router
from hyrule_cloud.api.threat import router as threat_router
from hyrule_cloud.api.voip import router as voip_router
from hyrule_cloud.api.web import router as web_router
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import create_db_engine, create_session_factory, init_db
from hyrule_cloud.middleware.metrics import install_metrics
from hyrule_cloud.middleware.x402 import PaymentGate
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.native_crypto import NativeCryptoProvider
from hyrule_cloud.providers.rates import RateProvider
from hyrule_cloud.services.intents import scan_pending_intents

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

    # Production guard: refuse to boot in simulation/dev-bypass mode when the
    # deployment declares it must provision real VMs.
    from hyrule_cloud.services.launch_proof import enforce_real_provisioning_guard
    enforce_real_provisioning_guard(config)

    # Database
    engine = create_db_engine(config.database_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)

    # Payment gate (official x402 SDK) + append-only payments ledger
    from hyrule_cloud.services.payments_ledger import PaymentLedger
    payment_ledger = PaymentLedger(session_factory)
    payment_gate = PaymentGate(
        config.payment,
        public_base_url=config.public_base_url,
        ledger=payment_ledger,
    )

    # Network proxy sidecar client. x402 stays in Hyrule Cloud; the sidecar
    # only executes already-authorized egress requests.
    from hyrule_cloud.providers.network_client import NetworkProvider
    network_provider = NetworkProvider(
        proxy_url=config.network_proxy_url,
        token=config.network_proxy_token,
        health_ttl_seconds=config.network_proxy_health_ttl_seconds,
    )

    # Prober sidecar client for x402-gated /v1/path/* active measurements.
    # Registered as the process-wide active prober so the synchronous manifest
    # gate (path_active_probe_enabled) sees the same configuration.
    from hyrule_cloud.providers.prober_client import ProberProvider, set_active_prober
    prober_provider = ProberProvider(
        prober_url=config.prober_url,
        token=config.prober_token,
        health_ttl_seconds=config.prober_health_ttl_seconds,
    )
    set_active_prober(prober_provider)

    # Orchestrator
    orchestrator = Orchestrator(config, session_factory)
    await orchestrator.startup()

    # Block E: native crypto (BTC/XMR) intent engine + rate provider
    rate_provider = RateProvider()
    await rate_provider.start()
    native_crypto = NativeCryptoProvider(config.payment)
    await native_crypto.start()
    native_payment_assets = await native_crypto.ready_assets()
    if config.payment.require_native and set(native_payment_assets) != {"BTC", "XMR"}:
        raise RuntimeError(
            "PAYMENT_REQUIRE_NATIVE=true but BTC/XMR are not both ready "
            f"(ready={','.join(native_payment_assets) or 'none'})"
        )

    # Wire up app state
    app.state._typed_state = AppState(
        config=config,
        orchestrator=orchestrator,
        payment_gate=payment_gate,
        network_provider=network_provider,
        prober_provider=prober_provider,
        native_crypto=native_crypto,
        rate_provider=rate_provider,
        native_payment_assets=native_payment_assets,
        session_factory=session_factory,
    )

    # Expiry scheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(orchestrator.check_expiries, "interval", minutes=5)
    scheduler.start()

    # Block E: background intent poller. Single worker; coordinated via the
    # exactly-once atomic SQL trigger in services/intents.py.
    async def _intent_poller_loop() -> None:
        while True:
            try:
                await scan_pending_intents(
                    session_factory=session_factory,
                    provider=native_crypto,
                    rates=rate_provider,
                    orch=orchestrator,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("intent_poller_iteration_failed")
            await asyncio.sleep(15)

    poller_task = asyncio.create_task(_intent_poller_loop())

    log.info(
        "hyrule_cloud_started",
        deploy_domain=config.deploy_domain,
        database=config.database_url.split("@")[-1] if "@" in config.database_url else "local",
    )

    yield

    scheduler.shutdown()
    poller_task.cancel()
    try:
        await poller_task
    except asyncio.CancelledError:
        pass
    await orchestrator.shutdown()
    await network_provider.close()
    set_active_prober(None)
    await prober_provider.close()
    await native_crypto.close()
    await rate_provider.close()
    await engine.dispose()
    log.info("hyrule_cloud_stopped")


app = FastAPI(
    title="Hyrule Cloud",
    # Deliberately product-list-free: the payable capability list is generated
    # from the enabled catalog (see services/discovery.py catalog_description)
    # so gated-off products can never be advertised here.
    description=(
        "First-party network infrastructure for AI agents on AS215932 (RIPE), "
        "paid per request in USDC via x402. The live payable capability list is "
        "generated from the enabled catalog in /.well-known/x402.json, "
        "/openapi.json, and /llms.txt."
    ),
    contact={
        "name": "Hyrule Cloud (AS215932)",
        "url": "https://github.com/AS215932",
        "email": "svag@servify.nl",
    },
    version="0.1.0",
    lifespan=lifespan,
)

_STATIC_DIR = Path(__file__).parent / "static"


# Brand icons (AS215932 "Hyrule Networks" shield). include_in_schema=False keeps
# them out of the OpenAPI/x402 surface so discovery crawlers don't probe them.
@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico() -> FileResponse:
    return FileResponse(_STATIC_DIR / "favicon.ico", media_type="image/x-icon")


@app.get("/apple-touch-icon.png", include_in_schema=False)
@app.get("/apple-touch-icon-precomposed.png", include_in_schema=False)
async def apple_touch_icon() -> FileResponse:
    return FileResponse(_STATIC_DIR / "apple-touch-icon.png", media_type="image/png")


# Referenced as iconUrl in 402 Bazaar resource metadata (middleware/x402.py).
@app.get("/icon-192.png", include_in_schema=False)
async def icon_192() -> FileResponse:
    return FileResponse(_STATIC_DIR / "icon-192.png", media_type="image/png")


@app.get("/llms.txt", include_in_schema=False)
async def llms_txt(request: Request) -> PlainTextResponse:
    """Agent-facing plaintext guide, generated from the enabled catalog only."""
    from hyrule_cloud.services.discovery import catalog_description, enabled_paid_operations

    state = getattr(request.app.state, "_typed_state", None)
    config = getattr(state, "config", None) or HyruleConfig()
    base = config.public_base_url.rstrip("/")
    lines = [
        "# Hyrule Cloud — x402-payable network services for AI agents",
        "",
        catalog_description(),
        "",
        f"Machine-readable catalog: {base}/.well-known/x402.json",
        f"OpenAPI (payable surface only): {base}/openapi.json",
        "Payment: HTTP 402 challenge (x402 v2), USDC; accepted networks at "
        f"{base}/v1/payments/networks",
        "",
        "Golden path:",
        f"  curl -s -X POST {base}/v1/dns/lookup \\",
        "    -H 'Content-Type: application/json' -d '{\"name\":\"example.com\",\"type\":\"AAAA\"}'",
        "  -> HTTP 402 with payment requirements; retry with an X-PAYMENT header to settle.",
        "",
        "Paid operations (method path — min USD — description):",
    ]
    for operation in enabled_paid_operations():
        price = operation.price.minimum(config.payment)
        lines.append(
            f"  {operation.method} {operation.path} — ${price} — {operation.description}"
        )
    return PlainTextResponse("\n".join(lines) + "\n")


@app.middleware("http")
async def attach_payment_response_headers(request: Request, call_next) -> Response:
    """Attach x402 settlement headers saved by PaymentGate to successful responses."""
    response = await call_next(request)
    headers = getattr(request.state, "payment_response_headers", None)
    if not headers:
        return response

    for key, value in headers.items():
        response.headers[key] = value

    exposed = {
        h.strip()
        for h in response.headers.get("Access-Control-Expose-Headers", "").split(",")
        if h.strip()
    }
    exposed.update({PAYMENT_RESPONSE_HEADER, X_PAYMENT_RESPONSE_HEADER})
    response.headers["Access-Control-Expose-Headers"] = ", ".join(sorted(exposed))
    return response


@app.middleware("http")
async def challenge_curated_x402_requests(request: Request, call_next) -> Response:
    """Return the advertised 402 before FastAPI validates an unpaid request.

    x402scan probes from OpenAPI and must be able to reach the payment challenge
    with an empty body or a literal path parameter. Valid dynamic-price inputs
    continue to the route handler so its first challenge carries the exact
    body-dependent amount; paid retries always continue to that handler too.
    """

    state = getattr(request.app.state, "_typed_state", None)
    gate = getattr(state, "payment_gate", None)
    if not isinstance(gate, PaymentGate) or gate.has_payment_credentials(request):
        return await call_next(request)

    from hyrule_cloud.services.discovery import match_enabled_operation

    operation = match_enabled_operation(request.method, request.url.path)
    if operation is None:
        return await call_next(request)

    # Dynamic prices depend on validated request data (VM size/duration, proxy
    # mode, BGP dataset/job type). Let a valid body reach the handler so a normal
    # x402 client can pay its first challenge successfully. Empty, malformed, or
    # schema-invalid scanner probes still receive the advertised minimum before
    # FastAPI can reject them.
    if operation.price.mode == "dynamic":
        try:
            payload = await request.json()
        except (UnicodeDecodeError, ValueError):
            pass
        else:
            if operation.accepts_input(payload):
                return await call_next(request)

    return await gate.challenge_payment(
        request,
        operation.price.minimum(state.config.payment),
        operation.description,
        route_path=operation.path,
    )


app.include_router(router)
# Contract-first network intelligence APIs. Implementations land behind these
# stable OpenAPI surfaces in the next execution steps.
app.include_router(bgp_router)
app.include_router(ip_router)
app.include_router(dns_router)
app.include_router(registry_router)
app.include_router(web_router)
app.include_router(mx_router)
app.include_router(path_router)
app.include_router(ports_router)
app.include_router(nat_router)
app.include_router(threat_router)
app.include_router(voip_router)
app.include_router(internal_bgp_router)
app.include_router(status_router)
# Block A1 (Wave 2): /v1/auth/* and /v1/me/* live in api/auth.py.
app.include_router(auth_router)
# Payments/fleet Prometheus exporter (bearer-token gated, off by default).
app.include_router(metrics_router)

# Block B (Wave 2): per-process request-latency middleware feeds
# `/v1/stats/runtime`. Cheap (one perf_counter per request + O(1) deque
# append) and bounded in memory.
install_metrics(app)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "hyrule-cloud"}


@app.get("/.well-known/x402.json", include_in_schema=False)
async def x402_manifest():
    """Compatibility manifest generated from the curated paid-operation catalog."""
    from hyrule_cloud.services.discovery import build_x402_manifest

    config: HyruleConfig = app.state._typed_state.config
    return build_x402_manifest(config)


def curated_openapi() -> dict:
    """Build x402scan's sole, curated OpenAPI document."""
    from hyrule_cloud.services.discovery import build_curated_openapi

    state = getattr(app.state, "_typed_state", None)
    # Production HTTP requests run inside lifespan and therefore always use the
    # exact live AppState config. The BaseSettings fallback intentionally keeps
    # import-time schema tooling and tests usable without starting databases or
    # providers; it still reads the deployment environment rather than using a
    # separate hard-coded price table.
    config = state.config if state is not None else HyruleConfig()
    return build_curated_openapi(app, config)


app.openapi = curated_openapi
