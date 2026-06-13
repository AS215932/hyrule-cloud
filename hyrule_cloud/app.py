"""
Hyrule Cloud API server.

Agentic VPS hosting on AS215932 with x402 payments.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from hyrule_cloud.api.auth import router as auth_router
from hyrule_cloud.api.bgp import router as bgp_router
from hyrule_cloud.api.dns import router as dns_router
from hyrule_cloud.api.internal_bgp import router as internal_bgp_router
from hyrule_cloud.api.ip import router as ip_router
from hyrule_cloud.api.mail import router as mail_router
from hyrule_cloud.api.mx import router as mx_router
from hyrule_cloud.api.nat import router as nat_router
from hyrule_cloud.api.path import router as path_router
from hyrule_cloud.api.ports import router as ports_router
from hyrule_cloud.api.registry import router as registry_router
from hyrule_cloud.api.routes import router
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

    # Database
    engine = create_db_engine(config.database_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)

    # Payment gate (official x402 SDK)
    payment_gate = PaymentGate(config.payment)

    # Network proxy sidecar client. x402 stays in Hyrule Cloud; the sidecar
    # only executes already-authorized egress requests.
    from hyrule_cloud.providers.network_client import NetworkProvider
    network_provider = NetworkProvider(
        proxy_url=config.network_proxy_url,
        token=config.network_proxy_token,
        health_ttl_seconds=config.network_proxy_health_ttl_seconds,
    )

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
    await native_crypto.close()
    await rate_provider.close()
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
app.include_router(mail_router)
app.include_router(internal_bgp_router)
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
            "automatic HTTPS subdomains, IPv6-native networking, domain "
            "registration, and paid direct/Tor/I2P/Yggdrasil network requests. x402 resources "
            "settle with facilitator-verified USDC; VM checkout may also offer "
            "BTC/XMR when the live payment catalog advertises native rails."
        ),
        "resources": [
            {
                "path": "/v1/vm/create",
                "method": "POST",
                "description": "Provision a bare VM with SSH access",
                "minPrice": str(config.payment.price_vm_xs),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/domain/register",
                "method": "POST",
                "description": "Register a domain via Openprovider",
                "minPrice": str(config.payment.price_domain_markup + 5),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/network/request",
                "method": "POST",
                "description": "Make a micro-proxy network request over Direct, Tor, I2P, or Yggdrasil",
                "minPrice": str(config.payment.price_proxy_direct),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/bgp/lookup",
                "method": "POST",
                "description": "Paid BGP/routing lookup by prefix, IP, ASN, or AS215932 router-table dataset",
                "minPrice": str(getattr(config.payment, "price_bgp_lookup", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/bgp/jobs",
                "method": "POST",
                "description": "Paid historical BGPStream job over RouteViews and RIPE RIS collectors",
                "minPrice": str(getattr(config.payment, "price_bgpstream_hour", "0.05")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/bgp/snapshots/router/{snapshot_id}/download",
                "method": "GET",
                "description": "Paid AS215932 active router table snapshot download",
                "minPrice": str(getattr(config.payment, "price_bgp_router_table", "0.10")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/ip/lookup",
                "method": "POST",
                "description": "Paid IP geolocation, ASN/ISP, reverse DNS, RDAP/WHOIS, reputation, and BGP-context lookup",
                "minPrice": str(getattr(config.payment, "price_ip_lookup", "0.003")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/dns/lookup",
                "method": "POST",
                "description": "Paid read-only DNS lookup, reverse lookup, DNSSEC, and trace diagnostics",
                "minPrice": str(getattr(config.payment, "price_dns_lookup", "0.001")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/rdap/lookup",
                "method": "POST",
                "description": "Paid structured RDAP lookup for domains, IPs, prefixes, ASNs, and entities",
                "minPrice": str(getattr(config.payment, "price_rdap_lookup", "0.003")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/whois/lookup",
                "method": "POST",
                "description": "Paid legacy WHOIS lookup for domains, IPs, prefixes/network blocks, and ASNs",
                "minPrice": str(getattr(config.payment, "price_whois_lookup", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/web/check",
                "method": "POST",
                "description": "Paid web reachability, HTTP/HTTPS, TLS certificate, security headers, and CDN/WAF diagnostic check",
                "minPrice": str(getattr(config.payment, "price_web_check", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/web/reports",
                "method": "POST",
                "description": "Paid web reachability evidence pack from Hyrule/extmon vantage",
                "minPrice": str(getattr(config.payment, "price_web_report", "0.03")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/web/tls/deep",
                "method": "POST",
                "description": "Paid Hyrule-native SSL Labs-style deep TLS scanner and grade",
                "minPrice": str(getattr(config.payment, "price_web_tls_deep", "0.10")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/mx/check",
                "method": "POST",
                "description": "Paid MXToolbox-compatible diagnostic check for mail, DNS, blacklist, SMTP, and domain troubleshooting",
                "minPrice": str(getattr(config.payment, "price_mx_check", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/mx/jobs",
                "method": "POST",
                "description": "Paid full mail-delivery diagnostic report for agentic ISP support workflows",
                "minPrice": str(getattr(config.payment, "price_mx_report", "0.03")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/path/report",
                "method": "POST",
                "description": "Paid routing/path evidence pack using extmon, AS215932, BGP/RPKI, and optional multi-vantage sources",
                "minPrice": str(getattr(config.payment, "price_path_report", "0.05")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/path/ping",
                "method": "POST",
                "description": "Paid ping/path probe from approved Hyrule diagnostic vantages",
                "minPrice": str(getattr(config.payment, "price_path_probe", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/ports/check",
                "method": "POST",
                "description": "Paid outside-in single declared service reachability check with strict port allowlist",
                "minPrice": str(getattr(config.payment, "price_port_check", "0.003")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/nat/lookup",
                "method": "POST",
                "description": "Paid server-only CGNAT/NAT hint report from caller and customer WAN/LAN evidence",
                "minPrice": str(getattr(config.payment, "price_nat_lookup", "0.003")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/nat/port-forward/check",
                "method": "POST",
                "description": "Paid outside-in NAT port-forward reachability check for one declared service",
                "minPrice": str(getattr(config.payment, "price_nat_port_forward_check", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/mail/accounts",
                "method": "POST",
                "description": "Create a paid Agent Mail mailbox with SMTP/IMAP and API access",
                "minPrice": str(getattr(config.payment, "price_mail_agent_basic_day", "0.05")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/mail/messages/send",
                "method": "POST",
                "description": "Send email through an Agent Mail mailbox via API",
                "minPrice": str(getattr(config.payment, "price_mail_outbound_message", "0.001")),
                "networks": getattr(config.payment, "networks", []),
            },
        ],
        "facilitator": getattr(config.payment, "facilitator_url", ""),
        "contact": "https://github.com/as215932",
    }
