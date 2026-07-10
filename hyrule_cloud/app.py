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
from fastapi.responses import FileResponse
from x402.http import PAYMENT_RESPONSE_HEADER, X_PAYMENT_RESPONSE_HEADER

from hyrule_cloud.api.auth import router as auth_router
from hyrule_cloud.api.bgp import router as bgp_router
from hyrule_cloud.api.dns import router as dns_router
from hyrule_cloud.api.internal_bgp import router as internal_bgp_router
from hyrule_cloud.api.ip import router as ip_router
from hyrule_cloud.api.mail import router as mail_router
from hyrule_cloud.api.metrics import router as metrics_router
from hyrule_cloud.api.mx import router as mx_router
from hyrule_cloud.api.nat import router as nat_router
from hyrule_cloud.api.path import router as path_router
from hyrule_cloud.api.ports import router as ports_router
from hyrule_cloud.api.registry import router as registry_router
from hyrule_cloud.api.routes import router
from hyrule_cloud.api.speedtest import router as speedtest_router
from hyrule_cloud.api.threat import router as threat_router
from hyrule_cloud.api.trust import router as trust_router
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
from hyrule_cloud.trust import build_trust_services
from hyrule_cloud.trust.receipts import (
    LEGACY_RECEIPT_HEADER,
    RECEIPT_HEADER,
    enforce_trust_key_guard,
)

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
    # Same philosophy for receipts: advertising receipts without working
    # signing keys would break the trust contract silently.
    enforce_trust_key_guard(config)

    # Database
    engine = create_db_engine(config.database_url)
    await init_db(engine)
    session_factory = create_session_factory(engine)

    # Agent-trust layer (dual-signed receipts + identity). Disabled services
    # when TRUST_* flags are unset — mint() is then a no-op returning None.
    trust = build_trust_services(config, session_factory)

    # Payment gate (official x402 SDK) + append-only payments ledger
    from hyrule_cloud.services.payments_ledger import PaymentLedger
    payment_ledger = PaymentLedger(session_factory)
    payment_gate = PaymentGate(
        config.payment,
        public_base_url=config.public_base_url,
        ledger=payment_ledger,
        receipts=trust.receipts,
        # x401 advisory block rides every 402 while TRUST_X401_MODE != off.
        advertised_extensions=(
            trust.x401.advisory_extension() if trust.x401 is not None else None
        ),
    )

    # Network proxy sidecar client. x402 stays in Hyrule Cloud; the sidecar
    # only executes already-authorized egress requests.
    from hyrule_cloud.providers.network_client import NetworkProvider
    network_provider = NetworkProvider(
        proxy_url=config.network_proxy_url,
        token=config.network_proxy_token,
        health_ttl_seconds=config.network_proxy_health_ttl_seconds,
    )

    # Orchestrator
    orchestrator = Orchestrator(config, session_factory, receipts=trust.receipts)
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
        trust=trust,
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
        "Full-stack network infrastructure for AI agents on AS215932 (RIPE): "
        "IPv6-native VMs with SSH and automatic HTTPS subdomains, domain "
        "registration and DNS, a broad network-intelligence suite (BGP/routing, "
        "IP/ASN & reputation, DNS, RDAP/WHOIS, web & deep TLS, mail "
        "deliverability, port/NAT/CGNAT, VoIP/SIP), and proxied requests over "
        "Direct/Tor/I2P/Yggdrasil. "
        "Pay per request in USDC on Base via x402; VM checkout may also accept "
        "BTC/XMR when advertised."
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
    # Receipt headers are exposed only when a receipt was actually minted so
    # trust-disabled deployments emit byte-identical responses.
    exposed.update(h for h in (RECEIPT_HEADER, LEGACY_RECEIPT_HEADER) if h in headers)
    response.headers["Access-Control-Expose-Headers"] = ", ".join(sorted(exposed))
    return response


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
app.include_router(speedtest_router)
app.include_router(mail_router)
app.include_router(internal_bgp_router)
# Block A1 (Wave 2): /v1/auth/* and /v1/me/* live in api/auth.py.
app.include_router(auth_router)
# Payments/fleet Prometheus exporter (bearer-token gated, off by default).
app.include_router(metrics_router)
# Agent-trust layer: receipts + JWKS (+ agent card / x401 proof later).
app.include_router(trust_router)

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
    from hyrule_cloud.services.discovery import discovery_for

    config: HyruleConfig = app.state._typed_state.config
    manifest = {
        "x402Version": 2,
        "name": "Hyrule Cloud",
        "description": (
            "Full-stack network infrastructure for AI agents, operated "
            "first-party on AS215932 (RIPE). "
            "Compute: bare IPv6-native VMs with SSH, automatic HTTPS "
            "subdomains, and optional registered domains. "
            "Network intelligence: BGP/routing over AS215932's own tables plus "
            "RouteViews and RIPE RIS, IP geolocation/ASN/reputation, DNS "
            "lookup/propagation/DNSSEC and record recommendations, RDAP and "
            "WHOIS, web reachability and deep TLS grading, MXToolbox-compatible "
            "mail deliverability (MX/SPF/DKIM/DMARC/blacklist/bounce), port and "
            "NAT/CGNAT reachability, and VoIP/SIP diagnostics. "
            "Domains & DNS: registration and management. "
            "Network proxy: outbound requests over Direct, Tor, I2P, or "
            "Yggdrasil. "
            "Pay per request in USDC on Base via x402; VM checkout may also "
            "accept BTC/XMR when advertised."
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
                "path": "/v1/dns/propagation",
                "method": "POST",
                "description": "Paid DNS propagation comparison across public recursive resolvers",
                "minPrice": str(getattr(config.payment, "price_dns_lookup", "0.001")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/dns/recommend-records",
                "method": "POST",
                "description": "Paid DNS record recommendations for web, mail, SIP, verification, and reverse DNS workflows",
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
                "path": "/v1/mx/bounce/parse",
                "method": "POST",
                "description": "Paid mail bounce/rejection parser and likely-cause classifier",
                "minPrice": str(getattr(config.payment, "price_mx_check", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/mx/recommend-records",
                "method": "POST",
                "description": "Paid SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and BIMI recommendation engine",
                "minPrice": str(getattr(config.payment, "price_mx_check", "0.005")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/mx/jobs",
                "method": "POST",
                "description": "Paid full mail-delivery diagnostic report (synchronous, results returned inline)",
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
                "path": "/v1/threat/lookup",
                "method": "POST",
                "description": "Paid open-source-first threat/reputation lookup with licensed provider adapters disabled until configured",
                "minPrice": str(getattr(config.payment, "price_threat_lookup", "0.01")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/voip/check",
                "method": "POST",
                "description": "Paid SIP DNS, SIP TLS, OPTIONS, STUN/TURN diagnostic check",
                "minPrice": str(getattr(config.payment, "price_voip_check", "0.01")),
                "networks": getattr(config.payment, "networks", []),
            },
            {
                "path": "/v1/voip/number/lookup",
                "method": "POST",
                "description": "Paid pluggable number carrier/CNAM/spam/E911 lookup",
                "minPrice": str(getattr(config.payment, "price_voip_number_lookup", "0.05")),
                "networks": getattr(config.payment, "networks", []),
            },
        ],
        "facilitator": getattr(config.payment, "facilitator_url", ""),
        "contact": "https://github.com/as215932",
    }
    # Don't advertise the paid VM route while provisioning is simulated — the
    # route itself refuses (503) until the Phase-3d real-provisioning flip, so
    # discovery must not point agents at a service that can't take their money.
    from hyrule_cloud.services.launch_proof import use_real_provisioning

    if not use_real_provisioning():
        manifest["resources"] = [
            r for r in manifest["resources"] if r.get("path") != "/v1/vm/create"
        ]
    # Don't advertise diagnostic routes whose real data source isn't configured
    # yet — they return 501 before charging, so pointing agents at them would
    # only produce failed payments. They re-appear automatically once a source
    # is wired up (same predicate the routes use).
    from hyrule_cloud.services.path.diagnostics import path_active_probe_enabled
    from hyrule_cloud.services.threat.lookup import threat_intel_enabled
    from hyrule_cloud.services.voip.diagnostics import number_intel_enabled

    unconfigured: set[str] = set()
    if not threat_intel_enabled():
        unconfigured.add("/v1/threat/lookup")
    if not number_intel_enabled():
        unconfigured.add("/v1/voip/number/lookup")
    # Gate each path endpoint on whether ITS OWN default request would probe:
    # the ping-family defaults to [extmon] (never an active vantage), so the
    # advertised default request 501s even when Globalping/RIPE is configured —
    # only /v1/path/report defaults to a vantage set that includes globalping.
    # Advertise an endpoint only when the request an agent gets from discovery
    # actually returns data.
    from hyrule_cloud.models import (
        PATH_PROBE_DEFAULT_VANTAGES,
        PATH_REPORT_DEFAULT_VANTAGES,
    )

    if not path_active_probe_enabled(PATH_PROBE_DEFAULT_VANTAGES):
        unconfigured.update(
            {"/v1/path/ping", "/v1/path/trace", "/v1/path/mtr", "/v1/path/asymmetry"}
        )
    if not path_active_probe_enabled(PATH_REPORT_DEFAULT_VANTAGES):
        unconfigured.add("/v1/path/report")
    if unconfigured:
        manifest["resources"] = [
            r for r in manifest["resources"] if r.get("path") not in unconfigured
        ]
    # Bazaar/x402scan: flag resources whose 402 responses carry a discovery
    # extension declaration (services/discovery.py).
    for resource in manifest["resources"]:
        if discovery_for(resource.get("method", ""), resource["path"]) is not None:
            resource["discoverable"] = True
    # Trust layer: each block appears ONLY when its flag is on, so the
    # manifest is byte-identical to the announced surface while flags are
    # off (guarded by tests/test_trust_identity.py).
    trust_cfg = getattr(config, "trust", None)
    base_url = getattr(config, "public_base_url", "").rstrip("/")
    if trust_cfg is not None and getattr(trust_cfg, "receipts_enabled", False):
        trust_services = getattr(app.state._typed_state, "trust", None)
        keys = getattr(getattr(trust_services, "receipts", None), "keys", None)
        manifest["receipts"] = {
            "profile": "x402-compute-fulfillment-receipt/0.1",
            "header": "HYRULE-RECEIPT",
            "endpoint": f"{base_url}/v1/receipts/{{receipt_id}}",
            "jwks": f"{base_url}/.well-known/jwks.json",
            "receiptSigners": [keys.evm_signer] if keys is not None else [],
        }
    if trust_cfg is not None and getattr(trust_cfg, "agent_card_enabled", False):
        identity: dict = {
            "agentRegistration": f"{base_url}/.well-known/agent-registration.json",
        }
        registry = getattr(trust_cfg, "erc8004_registry_caip10", "")
        agent_id = getattr(trust_cfg, "erc8004_agent_id", None)
        if registry and agent_id is not None:
            identity["registrations"] = [
                {"agentId": agent_id, "agentRegistry": registry}
            ]
        manifest["identity"] = identity
    return manifest
