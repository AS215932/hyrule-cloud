"""Contract-first MXToolbox-compatible diagnostics API routes."""

from __future__ import annotations

from datetime import timedelta

import structlog
from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import (
    not_implemented,
    now_utc,
    payment_price,
    quote,
    require_payment,
)
from hyrule_cloud.models import (
    CapabilityEndpoint,
    MailBounceParseRequest,
    MailBounceParseResponse,
    MXCheckRequest,
    MXCheckResponse,
    MXFinding,
    MXJobRequest,
    MXJobResponse,
    MXJobStatus,
    MXPricingResponse,
    MXProfile,
    MXStatus,
    MXTool,
    MXToolDescription,
    MXToolsResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
)
from hyrule_cloud.services.mx.checks import run_check
from hyrule_cloud.services.mx.deliverability import derive_recommendations, parse_bounce

router = APIRouter(prefix="/v1/mx", tags=["MX diagnostics"])
log = structlog.get_logger()

_TOOL_DESCRIPTIONS: dict[MXTool, tuple[str, str, bool]] = {
    MXTool.A: ("hostname", "DNS A record IPv4 address for host name", False),
    MXTool.AAAA: ("hostname", "DNS AAAA record IPv6 address for host name", False),
    MXTool.ARIN: ("ip_or_prefix", "IP address block information via RDAP/WHOIS", False),
    MXTool.ASN: ("ip", "ASN/ISP lookup for an IP address", False),
    MXTool.BIMI: ("domain", "BIMI record and syntax check", False),
    MXTool.BLACKLIST: ("ip_or_host", "IP/host/domain reputation and blocklist check", False),
    MXTool.CNAME: ("hostname", "DNS CNAME canonical host name lookup", False),
    MXTool.DKIM: ("domain", "DKIM selector record check", False),
    MXTool.DMARC: ("domain", "DMARC record and policy lookup", False),
    MXTool.DNS: ("domain", "DNS server, delegation, DNSSEC, and consistency diagnostics", False),
    MXTool.HTTP: ("url_or_host", "HTTP connectivity check", True),
    MXTool.HTTPS: ("url_or_host", "HTTPS/TLS connectivity and certificate check", True),
    MXTool.MTA_STS: ("domain", "MTA-STS TXT and HTTPS policy check", True),
    MXTool.MX: ("domain", "DNS MX records and mail host validation", False),
    MXTool.PING: ("ip_or_host", "ICMP ping from approved Hyrule vantage", True),
    MXTool.PTR: ("ip", "Reverse DNS PTR lookup", False),
    MXTool.SMTP: ("domain_or_mx_host", "SMTP TCP/25 banner, EHLO, STARTTLS, and TLS checks", True),
    MXTool.SOA: ("domain", "SOA lookup and sanity check", False),
    MXTool.SPF: ("domain", "SPF record parse and 10-DNS-lookup-limit check", False),
    MXTool.TCP: ("ip_or_host_port", "TCP connect probe with abuse-safe port allowlist", True),
    MXTool.TLSRPT: ("domain", "TLSRPT record lookup and parse", False),
    MXTool.TRACE: ("ip_or_host", "Traceroute from approved Hyrule vantage", True),
    MXTool.TXT: ("domain_or_host", "DNS TXT lookup", False),
    MXTool.WHOIS: ("domain_ip_or_prefix", "Domain or network WHOIS lookup", False),
}

# A job target is a domain. PTR and ASN are intentionally absent because those
# tools require an IP address; applying them to the domain itself is both
# misleading and, before the input hardening in checks.py, could raise after an
# x402 payment had already settled.
_DEFAULT_DOMAIN_JOB_CHECKS: tuple[MXTool, ...] = (
    MXTool.DNS,
    MXTool.MX,
    MXTool.SMTP,
    MXTool.SPF,
    MXTool.DKIM,
    MXTool.DMARC,
    MXTool.BIMI,
    MXTool.MTA_STS,
    MXTool.TLSRPT,
    MXTool.BLACKLIST,
    MXTool.WHOIS,
)


@router.get("/tools", response_model=MXToolsResponse)
async def get_mx_tools() -> MXToolsResponse:
    return MXToolsResponse(
        tools=[
            MXToolDescription(tool=tool, target=target, description=description, active_probe=active)
            for tool, (target, description, active) in _TOOL_DESCRIPTIONS.items()
        ]
    )


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_mx_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="mx",
        purpose="MXToolbox-compatible mail/domain deliverability diagnostics for AI agents and ISP support workflows.",
        separation_of_concerns="/v1/mx diagnoses mail/DNS delivery; /v1/dns is the lower-level read-only DNS API.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/mx/tools", method="GET", description="List supported SuperTool-compatible tools"),
            CapabilityEndpoint(path="/v1/mx/pricing", method="GET", description="MX diagnostic pricing"),
            CapabilityEndpoint(path="/v1/mx/check/quote", method="POST", description="Quote a single MX diagnostic check"),
            CapabilityEndpoint(path="/v1/mx/jobs/quote", method="POST", description="Quote an async MX report"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/mx/check", method="POST", paid=True, description="Run one MX diagnostic check"),
            CapabilityEndpoint(path="/v1/mx/{tool}/{target}", method="GET", paid=True, description="SuperTool-style single check"),
            CapabilityEndpoint(path="/v1/mx/bounce/parse", method="POST", paid=True, description="Parse and classify a mail bounce/rejection message"),
            CapabilityEndpoint(path="/v1/mx/reports/mail-delivery", method="POST", paid=True, description="Run full mail-delivery diagnostic report (results returned inline)"),
            CapabilityEndpoint(path="/v1/mx/jobs", method="POST", paid=True, description="Run full mail troubleshooting report (synchronous, results returned inline)"),
        ],
    )


@router.get("/pricing", response_model=MXPricingResponse)
async def get_mx_pricing(request: Request) -> MXPricingResponse:
    return MXPricingResponse(
        single_check_usd=str(payment_price(request, "price_mx_check", "0.005")),
        mail_delivery_report_usd=str(payment_price(request, "price_mx_report", "0.03")),
    )


@router.post("/check/quote", response_model=PaidEndpointQuote)
async def quote_mx_check(request: Request, body: MXCheckRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_mx_check", "0.005"), "mx_check", "/v1/mx/check")


@router.post("/jobs/quote", response_model=PaidEndpointQuote)
async def quote_mx_job(request: Request, body: MXJobRequest) -> PaidEndpointQuote:
    return quote(payment_price(request, "price_mx_report", "0.03"), "mx_report", "/v1/mx/jobs")


async def _paid_check(request: Request) -> Response | None:
    amount = payment_price(request, "price_mx_check", "0.005")
    result = await require_payment(request, amount, "Hyrule MX diagnostic check")
    return result if isinstance(result, Response) else None


async def _paid_job(request: Request) -> Response | None:
    amount = payment_price(request, "price_mx_report", "0.03")
    result = await require_payment(request, amount, "Hyrule MX mail-delivery diagnostic report")
    return result if isinstance(result, Response) else None


async def _run_job_check(body: MXJobRequest, tool: MXTool) -> MXCheckResponse:
    """Keep one diagnostic failure from discarding an already-paid report."""
    try:
        return await run_check(
            MXCheckRequest(tool=tool, target=body.target, options=body.options)
        )
    except Exception:
        log.exception("mx_job_check_failed", tool=tool.value, target=body.target)
        message = f"{tool.value.upper()} diagnostic failed unexpectedly."
        return MXCheckResponse(
            request_id="mxq_contract",
            tool=tool,
            target=body.target,
            status=MXStatus.ERROR,
            summary=message,
            findings=[
                MXFinding(
                    severity=MXStatus.ERROR,
                    code="diagnostic_failed",
                    message=message,
                )
            ],
            sources={"diagnostic": "error"},
            generated_at=now_utc(),
        )


@router.post("/check", response_model=MXCheckResponse)
async def mx_check(request: Request, body: MXCheckRequest) -> MXCheckResponse | Response:
    if payment := await _paid_check(request):
        return payment
    return await run_check(body)


@router.post("/bounce/parse", response_model=MailBounceParseResponse)
async def parse_mx_bounce(request: Request, body: MailBounceParseRequest) -> MailBounceParseResponse | Response:
    if payment := await _paid_check(request):
        return payment
    return parse_bounce(body)


@router.post("/reports/mail-delivery", response_model=MXJobResponse)
async def create_mx_mail_delivery_report(request: Request, body: MXJobRequest) -> MXJobResponse | Response:
    body.profile = MXProfile.MAIL_DELIVERY
    return await create_mx_job(request, body)


@router.post("/jobs", response_model=MXJobResponse)
async def create_mx_job(request: Request, body: MXJobRequest) -> MXJobResponse | Response:
    if payment := await _paid_job(request):
        return payment
    checks = body.checks or _DEFAULT_DOMAIN_JOB_CHECKS
    results = [await _run_job_check(body, tool) for tool in checks]
    created = now_utc()
    return MXJobResponse(
        job_id="mxj_inline_contract",
        status=MXJobStatus.COMPLETED,
        target=body.target,
        profile=body.profile,
        results=results,
        recommendations=(
            derive_recommendations(body.target, results)
            if body.options.include_recommendations
            else []
        ),
        created_at=created,
        expires_at=created + timedelta(hours=24),
    )


@router.get("/jobs/{job_id}", response_model=MXJobResponse)
async def get_mx_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("mx.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_mx_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("mx.jobs.download")


@router.get("/{tool}/{target}", response_model=MXCheckResponse)
async def mx_tool(request: Request, tool: MXTool, target: str) -> MXCheckResponse | Response:
    if payment := await _paid_check(request):
        return payment
    return await run_check(MXCheckRequest(tool=tool, target=target))
