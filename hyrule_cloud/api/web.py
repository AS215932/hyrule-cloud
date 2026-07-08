"""Web reachability, TLS, SecurityHeaders, and CDN/WAF diagnostics."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from hyrule_cloud.api._contract import (
    diagnostic_quote,
    not_implemented,
    payment_price,
    require_paid_diagnostic,
)
from hyrule_cloud.models import (
    CapabilityEndpoint,
    DiagnosticJobResponse,
    DiagnosticResponse,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    WebCheck,
    WebCheckRequest,
    WebPricingResponse,
    WebReportRequest,
    WebTLSDeepRequest,
)
from hyrule_cloud.services.web.checks import run_web_check, run_web_tls_deep

router = APIRouter(prefix="/v1/web", tags=["Web reachability"])


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_web_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="web",
        purpose="Paid web reachability, HTTP/HTTPS, TLS certificate, security header, CDN/WAF, and site-down evidence packs for AI-agent support workflows.",
        separation_of_concerns="/v1/web diagnoses public web endpoints; /v1/dns diagnoses DNS records; /v1/ports performs single declared service reachability checks.",
        free_endpoints=[
            CapabilityEndpoint(path="/v1/web/capabilities", method="GET", description="Web diagnostic capabilities"),
            CapabilityEndpoint(path="/v1/web/pricing", method="GET", description="Web diagnostic pricing"),
            CapabilityEndpoint(path="/v1/web/check/quote", method="POST", description="Quote a web diagnostic check"),
            CapabilityEndpoint(path="/v1/web/tls/deep/quote", method="POST", description="Quote a Hyrule-native SSL Labs-style scan"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/web/check", method="POST", paid=True, description="Run a synchronous web diagnostic check"),
            CapabilityEndpoint(path="/v1/web/http", method="GET", paid=True, description="HTTP reachability check"),
            CapabilityEndpoint(path="/v1/web/https", method="GET", paid=True, description="HTTPS/TLS reachability check"),
            CapabilityEndpoint(path="/v1/web/tls", method="GET", paid=True, description="TLS handshake and certificate check"),
            CapabilityEndpoint(path="/v1/web/cert", method="GET", paid=True, description="Certificate-focused check"),
            CapabilityEndpoint(path="/v1/web/headers", method="GET", paid=True, description="Security header check"),
            CapabilityEndpoint(path="/v1/web/cdn", method="GET", paid=True, description="CDN/WAF response hint check"),
            CapabilityEndpoint(path="/v1/web/down", method="GET", paid=True, description="Site-down evidence check"),
            CapabilityEndpoint(path="/v1/web/tls/deep", method="POST", paid=True, description="Run Hyrule-native deep TLS scan (synchronous)"),
        ],
    )


@router.get("/pricing", response_model=WebPricingResponse)
async def get_web_pricing(request: Request) -> WebPricingResponse:
    return WebPricingResponse(
        check_usd=str(payment_price(request, "price_web_check", "0.005")),
        report_usd=str(payment_price(request, "price_web_report", "0.03")),
        tls_deep_usd=str(payment_price(request, "price_web_tls_deep", "0.10")),
    )


@router.post("/check/quote", response_model=PaidEndpointQuote)
async def quote_web_check(request: Request, body: WebCheckRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_web_check", default="0.005", name="web_check", paid_endpoint="/v1/web/check")


@router.post("/reports/quote", response_model=PaidEndpointQuote)
async def quote_web_report(request: Request, body: WebReportRequest) -> Response:
    # The paid endpoint this quotes is 501 while async report retrieval is
    # unbuilt; a payable-looking quote for it would send agents into a dead end.
    return not_implemented("web.reports.quote")


@router.post("/tls/deep/quote", response_model=PaidEndpointQuote)
async def quote_web_tls_deep(request: Request, body: WebTLSDeepRequest) -> PaidEndpointQuote:
    return diagnostic_quote(request, price_attr="price_web_tls_deep", default="0.10", name="web_tls_deep", paid_endpoint="/v1/web/tls/deep")


@router.post("/check", response_model=DiagnosticResponse)
async def web_check(request: Request, body: WebCheckRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_web_check", default="0.005", description="Hyrule web reachability diagnostic check"):
        return payment
    return await run_web_check(body)


@router.get("/http", response_model=DiagnosticResponse)
async def web_http(request: Request, url: str) -> DiagnosticResponse | Response:
    return await web_check(request, WebCheckRequest(target=url, checks=[WebCheck.DNS, WebCheck.HTTP, WebCheck.HEADERS, WebCheck.CDN_WAF]))


@router.get("/https", response_model=DiagnosticResponse)
async def web_https(request: Request, url: str) -> DiagnosticResponse | Response:
    return await web_check(request, WebCheckRequest(target=url, checks=[WebCheck.DNS, WebCheck.HTTPS, WebCheck.TLS, WebCheck.CERT, WebCheck.HEADERS, WebCheck.CDN_WAF]))


@router.get("/tls", response_model=DiagnosticResponse)
async def web_tls(request: Request, host: str, port: int = 443) -> DiagnosticResponse | Response:
    return await web_check(request, WebCheckRequest(target=f"https://{host}:{port}", checks=[WebCheck.TLS, WebCheck.CERT]))


@router.get("/cert", response_model=DiagnosticResponse)
async def web_cert(request: Request, host: str, port: int = 443) -> DiagnosticResponse | Response:
    return await web_tls(request, host, port)


@router.get("/headers", response_model=DiagnosticResponse)
async def web_headers(request: Request, url: str) -> DiagnosticResponse | Response:
    return await web_check(request, WebCheckRequest(target=url, checks=[WebCheck.HTTP, WebCheck.HEADERS]))


@router.get("/cdn", response_model=DiagnosticResponse)
async def web_cdn(request: Request, host: str) -> DiagnosticResponse | Response:
    return await web_check(request, WebCheckRequest(target=f"https://{host}", checks=[WebCheck.HTTP, WebCheck.CDN_WAF]))


@router.get("/down", response_model=DiagnosticResponse)
async def web_down(request: Request, url: str) -> DiagnosticResponse | Response:
    return await web_check(request, WebCheckRequest(target=url, checks=[WebCheck.DNS, WebCheck.HTTP, WebCheck.HTTPS, WebCheck.DOWN]))


@router.post("/reports", response_model=DiagnosticJobResponse)
async def create_web_report(request: Request, body: WebReportRequest) -> DiagnosticJobResponse | Response:
    # Async report jobs have no retrieval backend yet: refuse before charging.
    return not_implemented("web.reports.create")


@router.post("/tls/deep", response_model=DiagnosticResponse)
async def create_web_tls_deep(request: Request, body: WebTLSDeepRequest) -> DiagnosticResponse | Response:
    if payment := await require_paid_diagnostic(request, price_attr="price_web_tls_deep", default="0.10", description="Hyrule SSL Labs-style deep TLS scan"):
        return payment
    return await run_web_tls_deep(body)


@router.get("/jobs/{job_id}", response_model=DiagnosticJobResponse)
async def get_web_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("web.jobs.status")


@router.get("/jobs/{job_id}/download", response_model=None)
async def download_web_job(job_id: str, token: str | None = None) -> Response:
    return not_implemented("web.jobs.download")
