"""Hyrule-native web reachability, TLS, header, and CDN/WAF diagnostics."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    SourceStatus,
    WebCheck,
    WebCheckRequest,
    WebTLSDeepRequest,
)
from hyrule_cloud.services.diagnostics.sources import source_error, source_ok
from hyrule_cloud.services.safety import (
    assert_safe_active_probe_target,
    normalize_host,
    safe_url,
)

_CDN_HINT_HEADERS = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "x-amz-cf-id": "cloudfront",
    "x-cache": "generic_cache",
    "x-served-by": "fastly",
    "x-akamai-transformed": "akamai",
    "server-timing": "cdn_or_edge",
}
_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _finding(
    severity: DiagnosticStatus,
    code: str,
    message: str,
    recommendation: str | None = None,
    **evidence: object,
) -> DiagnosticFinding:
    return DiagnosticFinding(
        severity=severity,
        code=code,
        message=message,
        evidence=evidence,
        recommendation=recommendation,
    )


def _overall(findings: list[DiagnosticFinding]) -> DiagnosticStatus:
    order = [
        DiagnosticStatus.ERROR,
        DiagnosticStatus.CRITICAL,
        DiagnosticStatus.WARNING,
        DiagnosticStatus.INFO,
        DiagnosticStatus.OK,
    ]
    severities = {finding.severity for finding in findings}
    for severity in order:
        if severity in severities:
            return severity
    return DiagnosticStatus.OK


def _target(value: str, normalized: str | None = None, type_: DiagnosticTargetType = DiagnosticTargetType.URL) -> DiagnosticTarget:
    return DiagnosticTarget(input=value, normalized=normalized or value, type=type_)


async def run_web_check(body: WebCheckRequest) -> DiagnosticResponse:
    url = safe_url(body.target, default_scheme="https")
    host = normalize_host(url)
    assert_safe_active_probe_target(host, port=443 if url.startswith("https://") else 80)
    findings: list[DiagnosticFinding] = []
    raw: dict[str, object] = {}
    sources = {"extmon": source_ok(), "web": source_ok()}

    parsed = urlparse(url)
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == "https" else 80)

    if WebCheck.DNS in body.checks:
        try:
            addresses = await asyncio.to_thread(assert_safe_active_probe_target, host, port=port)
            findings.append(_finding(DiagnosticStatus.OK, "dns_resolves_public", f"{host} resolved to public address(es).", addresses=addresses))
            raw["addresses"] = addresses
        except Exception as exc:
            findings.append(_finding(DiagnosticStatus.CRITICAL, "dns_resolution_failed", f"{host} did not resolve to a safe public target: {exc}"))

    http_response: httpx.Response | None = None
    if WebCheck.HTTP in body.checks or WebCheck.HTTPS in body.checks or WebCheck.DOWN in body.checks or WebCheck.HEADERS in body.checks or WebCheck.CDN_WAF in body.checks:
        try:
            async with httpx.AsyncClient(timeout=body.timeout_ms / 1000, follow_redirects=False) as client:
                http_response = await client.get(url, headers={"User-Agent": "HyruleCloud-WebDiag/1.0"})
            severity = DiagnosticStatus.OK if http_response.status_code < 500 else DiagnosticStatus.WARNING
            findings.append(_finding(severity, "http_response", f"{url} returned HTTP {http_response.status_code}.", status_code=http_response.status_code, final_url=str(http_response.url)))
            raw["http"] = {
                "status_code": http_response.status_code,
                "headers": dict(http_response.headers) if body.include_raw else _selected_headers(http_response.headers),
            }
        except Exception as exc:
            findings.append(_finding(DiagnosticStatus.CRITICAL, "http_failed", f"{url} could not be fetched: {exc}"))
            sources["web"] = source_error(str(exc))

    if WebCheck.TLS in body.checks or WebCheck.CERT in body.checks:
        try:
            cert_info = await asyncio.to_thread(_tls_certificate, host, port)
            findings.extend(_cert_findings(host, cert_info))
            raw["tls"] = cert_info
        except Exception as exc:
            findings.append(_finding(DiagnosticStatus.CRITICAL, "tls_handshake_failed", f"TLS handshake/certificate check failed: {exc}"))

    if WebCheck.HEADERS in body.checks and http_response is not None:
        findings.extend(_header_findings(http_response.headers))

    if WebCheck.CDN_WAF in body.checks and http_response is not None:
        findings.extend(_cdn_findings(http_response.headers))

    status = _overall(findings)
    return DiagnosticResponse(
        status=status,
        summary=f"Web reachability check for {host}: {len(findings)} finding(s).",
        target=_target(body.target, normalized=url),
        findings=findings,
        sources=sources,
        raw=raw if body.include_raw else None,
        partial=any(source.status != SourceStatus.OK for source in sources.values()),
        generated_at=datetime.now(UTC),
    )


async def run_web_tls_deep(body: WebTLSDeepRequest) -> DiagnosticResponse:
    assert_safe_active_probe_target(body.host, port=body.port)
    findings: list[DiagnosticFinding] = []
    raw: dict[str, object] = {}
    try:
        cert_info = await asyncio.to_thread(_tls_certificate, body.host, body.port)
        findings.extend(_cert_findings(body.host, cert_info))
        raw["certificate"] = cert_info
    except Exception as exc:
        findings.append(_finding(DiagnosticStatus.CRITICAL, "tls_handshake_failed", f"TLS handshake failed: {exc}"))

    protocols = await asyncio.to_thread(_tls_protocol_probe, body.host, body.port)
    raw["protocols"] = protocols
    if protocols.get("TLSv1") or protocols.get("TLSv1_1"):
        findings.append(_finding(DiagnosticStatus.CRITICAL, "tls_legacy_enabled", "Legacy TLS 1.0/1.1 appears enabled.", "Disable TLS 1.0 and TLS 1.1."))
    if not protocols.get("TLSv1_2") and not protocols.get("TLSv1_3"):
        findings.append(_finding(DiagnosticStatus.CRITICAL, "tls_modern_missing", "No modern TLS protocol was observed."))
    else:
        findings.append(_finding(DiagnosticStatus.OK, "tls_modern_supported", "TLS 1.2 and/or TLS 1.3 is supported.", protocols=protocols))

    score = _tls_score(findings)
    grade = _tls_grade(score, findings)
    status = _overall(findings)
    raw["score"] = score
    raw["grade"] = grade
    raw["ciphers"] = []
    raw["recommendations"] = [finding.recommendation for finding in findings if finding.recommendation]

    return DiagnosticResponse(
        status=status,
        summary=f"Hyrule-native SSL Labs-style TLS scan for {body.host}:{body.port}: grade {grade}.",
        target=_target(body.host, normalized=f"{body.host}:{body.port}", type_=DiagnosticTargetType.HOST),
        findings=findings,
        sources={"hyrule_tls_scanner": source_ok()},
        raw=raw,
        generated_at=datetime.now(UTC),
    )


def _selected_headers(headers: httpx.Headers) -> dict[str, str]:
    wanted = set(_SECURITY_HEADERS) | set(_CDN_HINT_HEADERS) | {"server", "location"}
    return {key: value for key, value in headers.items() if key.lower() in wanted}


def _tls_certificate(host: str, port: int) -> dict[str, object]:
    context = ssl.create_default_context()
    addresses = assert_safe_active_probe_target(host, port=port)
    with socket.create_connection((addresses[0], port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {
                "subject": cert.get("subject", []),
                "issuer": cert.get("issuer", []),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "subject_alt_names": cert.get("subjectAltName", []),
                "version": tls.version(),
                "cipher": tls.cipher(),
            }


def _cert_findings(host: str, cert: dict[str, object]) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    not_after = cert.get("not_after")
    if not_after:
        expires = datetime.strptime(str(not_after), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        days = (expires - datetime.now(UTC)).days
        severity = DiagnosticStatus.CRITICAL if days < 0 else DiagnosticStatus.WARNING if days < 14 else DiagnosticStatus.OK
        findings.append(_finding(severity, "tls_cert_expiry", f"Certificate expires in {days} day(s).", "Renew the certificate." if days < 14 else None, expires_at=expires.isoformat(), days_remaining=days))
    sans = [item[1] for item in cert.get("subject_alt_names", []) if isinstance(item, tuple) and len(item) == 2]
    if _host_matches_san(host, sans):
        findings.append(_finding(DiagnosticStatus.OK, "tls_name_matches", "Certificate subjectAltName matches host.", sans=sans[:20]))
    else:
        findings.append(_finding(DiagnosticStatus.CRITICAL, "tls_name_mismatch", "Certificate subjectAltName does not match host.", "Install a certificate covering this hostname.", sans=sans[:20]))
    return findings


def _host_matches_san(host: str, sans: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for san in sans:
        candidate = san.lower().rstrip(".")
        if candidate == host:
            return True
        if candidate.startswith("*.") and host.endswith(candidate[1:]) and host.count(".") == candidate.count("."):
            return True
    return False


def _header_findings(headers: httpx.Headers) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    lower = {key.lower(): value for key, value in headers.items()}
    for header in _SECURITY_HEADERS:
        if header in lower:
            findings.append(_finding(DiagnosticStatus.OK, f"header_{header.replace('-', '_')}_present", f"{header} header is present."))
        else:
            findings.append(_finding(DiagnosticStatus.WARNING, f"header_{header.replace('-', '_')}_missing", f"{header} header is missing."))
    return findings


def _cdn_findings(headers: httpx.Headers) -> list[DiagnosticFinding]:
    lower = {key.lower(): value for key, value in headers.items()}
    providers = sorted({provider for header, provider in _CDN_HINT_HEADERS.items() if header in lower})
    if providers:
        return [_finding(DiagnosticStatus.INFO, "cdn_waf_hints", "CDN/WAF/edge hints detected.", providers=providers)]
    return [_finding(DiagnosticStatus.INFO, "cdn_waf_not_obvious", "No obvious CDN/WAF response-header hints detected.")]


def _tls_protocol_probe(host: str, port: int) -> dict[str, bool | str]:
    protocols: dict[str, bool | str] = {}
    for label, minimum, maximum in [
        ("TLSv1", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
        ("TLSv1_1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ("TLSv1_2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ("TLSv1_3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            context = ssl.create_default_context()
            context.minimum_version = minimum
            context.maximum_version = maximum
            addresses = assert_safe_active_probe_target(host, port=port)
            with socket.create_connection((addresses[0], port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    protocols[label] = True
        except Exception:
            protocols[label] = False
    return protocols


def _tls_score(findings: list[DiagnosticFinding]) -> int:
    score = 100
    for finding in findings:
        if finding.severity == DiagnosticStatus.CRITICAL:
            score -= 30
        elif finding.severity == DiagnosticStatus.WARNING:
            score -= 10
    return max(score, 0)


def _tls_grade(score: int, findings: list[DiagnosticFinding]) -> str:
    if any(f.code == "tls_handshake_failed" for f in findings):
        return "T"
    if any(f.code == "tls_name_mismatch" for f in findings):
        return "M"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"
