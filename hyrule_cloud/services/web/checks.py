"""Hyrule-native web reachability, TLS, header, and CDN/WAF diagnostics."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from hyrule_cloud.config import GlobalpingConfig
from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    DiagnosticVantage,
    SourceStatus,
    WebAvailabilityStatus,
    WebAvailabilitySummary,
    WebCheck,
    WebCheckRequest,
    WebCheckResponse,
    WebFailurePhase,
    WebOutageScope,
    WebProbeLocation,
    WebRedirectHop,
    WebRootCauseAnalysis,
    WebRootCauseConfidence,
    WebTLSDeepRequest,
    WebTLSObservation,
    WebVantageResult,
)
from hyrule_cloud.services.diagnostics.sources import (
    source_degraded,
    source_not_configured,
    source_ok,
    source_unavailable,
)
from hyrule_cloud.services.safety import (
    UnsafeTargetError,
    assert_public_host,
    assert_safe_active_probe_target,
    assert_safe_port,
    normalize_host,
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
_SERVER_HEADERS = (
    {
        "age",
        "cache-control",
        "content-length",
        "content-type",
        "date",
        "etag",
        "location",
        "retry-after",
        "server",
        "server-timing",
        "via",
        "x-cache",
        "x-powered-by",
        "x-request-id",
    }
    | set(_SECURITY_HEADERS)
    | set(_CDN_HINT_HEADERS)
)
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


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


def _target(
    value: str,
    normalized: str | None = None,
    type_: DiagnosticTargetType = DiagnosticTargetType.URL,
) -> DiagnosticTarget:
    return DiagnosticTarget(input=value, normalized=normalized or value, type=type_)


def _normalize_web_url(target: str) -> str:
    value = target.strip()
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTargetError("only http and https URLs are allowed")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("URLs containing credentials are not allowed")
    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("target host is empty")
    assert_public_host(host)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    assert_safe_port(port)
    return parsed._replace(fragment="").geturl()


def normalize_web_target(target: str) -> str:
    """Validate + normalize a web-check target URL.

    Public wrapper over the request-shape checks (scheme, credentials, host,
    port range, unsafe IP literals) so a route can reject a malformed or
    unsafe-literal target *before* charging. Raises ``UnsafeTargetError`` (a
    ``ValueError``) on rejection. Does not resolve DNS — an unresolvable but
    well-formed public hostname passes here and becomes a paid diagnostic.
    """
    return _normalize_web_url(target)


async def _resolve_safe_target(host: str, port: int) -> list[str]:
    return await asyncio.to_thread(assert_safe_active_probe_target, host, port=port)


async def _read_tls_certificate(host: str, port: int) -> dict[str, object]:
    return await asyncio.to_thread(_tls_certificate, host, port)


def _status_for_http(
    status_code: int, tls: WebTLSObservation | None = None
) -> WebAvailabilityStatus:
    if tls is not None and tls.authorized is False:
        return WebAvailabilityStatus.DEGRADED
    if status_code < 400:
        return WebAvailabilityStatus.UP
    if status_code < 500:
        return WebAvailabilityStatus.DEGRADED
    return WebAvailabilityStatus.DOWN


def _classify_error(value: object) -> WebFailurePhase:
    message = str(value).lower()
    if any(
        token in message
        for token in ("enotfound", "name or service not known", "getaddrinfo", "resolve", "dns")
    ):
        return WebFailurePhase.DNS
    if any(token in message for token in ("certificate", "ssl", "tls", "hostname mismatch")):
        return WebFailurePhase.TLS
    if "timed out" in message or "timeout" in message:
        return WebFailurePhase.TIMEOUT
    if any(
        token in message for token in ("refused", "connect", "network is unreachable", "no route")
    ):
        return WebFailurePhase.TCP
    return WebFailurePhase.UNKNOWN


def _headers_from_httpx(headers: httpx.Headers, include_raw: bool) -> dict[str, str | list[str]]:
    result: dict[str, str | list[str]] = {}
    for key in headers:
        normalized = key.lower()
        if not include_raw and normalized not in _SERVER_HEADERS:
            continue
        values = headers.get_list(key)
        result[normalized] = values[0] if len(values) == 1 else values
    return result


def _headers_from_mapping(value: object, include_raw: bool) -> dict[str, str | list[str]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str | list[str]] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).lower()
        if not include_raw and key not in _SERVER_HEADERS:
            continue
        if isinstance(raw_value, list):
            result[key] = [str(item) for item in raw_value]
        else:
            result[key] = str(raw_value)
    return result


def _header_value(headers: dict[str, str | list[str]], key: str) -> str | None:
    value = headers.get(key.lower())
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _pin_to_address(url: str, connect_ip: str) -> tuple[str, dict[str, str], dict[str, object]]:
    """Rewrite a logical URL so the TCP connection targets the already-vetted
    IP, while TLS SNI, certificate verification, and the Host header stay bound
    to the original hostname.

    Without this the safety guard resolves and validates the hostname's
    addresses but httpx then re-resolves the same hostname independently at
    connect time — a DNS-rebinding target can pass the guard and still get the
    request delivered to a private/reserved address. Pinning the connect target
    to the vetted address closes that window; httpcore honours the
    ``sni_hostname`` extension for TLS, so certificate validation is unchanged.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    literal = f"[{connect_ip}]" if ":" in connect_ip else connect_ip
    connect_url = parsed._replace(netloc=f"{literal}:{port}").geturl()
    default_port = port == (443 if parsed.scheme == "https" else 80)
    headers = {"Host": host if default_port else f"{host}:{port}"}
    extensions: dict[str, object] = {}
    if parsed.scheme == "https":
        extensions["sni_hostname"] = host
    return connect_url, headers, extensions


async def _request_headers(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    connect_ip: str,
) -> tuple[int, httpx.Headers, float]:
    connect_url, host_headers, extensions = _pin_to_address(url, connect_ip)
    started = time.perf_counter()
    async with client.stream(
        method,
        connect_url,
        headers={
            "Accept": "*/*",
            "User-Agent": "HyruleCloud-WebDiag/2.0",
            **host_headers,
            **({"Range": "bytes=0-0"} if method == "GET" else {}),
        },
        extensions=extensions,
    ) as response:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return response.status_code, response.headers, latency_ms


async def _run_local_http_probe(
    url: str,
    *,
    timeout_seconds: float,
    max_redirects: int,
    include_raw: bool,
    resolved_address: str | None,
    client: httpx.AsyncClient | None = None,
) -> WebVantageResult:
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        )
    current = url
    visited = {url}
    redirects: list[WebRedirectHop] = []
    total_latency = 0.0
    current_resolved_address = resolved_address
    try:
        while True:
            parsed = urlparse(current)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            current_addresses = await _resolve_safe_target(host, port)
            current_resolved_address = current_addresses[0]

            status_code, response_headers, latency_ms = await _request_headers(
                client, "HEAD", current, connect_ip=current_resolved_address
            )
            total_latency += latency_ms
            if status_code in {405, 501}:
                status_code, response_headers, fallback_latency = await _request_headers(
                    client, "GET", current, connect_ip=current_resolved_address
                )
                latency_ms += fallback_latency
                total_latency += fallback_latency

            headers = _headers_from_httpx(response_headers, include_raw)
            location = _header_value(headers, "location")
            if status_code not in _REDIRECT_STATUSES or not location:
                return WebVantageResult(
                    vantage="extmon",
                    provider="hyrule",
                    location=WebProbeLocation(network="Hyrule external monitor"),
                    status=_status_for_http(status_code),
                    failure_phase=(WebFailurePhase.HTTP if status_code >= 500 else None),
                    status_code=status_code,
                    resolved_address=current_resolved_address,
                    latency_ms=round(total_latency, 2),
                    timings_ms={"total": round(total_latency, 2)},
                    redirects=redirects,
                    final_url=current,
                    headers=headers,
                )

            redirects.append(
                WebRedirectHop(
                    url=current,
                    status_code=status_code,
                    location=location,
                    latency_ms=latency_ms,
                )
            )
            if len(redirects) > max_redirects:
                return WebVantageResult(
                    vantage="extmon",
                    provider="hyrule",
                    location=WebProbeLocation(network="Hyrule external monitor"),
                    status=WebAvailabilityStatus.DOWN,
                    failure_phase=WebFailurePhase.REDIRECT,
                    status_code=status_code,
                    resolved_address=current_resolved_address,
                    latency_ms=round(total_latency, 2),
                    timings_ms={"total": round(total_latency, 2)},
                    redirects=redirects,
                    final_url=current,
                    headers=headers,
                    error=f"redirect limit exceeded ({max_redirects})",
                )
            try:
                next_url = _normalize_web_url(urljoin(current, location))
            except (UnsafeTargetError, ValueError) as exc:
                return WebVantageResult(
                    vantage="extmon",
                    provider="hyrule",
                    location=WebProbeLocation(network="Hyrule external monitor"),
                    status=WebAvailabilityStatus.DOWN,
                    failure_phase=WebFailurePhase.REDIRECT,
                    status_code=status_code,
                    resolved_address=current_resolved_address,
                    latency_ms=round(total_latency, 2),
                    timings_ms={"total": round(total_latency, 2)},
                    redirects=redirects,
                    final_url=current,
                    headers=headers,
                    error=f"unsafe or invalid redirect target: {exc}",
                )
            if next_url in visited:
                return WebVantageResult(
                    vantage="extmon",
                    provider="hyrule",
                    location=WebProbeLocation(network="Hyrule external monitor"),
                    status=WebAvailabilityStatus.DOWN,
                    failure_phase=WebFailurePhase.REDIRECT,
                    status_code=status_code,
                    resolved_address=current_resolved_address,
                    latency_ms=round(total_latency, 2),
                    timings_ms={"total": round(total_latency, 2)},
                    redirects=redirects,
                    final_url=current,
                    headers=headers,
                    error="redirect loop detected",
                )
            visited.add(next_url)
            current = next_url
    except Exception as exc:
        return WebVantageResult(
            vantage="extmon",
            provider="hyrule",
            location=WebProbeLocation(network="Hyrule external monitor"),
            status=WebAvailabilityStatus.DOWN,
            failure_phase=_classify_error(exc),
            resolved_address=current_resolved_address,
            latency_ms=round(total_latency, 2) if total_latency else None,
            timings_ms={"total": round(total_latency, 2)} if total_latency else {},
            redirects=redirects,
            final_url=current,
            error=str(exc),
        )
    finally:
        if owns_client:
            await client.aclose()


def _distinguished_name(value: object) -> dict[str, object]:
    result: dict[str, object] = {}

    def visit(node: object) -> None:
        if isinstance(node, (list, tuple)):
            if len(node) == 2 and isinstance(node[0], str):
                result[node[0]] = node[1]
                return
            for item in node:
                visit(item)

    visit(value)
    return result


def _local_tls_observation(cert: dict[str, object]) -> WebTLSObservation:
    not_after = cert.get("not_after")
    days_remaining: int | None = None
    if not_after:
        try:
            expires = datetime.strptime(str(not_after), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            days_remaining = (expires - datetime.now(UTC)).days
        except ValueError:
            pass
    cipher = cert.get("cipher")
    cipher_name = str(cipher[0]) if isinstance(cipher, tuple) and cipher else None
    return WebTLSObservation(
        authorized=True,
        protocol=str(cert.get("version")) if cert.get("version") else None,
        cipher=cipher_name,
        subject=_distinguished_name(cert.get("subject", [])),
        issuer=_distinguished_name(cert.get("issuer", [])),
        not_before=str(cert.get("not_before")) if cert.get("not_before") else None,
        not_after=str(not_after) if not_after else None,
        days_remaining=days_remaining,
    )


def _globalping_tls_observation(value: object) -> WebTLSObservation | None:
    if not isinstance(value, dict):
        return None
    subject: dict[object, object] = {}
    subject_value = value.get("subject")
    if isinstance(subject_value, dict):
        subject = subject_value
    issuer: dict[object, object] = {}
    issuer_value = value.get("issuer")
    if isinstance(issuer_value, dict):
        issuer = issuer_value
    expires_at = value.get("expiresAt")
    days_remaining: int | None = None
    if isinstance(expires_at, str):
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            days_remaining = (expires - datetime.now(UTC)).days
        except ValueError:
            pass
    return WebTLSObservation(
        authorized=value.get("authorized") if isinstance(value.get("authorized"), bool) else None,
        protocol=str(value.get("protocol")) if value.get("protocol") else None,
        cipher=str(value.get("cipherName")) if value.get("cipherName") else None,
        subject={str(key): item for key, item in subject.items()},
        issuer={str(key): item for key, item in issuer.items()},
        not_before=str(value.get("createdAt")) if value.get("createdAt") else None,
        not_after=str(expires_at) if expires_at else None,
        days_remaining=days_remaining,
        fingerprint_sha256=(
            str(value.get("fingerprint256")) if value.get("fingerprint256") else None
        ),
        error=str(value.get("error")) if value.get("error") else None,
    )


def _globalping_location(value: object) -> WebProbeLocation | None:
    if not isinstance(value, dict):
        return None
    return WebProbeLocation(
        city=str(value.get("city")) if value.get("city") else None,
        state=str(value.get("state")) if value.get("state") else None,
        country=str(value.get("country")) if value.get("country") else None,
        continent=str(value.get("continent")) if value.get("continent") else None,
        region=str(value.get("region")) if value.get("region") else None,
        asn=value.get("asn") if isinstance(value.get("asn"), int) else None,
        network=str(value.get("network")) if value.get("network") else None,
    )


def _globalping_vantage_name(location: WebProbeLocation | None, index: int) -> str:
    if location is None:
        return f"globalping:{index + 1}"
    parts = [location.country, location.city]
    if location.asn is not None:
        parts.append(f"AS{location.asn}")
    suffix = ":".join(part for part in parts if part)
    return f"globalping:{suffix or index + 1}"


def _parse_globalping_results(
    document: dict[str, Any],
    *,
    url: str,
    include_raw: bool,
) -> list[WebVantageResult]:
    parsed_results: list[WebVantageResult] = []
    raw_results = document.get("results")
    if not isinstance(raw_results, list):
        return parsed_results
    for index, item in enumerate(raw_results):
        if not isinstance(item, dict):
            continue
        location = _globalping_location(item.get("probe"))
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        result_status = str(result.get("status") or "unknown")
        vantage = _globalping_vantage_name(location, index)
        if result_status != "finished":
            error = str(result.get("error") or result.get("rawOutput") or result_status)
            parsed_results.append(
                WebVantageResult(
                    vantage=vantage,
                    provider="globalping",
                    location=location,
                    status=(
                        WebAvailabilityStatus.INCONCLUSIVE
                        if result_status in {"offline", "in-progress"}
                        else WebAvailabilityStatus.DOWN
                    ),
                    failure_phase=(
                        WebFailurePhase.PROBE
                        if result_status in {"offline", "in-progress"}
                        else _classify_error(error)
                    ),
                    final_url=url,
                    error=error[:1000],
                )
            )
            continue

        status_code = result.get("statusCode")
        if not isinstance(status_code, int):
            parsed_results.append(
                WebVantageResult(
                    vantage=vantage,
                    provider="globalping",
                    location=location,
                    status=WebAvailabilityStatus.INCONCLUSIVE,
                    failure_phase=WebFailurePhase.PROBE,
                    final_url=url,
                    error="Globalping returned a finished HTTP probe without a status code",
                )
            )
            continue
        tls = _globalping_tls_observation(result.get("tls"))
        headers = _headers_from_mapping(result.get("headers"), include_raw)
        timings_raw = result.get("timings")
        timings: dict[str, float | int | None] = {}
        if isinstance(timings_raw, dict):
            for key, value in timings_raw.items():
                if value is None or isinstance(value, (int, float)):
                    timings[str(key)] = value
        location_header = _header_value(headers, "location")
        total_timing = timings.get("total")
        redirects = (
            [
                WebRedirectHop(
                    url=url,
                    status_code=status_code,
                    location=location_header,
                    latency_ms=float(total_timing)
                    if isinstance(total_timing, (int, float))
                    else None,
                )
            ]
            if status_code in _REDIRECT_STATUSES and location_header
            else []
        )
        availability = _status_for_http(status_code, tls)
        parsed_results.append(
            WebVantageResult(
                vantage=vantage,
                provider="globalping",
                location=location,
                status=availability,
                failure_phase=(
                    WebFailurePhase.TLS
                    if tls is not None and tls.authorized is False
                    else WebFailurePhase.HTTP
                    if status_code >= 500
                    else None
                ),
                status_code=status_code,
                status_text=(
                    str(result.get("statusCodeName")) if result.get("statusCodeName") else None
                ),
                resolved_address=(
                    str(result.get("resolvedAddress")) if result.get("resolvedAddress") else None
                ),
                latency_ms=(
                    float(total_timing) if isinstance(total_timing, (int, float)) else None
                ),
                timings_ms=timings,
                redirects=redirects,
                final_url=url,
                headers=headers,
                tls=tls,
            )
        )
    return parsed_results


async def _run_globalping_http_probes(
    url: str,
    *,
    locations: list[str],
    timeout_ms: int,
    include_raw: bool,
    config: GlobalpingConfig,
    client: httpx.AsyncClient | None = None,
) -> tuple[list[WebVantageResult], str]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    protocol = "HTTPS" if parsed.scheme == "https" else "HTTP"
    port = parsed.port or (443 if protocol == "HTTPS" else 80)
    # GET, not HEAD: the local probe falls back to GET on a HEAD rejection
    # (405/501), but a single Globalping measurement cannot retry, so a
    # HEAD-averse-but-healthy origin would otherwise be scored DEGRADED from
    # every distributed vantage and contradict the local vantage.
    request_options: dict[str, object] = {
        "method": "GET",
        "path": parsed.path or "/",
    }
    if parsed.query:
        request_options["query"] = parsed.query
    payload = {
        "type": "http",
        "target": host,
        "locations": [{"magic": location, "limit": 1} for location in locations],
        "measurementOptions": {
            "protocol": protocol,
            "port": port,
            "request": request_options,
        },
    }
    headers = {
        "Accept": "application/json",
        "User-Agent": "hyrule-cloud/0.1 (+https://cloud.hyrule.host)",
    }
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            base_url=config.api_url.rstrip("/"),
            timeout=httpx.Timeout(config.request_timeout_seconds),
            headers=headers,
        )
    try:
        create = await client.post("/v1/measurements", json=payload, headers=headers)
        create.raise_for_status()
        created = create.json()
        measurement_id = str(created["id"])
        deadline = time.monotonic() + min(
            config.request_timeout_seconds,
            max(timeout_ms / 1000 + 2, 3),
        )
        while True:
            await asyncio.sleep(config.poll_interval_seconds)
            response = await client.get(f"/v1/measurements/{measurement_id}", headers=headers)
            response.raise_for_status()
            document = response.json()
            if document.get("status") != "in-progress":
                return (
                    _parse_globalping_results(
                        document,
                        url=url,
                        include_raw=include_raw,
                    ),
                    measurement_id,
                )
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Globalping measurement {measurement_id} did not finish before deadline"
                )
    finally:
        if owns_client:
            await client.aclose()


def _availability(results: list[WebVantageResult]) -> WebAvailabilitySummary:
    determinate = [
        result for result in results if result.status != WebAvailabilityStatus.INCONCLUSIVE
    ]
    failed = sum(result.status == WebAvailabilityStatus.DOWN for result in determinate)
    degraded = sum(result.status == WebAvailabilityStatus.DEGRADED for result in determinate)
    responding = sum(result.status_code is not None for result in determinate)
    down_ratio = failed / len(determinate) if determinate else 0.0
    if not determinate:
        status = WebAvailabilityStatus.INCONCLUSIVE
        is_down: bool | None = None
    elif failed == len(determinate):
        status = WebAvailabilityStatus.DOWN
        is_down = True
    elif failed or degraded:
        status = WebAvailabilityStatus.DEGRADED
        is_down = False
    else:
        status = WebAvailabilityStatus.UP
        is_down = False
    return WebAvailabilitySummary(
        status=status,
        is_down=is_down,
        total_vantages=len(results),
        responding_vantages=responding,
        degraded_vantages=degraded,
        failed_vantages=failed,
        down_ratio=round(down_ratio, 3),
    )


def _root_cause(
    results: list[WebVantageResult],
    availability: WebAvailabilitySummary,
) -> WebRootCauseAnalysis:
    determinate = [
        result for result in results if result.status != WebAvailabilityStatus.INCONCLUSIVE
    ]
    down = [result for result in determinate if result.status == WebAvailabilityStatus.DOWN]
    up = [result for result in determinate if result.status == WebAvailabilityStatus.UP]
    degraded = [result for result in determinate if result.status == WebAvailabilityStatus.DEGRADED]
    status_codes = [result.status_code for result in determinate if result.status_code]
    evidence = [
        f"{len(up)} up, {len(degraded)} degraded, {len(down)} down across {len(determinate)} conclusive vantage(s)"
    ]
    if status_codes:
        evidence.append(f"Observed HTTP status codes: {sorted(status_codes)}")

    if availability.status == WebAvailabilityStatus.UP:
        return WebRootCauseAnalysis(
            code="healthy",
            scope=WebOutageScope.NONE,
            confidence=(
                WebRootCauseConfidence.HIGH
                if len(determinate) >= 3
                else WebRootCauseConfidence.MEDIUM
            ),
            summary="The site responded successfully from every conclusive vantage.",
            evidence=evidence,
        )
    if availability.status == WebAvailabilityStatus.INCONCLUSIVE:
        return WebRootCauseAnalysis(
            code="insufficient_evidence",
            scope=WebOutageScope.UNKNOWN,
            confidence=WebRootCauseConfidence.LOW,
            summary="No vantage returned enough evidence to determine site availability.",
            evidence=evidence,
            recommendations=["Retry the check or select different Globalping locations."],
        )

    redirect_failures = [
        result for result in down if result.failure_phase == WebFailurePhase.REDIRECT
    ]
    if redirect_failures:
        evidence.extend(result.error or "redirect failure" for result in redirect_failures)
        return WebRootCauseAnalysis(
            code="redirect_failure",
            scope=WebOutageScope.REDIRECT,
            confidence=WebRootCauseConfidence.HIGH,
            summary="The redirect chain loops or exceeds the configured hop limit.",
            evidence=evidence,
            recommendations=["Inspect Location headers and remove the redirect cycle."],
        )

    if down and (up or degraded):
        failed_locations = [result.vantage for result in down]
        evidence.append(f"Failures were limited to: {', '.join(failed_locations)}")
        return WebRootCauseAnalysis(
            code="regional_or_edge_failure",
            scope=WebOutageScope.REGIONAL,
            confidence=(
                WebRootCauseConfidence.HIGH
                if len(determinate) >= 3
                else WebRootCauseConfidence.MEDIUM
            ),
            summary="The site works from some vantages and fails from others, indicating a regional path, DNS, CDN, or edge issue.",
            evidence=evidence,
            recommendations=["Compare DNS answers and CDN/origin health for the failing regions."],
        )

    tls_issues = [
        result
        for result in determinate
        if result.failure_phase == WebFailurePhase.TLS
        or (result.tls is not None and result.tls.authorized is False)
    ]
    if tls_issues and len(tls_issues) * 2 >= len(determinate):
        return WebRootCauseAnalysis(
            code="tls_handshake_failure",
            scope=WebOutageScope.TLS,
            confidence=(
                WebRootCauseConfidence.HIGH
                if len(determinate) >= 3
                else WebRootCauseConfidence.MEDIUM
            ),
            summary="TLS negotiation or certificate validation failed from most vantages.",
            evidence=evidence,
            recommendations=[
                "Check certificate expiry, hostname coverage, intermediates, SNI, and supported TLS versions."
            ],
        )

    for phase, code, scope, summary, recommendations in (
        (
            WebFailurePhase.DNS,
            "dns_resolution_failure",
            WebOutageScope.DNS,
            "DNS resolution failed from most failing vantages.",
            ["Check authoritative nameservers, A/AAAA records, DNSSEC, and recent DNS changes."],
        ),
        (
            WebFailurePhase.TLS,
            "tls_handshake_failure",
            WebOutageScope.TLS,
            "TLS negotiation or certificate validation failed from most failing vantages.",
            [
                "Check certificate expiry, hostname coverage, intermediates, SNI, and supported TLS versions."
            ],
        ),
        (
            WebFailurePhase.TCP,
            "origin_unreachable",
            WebOutageScope.ORIGIN,
            "The hostname resolves, but most failing vantages cannot establish a TCP connection.",
            [
                "Check the origin/load balancer, listener port, firewall rules, and upstream routing."
            ],
        ),
        (
            WebFailurePhase.TIMEOUT,
            "origin_timeout",
            WebOutageScope.ORIGIN,
            "Most failing vantages timed out before receiving an HTTP response.",
            [
                "Check origin saturation, firewall drops, upstream latency, and load-balancer health."
            ],
        ),
    ):
        matching = [result for result in down if result.failure_phase == phase]
        if matching and len(matching) * 2 >= max(len(down), 1):
            return WebRootCauseAnalysis(
                code=code,
                scope=scope,
                confidence=(
                    WebRootCauseConfidence.HIGH
                    if availability.status == WebAvailabilityStatus.DOWN and len(determinate) >= 3
                    else WebRootCauseConfidence.MEDIUM
                ),
                summary=summary,
                evidence=evidence,
                recommendations=recommendations,
            )

    server_errors = [
        result
        for result in determinate
        if result.status_code is not None and result.status_code >= 500
    ]
    if server_errors and len(server_errors) * 2 >= len(determinate):
        return WebRootCauseAnalysis(
            code="http_server_error",
            scope=WebOutageScope.APPLICATION,
            confidence=(
                WebRootCauseConfidence.HIGH
                if len(server_errors) >= 3
                else WebRootCauseConfidence.MEDIUM
            ),
            summary="The server is reachable but returns 5xx responses from most vantages.",
            evidence=evidence,
            recommendations=["Inspect application, reverse-proxy, and upstream dependency logs."],
        )

    access_control = [
        result for result in degraded if result.status_code in {401, 403, 407, 429, 451}
    ]
    if access_control and len(access_control) * 2 >= max(len(determinate), 1):
        return WebRootCauseAnalysis(
            code="access_control_or_waf",
            scope=WebOutageScope.ACCESS_CONTROL,
            confidence=WebRootCauseConfidence.MEDIUM,
            summary="The site is reachable, but access controls, a WAF, or rate limiting reject the probes.",
            evidence=evidence,
            recommendations=[
                "Review WAF/bot rules, rate limits, authentication, and geographic policy."
            ],
        )

    if degraded:
        return WebRootCauseAnalysis(
            code="http_client_error",
            scope=WebOutageScope.APPLICATION,
            confidence=WebRootCauseConfidence.MEDIUM,
            summary="The site is reachable but returns non-success application responses.",
            evidence=evidence,
            recommendations=[
                "Confirm the requested path and inspect application or access-control rules."
            ],
        )

    return WebRootCauseAnalysis(
        code="unclassified_outage",
        scope=WebOutageScope.UNKNOWN,
        confidence=WebRootCauseConfidence.LOW,
        summary="The site appears unavailable, but the evidence does not isolate one failure phase.",
        evidence=evidence,
        recommendations=[
            "Retry with more locations and correlate with DNS, firewall, and origin logs."
        ],
    )


def _availability_finding(
    availability: WebAvailabilitySummary,
    root_cause: WebRootCauseAnalysis,
) -> DiagnosticFinding:
    severity = {
        WebAvailabilityStatus.UP: DiagnosticStatus.OK,
        WebAvailabilityStatus.DEGRADED: DiagnosticStatus.WARNING,
        WebAvailabilityStatus.DOWN: DiagnosticStatus.CRITICAL,
        WebAvailabilityStatus.INCONCLUSIVE: DiagnosticStatus.ERROR,
    }[availability.status]
    recommendation = root_cause.recommendations[0] if root_cause.recommendations else None
    return _finding(
        severity,
        f"availability_{availability.status.value}",
        root_cause.summary,
        recommendation,
        availability=availability.model_dump(mode="json"),
        root_cause=root_cause.model_dump(mode="json"),
    )


async def run_web_check(
    body: WebCheckRequest,
    *,
    globalping_config: GlobalpingConfig | None = None,
) -> WebCheckResponse:
    url = _normalize_web_url(body.target)
    parsed = urlparse(url)
    host = normalize_host(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    findings: list[DiagnosticFinding] = []
    raw: dict[str, object] = {}
    sources = {"web": source_ok()}
    requested_vantages = set(body.vantages)
    addresses: list[str] = []
    dns_error: str | None = None
    try:
        addresses = await _resolve_safe_target(host, port)
        if WebCheck.DNS in body.checks:
            findings.append(
                _finding(
                    DiagnosticStatus.OK,
                    "dns_resolves_public",
                    f"{host} resolved to public address(es).",
                    addresses=addresses,
                )
            )
            raw["addresses"] = addresses
    except UnsafeTargetError as exc:
        # Post-charge resolution failures are diagnostic evidence, not a crash.
        # A hostname that will not resolve, or that resolves to a private/
        # reserved address, is reported as a finding; `addresses` stays empty so
        # the local prober is skipped and a blocked address is never dialled.
        # Globalping (external, never connected from here) still contributes the
        # public-internet view. Malformed or unsafe-literal targets are already
        # rejected before payment in the route.
        dns_error = str(exc)
        if WebCheck.DNS in body.checks:
            unresolved = "unable to resolve target" in dns_error or "no usable addresses" in dns_error
            findings.append(
                _finding(
                    DiagnosticStatus.CRITICAL,
                    "dns_resolution_failed" if unresolved else "dns_resolves_non_public",
                    f"{host} did not resolve to a safe public target: {exc}",
                )
            )

    local_task: asyncio.Task[WebVantageResult] | None = None
    if DiagnosticVantage.EXTMON in requested_vantages:
        sources[DiagnosticVantage.EXTMON.value] = source_ok()
        if addresses:
            local_task = asyncio.create_task(
                _run_local_http_probe(
                    url,
                    timeout_seconds=body.timeout_ms / 1000,
                    max_redirects=body.max_redirects,
                    include_raw=body.include_raw,
                    resolved_address=addresses[0],
                )
            )

    config = globalping_config or GlobalpingConfig()
    globalping_task: asyncio.Task[tuple[list[WebVantageResult], str]] | None = None
    if DiagnosticVantage.GLOBALPING in requested_vantages:
        if config.enabled:
            globalping_task = asyncio.create_task(
                _run_globalping_http_probes(
                    url,
                    locations=body.locations,
                    timeout_ms=body.timeout_ms,
                    include_raw=body.include_raw,
                    config=config,
                )
            )
        else:
            sources[DiagnosticVantage.GLOBALPING.value] = source_not_configured(
                "Globalping probes are disabled by configuration.",
                source_url=config.api_url,
            )

    for vantage in requested_vantages - {
        DiagnosticVantage.EXTMON,
        DiagnosticVantage.GLOBALPING,
    }:
        sources[vantage.value] = source_not_configured(
            f"{vantage.value} web probing is not configured."
        )

    vantage_results: list[WebVantageResult] = []
    if local_task is not None:
        completed_local_result = await local_task
        vantage_results.append(completed_local_result)
    elif DiagnosticVantage.EXTMON in requested_vantages and dns_error:
        vantage_results.append(
            WebVantageResult(
                vantage="extmon",
                provider="hyrule",
                location=WebProbeLocation(network="Hyrule external monitor"),
                status=WebAvailabilityStatus.DOWN,
                failure_phase=WebFailurePhase.DNS,
                final_url=url,
                error=dns_error,
            )
        )

    measurement_id: str | None = None
    if globalping_task is not None:
        try:
            global_results, measurement_id = await globalping_task
            vantage_results.extend(global_results)
            measurement_url = f"{config.api_url.rstrip('/')}/v1/measurements/{measurement_id}"
            if len(global_results) < len(body.locations) or any(
                result.status == WebAvailabilityStatus.INCONCLUSIVE for result in global_results
            ):
                sources[DiagnosticVantage.GLOBALPING.value] = source_degraded(
                    f"Globalping returned {len(global_results)} result(s) for {len(body.locations)} requested location(s).",
                    source_url=measurement_url,
                )
            else:
                sources[DiagnosticVantage.GLOBALPING.value] = source_ok(source_url=measurement_url)
        except Exception as exc:
            sources[DiagnosticVantage.GLOBALPING.value] = source_unavailable(
                str(exc), source_url=config.api_url
            )

    local_result: WebVantageResult | None = next(
        (result for result in vantage_results if result.vantage == "extmon"), None
    )
    cert_info: dict[str, object] | None = None
    if (
        parsed.scheme == "https"
        and addresses
        and (WebCheck.TLS in body.checks or WebCheck.CERT in body.checks)
    ):
        try:
            cert_info = await _read_tls_certificate(host, port)
            findings.extend(_cert_findings(host, cert_info))
            raw["tls"] = cert_info
            if local_result is not None:
                local_result.tls = _local_tls_observation(cert_info)
        except Exception as exc:
            findings.append(
                _finding(
                    DiagnosticStatus.CRITICAL,
                    "tls_handshake_failed",
                    f"TLS handshake/certificate check failed: {exc}",
                )
            )
            if local_result is not None:
                local_result.tls = WebTLSObservation(authorized=False, error=str(exc))
                local_result.failure_phase = WebFailurePhase.TLS
                if local_result.status == WebAvailabilityStatus.UP:
                    local_result.status = WebAvailabilityStatus.DEGRADED

    if local_result is not None and local_result.status_code is not None:
        severity = (
            DiagnosticStatus.OK
            if local_result.status == WebAvailabilityStatus.UP
            else DiagnosticStatus.WARNING
        )
        findings.append(
            _finding(
                severity,
                "http_response",
                f"{local_result.final_url or url} returned HTTP {local_result.status_code}.",
                status_code=local_result.status_code,
                latency_ms=local_result.latency_ms,
                redirects=[hop.model_dump(mode="json") for hop in local_result.redirects],
                final_url=local_result.final_url,
            )
        )
        raw["http"] = {
            "status_code": local_result.status_code,
            "latency_ms": local_result.latency_ms,
            "redirects": [hop.model_dump(mode="json") for hop in local_result.redirects],
            "final_url": local_result.final_url,
            "headers": local_result.headers,
        }
        local_headers = httpx.Headers(
            [
                (key, item)
                for key, value in local_result.headers.items()
                for item in (value if isinstance(value, list) else [value])
            ]
        )
        if WebCheck.HEADERS in body.checks:
            findings.extend(_header_findings(local_headers))
        if WebCheck.CDN_WAF in body.checks:
            findings.extend(_cdn_findings(local_headers))

    availability = _availability(vantage_results)
    root_cause = _root_cause(vantage_results, availability)
    findings.insert(0, _availability_finding(availability, root_cause))
    if measurement_id:
        raw["globalping_measurement_id"] = measurement_id
    raw["requested_vantages"] = [vantage.value for vantage in body.vantages]
    raw["requested_locations"] = body.locations

    status = _overall(findings)
    summary = (
        f"{host} is {availability.status.value} across "
        f"{availability.total_vantages} observed vantage(s): {root_cause.summary}"
    )
    return WebCheckResponse(
        status=status,
        summary=summary,
        target=_target(body.target, normalized=url),
        findings=findings,
        sources=sources,
        raw=raw if body.include_raw else None,
        availability=availability,
        vantage_results=vantage_results,
        root_cause=root_cause,
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
        findings.append(
            _finding(
                DiagnosticStatus.CRITICAL, "tls_handshake_failed", f"TLS handshake failed: {exc}"
            )
        )

    protocols, ciphers = await asyncio.to_thread(_tls_protocol_probe, body.host, body.port)
    raw["protocols"] = protocols
    if protocols.get("TLSv1") or protocols.get("TLSv1_1"):
        findings.append(
            _finding(
                DiagnosticStatus.CRITICAL,
                "tls_legacy_enabled",
                "Legacy TLS 1.0/1.1 appears enabled.",
                "Disable TLS 1.0 and TLS 1.1.",
            )
        )
    if not protocols.get("TLSv1_2") and not protocols.get("TLSv1_3"):
        findings.append(
            _finding(
                DiagnosticStatus.CRITICAL,
                "tls_modern_missing",
                "No modern TLS protocol was observed.",
            )
        )
    else:
        findings.append(
            _finding(
                DiagnosticStatus.OK,
                "tls_modern_supported",
                "TLS 1.2 and/or TLS 1.3 is supported.",
                protocols=protocols,
            )
        )

    score = _tls_score(findings)
    grade = _tls_grade(score, findings)
    status = _overall(findings)
    raw["score"] = score
    raw["grade"] = grade
    raw["ciphers"] = ciphers
    raw["recommendations"] = [
        finding.recommendation for finding in findings if finding.recommendation
    ]

    return DiagnosticResponse(
        status=status,
        summary=f"Deep TLS protocol/certificate/cipher scan for {body.host}:{body.port}: grade {grade}.",
        target=_target(
            body.host, normalized=f"{body.host}:{body.port}", type_=DiagnosticTargetType.HOST
        ),
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
            cert: dict[str, object] = dict(tls.getpeercert() or {})
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
        severity = (
            DiagnosticStatus.CRITICAL
            if days < 0
            else DiagnosticStatus.WARNING
            if days < 14
            else DiagnosticStatus.OK
        )
        findings.append(
            _finding(
                severity,
                "tls_cert_expiry",
                f"Certificate expires in {days} day(s).",
                "Renew the certificate." if days < 14 else None,
                expires_at=expires.isoformat(),
                days_remaining=days,
            )
        )
    raw_sans = cert.get("subject_alt_names", [])
    sans: list[str] = []
    if isinstance(raw_sans, (list, tuple)):
        for item in raw_sans:
            if isinstance(item, tuple) and len(item) == 2:
                sans.append(str(item[1]))
    if _host_matches_san(host, sans):
        findings.append(
            _finding(
                DiagnosticStatus.OK,
                "tls_name_matches",
                "Certificate subjectAltName matches host.",
                sans=sans[:20],
            )
        )
    else:
        findings.append(
            _finding(
                DiagnosticStatus.CRITICAL,
                "tls_name_mismatch",
                "Certificate subjectAltName does not match host.",
                "Install a certificate covering this hostname.",
                sans=sans[:20],
            )
        )
    return findings


def _host_matches_san(host: str, sans: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for san in sans:
        candidate = san.lower().rstrip(".")
        if candidate == host:
            return True
        if (
            candidate.startswith("*.")
            and host.endswith(candidate[1:])
            and host.count(".") == candidate.count(".")
        ):
            return True
    return False


def _header_findings(headers: httpx.Headers) -> list[DiagnosticFinding]:
    findings: list[DiagnosticFinding] = []
    lower = {key.lower(): value for key, value in headers.items()}
    for header in _SECURITY_HEADERS:
        if header in lower:
            findings.append(
                _finding(
                    DiagnosticStatus.OK,
                    f"header_{header.replace('-', '_')}_present",
                    f"{header} header is present.",
                )
            )
        else:
            findings.append(
                _finding(
                    DiagnosticStatus.WARNING,
                    f"header_{header.replace('-', '_')}_missing",
                    f"{header} header is missing.",
                )
            )
    return findings


def _cdn_findings(headers: httpx.Headers) -> list[DiagnosticFinding]:
    lower = {key.lower(): value for key, value in headers.items()}
    providers = sorted(
        {provider for header, provider in _CDN_HINT_HEADERS.items() if header in lower}
    )
    if providers:
        return [
            _finding(
                DiagnosticStatus.INFO,
                "cdn_waf_hints",
                "CDN/WAF/edge hints detected.",
                providers=providers,
            )
        ]
    return [
        _finding(
            DiagnosticStatus.INFO,
            "cdn_waf_not_obvious",
            "No obvious CDN/WAF response-header hints detected.",
        )
    ]


def _tls_protocol_probe(host: str, port: int) -> tuple[dict[str, bool], list[dict[str, object]]]:
    """Probe each TLS version and record the cipher negotiated on success.

    Ciphers are the per-version negotiated suites (one handshake per version
    with default client ciphers), not an exhaustive suite enumeration.
    """
    protocols: dict[str, bool] = {}
    ciphers: list[dict[str, object]] = []
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
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    protocols[label] = True
                    negotiated = tls.cipher()
                    if negotiated:
                        name, tls_version, bits = negotiated
                        ciphers.append(
                            {
                                "protocol": label,
                                "cipher": name,
                                "tls_version": tls_version,
                                "bits": bits,
                            }
                        )
        except Exception:
            protocols[label] = False
    return protocols, ciphers


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
