from __future__ import annotations

import json

import httpx
import pytest

from hyrule_cloud.config import GlobalpingConfig
from hyrule_cloud.models import (
    WebAvailabilityStatus,
    WebCheckRequest,
    WebFailurePhase,
    WebTLSObservation,
    WebVantageResult,
)
from hyrule_cloud.services.safety import UnsafeTargetError
from hyrule_cloud.services.web import checks as web_checks


def _vantage(
    name: str,
    status: WebAvailabilityStatus,
    *,
    status_code: int | None = None,
    phase: WebFailurePhase | None = None,
) -> WebVantageResult:
    return WebVantageResult(
        vantage=name,
        provider="test",
        status=status,
        status_code=status_code,
        failure_phase=phase,
        final_url="https://example.com",
    )


def test_root_cause_classifies_consistent_http_5xx_as_application_failure() -> None:
    results = [
        _vantage(f"probe-{index}", WebAvailabilityStatus.DOWN, status_code=503)
        for index in range(3)
    ]

    availability = web_checks._availability(results)
    root_cause = web_checks._root_cause(results, availability)

    assert availability.status == WebAvailabilityStatus.DOWN
    assert availability.down_ratio == 1
    assert root_cause.code == "http_server_error"
    assert root_cause.scope == "application"
    assert root_cause.confidence == "high"


def test_root_cause_classifies_split_results_as_regional() -> None:
    results = [
        _vantage("eu", WebAvailabilityStatus.UP, status_code=200),
        _vantage(
            "us",
            WebAvailabilityStatus.DOWN,
            phase=WebFailurePhase.TCP,
        ),
        _vantage("asia", WebAvailabilityStatus.UP, status_code=200),
    ]

    availability = web_checks._availability(results)
    root_cause = web_checks._root_cause(results, availability)

    assert availability.status == WebAvailabilityStatus.DEGRADED
    assert root_cause.code == "regional_or_edge_failure"
    assert root_cause.scope == "regional"
    assert "us" in root_cause.evidence[-1]


def test_root_cause_classifies_certificate_rejection() -> None:
    results = [
        WebVantageResult(
            vantage=f"probe-{index}",
            provider="test",
            status=WebAvailabilityStatus.DEGRADED,
            status_code=200,
            failure_phase=WebFailurePhase.TLS,
            tls=WebTLSObservation(authorized=False, error="certificate expired"),
        )
        for index in range(3)
    ]

    availability = web_checks._availability(results)
    root_cause = web_checks._root_cause(results, availability)

    assert root_cause.code == "tls_handshake_failure"
    assert root_cause.scope == "tls"
    assert root_cause.confidence == "high"


@pytest.mark.parametrize(
    ("phase", "expected_code", "expected_scope"),
    [
        (WebFailurePhase.DNS, "dns_resolution_failure", "dns"),
        (WebFailurePhase.TCP, "origin_unreachable", "origin"),
        (WebFailurePhase.TIMEOUT, "origin_timeout", "origin"),
    ],
)
def test_root_cause_classifies_transport_failure_phases(
    phase: WebFailurePhase,
    expected_code: str,
    expected_scope: str,
) -> None:
    results = [
        _vantage(f"probe-{index}", WebAvailabilityStatus.DOWN, phase=phase)
        for index in range(3)
    ]

    availability = web_checks._availability(results)
    root_cause = web_checks._root_cause(results, availability)

    assert root_cause.code == expected_code
    assert root_cause.scope == expected_scope
    assert root_cause.confidence == "high"


def test_parse_globalping_http_result_preserves_timing_tls_and_headers() -> None:
    document = {
        "results": [
            {
                "probe": {
                    "continent": "NA",
                    "region": "Northern America",
                    "country": "US",
                    "state": "NY",
                    "city": "New York",
                    "asn": 64500,
                    "network": "Example Network",
                },
                "result": {
                    "status": "finished",
                    "resolvedAddress": "93.184.216.34",
                    "statusCode": 200,
                    "statusCodeName": "OK",
                    "headers": {
                        "server": "example-edge",
                        "content-type": "text/html",
                        "set-cookie": "not-returned-without-include-raw",
                    },
                    "timings": {
                        "total": 87,
                        "dns": 12,
                        "tcp": 20,
                        "tls": 25,
                        "firstByte": 29,
                        "download": 1,
                    },
                    "tls": {
                        "authorized": True,
                        "protocol": "TLSv1.3",
                        "cipherName": "TLS_AES_256_GCM_SHA384",
                        "createdAt": "2026-01-01T00:00:00.000Z",
                        "expiresAt": "2027-01-01T00:00:00.000Z",
                        "subject": {"CN": "example.com"},
                        "issuer": {"O": "Example CA"},
                        "fingerprint256": "AA:BB",
                    },
                },
            }
        ]
    }

    results = web_checks._parse_globalping_results(
        document,
        url="https://example.com",
        include_raw=False,
    )

    assert len(results) == 1
    result = results[0]
    assert result.vantage == "globalping:US:New York:AS64500"
    assert result.status == WebAvailabilityStatus.UP
    assert result.latency_ms == 87
    assert result.timings_ms["firstByte"] == 29
    assert result.headers == {
        "server": "example-edge",
        "content-type": "text/html",
    }
    assert result.tls is not None
    assert result.tls.authorized is True
    assert result.tls.fingerprint_sha256 == "AA:BB"


def test_parse_globalping_failure_classifies_dns_phase() -> None:
    results = web_checks._parse_globalping_results(
        {
            "results": [
                {
                    "probe": {"country": "NL", "city": "Amsterdam"},
                    "result": {
                        "status": "failed",
                        "rawOutput": "curl: (6) Could not resolve host: missing.example",
                    },
                }
            ]
        },
        url="https://missing.example",
        include_raw=False,
    )

    assert results[0].status == WebAvailabilityStatus.DOWN
    assert results[0].failure_phase == WebFailurePhase.DNS


@pytest.mark.asyncio
async def test_local_probe_follows_redirects_and_falls_back_from_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    async def resolve_safe_target(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(
            200,
            headers={"server": "origin", "content-type": "text/html"},
        )

    monkeypatch.setattr(web_checks, "_resolve_safe_target", resolve_safe_target)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    ) as client:
        result = await web_checks._run_local_http_probe(
            "https://example.com/start",
            timeout_seconds=2,
            max_redirects=5,
            include_raw=False,
            resolved_address="93.184.216.34",
            client=client,
        )

    assert calls == [("HEAD", "/start"), ("HEAD", "/final"), ("GET", "/final")]
    assert result.status == WebAvailabilityStatus.UP
    assert result.status_code == 200
    assert result.final_url == "https://example.com/final"
    assert [hop.status_code for hop in result.redirects] == [302]
    assert result.headers["server"] == "origin"


@pytest.mark.asyncio
async def test_local_probe_rejects_private_redirect_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve_safe_target(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    monkeypatch.setattr(web_checks, "_resolve_safe_target", resolve_safe_target)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    ) as client:
        result = await web_checks._run_local_http_probe(
            "https://example.com/start",
            timeout_seconds=2,
            max_redirects=5,
            include_raw=False,
            resolved_address="93.184.216.34",
            client=client,
        )

    assert result.status == WebAvailabilityStatus.DOWN
    assert result.failure_phase == WebFailurePhase.REDIRECT
    assert "blocked non-public target" in (result.error or "")


@pytest.mark.asyncio
async def test_globalping_client_requests_one_probe_per_location() -> None:
    seen_payload: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            seen_payload.update(json.loads(request.content))
            return httpx.Response(202, json={"id": "measurement-1", "probesCount": 2})
        return httpx.Response(
            200,
            json={
                "id": "measurement-1",
                "status": "finished",
                "results": [
                    {
                        "probe": {"country": "NL", "city": "Amsterdam", "asn": 64500},
                        "result": {
                            "status": "finished",
                            "statusCode": 200,
                            "statusCodeName": "OK",
                            "headers": {"server": "edge"},
                            "resolvedAddress": "93.184.216.34",
                            "timings": {"total": 42},
                            "tls": None,
                        },
                    }
                ],
            },
        )

    config = GlobalpingConfig(
        api_url="https://api.globalping.test",
        request_timeout_seconds=3,
    )
    async with httpx.AsyncClient(
        base_url=config.api_url,
        transport=httpx.MockTransport(handler),
    ) as client:
        results, measurement_id = await web_checks._run_globalping_http_probes(
            "https://example.com/path?q=1",
            locations=["Western Europe", "Northern America"],
            timeout_ms=1000,
            include_raw=False,
            config=config,
            client=client,
        )

    assert measurement_id == "measurement-1"
    assert seen_payload["target"] == "example.com"
    assert seen_payload["locations"] == [
        {"magic": "Western Europe", "limit": 1},
        {"magic": "Northern America", "limit": 1},
    ]
    assert seen_payload["measurementOptions"] == {
        "protocol": "HTTPS",
        "port": 443,
        "request": {"method": "HEAD", "path": "/path", "query": "q=1"},
    }
    assert results[0].status == WebAvailabilityStatus.UP


@pytest.mark.asyncio
async def test_run_web_check_combines_local_and_distributed_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve_safe_target(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    async def read_tls_certificate(_host: str, _port: int) -> dict[str, object]:
        return {
            "subject": (("commonName", "example.com"),),
            "issuer": (("organizationName", "Example CA"),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jan  1 00:00:00 2035 GMT",
            "subject_alt_names": [("DNS", "example.com")],
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    async def local_probe(*_args: object, **_kwargs: object) -> WebVantageResult:
        return WebVantageResult(
            vantage="extmon",
            provider="hyrule",
            status=WebAvailabilityStatus.UP,
            status_code=200,
            latency_ms=25,
            final_url="https://example.com",
            headers={
                "server": "origin",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "same-origin",
                "permissions-policy": "geolocation=()",
            },
        )

    async def global_probes(
        *_args: object, **_kwargs: object
    ) -> tuple[list[WebVantageResult], str]:
        return (
            [
                _vantage(location, WebAvailabilityStatus.UP, status_code=200)
                for location in ("eu", "us", "asia")
            ],
            "measurement-1",
        )

    monkeypatch.setattr(web_checks, "_resolve_safe_target", resolve_safe_target)
    monkeypatch.setattr(web_checks, "_run_local_http_probe", local_probe)
    monkeypatch.setattr(web_checks, "_run_globalping_http_probes", global_probes)
    monkeypatch.setattr(web_checks, "_read_tls_certificate", read_tls_certificate)

    response = await web_checks.run_web_check(
        WebCheckRequest(target="https://example.com"),
        globalping_config=GlobalpingConfig(),
    )

    assert response.availability.status == WebAvailabilityStatus.UP
    assert response.availability.total_vantages == 4
    assert response.root_cause.code == "healthy"
    assert response.root_cause.confidence == "high"
    assert {result.vantage for result in response.vantage_results} == {
        "extmon",
        "eu",
        "us",
        "asia",
    }
    assert response.sources["globalping"].source_url is not None
    assert response.partial is False


@pytest.mark.asyncio
async def test_run_web_check_does_not_count_provider_failure_as_target_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve_safe_target(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    async def local_probe(*_args: object, **_kwargs: object) -> WebVantageResult:
        return _vantage("extmon", WebAvailabilityStatus.UP, status_code=200)

    async def failed_global_probes(*_args: object, **_kwargs: object) -> None:
        raise httpx.ConnectError("provider unavailable")

    monkeypatch.setattr(web_checks, "_resolve_safe_target", resolve_safe_target)
    monkeypatch.setattr(web_checks, "_run_local_http_probe", local_probe)
    monkeypatch.setattr(web_checks, "_run_globalping_http_probes", failed_global_probes)

    response = await web_checks.run_web_check(
        WebCheckRequest(target="http://example.com", checks=[]),
        globalping_config=GlobalpingConfig(),
    )

    assert response.availability.status == WebAvailabilityStatus.UP
    assert response.availability.total_vantages == 1
    assert response.sources["globalping"].status == "unavailable"
    assert response.partial is True


def test_private_web_target_is_rejected() -> None:
    with pytest.raises(UnsafeTargetError, match="blocked non-public target"):
        web_checks._normalize_web_url("http://127.0.0.1")
