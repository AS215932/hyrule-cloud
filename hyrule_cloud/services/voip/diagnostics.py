"""VoIP/SIP diagnostics with pluggable number-provider source statuses."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    DNSLookupRecordType,
    DNSLookupRequest,
    SourceHealth,
    VoIPCheck,
    VoIPCheckRequest,
    VoIPNumberLookupRequest,
)
from hyrule_cloud.services.diagnostics.sources import (
    source_not_configured,
    source_ok,
    source_unavailable,
    source_usable,
)
from hyrule_cloud.services.dns.lookup import lookup
from hyrule_cloud.services.safety import assert_safe_active_probe_target, normalize_host

_NUMBER_PROVIDERS = ["twilio", "telnyx", "numverify", "cnam_provider", "e911_provider", "number_spam_reputation"]


def _stun_host() -> str:
    from hyrule_cloud.config import HyruleConfig

    return HyruleConfig().stun_test_host


def voip_sources() -> dict[str, SourceHealth]:
    stun_source = (
        source_ok()
        if _stun_host()
        else source_not_configured("STUN active tester is not configured (set HYRULE_STUN_TEST_HOST).")
    )
    sources = {
        "dns": source_ok(),
        "sip_tls": source_ok(),
        "stun_turn": stun_source,
    }
    sources.update({provider: source_not_configured("number intelligence provider API key is not configured") for provider in _NUMBER_PROVIDERS})
    return sources


def number_intel_enabled() -> bool:
    """Whether a real number-intelligence provider is configured.

    voip_number_lookup returns only a contract stub until a carrier/CNAM/spam
    provider is wired up, so the route returns 501 before charging rather than
    billing for a disabled-adapter notice. (voip_check does real SIP DNS/TLS
    work and is unaffected.)
    """
    sources = voip_sources()
    return any(source_usable(sources[provider]) for provider in _NUMBER_PROVIDERS)


# Checks in voip_check that execute a real probe. SIP_OPTIONS and STUN_TURN only
# emit contract findings (no active prober/relay configured in the server-only
# MVP), so a request limited to those returns no live data.
_LIVE_VOIP_CHECKS = frozenset({VoIPCheck.SIP_DNS, VoIPCheck.SIP_TLS})


def voip_check_has_live_backend(checks: list[VoIPCheck]) -> bool:
    """Whether the requested checks include at least one that runs real work.

    A voip_check request that only asks for SIP_OPTIONS/STUN_TURN gets nothing
    but contract findings, so the route must 501 before charging rather than
    bill for a non-answer — mirroring the number-lookup and path gates. STUN
    becomes live once a public STUN responder is configured.
    """
    live = set(_LIVE_VOIP_CHECKS)
    if _stun_host():
        live.add(VoIPCheck.STUN_TURN)
    return any(check in live for check in checks)


async def _stun_check() -> tuple[list[DiagnosticFinding], SourceHealth]:
    """Confirm a public STUN responder is reachable.

    Returns the findings and the resolved ``stun_turn`` source health, so the
    response never reports the source as healthy while a finding says the
    responder is unreachable.
    """
    host = _stun_host()
    if not host:
        return (
            [
                _finding(
                    DiagnosticStatus.INFO,
                    "stun_turn_not_configured",
                    "STUN tester requires a configured public STUN responder.",
                )
            ],
            source_not_configured("STUN active tester is not configured (set HYRULE_STUN_TEST_HOST)."),
        )
    from hyrule_cloud.services.voip.stun_probe import stun_binding

    hostname, _, port_str = host.partition(":")
    port = int(port_str) if port_str else 3478
    mapped = await stun_binding(hostname, port)
    if mapped is None:
        return (
            [
                _finding(
                    DiagnosticStatus.WARNING,
                    "stun_responder_unreachable",
                    f"Public STUN responder {host} did not answer a binding request.",
                )
            ],
            source_unavailable(f"configured STUN responder {host} did not answer a binding request"),
        )
    return (
        [
            _finding(
                DiagnosticStatus.OK,
                "stun_responder_available",
                f"Public STUN responder {host} answered; mapped address {mapped[0]}:{mapped[1]}.",
                mapped_ip=mapped[0],
                mapped_port=mapped[1],
            )
        ],
        source_ok(),
    )


async def voip_check(body: VoIPCheckRequest) -> DiagnosticResponse:
    target = normalize_host(body.target)
    findings: list[DiagnosticFinding] = []
    raw: dict[str, object] = {}
    if VoIPCheck.SIP_DNS in body.checks:
        srv_udp = await lookup(DNSLookupRequest(name=f"_sip._udp.{target}", type=DNSLookupRecordType.SRV))
        srv_tls = await lookup(DNSLookupRequest(name=f"_sips._tcp.{target}", type=DNSLookupRecordType.SRV))
        naptr = await lookup(DNSLookupRequest(name=target, type=DNSLookupRecordType.NAPTR))
        raw["sip_dns"] = {"srv_udp": srv_udp.model_dump(mode="json"), "srv_tls": srv_tls.model_dump(mode="json"), "naptr": naptr.model_dump(mode="json")}
        count = len(srv_udp.answers) + len(srv_tls.answers) + len(naptr.answers)
        findings.append(_finding(DiagnosticStatus.OK if count else DiagnosticStatus.WARNING, "sip_dns_records", f"Found {count} SIP SRV/NAPTR record(s).", records=count))
    if VoIPCheck.SIP_TLS in body.checks:
        findings.extend(await _sip_tls(target, body.sip_port))
    if VoIPCheck.SIP_OPTIONS in body.checks:
        findings.append(_finding(DiagnosticStatus.INFO, "sip_options_contract", "SIP OPTIONS active probe is supported by contract and runs from configured VoIP-safe vantages when enabled."))
    sources = voip_sources()
    if VoIPCheck.STUN_TURN in body.checks:
        stun_findings, stun_source = await _stun_check()
        findings.extend(stun_findings)
        # Reflect the live probe outcome, not just "a host is configured".
        sources["stun_turn"] = stun_source
    status = DiagnosticStatus.OK if findings and all(f.severity in {DiagnosticStatus.OK, DiagnosticStatus.INFO} for f in findings) else DiagnosticStatus.WARNING
    return DiagnosticResponse(
        status=status,
        summary=f"VoIP/SIP check for {target}: {len(findings)} finding(s).",
        target=DiagnosticTarget(input=body.target, normalized=target, type=DiagnosticTargetType.DOMAIN),
        findings=findings,
        sources=sources,
        raw=raw if body.include_raw else None,
        generated_at=datetime.now(UTC),
    )


async def voip_number_lookup(body: VoIPNumberLookupRequest) -> DiagnosticResponse:
    findings = [
        _finding(DiagnosticStatus.INFO, "number_lookup_contract", "Number carrier/CNAM/spam/E911 providers are pluggable and disabled until configured.", checks=[check.value for check in body.checks]),
    ]
    return DiagnosticResponse(
        status=DiagnosticStatus.INFO,
        summary=f"VoIP number intelligence contract for {body.number}; provider adapters are disabled until configured.",
        target=DiagnosticTarget(input=body.number, normalized=body.number, type=DiagnosticTargetType.PHONE_NUMBER),
        findings=findings,
        sources=voip_sources(),
        raw={"country": body.country, "checks": [check.value for check in body.checks]} if body.include_raw else None,
        generated_at=datetime.now(UTC),
    )


async def _sip_tls(host: str, port: int) -> list[DiagnosticFinding]:
    try:
        await asyncio.to_thread(_tls_connect, host, port)
        return [_finding(DiagnosticStatus.OK, "sip_tls_connect_ok", f"SIP TLS connected to {host}:{port}.", port=port)]
    except Exception as exc:
        return [_finding(DiagnosticStatus.WARNING, "sip_tls_connect_failed", f"SIP TLS connection to {host}:{port} failed: {exc}", port=port)]


def _tls_connect(host: str, port: int) -> None:
    addresses = assert_safe_active_probe_target(host, port=port)
    context = ssl.create_default_context()
    with socket.create_connection((addresses[0], port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=host):
            return


def _finding(severity: DiagnosticStatus, code: str, message: str, **evidence: object) -> DiagnosticFinding:
    return DiagnosticFinding(severity=severity, code=code, message=message, evidence=evidence)
