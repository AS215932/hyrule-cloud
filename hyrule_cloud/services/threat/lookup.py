"""Open-source-first threat and reputation lookup helpers."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    SourceHealth,
    SourceStatus,
    ThreatLookupRequest,
    ThreatSubjectType,
    ThreatView,
)
from hyrule_cloud.services.diagnostics.sources import source_not_configured, source_ok

_LICENSED_SOURCES = [
    "spamhaus_commercial",
    "spamcop",
    "barracuda",
    "talos",
    "senderscore",
    "microsoft_snds",
    "google_postmaster",
]


def threat_sources() -> dict[str, SourceHealth]:
    sources = {
        "rdap": source_ok(),
        "whois": source_ok(),
        "dns": source_ok(),
        "crtsh": source_ok(source_url="https://crt.sh"),
        "basic_dnsbl": source_ok(),
    }
    sources.update({name: source_not_configured("licensed or owner-verified provider is not configured") for name in _LICENSED_SOURCES})
    return sources


def threat_intel_enabled() -> bool:
    """Whether a real reputation source is configured.

    Until a licensed/owner-verified provider is wired up, threat_lookup only
    emits contract metadata (no external calls), so the route returns 501
    before charging rather than billing for a non-answer.
    """
    sources = threat_sources()
    return any(
        sources[name].status != SourceStatus.SOURCE_NOT_CONFIGURED for name in _LICENSED_SOURCES
    )


async def threat_lookup(body: ThreatLookupRequest) -> DiagnosticResponse:
    subject = body.subject
    target_type = _target_type(subject.type)
    findings = [_finding(DiagnosticStatus.INFO, "threat_lookup_scope", "Threat/reputation report prepared from open sources and configured provider adapters.", views=[view.value for view in body.views])]
    raw: dict[str, object] = {"subject": subject.model_dump(mode="json"), "views": [view.value for view in body.views]}

    if ThreatView.CT in body.views and subject.type in {ThreatSubjectType.DOMAIN, ThreatSubjectType.URL}:
        findings.append(_finding(DiagnosticStatus.INFO, "ct_available", "Certificate Transparency lookup is available through crt.sh-compatible source adapter.", source="crtsh"))
        raw["ct"] = {"source": "crtsh", "status": "adapter_contract"}
    if ThreatView.RBL in body.views:
        findings.append(_rbl_finding(subject.value))
    if ThreatView.REPUTATION in body.views:
        findings.append(_finding(DiagnosticStatus.INFO, "licensed_reputation_sources", "Licensed/owner-verified reputation sources return source_not_configured until credentials are configured.", sources=_LICENSED_SOURCES))

    return DiagnosticResponse(
        status=DiagnosticStatus.INFO,
        summary=f"Threat/reputation lookup for {subject.type.value} {subject.value}: {len(findings)} finding(s).",
        target=DiagnosticTarget(input=subject.value, normalized=subject.value, type=target_type),
        findings=findings,
        sources=threat_sources(),
        raw=raw if body.include_raw else None,
        generated_at=datetime.now(UTC),
    )


def _target_type(subject_type: ThreatSubjectType) -> DiagnosticTargetType:
    return {
        ThreatSubjectType.DOMAIN: DiagnosticTargetType.DOMAIN,
        ThreatSubjectType.IP: DiagnosticTargetType.IP,
        ThreatSubjectType.CERT: DiagnosticTargetType.CERTIFICATE,
        ThreatSubjectType.URL: DiagnosticTargetType.URL,
    }[subject_type]


def _finding(severity: DiagnosticStatus, code: str, message: str, **evidence: object) -> DiagnosticFinding:
    return DiagnosticFinding(severity=severity, code=code, message=message, evidence=evidence)


def _rbl_finding(value: str) -> DiagnosticFinding:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return _finding(DiagnosticStatus.INFO, "rbl_domain_contract", "Domain RBL/reputation adapters are available where provider terms permit.", target=value)
    if ip.version == 6:
        return _finding(DiagnosticStatus.INFO, "rbl_ipv6_limited", "IPv6 RBL coverage depends on provider support and configured feeds.", target=value)
    return _finding(DiagnosticStatus.INFO, "rbl_ipv4_contract", "IPv4 DNSBL/RBL checks are available through permitted open/provider sources.", target=value)
