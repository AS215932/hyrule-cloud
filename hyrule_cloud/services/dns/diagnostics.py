"""Higher-level read-only DNS diagnostics for support workflows."""

from __future__ import annotations

from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    DNSAuthorityCompareRequest,
    DNSDiagnosticResponse,
    DNSLookupRecordType,
    DNSLookupRequest,
    DNSPropagationRequest,
)
from hyrule_cloud.services.diagnostics.sources import source_ok
from hyrule_cloud.services.dns.lookup import lookup

_RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
    "system": "system",
    "default": "system",
}


def _finding(severity: DiagnosticStatus, code: str, message: str, **evidence: object) -> DiagnosticFinding:
    return DiagnosticFinding(severity=severity, code=code, message=message, evidence=evidence)


async def propagation(body: DNSPropagationRequest) -> DNSDiagnosticResponse:
    findings: list[DiagnosticFinding] = []
    raw: dict[str, object] = {}
    matched = 0
    for resolver_name in body.resolvers:
        resolver = _RESOLVERS.get(resolver_name, resolver_name)
        resp = await lookup(DNSLookupRequest(name=body.name, type=body.type, resolver=resolver, timeout_ms=body.timeout_ms))
        values = [answer.value for answer in resp.answers]
        raw[resolver_name] = resp.model_dump(mode="json")
        ok = not body.expected or sorted(values) == sorted(body.expected) or all(item in values for item in body.expected)
        if ok:
            matched += 1
        findings.append(_finding(DiagnosticStatus.OK if ok else DiagnosticStatus.WARNING, "resolver_answer", f"{resolver_name} returned {len(values)} {body.type.value} answer(s).", resolver=resolver_name, values=values, expected=body.expected))
    status = DiagnosticStatus.OK if matched == len(body.resolvers) else DiagnosticStatus.WARNING
    return DNSDiagnosticResponse(
        status=status,
        summary=f"DNS propagation for {body.name} {body.type.value}: {matched}/{len(body.resolvers)} resolver(s) matched expectation.",
        target=DiagnosticTarget(input=body.name, normalized=body.name.rstrip("."), type=DiagnosticTargetType.DOMAIN),
        findings=findings,
        sources={"dns": source_ok()},
        raw=raw,
        generated_at=datetime.now(UTC),
    )


async def authority_vs_recursive(body: DNSAuthorityCompareRequest) -> DNSDiagnosticResponse:
    findings: list[DiagnosticFinding] = []
    raw: dict[str, object] = {}
    baseline = await lookup(DNSLookupRequest(name=body.name, type=body.type, resolver="system", trace=body.authoritative, timeout_ms=body.timeout_ms))
    baseline_values = sorted(answer.value for answer in baseline.answers)
    raw["system"] = baseline.model_dump(mode="json")
    for resolver in body.recursive_resolvers:
        resp = await lookup(DNSLookupRequest(name=body.name, type=body.type, resolver=resolver, timeout_ms=body.timeout_ms))
        values = sorted(answer.value for answer in resp.answers)
        raw[resolver] = resp.model_dump(mode="json")
        findings.append(_finding(DiagnosticStatus.OK if values == baseline_values else DiagnosticStatus.WARNING, "recursive_comparison", f"Resolver {resolver} {'matches' if values == baseline_values else 'differs from'} system/authoritative baseline.", resolver=resolver, baseline=baseline_values, values=values))
    status = DiagnosticStatus.OK if all(f.severity == DiagnosticStatus.OK for f in findings) else DiagnosticStatus.WARNING
    return DNSDiagnosticResponse(
        status=status,
        summary=f"Authoritative-vs-recursive comparison for {body.name} {body.type.value}: {len(findings)} resolver(s) checked.",
        target=DiagnosticTarget(input=body.name, normalized=body.name.rstrip("."), type=DiagnosticTargetType.DOMAIN),
        findings=findings,
        sources={"dns": source_ok()},
        raw=raw,
        generated_at=datetime.now(UTC),
    )


async def dnssec_report(name: str) -> DNSDiagnosticResponse:
    resp = await lookup(DNSLookupRequest(name=name, type=DNSLookupRecordType.DS, dnssec=True, trace=True))
    severity = DiagnosticStatus.INFO
    message = "DNSSEC validation status is resolver-dependent."
    if resp.answers:
        severity = DiagnosticStatus.OK
        message = "DS record(s) found; domain appears delegated for DNSSEC."
    return DNSDiagnosticResponse(
        status=severity,
        summary=f"DNSSEC report for {name}: {message}",
        target=DiagnosticTarget(input=name, normalized=name.rstrip("."), type=DiagnosticTargetType.DOMAIN),
        findings=[_finding(severity, "dnssec_report", message, answers=[answer.value for answer in resp.answers])],
        sources={"dns": source_ok()},
        raw=resp.model_dump(mode="json"),
        generated_at=datetime.now(UTC),
    )


def resolver_detect(headers: dict[str, str | None] | None = None) -> DNSDiagnosticResponse:
    headers = headers or {}
    evidence: dict[str, object] = {
        "x_forwarded_for": headers.get("x-forwarded-for"),
        "cf_connecting_ip": headers.get("cf-connecting-ip"),
        "note": "Server-side APIs cannot reliably detect the end user's recursive resolver without a client-side DNS token test.",
    }
    return DNSDiagnosticResponse(
        status=DiagnosticStatus.INFO,
        summary="Server-side resolver detection is limited; use propagation/recursive comparisons for objective evidence.",
        target=DiagnosticTarget(input="caller", normalized="caller", type=DiagnosticTargetType.UNKNOWN),
        findings=[_finding(DiagnosticStatus.INFO, "resolver_detect_limited", "Server-side resolver-in-use detection requires client participation for precision.", **evidence)],
        sources={"dns": source_ok()},
        raw=evidence,
        generated_at=datetime.now(UTC),
    )

