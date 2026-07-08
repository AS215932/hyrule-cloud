"""Path, traceroute/MTR, and AS215932 routing evidence helpers."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticAddressFamily,
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    DiagnosticVantage,
    PathProbeKind,
    PathProbeRequest,
    PathReportRequest,
    SourceHealth,
    SourceStatus,
)
from hyrule_cloud.services.diagnostics.sources import source_not_configured, source_ok
from hyrule_cloud.services.safety import assert_safe_active_probe_target, normalize_host


def _finding(severity: DiagnosticStatus, code: str, message: str, **evidence: object) -> DiagnosticFinding:
    return DiagnosticFinding(severity=severity, code=code, message=message, evidence=evidence)


def _family(value: DiagnosticAddressFamily) -> int:
    if value == DiagnosticAddressFamily.IPV4:
        return socket.AF_INET
    if value == DiagnosticAddressFamily.IPV6:
        return socket.AF_INET6
    return socket.AF_UNSPEC


def _sources(vantages: list[DiagnosticVantage]) -> dict[str, SourceHealth]:
    sources: dict[str, SourceHealth] = {}
    for vantage in vantages:
        if vantage in {DiagnosticVantage.EXTMON, DiagnosticVantage.AS215932}:
            sources[vantage.value] = source_ok()
        elif vantage == DiagnosticVantage.GLOBALPING:
            sources[vantage.value] = source_not_configured("Globalping adapter is token-ready and will run when enabled.")
        elif vantage == DiagnosticVantage.RIPE_ATLAS:
            sources[vantage.value] = source_not_configured("RIPE Atlas adapter requires token/credits.")
        else:
            sources[vantage.value] = source_ok()
    return sources


def path_active_probe_enabled() -> bool:
    """Whether an external active-probe vantage is configured.

    The built-in vantages (extmon/AS215932) don't actually execute probes, so
    real reachability data requires Globalping or RIPE Atlas. Until one is
    configured, path_probe/path_report only return a "probe accepted"
    acknowledgement, so the routes return 501 before charging.
    """
    sources = _sources([DiagnosticVantage.GLOBALPING, DiagnosticVantage.RIPE_ATLAS])
    return any(
        source.status != SourceStatus.SOURCE_NOT_CONFIGURED for source in sources.values()
    )


async def path_probe(body: PathProbeRequest) -> DiagnosticResponse:
    host = normalize_host(body.target)
    addresses = await asyncio.to_thread(assert_safe_active_probe_target, host, family=_family(body.address_family))
    findings = [
        _finding(
            DiagnosticStatus.INFO,
            f"{body.probe.value}_accepted",
            f"{body.probe.value} probe accepted for {host}; active execution is delegated to configured diagnostic vantages.",
            host=host,
            addresses=addresses,
            vantages=[v.value for v in body.vantages],
            count=body.count,
        )
    ]
    if body.probe in {PathProbeKind.TRACE, PathProbeKind.MTR, PathProbeKind.ASYMMETRY}:
        findings.append(_finding(DiagnosticStatus.INFO, "active_path_evidence", "Traceroute/MTR/asymmetry evidence is collected from extmon/AS215932/global adapters when configured."))
    return DiagnosticResponse(
        status=DiagnosticStatus.INFO,
        summary=f"Path {body.probe.value} diagnostic prepared for {host}.",
        target=DiagnosticTarget(input=body.target, normalized=host, type=DiagnosticTargetType.HOST),
        findings=findings,
        sources=_sources(body.vantages),
        raw={"addresses": addresses, "probe": body.probe.value},
        generated_at=datetime.now(UTC),
    )


async def path_report(body: PathReportRequest) -> DiagnosticResponse:
    host = normalize_host(body.target)
    addresses = await asyncio.to_thread(assert_safe_active_probe_target, host, family=_family(body.address_family))
    checks = [check.value for check in body.checks]
    findings = [
        _finding(DiagnosticStatus.INFO, "path_report_scope", "Routing/path report combines active probes, BGP/RPKI lookup, AS215932 router-table context, and optional public multi-vantage evidence.", checks=checks, vantages=[v.value for v in body.vantages]),
        _finding(DiagnosticStatus.INFO, "classification_inconclusive_until_probe", "No packet-loss classification is emitted until configured active probe evidence is attached.", classification="inconclusive"),
    ]
    if "router_table" in checks:
        findings.append(_finding(DiagnosticStatus.INFO, "as215932_router_table_supported", "AS215932 router-table snapshots are supported as a paid evidence source when available."))
    return DiagnosticResponse(
        status=DiagnosticStatus.INFO,
        summary=f"Routing/path evidence pack prepared for {host}; classification is inconclusive until probe data completes.",
        target=DiagnosticTarget(input=body.target, normalized=host, type=DiagnosticTargetType.HOST),
        findings=findings,
        sources=_sources(body.vantages),
        raw={
            "addresses": addresses,
            "classification": "inconclusive",
            "packet_loss": {"detected": False, "first_loss_hop": None, "suspect": None},
            "checks": checks,
        },
        generated_at=datetime.now(UTC),
    )
