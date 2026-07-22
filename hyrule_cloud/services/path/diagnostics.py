"""Path, traceroute, and AS215932 routing evidence helpers.

Active reachability evidence (ping/traceroute) is executed by the internal
hyrule-prober sidecar from AS215932 vantage points. Hyrule Cloud verifies and
(deliver-then-settle) settles x402; a measurement that the prober can't produce
raises ProbeUnavailableError so the route returns without charging.
"""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime
from typing import Any

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
    PathReportCheck,
    PathReportRequest,
    SourceHealth,
)
from hyrule_cloud.providers.prober_client import (
    ProbeOutcome,
    ProbeRejectedError,
    ProberProvider,
    ProbeUnavailableError,
    VantageOutcome,
    prober_configured,
)
from hyrule_cloud.services.diagnostics.sources import (
    source_not_configured,
    source_ok,
    source_unavailable,
    source_usable,
)
from hyrule_cloud.services.safety import assert_safe_active_probe_target, normalize_host

__all__ = [
    "ProbeRejectedError",
    "ProbeUnavailableError",
    "path_active_probe_enabled",
    "path_probe",
    "path_report",
]

# Vantages executed by the AS215932 prober sidecar. GLOBALPING/RIPE_ATLAS remain
# third-party adapters (still not configured); SYSTEM is not an active vantage.
_PROBER_VANTAGES = frozenset({DiagnosticVantage.EXTMON, DiagnosticVantage.AS215932})
_THIRD_PARTY_VANTAGES = (DiagnosticVantage.GLOBALPING, DiagnosticVantage.RIPE_ATLAS)

# Bound how much traceroute detail we echo into a finding's evidence.
_MAX_HOPS_IN_EVIDENCE = 40


def _finding(severity: DiagnosticStatus, code: str, message: str, **evidence: object) -> DiagnosticFinding:
    return DiagnosticFinding(severity=severity, code=code, message=message, evidence=evidence)


def _family(value: DiagnosticAddressFamily) -> int:
    if value == DiagnosticAddressFamily.IPV4:
        return socket.AF_INET
    if value == DiagnosticAddressFamily.IPV6:
        return socket.AF_INET6
    return socket.AF_UNSPEC


def _prober_family(value: DiagnosticAddressFamily) -> str:
    if value == DiagnosticAddressFamily.IPV4:
        return "ipv4"
    if value == DiagnosticAddressFamily.IPV6:
        return "ipv6"
    return "any"


def _third_party_source(vantage: DiagnosticVantage) -> SourceHealth:
    if vantage == DiagnosticVantage.GLOBALPING:
        return source_not_configured("Globalping adapter is token-ready and will run when enabled.")
    if vantage == DiagnosticVantage.RIPE_ATLAS:
        return source_not_configured("RIPE Atlas adapter requires token/credits.")
    return source_not_configured("vantage not configured")


def path_active_probe_enabled(vantages: list[DiagnosticVantage] | None = None) -> bool:
    """Whether a configured active-probe vantage can service the request.

    Kept synchronous (no async health call) so the manifest/discovery gate can
    call it while projecting the catalog. A prober vantage (extmon/AS215932) is
    active when a prober is configured for this instance; third-party vantages
    (Globalping/RIPE Atlas) are active only when their adapter is configured
    (not yet). With ``vantages`` (the caller's requested set) the check is
    restricted to those, so a request for only unconfigured vantages is refused
    before charging even when a prober is otherwise deployed.
    """
    requested = set(vantages) if vantages is not None else None

    prober_candidates = [
        v for v in _PROBER_VANTAGES if requested is None or v in requested
    ]
    if prober_candidates and prober_configured():
        return True

    third_party = [v for v in _THIRD_PARTY_VANTAGES if requested is None or v in requested]
    return any(source_usable(_third_party_source(v)) for v in third_party)


def _requested_prober_vantages(vantages: list[DiagnosticVantage]) -> list[DiagnosticVantage]:
    seen: set[DiagnosticVantage] = set()
    ordered: list[DiagnosticVantage] = []
    for v in vantages:
        if v in _PROBER_VANTAGES and v not in seen:
            seen.add(v)
            ordered.append(v)
    return ordered


async def _run_prober(
    provider: ProberProvider | None,
    *,
    host: str,
    kind: str,
    family: DiagnosticAddressFamily,
    count: int,
    vantages: list[DiagnosticVantage],
    timeout_ms: int,
) -> tuple[ProbeOutcome, list[DiagnosticVantage]]:
    """Execute one probe kind on the healthy subset of requested prober vantages.

    Returns the outcome and the vantages actually run. Raises ProbeUnavailableError
    when no configured/healthy prober vantage can service the request, so the
    caller never settles payment for an empty measurement.
    """
    if provider is None or not provider.configured():
        raise ProbeUnavailableError("prober is not configured")
    requested = _requested_prober_vantages(vantages)
    if not requested:
        raise ProbeUnavailableError("no AS215932 prober vantage was requested")
    healthy = await provider.healthy_vantage_names()
    to_run = [v for v in requested if v.value in healthy]
    if not to_run:
        raise ProbeUnavailableError("no requested AS215932 vantage is currently healthy")
    outcome = await provider.probe(
        target=host,
        kind=kind,
        family=_prober_family(family),
        count=count,
        vantages=[v.value for v in to_run],
        timeout_s=max(2, min(30, round(timeout_ms / 1000))),
    )
    return outcome, to_run


def _ping_measured(result: VantageOutcome) -> bool:
    return result.ping is not None and result.ping.get("loss_pct") is not None


def _trace_measured(result: VantageOutcome) -> bool:
    return result.traceroute is not None and int(result.traceroute.get("hop_count") or 0) > 0


def _ping_finding(result: VantageOutcome) -> DiagnosticFinding:
    ping = result.ping or {}
    loss = ping.get("loss_pct")
    rtt = ping.get("rtt_ms")
    evidence = {
        "vantage": result.vantage,
        "loss_pct": loss,
        "rtt_ms": rtt,
        "packets_transmitted": ping.get("packets_transmitted"),
        "packets_received": ping.get("packets_received"),
    }
    if loss == 0:
        return _finding(DiagnosticStatus.OK, f"ping_reachable_{result.vantage}", f"{result.vantage}: target reachable, 0% loss.", **evidence)
    if loss == 100:
        return _finding(DiagnosticStatus.WARNING, f"ping_no_response_{result.vantage}", f"{result.vantage}: no ping response (100% loss).", **evidence)
    return _finding(DiagnosticStatus.WARNING, f"ping_degraded_{result.vantage}", f"{result.vantage}: partial loss {loss}%.", **evidence)


def _first_unresponsive_hop(hops: list[dict[str, Any]]) -> int | None:
    for hop in hops:
        if "*" in str(hop.get("raw", "")):
            hop_num = hop.get("hop")
            return int(hop_num) if hop_num is not None else None
    return None


def _trace_finding(result: VantageOutcome) -> DiagnosticFinding:
    trace = result.traceroute or {}
    hops = list(trace.get("hops") or [])
    reached = bool(trace.get("last_hop_responded"))
    first_loss = _first_unresponsive_hop(hops)
    evidence = {
        "vantage": result.vantage,
        "hop_count": trace.get("hop_count"),
        "last_hop_responded": reached,
        "first_unresponsive_hop": first_loss,
        "hops": hops[:_MAX_HOPS_IN_EVIDENCE],
    }
    severity = DiagnosticStatus.OK if reached else DiagnosticStatus.WARNING
    message = (
        f"{result.vantage}: traceroute completed to the target ({trace.get('hop_count')} hops)."
        if reached
        else f"{result.vantage}: traceroute did not reach the target ({trace.get('hop_count')} hops observed)."
    )
    return _finding(severity, f"traceroute_{result.vantage}", message, **evidence)


def _unavailable_finding(result: VantageOutcome) -> DiagnosticFinding:
    return _finding(
        DiagnosticStatus.WARNING,
        f"vantage_unavailable_{result.vantage}",
        f"{result.vantage}: no measurement returned ({result.error or 'unknown error'}).",
        vantage=result.vantage,
        error=result.error,
    )


def _sources_for(
    requested: list[DiagnosticVantage],
    ran: list[DiagnosticVantage],
    measured: set[str],
) -> dict[str, SourceHealth]:
    sources: dict[str, SourceHealth] = {}
    ran_names = {v.value for v in ran}
    for vantage in requested:
        if vantage in _PROBER_VANTAGES:
            if vantage.value in measured:
                sources[vantage.value] = source_ok()
            elif vantage.value in ran_names:
                sources[vantage.value] = source_unavailable("vantage ran but returned no measurement")
            else:
                sources[vantage.value] = source_unavailable("vantage not currently healthy")
        else:
            sources[vantage.value] = _third_party_source(vantage)
    return sources


async def path_probe(body: PathProbeRequest, provider: ProberProvider | None) -> DiagnosticResponse:
    host = normalize_host(body.target)
    addresses = await asyncio.to_thread(
        assert_safe_active_probe_target, host, family=_family(body.address_family)
    )
    kind = "ping" if body.probe == PathProbeKind.PING else "traceroute"
    outcome, ran = await _run_prober(
        provider,
        host=host,
        kind=kind,
        family=body.address_family,
        count=body.count,
        vantages=body.vantages,
        timeout_ms=body.timeout_ms,
    )

    findings: list[DiagnosticFinding] = []
    measured: set[str] = set()
    reachable = False
    for result in outcome.results:
        if body.probe == PathProbeKind.PING and _ping_measured(result):
            findings.append(_ping_finding(result))
            measured.add(result.vantage)
            if (result.ping or {}).get("loss_pct") != 100:
                reachable = True
        elif body.probe == PathProbeKind.TRACE and _trace_measured(result):
            findings.append(_trace_finding(result))
            measured.add(result.vantage)
            if (result.traceroute or {}).get("last_hop_responded"):
                reachable = True
        else:
            findings.append(_unavailable_finding(result))

    if not measured:
        # Prober answered but produced no measurement on any vantage (e.g. SSH
        # to every vantage failed): treat as undelivered so we never settle.
        raise ProbeUnavailableError("prober returned no measurement from any vantage")

    status = DiagnosticStatus.OK if reachable else DiagnosticStatus.WARNING
    summary = (
        f"Path {body.probe.value} for {host} from {', '.join(sorted(measured))}: "
        + ("target reachable." if reachable else "target did not respond.")
    )
    return DiagnosticResponse(
        status=status,
        summary=summary,
        target=DiagnosticTarget(input=body.target, normalized=host, type=DiagnosticTargetType.HOST),
        findings=findings,
        sources=_sources_for(body.vantages, ran, measured),
        partial=len(measured) < len(_requested_prober_vantages(body.vantages)),
        raw={
            "probe": body.probe.value,
            "addresses": addresses,
            "probed_address": outcome.probed_address,
            "vantages_run": [v.value for v in ran],
        },
        generated_at=datetime.now(UTC),
    )


def _classify(ping_results: list[VantageOutcome]) -> tuple[str, float | None]:
    """Best (lowest) observed loss across vantages → a coarse classification."""
    losses = [
        r.ping["loss_pct"]
        for r in ping_results
        if r.ping is not None and r.ping.get("loss_pct") is not None
    ]
    if not losses:
        return "inconclusive", None
    best = min(losses)
    if best == 0:
        return "reachable", best
    if best >= 100:
        return "unreachable", best
    return "degraded", best


async def path_report(body: PathReportRequest, provider: ProberProvider | None) -> DiagnosticResponse:
    host = normalize_host(body.target)
    addresses = await asyncio.to_thread(
        assert_safe_active_probe_target, host, family=_family(body.address_family)
    )
    checks = [check.value for check in body.checks]

    # Active evidence: ping (loss/RTT) and traceroute (path) run concurrently on
    # the healthy prober vantages. Both share the same healthy-vantage gate, so
    # if the prober can't deliver either, ProbeUnavailableError bubbles up unsettled.
    ping_outcome, ran = await _run_prober(
        provider, host=host, kind="ping", family=body.address_family,
        count=4, vantages=body.vantages, timeout_ms=10000,
    )
    trace_outcome, _ = await _run_prober(
        provider, host=host, kind="traceroute", family=body.address_family,
        count=4, vantages=body.vantages, timeout_ms=15000,
    )

    findings: list[DiagnosticFinding] = []
    ping_vantages: set[str] = set()
    trace_vantages: set[str] = set()
    for result in ping_outcome.results:
        if _ping_measured(result):
            findings.append(_ping_finding(result))
            ping_vantages.add(result.vantage)
        else:
            findings.append(_unavailable_finding(result))
    for result in trace_outcome.results:
        if _trace_measured(result):
            findings.append(_trace_finding(result))
            trace_vantages.add(result.vantage)
        else:
            findings.append(
                _finding(
                    DiagnosticStatus.WARNING,
                    f"traceroute_unavailable_{result.vantage}",
                    f"{result.vantage}: no traceroute measurement returned "
                    f"({result.error or 'unknown error'}).",
                    vantage=result.vantage,
                    error=result.error,
                )
            )
    measured = ping_vantages | trace_vantages

    # Deliver-then-settle: this pack is sold as ping + traceroute + classification,
    # so every requested active measurement kind must actually produce evidence
    # before the payment is captured. A sidecar that returns ping but no
    # traceroute (a filtered target still yields hops, so an empty set means the
    # traceroute itself did not run) is an undelivered pack — raise so we never
    # settle for a partial deliverable, consistent with path_probe.
    if PathReportCheck.PING.value in checks and not ping_vantages:
        raise ProbeUnavailableError("prober returned no ping measurement from any vantage")
    if PathReportCheck.TRACEROUTE.value in checks and not trace_vantages:
        raise ProbeUnavailableError("prober returned no traceroute measurement from any vantage")
    if not measured:
        raise ProbeUnavailableError("prober returned no measurement from any vantage")

    classification, best_loss = _classify(ping_outcome.results)
    first_loss_hop = None
    for result in trace_outcome.results:
        if _trace_measured(result):
            first_loss_hop = _first_unresponsive_hop(list((result.traceroute or {}).get("hops") or []))
            if first_loss_hop is not None:
                break

    findings.insert(
        0,
        _finding(
            DiagnosticStatus.OK if classification == "reachable" else DiagnosticStatus.WARNING,
            "path_classification",
            f"Path to {host} classified as {classification} (best observed loss {best_loss}%).",
            classification=classification,
            best_loss_pct=best_loss,
            first_unresponsive_hop=first_loss_hop,
            vantages=[v.value for v in ran],
        ),
    )

    # Control-plane checks are delivered by dedicated paid endpoints; the report
    # points at them rather than re-selling them, so its price buys real active
    # evidence + classification, never a placeholder.
    control_plane = {
        PathReportCheck.BGP.value: "/v1/bgp/lookup",
        PathReportCheck.RPKI.value: "/v1/bgp/lookup",
        PathReportCheck.ROUTER_TABLE.value: "/v1/bgp/snapshots/router",
    }
    for check in checks:
        if check in control_plane:
            findings.append(
                _finding(
                    DiagnosticStatus.INFO,
                    f"control_plane_available_{check}",
                    f"{check} control-plane evidence is available from {control_plane[check]}.",
                    endpoint=control_plane[check],
                )
            )
        elif check == PathReportCheck.MTR.value:
            findings.append(
                _finding(
                    DiagnosticStatus.INFO,
                    "mtr_not_collected",
                    "Per-hop loss (MTR) is not part of this pack; ping loss and traceroute path are reported instead.",
                )
            )

    status = DiagnosticStatus.OK if classification == "reachable" else DiagnosticStatus.WARNING
    raw: dict[str, object] = {
        "addresses": addresses,
        "classification": classification,
        "packet_loss": {
            "best_loss_pct": best_loss,
            "first_loss_hop": first_loss_hop,
            "detected": bool(best_loss),
        },
        "checks": checks,
        "vantages_run": [v.value for v in ran],
    }
    if body.include_raw:
        raw["ping_raw"] = {r.vantage: r.raw_excerpt for r in ping_outcome.results}
        raw["traceroute_raw"] = {r.vantage: r.raw_excerpt for r in trace_outcome.results}

    return DiagnosticResponse(
        status=status,
        summary=f"Routing/path evidence pack for {host}: classified {classification}.",
        target=DiagnosticTarget(input=body.target, normalized=host, type=DiagnosticTargetType.HOST),
        findings=findings,
        sources=_sources_for(body.vantages, ran, measured),
        # A requested prober vantage that returned no measurement is a degraded
        # evidence set: flag it so callers relying on the top-level completeness
        # signal do not treat a single-vantage report as full coverage.
        partial=len(measured) < len(_requested_prober_vantages(body.vantages)),
        raw=raw,
        generated_at=datetime.now(UTC),
    )
