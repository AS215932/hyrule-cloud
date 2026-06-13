"""Safe single-service TCP/UDP reachability checks."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    PortCheckRequest,
    PortProtocol,
)
from hyrule_cloud.services.diagnostics.sources import source_ok
from hyrule_cloud.services.safety import assert_safe_active_probe_target, normalize_host


def _finding(severity: DiagnosticStatus, code: str, message: str, **evidence: object) -> DiagnosticFinding:
    return DiagnosticFinding(severity=severity, code=code, message=message, evidence=evidence)


async def run_port_check(body: PortCheckRequest) -> DiagnosticResponse:
    host = normalize_host(body.target)
    addresses = await asyncio.to_thread(assert_safe_active_probe_target, host, port=body.port)
    if body.protocol == PortProtocol.UDP:
        findings = [_finding(DiagnosticStatus.INFO, "udp_probe_not_active", "UDP reachability requires protocol-specific checks and is contract-only in MVP.", host=host, port=body.port)]
    else:
        findings = await _tcp_findings(host, addresses[0], body.port, body.timeout_ms, body.include_banner)
    status = DiagnosticStatus.OK if all(f.severity in {DiagnosticStatus.OK, DiagnosticStatus.INFO} for f in findings) else DiagnosticStatus.CRITICAL
    return DiagnosticResponse(
        status=status,
        summary=f"{body.protocol.value.upper()} {host}:{body.port} reachability: {findings[0].message}",
        target=DiagnosticTarget(input=body.target, normalized=f"{host}:{body.port}", type=DiagnosticTargetType.HOST),
        findings=findings,
        sources={body.vantage.value: source_ok(), "ports": source_ok()},
        raw={"addresses": addresses, "profile": body.profile.value},
        generated_at=datetime.now(UTC),
    )


async def _tcp_findings(host: str, address: str, port: int, timeout_ms: int, include_banner: bool) -> list[DiagnosticFinding]:
    try:
        banner = await asyncio.to_thread(_tcp_connect, address, port, timeout_ms / 1000, include_banner)
        evidence: dict[str, object] = {"host": host, "address": address, "port": port}
        if banner:
            evidence["banner"] = banner
        return [_finding(DiagnosticStatus.OK, "tcp_connect_ok", f"Connected to {host}:{port}.", **evidence)]
    except Exception as exc:
        return [_finding(DiagnosticStatus.CRITICAL, "tcp_connect_failed", f"Could not connect to {host}:{port}: {exc}", host=host, address=address, port=port)]


def _tcp_connect(address: str, port: int, timeout: float, include_banner: bool) -> str | None:
    with socket.create_connection((address, port), timeout=timeout) as sock:
        if not include_banner:
            return None
        sock.settimeout(min(timeout, 3))
        try:
            return sock.recv(512).decode("utf-8", errors="replace")
        except Exception:
            return None
