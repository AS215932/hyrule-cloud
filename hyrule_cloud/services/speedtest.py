"""Hyrule/AS215932 throughput evidence helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    SpeedtestRequest,
)
from hyrule_cloud.services.diagnostics.sources import source_ok


def speedtest_contract(body: SpeedtestRequest) -> DiagnosticResponse:
    findings = [
        DiagnosticFinding(
            severity=DiagnosticStatus.INFO,
            code="speedtest_scope",
            message="Speedtest measures throughput/latency/jitter to Hyrule/AS215932 endpoints, not a global Ookla/Fast.com replacement.",
            evidence={
                "direction": body.direction.value,
                "duration_seconds": body.duration_seconds,
                "max_megabytes": body.max_megabytes,
                "vantages": [v.value for v in body.vantages],
            },
        ),
        DiagnosticFinding(
            severity=DiagnosticStatus.INFO,
            code="client_participation_needed",
            message="Accurate download/upload throughput requires the client to transfer test payloads to/from Hyrule endpoints.",
            evidence={},
            recommendation="Use this result as an evidence-pack contract and run the generated test from the customer/client side when available.",
        ),
    ]
    return DiagnosticResponse(
        status=DiagnosticStatus.INFO,
        summary=f"Hyrule speedtest contract prepared for {body.direction.value} with {body.max_megabytes} MB cap.",
        target=DiagnosticTarget(input=body.target, normalized=body.target, type=DiagnosticTargetType.HOST),
        findings=findings,
        sources={"as215932": source_ok(), "extmon": source_ok()},
        raw={
            "download_url": "/v1/speedtest/payload/{token}",
            "upload_url": "/v1/speedtest/upload/{token}",
            "latency_probe": "/health",
        },
        generated_at=datetime.now(UTC),
    )
