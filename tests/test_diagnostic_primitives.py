from datetime import UTC

import pytest

from hyrule_cloud.models import (
    DiagnosticFinding,
    DiagnosticJobKind,
    DiagnosticJobStatus,
    DiagnosticResponse,
    DiagnosticStatus,
    DiagnosticTarget,
    DiagnosticTargetType,
    SourceStatus,
)
from hyrule_cloud.services.diagnostics.jobs import (
    build_job_response,
    generate_job_identity,
    hash_job_access_token,
)
from hyrule_cloud.services.diagnostics.sources import source_not_configured, source_ok
from hyrule_cloud.services.safety import (
    UnsafeTargetError,
    allowed_tcp_ports,
    assert_public_host,
    assert_safe_active_probe_target,
    assert_safe_port,
)


def test_common_diagnostic_response_shape():
    response = DiagnosticResponse(
        status=DiagnosticStatus.WARNING,
        summary="TLS certificate expires soon.",
        target=DiagnosticTarget(input="example.com", normalized="example.com", type=DiagnosticTargetType.DOMAIN),
        findings=[
            DiagnosticFinding(
                severity=DiagnosticStatus.WARNING,
                code="tls_cert_expires_soon",
                message="Certificate expires in 9 days.",
                evidence={"days_remaining": 9},
                recommendation="Renew or replace the certificate.",
            )
        ],
        sources={"extmon": source_ok(), "ssllabs": source_not_configured()},
    )

    assert response.request_id.startswith("diag_")
    assert response.generated_at.tzinfo == UTC
    assert response.sources["extmon"].status == SourceStatus.OK
    assert response.sources["ssllabs"].status == SourceStatus.SOURCE_NOT_CONFIGURED


def test_diagnostic_job_identity_and_response_shape():
    job_id, token, token_hash = generate_job_identity()

    assert job_id.startswith("job_")
    assert token.startswith("hyr_job_")
    assert token_hash == hash_job_access_token(token)

    response = build_job_response(
        service="web",
        kind=DiagnosticJobKind.WEB_TLS_DEEP,
        job_id=job_id,
        job_access_token=token,
        status=DiagnosticJobStatus.QUEUED,
        charged_amount_usd="0.10",
    )
    assert response.status_url == f"/v1/web/jobs/{job_id}"
    assert response.download_url == f"/v1/web/jobs/{job_id}/download"
    assert response.charged_amount_usd == "0.10"


def test_public_diagnostic_safety_allowlist_and_private_target_blocks():
    assert 443 in allowed_tcp_ports()
    assert 5061 in allowed_tcp_ports()
    assert_safe_port(443)
    assert_safe_port(5061)

    with pytest.raises(UnsafeTargetError):
        assert_safe_port(12345)
    with pytest.raises(UnsafeTargetError):
        assert_public_host("10.0.0.1")
    with pytest.raises(UnsafeTargetError):
        assert_safe_active_probe_target("127.0.0.1", port=443)
