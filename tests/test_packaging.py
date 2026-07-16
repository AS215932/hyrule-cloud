"""Regression checks for packaged process topology."""

from pathlib import Path

import yaml


def test_compose_starts_api_and_worker_after_migrations() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    dockerfile = (root / "Dockerfile").read_text()
    services = compose["services"]

    assert services["migrate"]["command"] == "alembic upgrade head"
    assert services["api"]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )
    assert services["worker"]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )
    assert services["api"]["command"] == (
        "uvicorn hyrule_cloud.app:app --host :: --port 8402"
    )
    assert services["api"]["build"]["target"] == "api"
    assert services["worker"]["build"]["target"] == "worker"
    assert "FROM runtime AS worker" in dockerfile
    assert 'CMD ["hyrule-cloud-worker"]' in dockerfile
