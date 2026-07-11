"""Customer-safe aggregate service status backed by curated Prometheus alerts."""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hyrule_cloud.providers.prometheus import PrometheusClient

router = APIRouter(prefix="/v1/status", tags=["Service status"])


class ServiceState(StrEnum):
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    OUTAGE = "outage"
    UNKNOWN = "unknown"


class ServiceComponentStatus(BaseModel):
    id: str
    name: str
    status: ServiceState
    message: str


class ServiceIncident(BaseModel):
    id: str
    title: str
    message: str
    status: ServiceState
    component_ids: list[str]
    started_at: datetime | None = None


class ServiceStatusResponse(BaseModel):
    status: ServiceState
    checked_at: datetime
    stale: bool = False
    components: list[ServiceComponentStatus]
    incidents: list[ServiceIncident] = Field(default_factory=list)


_COMPONENTS: dict[str, tuple[str, str]] = {
    "api_checkout": ("API & checkout", "Purchasing and management API"),
    "compute": ("Compute", "VM provisioning and reachability"),
    "intelligence": ("Network intelligence", "Network diagnostics endpoints"),
    "domains_dns": ("Domains & DNS", "Registration and authoritative DNS"),
    "network_proxy": ("Network proxy", "Direct, Tor, I2P, and Yggdrasil egress"),
}
_RANK = {
    ServiceState.OPERATIONAL: 0,
    ServiceState.UNKNOWN: 1,
    ServiceState.DEGRADED: 2,
    ServiceState.OUTAGE: 3,
}
_CACHE_TTL_SECONDS = 15
_STALE_MAX_SECONDS = 120
_REQUIRED_PUBLIC_RULES = {
    "HyrulePublicApiUnavailable",
    "HyrulePublicComputeControlPlaneUnavailable",
    "HyrulePublicPaymentFailureRatio",
    "HyrulePublicComputeHostDegraded",
    "HyrulePublicRoutingDegraded",
    "HyrulePublicDNSDegraded",
    "HyrulePublicDNSOutage",
}
_STATUS_CACHE: dict[str, Any] = {
    "value": None,
    "expires_at": 0.0,
    "successful_at": 0.0,
}


def _now() -> datetime:
    return datetime.now(UTC)


def _component_rows(state: ServiceState = ServiceState.OPERATIONAL) -> list[ServiceComponentStatus]:
    return [
        ServiceComponentStatus(
            id=component_id,
            name=name,
            status=state,
            message=(description if state == ServiceState.OPERATIONAL else "Current health could not be confirmed."),
        )
        for component_id, (name, description) in _COMPONENTS.items()
    ]


def _unknown_response() -> ServiceStatusResponse:
    return ServiceStatusResponse(
        status=ServiceState.UNKNOWN,
        checked_at=_now(),
        stale=True,
        components=_component_rows(ServiceState.UNKNOWN),
    )


def _public_text(value: Any, fallback: str, max_length: int) -> str:
    if not isinstance(value, str):
        return fallback
    value = " ".join(value.split()).strip()
    return value[:max_length] if value else fallback


def _started_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _incident_from_alert(alert: dict[str, Any]) -> ServiceIncident | None:
    if alert.get("state") != "firing":
        return None
    labels = alert.get("labels")
    if not isinstance(labels, dict) or labels.get("public_status") != "true":
        return None

    raw_state = labels.get("public_state")
    if raw_state not in {ServiceState.DEGRADED.value, ServiceState.OUTAGE.value}:
        return None
    state = ServiceState(raw_state)

    raw_components = labels.get("public_components")
    if not isinstance(raw_components, str):
        return None
    component_ids = [
        component_id
        for component_id in (item.strip() for item in raw_components.split(","))
        if component_id in _COMPONENTS
    ]
    component_ids = list(dict.fromkeys(component_ids))
    if not component_ids:
        return None

    annotations = alert.get("annotations")
    safe_annotations = annotations if isinstance(annotations, dict) else {}
    title = _public_text(safe_annotations.get("public_title"), "Service disruption", 160)
    message = _public_text(
        safe_annotations.get("public_message"),
        "A monitored Hyrule Cloud service is currently affected.",
        500,
    )
    started_at = _started_at(alert.get("activeAt"))
    raw_alert_name = labels.get("alertname")
    alert_name = raw_alert_name if isinstance(raw_alert_name, str) else "alert"
    identity = "|".join(
        [alert_name, started_at.isoformat() if started_at else "", *component_ids]
    )
    incident_id = "inc_" + hashlib.sha256(identity.encode()).hexdigest()[:16]
    return ServiceIncident(
        id=incident_id,
        title=title,
        message=message,
        status=state,
        component_ids=component_ids,
        started_at=started_at,
    )


def _build_response(alerts: list[dict[str, Any]]) -> ServiceStatusResponse:
    incidents = [incident for alert in alerts if (incident := _incident_from_alert(alert))]
    incidents.sort(
        key=lambda incident: (
            -_RANK[incident.status],
            incident.started_at or datetime.min.replace(tzinfo=UTC),
            incident.id,
        )
    )

    components = {component.id: component for component in _component_rows()}
    for incident in incidents:
        for component_id in incident.component_ids:
            component = components[component_id]
            if _RANK[incident.status] > _RANK[component.status]:
                component.status = incident.status
                component.message = incident.message

    overall = max(
        (component.status for component in components.values()),
        key=lambda state: _RANK[state],
        default=ServiceState.OPERATIONAL,
    )
    return ServiceStatusResponse(
        status=overall,
        checked_at=_now(),
        components=list(components.values()),
        incidents=incidents,
    )


@router.get("", response_model=ServiceStatusResponse)
async def get_service_status(request: Request) -> ServiceStatusResponse:
    """Return current customer impact without exposing monitoring internals."""
    now_ts = time.time()
    cached = _STATUS_CACHE.get("value")
    if isinstance(cached, ServiceStatusResponse) and now_ts < float(_STATUS_CACHE["expires_at"]):
        return cached

    app_state = getattr(request.app.state, "_typed_state", None)
    config = getattr(app_state, "config", None)
    prometheus_url = getattr(config, "prometheus_url", "") or ""
    alerts: list[dict[str, Any]] | None = None
    if prometheus_url:
        client = PrometheusClient(prometheus_url)
        try:
            loaded_rules = await client.alerting_rule_names()
            if loaded_rules is not None and _REQUIRED_PUBLIC_RULES <= loaded_rules:
                alerts = await client.active_alerts()
        finally:
            await client.aclose()

    if alerts is not None:
        response = _build_response(alerts)
        _STATUS_CACHE.update(
            value=response,
            expires_at=now_ts + _CACHE_TTL_SECONDS,
            successful_at=now_ts,
        )
        return response

    successful_at = float(_STATUS_CACHE.get("successful_at", 0.0))
    if isinstance(cached, ServiceStatusResponse) and now_ts - successful_at <= _STALE_MAX_SECONDS:
        stale = cached.model_copy(update={"stale": True})
        _STATUS_CACHE.update(value=stale, expires_at=now_ts + _CACHE_TTL_SECONDS)
        return stale
    unknown = _unknown_response()
    _STATUS_CACHE.update(value=unknown, expires_at=now_ts + _CACHE_TTL_SECONDS)
    return unknown
