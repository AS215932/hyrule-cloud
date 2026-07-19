"""Customer-safe aggregate service status backed by curated Prometheus alerts."""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import structlog
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hyrule_cloud.providers.prometheus import PrometheusClient

router = APIRouter(prefix="/v1/status", tags=["Service status"])
log = structlog.get_logger()


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
_CAPACITY_PROBE_TIMEOUT_SECONDS = 3.0
_CAPACITY_INCIDENT_ID = "inc_" + hashlib.sha256(b"vm-capacity-admission").hexdigest()[:16]
_CAPACITY_INCIDENT_TITLE = "New VM orders temporarily unavailable"
_CAPACITY_INCIDENT_MESSAGE = (
    "New VM orders are temporarily unavailable while compute capacity checks recover."
)
_REQUIRED_PUBLIC_RULES: dict[str, tuple[ServiceState, frozenset[str]]] = {
    "HyrulePublicApiUnavailable": (
        ServiceState.OUTAGE,
        frozenset({"api_checkout", "intelligence", "domains_dns", "network_proxy"}),
    ),
    "HyrulePublicComputeControlPlaneUnavailable": (
        ServiceState.DEGRADED,
        frozenset({"compute"}),
    ),
    "HyrulePublicApiAddressFamilyDegraded": (
        ServiceState.DEGRADED,
        frozenset({"api_checkout", "compute", "intelligence", "domains_dns", "network_proxy"}),
    ),
    "HyrulePublicPaymentFailureRatio": (
        ServiceState.DEGRADED,
        frozenset({"api_checkout"}),
    ),
    "HyrulePublicComputeHostDegraded": (
        ServiceState.DEGRADED,
        frozenset({"compute"}),
    ),
    "HyrulePublicRoutingDegraded": (
        ServiceState.DEGRADED,
        frozenset({"compute", "domains_dns", "network_proxy"}),
    ),
    "HyrulePublicDNSDegraded": (
        ServiceState.DEGRADED,
        frozenset({"domains_dns"}),
    ),
    "HyrulePublicDNSOutage": (
        ServiceState.OUTAGE,
        frozenset({"domains_dns"}),
    ),
    "HyruleVMProvisionFailureRatio": (
        ServiceState.DEGRADED,
        frozenset({"compute"}),
    ),
    "HyruleNetworkProxyDown": (
        ServiceState.DEGRADED,
        frozenset({"network_proxy"}),
    ),
}
_STATUS_CACHE: dict[str, Any] = {
    "value": None,
    "expires_at": 0.0,
    "successful_at": 0.0,
}
_STATUS_REFRESH_LOCK = asyncio.Lock()


def _now() -> datetime:
    return datetime.now(UTC)


def _component_rows(state: ServiceState = ServiceState.OPERATIONAL) -> list[ServiceComponentStatus]:
    return [
        ServiceComponentStatus(
            id=component_id,
            name=name,
            status=state,
            message=(
                description
                if state == ServiceState.OPERATIONAL
                else "Current health could not be confirmed."
            ),
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

    raw_alert_name = labels.get("alertname")
    if not isinstance(raw_alert_name, str):
        return None
    expected_metadata = _REQUIRED_PUBLIC_RULES.get(raw_alert_name)
    if expected_metadata is None:
        return None
    expected_state, expected_components = expected_metadata

    raw_state = labels.get("public_state")
    if raw_state != expected_state.value:
        return None
    state = expected_state

    raw_components = labels.get("public_components")
    if not isinstance(raw_components, str):
        return None
    parsed_components = frozenset(
        component_id
        for component_id in (item.strip() for item in raw_components.split(","))
        if component_id
    )
    if parsed_components != expected_components:
        return None
    component_ids = [
        component_id for component_id in _COMPONENTS if component_id in expected_components
    ]

    annotations = alert.get("annotations")
    safe_annotations = annotations if isinstance(annotations, dict) else {}
    title = _public_text(safe_annotations.get("public_title"), "Service disruption", 160)
    message = _public_text(
        safe_annotations.get("public_message"),
        "A monitored Hyrule Cloud service is currently affected.",
        500,
    )
    started_at = _started_at(alert.get("activeAt"))
    identity = "|".join([raw_alert_name, *component_ids])
    incident_id = "inc_" + hashlib.sha256(identity.encode()).hexdigest()[:16]
    return ServiceIncident(
        id=incident_id,
        title=title,
        message=message,
        status=state,
        component_ids=component_ids,
        started_at=started_at,
    )


def _public_rules_ready(rules: list[dict[str, Any]]) -> bool:
    """Require one healthy, correctly-labelled definition for every public rule."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        name = rule.get("name")
        if isinstance(name, str) and name in _REQUIRED_PUBLIC_RULES:
            by_name.setdefault(name, []).append(rule)

    for name, (expected_state, expected_components) in _REQUIRED_PUBLIC_RULES.items():
        matches = by_name.get(name, [])
        if len(matches) != 1:
            return False
        rule = matches[0]
        if rule.get("health") != "ok":
            return False

        labels = rule.get("labels")
        if not isinstance(labels, dict) or labels.get("public_status") != "true":
            return False
        if labels.get("public_state") != expected_state.value:
            return False
        raw_components = labels.get("public_components")
        if not isinstance(raw_components, str):
            return False
        components = frozenset(
            component.strip() for component in raw_components.split(",") if component.strip()
        )
        if components != expected_components:
            return False

        annotations = rule.get("annotations")
        if not isinstance(annotations, dict):
            return False
        for field in ("public_title", "public_message"):
            value = annotations.get(field)
            if not isinstance(value, str) or not value.strip():
                return False
    return True


def _build_response(alerts: list[dict[str, Any]]) -> ServiceStatusResponse:
    incidents_by_id: dict[str, ServiceIncident] = {}
    for alert in alerts:
        incident = _incident_from_alert(alert)
        if incident is None:
            continue
        existing = incidents_by_id.get(incident.id)
        if existing is None:
            incidents_by_id[incident.id] = incident
        elif incident.started_at is not None and (
            existing.started_at is None or incident.started_at < existing.started_at
        ):
            existing.started_at = incident.started_at

    incidents = list(incidents_by_id.values())
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


async def _probe_vm_capacity(app_state: Any) -> bool | None:
    """Exercise the same live XO capacity path that gates paid VM checkout.

    Local and test deployments can intentionally run in simulation mode. Only
    installations guarded by ``HYRULE_REQUIRE_REAL_PROVISIONING`` should
    advertise the real checkout path, so only those installations are probed.
    """
    config = getattr(app_state, "config", None)
    if not bool(getattr(config, "require_real_provisioning", False)):
        return None

    orchestrator = getattr(app_state, "orchestrator", None)
    provider = getattr(orchestrator, "xcpng", None)
    capacity = getattr(provider, "capacity", None)
    if not callable(capacity):
        log.warning("status_vm_capacity_probe_unavailable")
        return False

    try:
        await asyncio.wait_for(capacity(), timeout=_CAPACITY_PROBE_TIMEOUT_SECONDS)
    except TimeoutError:
        log.warning(
            "status_vm_capacity_probe_timed_out",
            timeout_seconds=_CAPACITY_PROBE_TIMEOUT_SECONDS,
        )
        return False
    except Exception as exc:
        # The public response remains deliberately generic. The exception type
        # is enough to distinguish transport/schema failures in private logs
        # without risking provider payloads crossing the status boundary.
        log.warning("status_vm_capacity_probe_failed", error_type=type(exc).__name__)
        return False
    return True


async def _load_public_monitoring(
    prometheus_url: str,
) -> tuple[list[dict[str, Any]] | None, bool]:
    if not prometheus_url:
        return None, False

    alerts: list[dict[str, Any]] | None = None
    rules_unready = False
    client = PrometheusClient(prometheus_url)
    try:
        loaded_rules = await client.alerting_rules()
        if loaded_rules is not None and not _public_rules_ready(loaded_rules):
            rules_unready = True
        elif loaded_rules is not None:
            alerts = await client.active_alerts()
    finally:
        await client.aclose()
    return alerts, rules_unready


def _apply_vm_capacity_health(
    response: ServiceStatusResponse,
    capacity_available: bool | None,
) -> ServiceStatusResponse:
    if capacity_available is not False:
        return response

    updated = response.model_copy(deep=True)
    incident = ServiceIncident(
        id=_CAPACITY_INCIDENT_ID,
        title=_CAPACITY_INCIDENT_TITLE,
        message=_CAPACITY_INCIDENT_MESSAGE,
        status=ServiceState.DEGRADED,
        component_ids=["api_checkout", "compute"],
    )
    updated.incidents = [
        existing for existing in updated.incidents if existing.id != _CAPACITY_INCIDENT_ID
    ]
    updated.incidents.append(incident)
    updated.incidents.sort(
        key=lambda current: (
            -_RANK[current.status],
            current.started_at or datetime.min.replace(tzinfo=UTC),
            current.id,
        )
    )

    for component in updated.components:
        if (
            component.id in incident.component_ids
            and _RANK[incident.status] > _RANK[component.status]
        ):
            component.status = incident.status
            component.message = incident.message

    updated.status = max(
        (component.status for component in updated.components),
        key=lambda state: _RANK[state],
        default=ServiceState.OPERATIONAL,
    )
    return updated


@router.get("", response_model=ServiceStatusResponse)
async def get_service_status(request: Request) -> ServiceStatusResponse:
    """Return current customer impact without exposing monitoring internals."""
    now_ts = time.time()
    cached = _STATUS_CACHE.get("value")
    if isinstance(cached, ServiceStatusResponse) and now_ts < float(_STATUS_CACHE["expires_at"]):
        return cached

    async with _STATUS_REFRESH_LOCK:
        # Another request may have refreshed the shared snapshot while this
        # coroutine waited. Re-read it before touching Prometheus.
        now_ts = time.time()
        cached = _STATUS_CACHE.get("value")
        if isinstance(cached, ServiceStatusResponse) and now_ts < float(
            _STATUS_CACHE["expires_at"]
        ):
            return cached

        app_state = getattr(request.app.state, "_typed_state", None)
        config = getattr(app_state, "config", None)
        prometheus_url = getattr(config, "prometheus_url", "") or ""
        (alerts, rules_unready), capacity_available = await asyncio.gather(
            _load_public_monitoring(prometheus_url),
            _probe_vm_capacity(app_state),
        )

        if alerts is not None:
            response = _apply_vm_capacity_health(
                _build_response(alerts),
                capacity_available,
            )
            _STATUS_CACHE.update(
                value=response,
                expires_at=now_ts + _CACHE_TTL_SECONDS,
                successful_at=now_ts,
            )
            return response

        if rules_unready:
            unknown = _apply_vm_capacity_health(_unknown_response(), capacity_available)
            _STATUS_CACHE.update(value=unknown, expires_at=now_ts + _CACHE_TTL_SECONDS)
            return unknown

        successful_at = float(_STATUS_CACHE.get("successful_at", 0.0))
        if (
            isinstance(cached, ServiceStatusResponse)
            and now_ts - successful_at <= _STALE_MAX_SECONDS
        ):
            stale = _apply_vm_capacity_health(
                cached.model_copy(update={"stale": True}),
                capacity_available,
            )
            _STATUS_CACHE.update(value=stale, expires_at=now_ts + _CACHE_TTL_SECONDS)
            return stale
        unknown = _apply_vm_capacity_health(_unknown_response(), capacity_available)
        _STATUS_CACHE.update(value=unknown, expires_at=now_ts + _CACHE_TTL_SECONDS)
        return unknown
