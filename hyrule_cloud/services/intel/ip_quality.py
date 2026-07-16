"""IP-quality report assembly, launch gating, consistency, and verdict logic."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Protocol

import httpx

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.models import (
    BGPLookupRequest,
    BGPLookupResponse,
    BGPResolvedSubject,
    BGPSubject,
    BGPSubjectType,
    IPLookupRequest,
    IPLookupResponse,
    IPLookupView,
    IPQualityConnection,
    IPQualityConsistency,
    IPQualityLocation,
    IPQualityNetwork,
    IPQualityRegistrationHistory,
    IPQualityRegistrationVersion,
    IPQualityRequest,
    IPQualityResponse,
    IPQualityRisk,
    IPQualityRouting,
    IPQualityRoutingHistory,
    IPQualityRoutingHistoryEvent,
    IPQualityUsageSignals,
    IPQualityVerdict,
    IPQualityVerdictLevel,
    IPSourceDescriptor,
    IPSourcesResponse,
    SourceHealth,
)
from hyrule_cloud.providers.ip_quality import IPQSEvidence, MaxMindEvidence
from hyrule_cloud.services.bgp.lookup import lookup_bgp
from hyrule_cloud.services.intel.ip import lookup_ip

_RIPESTAT = "https://stat.ripe.net/data"
_COST_SHARE_LIMIT = Decimal("0.40")


class QualityProvider(Protocol):
    async def fetch(self, request: IPQualityRequest) -> tuple[MaxMindEvidence, IPQSEvidence]: ...


@dataclass(frozen=True, slots=True)
class IPQualityGateStatus:
    enabled: bool
    reason: str | None = None


async def _safe_network_lookup(address: str) -> IPLookupResponse:
    try:
        return await lookup_ip(
            IPLookupRequest(
                address=address,
                views=[IPLookupView.ASN],
                max_age_seconds=900,
            )
        )
    except Exception:
        return IPLookupResponse(
            request_id="ipq_unavailable",
            address=address,
            sources={"team_cymru": "degraded"},
            partial=True,
            generated_at=datetime.now(UTC),
        )


async def _safe_bgp_lookup(address: str) -> BGPLookupResponse:
    try:
        return await lookup_bgp(
            BGPLookupRequest(
                subject=BGPSubject(type=BGPSubjectType.IP, value=address)
            )
        )
    except Exception:
        return BGPLookupResponse(
            request_id="bgpq_unavailable",
            subject={"type": "ip", "value": address},
            resolved=BGPResolvedSubject(),
            sources={
                "ripestat_current_routing": SourceHealth(
                    status="degraded", message="Current routing evidence unavailable."
                )
            },
            partial=True,
            generated_at=datetime.now(UTC),
        )


async def _safe_routing_history(
    client: httpx.AsyncClient, address: str, days: int
) -> tuple[IPQualityRoutingHistory, SourceHealth]:
    try:
        return await _routing_history(client, address, days)
    except Exception:
        return (
            IPQualityRoutingHistory(
                status="unavailable",
                days_requested=days,
                message="RIPEstat routing history was unavailable.",
            ),
            SourceHealth(status="degraded", message="Routing history unavailable."),
        )


def quality_gate_status(config: HyruleConfig | None = None) -> IPQualityGateStatus:
    config = config or HyruleConfig()
    quality = config.ip_quality
    if not quality.enabled:
        return IPQualityGateStatus(False, "operator_disabled")
    if not quality.maxmind_account_id or not quality.maxmind_license_key:
        return IPQualityGateStatus(False, "maxmind_credentials_missing")
    if not quality.ipqs_api_key:
        return IPQualityGateStatus(False, "ipqs_credentials_missing")
    if not quality.maxmind_resale_approved:
        return IPQualityGateStatus(False, "maxmind_resale_not_approved")
    if not quality.ipqs_resale_approved:
        return IPQualityGateStatus(False, "ipqs_resale_not_approved")
    price = Decimal(str(config.payment.price_ip_quality))
    provider_cost = Decimal(str(quality.maxmind_unit_cost_usd)) + Decimal(
        str(quality.ipqs_unit_cost_usd)
    )
    if price <= 0 or provider_cost > price * _COST_SHARE_LIMIT:
        return IPQualityGateStatus(False, "provider_cost_exceeds_margin_guard")
    return IPQualityGateStatus(True)


def quality_report_enabled(config: HyruleConfig | None = None) -> bool:
    return quality_gate_status(config).enabled


def quality_sources(config: HyruleConfig) -> IPSourcesResponse:
    quality = config.ip_quality
    enabled = quality_report_enabled(config)
    return IPSourcesResponse(
        quality_report_enabled=enabled,
        sources=[
            IPSourceDescriptor(
                name="team_cymru",
                category="public",
                provides=["origin_asn", "prefix", "registry", "registration_country", "asn_organization"],
                configured=True,
                enabled=True,
            ),
            IPSourceDescriptor(
                name="ripestat",
                category="public",
                provides=["current_routing", "rpki", "routing_history", "ripe_registration_history"],
                configured=True,
                enabled=True,
            ),
            IPSourceDescriptor(
                name="maxmind_insights",
                category="licensed",
                provides=["geolocation", "registration", "network", "anonymizer", "user_count"],
                configured=bool(quality.maxmind_account_id and quality.maxmind_license_key),
                approved_for_resale=quality.maxmind_resale_approved,
                enabled=enabled,
            ),
            IPSourceDescriptor(
                name="ipqualityscore",
                category="licensed",
                provides=["fraud_score", "proxy", "vpn", "tor", "abuse", "connection_type"],
                configured=bool(quality.ipqs_api_key),
                approved_for_resale=quality.ipqs_resale_approved,
                enabled=enabled,
            ),
        ],
    )


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


async def _ripestat_get(
    client: httpx.AsyncClient,
    endpoint: str,
    params: dict[str, str | int],
) -> dict[str, Any] | None:
    try:
        response = await client.get(
            f"{_RIPESTAT}/{endpoint}/data.json",
            params=params,
            headers={"User-Agent": "HyruleCloud-IPQuality/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _routing_history_from_data(data: dict[str, Any], days: int) -> IPQualityRoutingHistory:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    events: list[IPQualityRoutingHistoryEvent] = []
    by_origin = data.get("by_origin")
    if not isinstance(by_origin, list):
        by_origin = []
    for origin_group in by_origin:
        if not isinstance(origin_group, dict):
            continue
        origin_value = origin_group.get("origin")
        try:
            origin_asn = int(origin_value) if isinstance(origin_value, (str, int)) else None
        except (TypeError, ValueError):
            continue
        if origin_asn is None:
            continue
        prefixes = origin_group.get("prefixes")
        if not isinstance(prefixes, list):
            prefixes = [origin_group]
        for prefix in prefixes:
            if not isinstance(prefix, dict):
                continue
            timelines = prefix.get("timelines")
            if not isinstance(timelines, list):
                timelines = []
            for timeline in timelines:
                if not isinstance(timeline, dict):
                    continue
                first_seen = _parse_datetime(
                    timeline.get("starttime") or timeline.get("start_time")
                )
                last_seen = _parse_datetime(
                    timeline.get("endtime") or timeline.get("end_time")
                )
                if last_seen is not None and last_seen < cutoff:
                    continue
                visibility_value = timeline.get("visibility")
                try:
                    visibility = float(visibility_value) if visibility_value is not None else None
                except (TypeError, ValueError):
                    visibility = None
                if visibility is not None and visibility < 0:
                    visibility = None
                elif visibility is not None and visibility > 1:
                    visibility /= 100
                events.append(
                    IPQualityRoutingHistoryEvent(
                        origin_asn=origin_asn,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        visibility=visibility,
                    )
                )
    events.sort(
        key=lambda event: event.last_seen or event.first_seen or datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    events = events[:64]
    return IPQualityRoutingHistory(
        status="available",
        days_requested=days,
        events=events,
        origin_changed=len({event.origin_asn for event in events}) > 1,
    )


async def _routing_history(
    client: httpx.AsyncClient, address: str, days: int
) -> tuple[IPQualityRoutingHistory, SourceHealth]:
    if days == 0:
        return (
            IPQualityRoutingHistory(status="not_requested", days_requested=0),
            SourceHealth(status="info", message="History was not requested."),
        )
    now = datetime.now(UTC)
    data = await _ripestat_get(
        client,
        "routing-history",
        {
            "resource": address,
            "max_rows": 256,
            "normalise_visibility": "true",
            "starttime": (now - timedelta(days=days)).isoformat(),
            "endtime": now.isoformat(),
        },
    )
    if data is None:
        return (
            IPQualityRoutingHistory(
                status="unavailable",
                days_requested=days,
                message="RIPEstat routing history was unavailable.",
            ),
            SourceHealth(status="degraded", message="Routing history unavailable."),
        )
    return _routing_history_from_data(data, days), SourceHealth(status="ok")


def _version_metadata(value: object) -> tuple[int | None, datetime | None, datetime | None]:
    if not isinstance(value, dict):
        return None, None, None
    version_value = value.get("version")
    try:
        version = int(version_value) if isinstance(version_value, (str, int)) else None
    except (TypeError, ValueError):
        version = None
    valid_from = _parse_datetime(
        value.get("valid_from")
        or value.get("from_time")
        or value.get("from")
        or value.get("timestamp")
    )
    valid_until = _parse_datetime(
        value.get("valid_until") or value.get("to_time") or value.get("until")
    )
    return version, valid_from, valid_until


def _registration_fields(data: dict[str, Any]) -> tuple[str | None, str | None]:
    objects = data.get("objects")
    if not isinstance(objects, list):
        return None, None
    country: str | None = None
    organization: str | None = None
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        details = obj.get("attributes") or obj.get("details")
        if not isinstance(details, list):
            continue
        for detail in details:
            if not isinstance(detail, dict):
                continue
            key = str(detail.get("attribute") or detail.get("key") or "").lower()
            value = detail.get("value")
            if key == "country" and isinstance(value, str) and len(value.strip()) == 2:
                country = value.strip().upper()
            if key in {"org-name", "organisation", "organization", "netname"}:
                if organization is None and isinstance(value, str) and value.strip():
                    organization = value.strip()
    return country, organization


async def _registration_history(
    client: httpx.AsyncClient,
    resource: str,
    registry: str | None,
    days: int,
) -> tuple[IPQualityRegistrationHistory, SourceHealth]:
    if days == 0:
        return (
            IPQualityRegistrationHistory(status="not_requested", days_requested=0),
            SourceHealth(status="info", message="History was not requested."),
        )
    if (registry or "").lower() != "ripe":
        return (
            IPQualityRegistrationHistory(
                status="unsupported",
                days_requested=days,
                message="Historical registration is currently available only for RIPE DB objects.",
            ),
            SourceHealth(status="info", message="Registry is outside the RIPE DB."),
        )
    index = await _ripestat_get(client, "historical-whois", {"resource": resource})
    if index is None:
        return (
            IPQualityRegistrationHistory(
                status="unavailable",
                days_requested=days,
                message="RIPE historical WHOIS was unavailable.",
            ),
            SourceHealth(status="degraded", message="Registration history unavailable."),
        )
    versions_raw = index.get("versions")
    if isinstance(versions_raw, list) and not versions_raw:
        suggestions = index.get("suggestions")
        if isinstance(suggestions, list):
            for suggestion in suggestions:
                if not isinstance(suggestion, dict):
                    continue
                object_type = suggestion.get("type")
                object_key = suggestion.get("key")
                if object_type not in {"inetnum", "inet6num"} or not isinstance(
                    object_key, str
                ):
                    continue
                resource = f"{object_type}:{object_key}"
                suggested = await _ripestat_get(
                    client, "historical-whois", {"resource": resource}
                )
                if suggested is not None:
                    index = suggested
                    versions_raw = index.get("versions")
                break
    if not isinstance(versions_raw, list):
        versions_raw = []
    cutoff = datetime.now(UTC) - timedelta(days=days)
    selected: list[tuple[int | None, datetime | None, datetime | None]] = []
    for raw in versions_raw:
        metadata = _version_metadata(raw)
        if metadata[1] is not None and metadata[1] < cutoff and selected:
            continue
        selected.append(metadata)
    selected = selected[-16:]

    async def fetch_version(
        metadata: tuple[int | None, datetime | None, datetime | None]
    ) -> IPQualityRegistrationVersion | None:
        version, valid_from, valid_until = metadata
        if version is None:
            return None
        detail = await _ripestat_get(
            client, "historical-whois", {"resource": resource, "version": version}
        )
        if detail is None:
            return None
        country, organization = _registration_fields(detail)
        return IPQualityRegistrationVersion(
            version=version,
            valid_from=valid_from,
            valid_until=valid_until,
            country_code=country,
            organization=organization,
        )

    fetched = await asyncio.gather(*(fetch_version(item) for item in selected))
    versions = [item for item in fetched if item is not None]
    country_codes = {item.country_code for item in versions if item.country_code}
    return (
        IPQualityRegistrationHistory(
            status="available",
            days_requested=days,
            versions=versions,
            country_changed=len(country_codes) > 1,
        ),
        SourceHealth(status="ok"),
    )


def _prefer[T](primary: T | None, secondary: T | None, tertiary: T | None = None) -> T | None:
    return primary if primary is not None else secondary if secondary is not None else tertiary


def _any_signal(*values: bool | None) -> bool | None:
    concrete = [value for value in values if value is not None]
    if not concrete:
        return None
    return any(concrete)


def _disagrees(first: object, second: object) -> bool:
    return first is not None and second is not None and first != second


def classify_quality_verdict(
    *,
    risk: IPQualityRisk,
    connection: IPQualityConnection,
    network: IPQualityNetwork,
    consistency: IPQualityConsistency,
    routing: IPQualityRouting,
    routing_history: IPQualityRoutingHistory,
    providers_successful: bool,
) -> IPQualityVerdict:
    high_risk_reasons: list[str] = []
    if risk.fraud_score is not None and risk.fraud_score >= 90:
        high_risk_reasons.append("ipqs_fraud_score_at_least_90")
    if risk.high_risk_attacks:
        high_risk_reasons.append("ipqs_high_risk_attacks")
    if risk.frequent_abuser:
        high_risk_reasons.append("ipqs_frequent_abuser")
    if high_risk_reasons:
        return IPQualityVerdict(level=IPQualityVerdictLevel.HIGH_RISK, reasons=high_risk_reasons)

    review_reasons: list[str] = []
    if risk.fraud_score is not None and 75 <= risk.fraud_score < 90:
        review_reasons.append("ipqs_fraud_score_75_to_89")
    if risk.recent_abuse:
        review_reasons.append("ipqs_recent_abuse")
    if risk.bot_status:
        review_reasons.append("ipqs_bot_activity")
    signal_names = {
        "proxy": connection.proxy,
        "vpn": connection.vpn,
        "tor": connection.tor,
        "hosting_provider": connection.hosting_provider,
        "public_proxy": connection.public_proxy,
        "residential_proxy": connection.residential_proxy,
    }
    review_reasons.extend(
        f"connection_{name}" for name, enabled in signal_names.items() if enabled
    )
    connection_type = (network.connection_type or "").lower().replace("_", " ")
    if "data center" in connection_type or "datacenter" in connection_type:
        review_reasons.append("connection_data_center")
    if consistency.country_matches_expectation is False:
        review_reasons.append("country_mismatch")
    if consistency.provider_disagreements:
        review_reasons.append("provider_disagreement")
    if (routing.rpki_status or "").lower() == "invalid":
        review_reasons.append("rpki_invalid")
    if routing_history.origin_changed:
        review_reasons.append("routing_origin_changed")
    review_reasons = list(dict.fromkeys(review_reasons))
    if review_reasons:
        return IPQualityVerdict(level=IPQualityVerdictLevel.REVIEW, reasons=review_reasons)
    if providers_successful and risk.fraud_score is not None and risk.fraud_score < 75:
        return IPQualityVerdict(level=IPQualityVerdictLevel.LOW_RISK, reasons=[])
    return IPQualityVerdict(
        level=IPQualityVerdictLevel.INCONCLUSIVE,
        reasons=["insufficient_successful_evidence"],
    )


async def build_quality_report(
    request: IPQualityRequest,
    provider: QualityProvider,
) -> IPQualityResponse:
    timeout = httpx.Timeout(8.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as public_client:
        premium_task = asyncio.create_task(provider.fetch(request))
        network_task = asyncio.create_task(_safe_network_lookup(request.address))
        bgp_task = asyncio.create_task(_safe_bgp_lookup(request.address))
        routing_history_task = asyncio.create_task(
            _safe_routing_history(public_client, request.address, request.history_days)
        )

        try:
            (maxmind, ipqs), network_lookup, bgp, routing_history_result = await asyncio.gather(
                premium_task,
                network_task,
                bgp_task,
                routing_history_task,
            )
        except BaseException:
            for task in (network_task, bgp_task, routing_history_task):
                task.cancel()
            await asyncio.gather(
                network_task,
                bgp_task,
                routing_history_task,
                return_exceptions=True,
            )
            raise
        routing_history, routing_history_health = routing_history_result
        registry = network_lookup.network.registry if network_lookup.network else None
        history_resource = bgp.resolved.best_prefix or (
            network_lookup.network.prefix if network_lookup.network else None
        ) or request.address
        try:
            registration_history, registration_history_health = await _registration_history(
                public_client,
                history_resource,
                registry,
                request.history_days,
            )
        except Exception:
            registration_history = IPQualityRegistrationHistory(
                status="unavailable",
                days_requested=request.history_days,
                message="Registration history was unavailable.",
            )
            registration_history_health = SourceHealth(
                status="degraded", message="Registration history unavailable."
            )

    public_network = network_lookup.network
    location = IPQualityLocation(
        country_code=_prefer(maxmind.location.country_code, ipqs.location.country_code),
        country=_prefer(maxmind.location.country, ipqs.location.country),
        region=_prefer(maxmind.location.region, ipqs.location.region),
        city=_prefer(maxmind.location.city, ipqs.location.city),
        postal_code=_prefer(maxmind.location.postal_code, ipqs.location.postal_code),
        timezone=_prefer(maxmind.location.timezone, ipqs.location.timezone),
        latitude=_prefer(maxmind.location.latitude, ipqs.location.latitude),
        longitude=_prefer(maxmind.location.longitude, ipqs.location.longitude),
    )
    registration = maxmind.registration.model_copy(
        update={
            "country_code": _prefer(
                maxmind.registration.country_code,
                public_network.country_code if public_network else None,
            ),
            "registry": registry,
        }
    )
    network = IPQualityNetwork(
        asn=_prefer(
            maxmind.network.asn,
            ipqs.network.asn,
            public_network.asn if public_network else None,
        ),
        asn_organization=_prefer(
            maxmind.network.asn_organization,
            public_network.organization if public_network else None,
            ipqs.network.organization,
        ),
        isp=_prefer(maxmind.network.isp, ipqs.network.isp),
        organization=_prefer(
            maxmind.network.organization,
            ipqs.network.organization,
            public_network.organization if public_network else None,
        ),
        network=_prefer(
            maxmind.network.network,
            public_network.prefix if public_network else None,
        ),
        connection_type=_prefer(
            maxmind.network.connection_type, ipqs.network.connection_type
        ),
        user_type=maxmind.network.user_type,
    )
    connection = IPQualityConnection(
        proxy=ipqs.connection.proxy,
        vpn=_any_signal(maxmind.connection.vpn, ipqs.connection.vpn),
        tor=_any_signal(maxmind.connection.tor, ipqs.connection.tor),
        active_vpn=ipqs.connection.active_vpn,
        active_tor=ipqs.connection.active_tor,
        anonymous=maxmind.connection.anonymous,
        hosting_provider=maxmind.connection.hosting_provider,
        public_proxy=maxmind.connection.public_proxy,
        residential_proxy=maxmind.connection.residential_proxy,
    )
    usage = IPQualityUsageSignals(
        estimated_users_24h=maxmind.usage.estimated_users_24h,
        static_ip_score=maxmind.usage.static_ip_score,
        shared_connection=ipqs.usage.shared_connection,
        dynamic_connection=ipqs.usage.dynamic_connection,
        mobile=ipqs.usage.mobile,
    )
    rpki_values = [origin.rpki for origin in bgp.resolved.origins if origin.rpki]
    rpki_status = None
    if "invalid" in rpki_values:
        rpki_status = "invalid"
    elif "valid" in rpki_values:
        rpki_status = "valid"
    elif rpki_values:
        rpki_status = rpki_values[0]
    routing = IPQualityRouting(
        routed=bgp.resolved.routed,
        best_prefix=bgp.resolved.best_prefix,
        origin_asns=bgp.resolved.observed_origin_asns,
        rpki_status=rpki_status,
    )

    observed_countries = {
        key: value
        for key, value in {
            "maxmind_location": maxmind.location.country_code,
            "maxmind_registration": maxmind.registration.country_code,
            "ipqs_location": ipqs.location.country_code,
            "team_cymru_registration": public_network.country_code if public_network else None,
        }.items()
        if value is not None
    }
    disagreements: list[str] = []
    if _disagrees(maxmind.location.country_code, ipqs.location.country_code):
        disagreements.append("location_country")
    if _disagrees(maxmind.network.asn, ipqs.network.asn):
        disagreements.append("origin_asn")
    if _disagrees(maxmind.connection.vpn, ipqs.connection.vpn):
        disagreements.append("vpn")
    if _disagrees(maxmind.connection.tor, ipqs.connection.tor):
        disagreements.append("tor")
    expected = request.expected_country_code
    location_codes = [
        code for code in (maxmind.location.country_code, ipqs.location.country_code) if code
    ]
    country_match = None
    if expected is not None and location_codes:
        country_match = all(code == expected for code in location_codes)
    requested_timezone = request.client_context.timezone if request.client_context else None
    timezone_match = None
    if requested_timezone is not None and location.timezone is not None:
        timezone_match = requested_timezone == location.timezone
    consistency = IPQualityConsistency(
        expected_country_code=expected,
        observed_country_codes=observed_countries,
        country_matches_expectation=country_match,
        timezone_matches_location=timezone_match,
        provider_disagreements=disagreements,
    )

    sources: dict[str, SourceHealth] = {
        "maxmind_insights": SourceHealth(status="ok"),
        "ipqualityscore": SourceHealth(status="ok"),
        "ripestat_routing_history": routing_history_health,
        "ripestat_historical_whois": registration_history_health,
    }
    for name, status in network_lookup.sources.items():
        sources[name] = SourceHealth(status=status)
    for name, health in bgp.sources.items():
        sources[name] = health
    partial = network_lookup.partial or bgp.partial or any(
        health.status in {"degraded", "unavailable", "error"}
        for health in (routing_history_health, registration_history_health)
    )
    verdict = classify_quality_verdict(
        risk=ipqs.risk,
        connection=connection,
        network=network,
        consistency=consistency,
        routing=routing,
        routing_history=routing_history,
        providers_successful=True,
    )
    return IPQualityResponse(
        address=request.address,
        location=location,
        registration=registration,
        network=network,
        connection=connection,
        risk=ipqs.risk,
        usage=usage,
        routing=routing,
        routing_history=routing_history,
        registration_history=registration_history,
        consistency=consistency,
        sources=sources,
        partial=partial,
        verdict=verdict,
    )
