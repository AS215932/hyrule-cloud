"""Licensed MaxMind Insights and IPQS adapters for IP-quality reports.

Only normalized, explicitly modelled fields leave this module. Provider
payloads and credentials are never returned to callers or placed in URLs.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from hyrule_cloud.config import IPQualityConfig
from hyrule_cloud.models import (
    IPQualityConnection,
    IPQualityLocation,
    IPQualityNetwork,
    IPQualityRegistration,
    IPQualityRequest,
    IPQualityRisk,
    IPQualityUsageSignals,
)
from hyrule_cloud.services.cache import TTLCache


class IPQualityProviderError(RuntimeError):
    """A required licensed provider did not return usable evidence."""

    def __init__(self, providers: tuple[str, ...]) -> None:
        self.providers = providers
        super().__init__("required IP-quality evidence is unavailable")


@dataclass(frozen=True, slots=True)
class MaxMindEvidence:
    location: IPQualityLocation
    registration: IPQualityRegistration
    network: IPQualityNetwork
    connection: IPQualityConnection
    usage: IPQualityUsageSignals


@dataclass(frozen=True, slots=True)
class IPQSEvidence:
    location: IPQualityLocation
    network: IPQualityNetwork
    connection: IPQualityConnection
    risk: IPQualityRisk
    usage: IPQualityUsageSignals


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or stripped.upper() == "N/A":
        return None
    return stripped


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if not isinstance(value, (int, float, str, bytes, bytearray)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _english_name(value: object) -> str | None:
    names = _mapping(_mapping(value).get("names"))
    return _text(names.get("en"))


def _country_code(value: object) -> str | None:
    code = _text(_mapping(value).get("iso_code"))
    return code.upper() if code and len(code) == 2 else None


def _maxmind_evidence(payload: dict[str, Any]) -> MaxMindEvidence:
    country = _mapping(payload.get("country"))
    registered = _mapping(payload.get("registered_country"))
    represented = _mapping(payload.get("represented_country"))
    city = _mapping(payload.get("city"))
    postal = _mapping(payload.get("postal"))
    location = _mapping(payload.get("location"))
    subdivisions = payload.get("subdivisions")
    region: str | None = None
    if isinstance(subdivisions, list) and subdivisions:
        region = _english_name(subdivisions[-1])

    traits = _mapping(payload.get("traits"))
    anonymizer = _mapping(payload.get("anonymizer"))
    # MaxMind moved these flags from traits to anonymizer. Falling back keeps
    # compatibility during the documented transition without exposing either
    # provider object in the public response.
    def anonymous_flag(name: str) -> bool | None:
        return _boolean(anonymizer.get(name)) if name in anonymizer else _boolean(traits.get(name))

    return MaxMindEvidence(
        location=IPQualityLocation(
            country_code=_country_code(country),
            country=_english_name(country),
            region=region,
            city=_english_name(city),
            postal_code=_text(postal.get("code")),
            timezone=_text(location.get("time_zone")),
            latitude=_number(location.get("latitude")),
            longitude=_number(location.get("longitude")),
        ),
        registration=IPQualityRegistration(
            country_code=_country_code(registered),
            country=_english_name(registered),
            represented_country_code=_country_code(represented),
        ),
        network=IPQualityNetwork(
            asn=_integer(traits.get("autonomous_system_number")),
            asn_organization=_text(traits.get("autonomous_system_organization")),
            isp=_text(traits.get("isp")),
            organization=_text(traits.get("organization")),
            network=_text(traits.get("network")),
            connection_type=_text(traits.get("connection_type")),
            user_type=_text(traits.get("user_type")),
        ),
        connection=IPQualityConnection(
            anonymous=anonymous_flag("is_anonymous"),
            vpn=anonymous_flag("is_anonymous_vpn"),
            tor=anonymous_flag("is_tor_exit_node"),
            hosting_provider=anonymous_flag("is_hosting_provider"),
            public_proxy=anonymous_flag("is_public_proxy"),
            residential_proxy=anonymous_flag("is_residential_proxy"),
        ),
        usage=IPQualityUsageSignals(
            estimated_users_24h=_integer(traits.get("user_count")),
            static_ip_score=_number(traits.get("static_ip_score")),
        ),
    )


def _ipqs_evidence(payload: dict[str, Any]) -> IPQSEvidence:
    return IPQSEvidence(
        location=IPQualityLocation(
            country_code=(_text(payload.get("country_code")) or "").upper() or None,
            region=_text(payload.get("region")),
            city=_text(payload.get("city")),
            postal_code=_text(payload.get("zip_code")),
            timezone=_text(payload.get("timezone")),
            latitude=_number(payload.get("latitude")),
            longitude=_number(payload.get("longitude")),
        ),
        network=IPQualityNetwork(
            asn=_integer(payload.get("ASN")),
            isp=_text(payload.get("ISP")),
            organization=_text(payload.get("organization") or payload.get("Organization")),
            connection_type=_text(payload.get("connection_type")),
        ),
        connection=IPQualityConnection(
            proxy=_boolean(payload.get("proxy")),
            vpn=_boolean(payload.get("vpn")),
            tor=_boolean(payload.get("tor")),
            active_vpn=_boolean(payload.get("active_vpn")),
            active_tor=_boolean(payload.get("active_tor")),
        ),
        risk=IPQualityRisk(
            fraud_score=_number(payload.get("fraud_score")),
            recent_abuse=_boolean(payload.get("recent_abuse")),
            bot_status=_boolean(payload.get("bot_status")),
            frequent_abuser=_boolean(payload.get("frequent_abuser")),
            high_risk_attacks=_boolean(payload.get("high_risk_attacks")),
            abuse_velocity=_text(payload.get("abuse_velocity")),
        ),
        usage=IPQualityUsageSignals(
            shared_connection=_boolean(payload.get("shared_connection")),
            dynamic_connection=_boolean(payload.get("dynamic_connection")),
            mobile=_boolean(payload.get("mobile")),
        ),
    )


class IPQualityProvider:
    """Concurrent, no-retry client for the two required licensed sources."""

    def __init__(
        self,
        config: IPQualityConfig,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(config.provider_timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": "HyruleCloud-IPQuality/1.0", "Accept": "application/json"},
        )
        self._maxmind_cache: TTLCache[MaxMindEvidence] = TTLCache(max_entries=1024)
        self._ipqs_cache: TTLCache[IPQSEvidence] = TTLCache(max_entries=1024)

    @property
    def _cache_enabled(self) -> bool:
        return self.config.cache_rights_approved and self.config.cache_ttl_seconds > 0

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _maxmind(self, address: str) -> MaxMindEvidence:
        cached = self._maxmind_cache.get(address) if self._cache_enabled else None
        if cached is not None:
            return cached
        url = f"{self.config.maxmind_base_url.rstrip('/')}/{quote(address, safe=':')}"
        response = await self._client.get(
            url,
            auth=(self.config.maxmind_account_id, self.config.maxmind_license_key),
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not any(
            isinstance(payload.get(key), dict)
            for key in ("country", "registered_country", "traits", "anonymizer")
        ):
            raise ValueError("MaxMind response contained no usable evidence")
        evidence = _maxmind_evidence(payload)
        if self._cache_enabled:
            self._maxmind_cache.set(address, evidence, self.config.cache_ttl_seconds)
        return evidence

    async def _ipqs(self, request: IPQualityRequest) -> IPQSEvidence:
        context = request.client_context
        cache_material = request.address
        if context is not None:
            cache_material += context.model_dump_json(exclude_none=True)
        cache_key = hashlib.sha256(cache_material.encode()).hexdigest()
        cached = self._ipqs_cache.get(cache_key) if self._cache_enabled else None
        if cached is not None:
            return cached

        params: dict[str, str | int] = {
            "ip": request.address,
            "strictness": 0,
            "allow_public_access_points": "true",
            "lighter_penalties": "true",
        }
        if context is not None and context.user_agent is not None:
            params["user_agent"] = context.user_agent
        if context is not None and context.accept_language is not None:
            params["user_language"] = context.accept_language

        response = await self._client.get(
            self.config.ipqs_base_url,
            params=params,
            headers={"IPQS-KEY": self.config.ipqs_api_key},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ValueError("IPQS response was not successful")
        evidence = _ipqs_evidence(payload)
        if evidence.risk.fraud_score is None:
            raise ValueError("IPQS response contained no fraud score")
        if self._cache_enabled:
            self._ipqs_cache.set(cache_key, evidence, self.config.cache_ttl_seconds)
        return evidence

    async def fetch(self, request: IPQualityRequest) -> tuple[MaxMindEvidence, IPQSEvidence]:
        maxmind_result, ipqs_result = await asyncio.gather(
            self._maxmind(request.address),
            self._ipqs(request),
            return_exceptions=True,
        )
        failed: list[str] = []
        if isinstance(maxmind_result, BaseException):
            failed.append("maxmind_insights")
        if isinstance(ipqs_result, BaseException):
            failed.append("ipqualityscore")
        if failed:
            raise IPQualityProviderError(tuple(failed))
        assert isinstance(maxmind_result, MaxMindEvidence)
        assert isinstance(ipqs_result, IPQSEvidence)
        return maxmind_result, ipqs_result
