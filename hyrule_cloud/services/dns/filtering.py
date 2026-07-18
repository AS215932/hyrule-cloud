"""Live DNS-over-HTTPS checks against curated public filtering profiles."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import dns.asyncquery
import dns.edns
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import httpx
import structlog

from hyrule_cloud.config import DNSFilteringConfig, HyruleConfig
from hyrule_cloud.models import (
    DNSBlocklistCategory,
    DNSFilteringCheckResponse,
    DNSFilteringObservation,
    DNSFilteringOverallStatus,
    DNSFilteringProfileResult,
    DNSFilteringProfileStatus,
    DNSFilteringResolverInfo,
    DNSFilteringResolversResponse,
    generate_diagnostic_request_id,
)
from hyrule_cloud.services.cache import TTLCache
from hyrule_cloud.services.dns.domain import normalize_domain

log = structlog.get_logger().bind(component="dns_filtering")


class DomainNotResolvableError(ValueError):
    """The target has no usable A/AAAA baseline from any control resolver."""


class FilteringCoverageError(RuntimeError):
    """Too few filtering profiles produced conclusive paid evidence."""


@dataclass(frozen=True, slots=True)
class ResolverProfile:
    profile_id: str
    name: str
    provider: str
    categories: tuple[DNSBlocklistCategory, ...]
    filtered_endpoint: str
    control_endpoint: str
    blocking_signals: tuple[str, ...]


_ADS_PRIVACY = (
    DNSBlocklistCategory.ADS,
    DNSBlocklistCategory.TRACKERS,
    DNSBlocklistCategory.TELEMETRY,
)
_SECURITY = (
    DNSBlocklistCategory.PHISHING,
    DNSBlocklistCategory.MALWARE,
    DNSBlocklistCategory.SCAM,
    DNSBlocklistCategory.C2,
)
_CLOUDFLARE_CONTROL = "https://cloudflare-dns.com/dns-query"
_MULLVAD_CONTROL = "https://dns.mullvad.net/dns-query"

RESOLVER_PROFILES: tuple[ResolverProfile, ...] = (
    ResolverProfile(
        "cloudflare_security",
        "Cloudflare Malware Blocking",
        "Cloudflare",
        (DNSBlocklistCategory.PHISHING, DNSBlocklistCategory.MALWARE),
        "https://security.cloudflare-dns.com/dns-query",
        _CLOUDFLARE_CONTROL,
        ("null_address", "nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "quad9_secure",
        "Quad9 Secure",
        "Quad9",
        _SECURITY,
        "https://dns.quad9.net/dns-query",
        "https://dns10.quad9.net/dns-query",
        ("nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "adguard_default",
        "AdGuard Default",
        "AdGuard",
        _ADS_PRIVACY,
        "https://dns.adguard-dns.com/dns-query",
        "https://unfiltered.adguard-dns.com/dns-query",
        ("null_address", "nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "controld_malware",
        "Control D Malware",
        "Control D",
        _SECURITY,
        "https://freedns.controld.com/p1",
        "https://freedns.controld.com/p0",
        ("null_address", "nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "controld_ads_tracking",
        "Control D Ads & Tracking",
        "Control D",
        _ADS_PRIVACY,
        "https://freedns.controld.com/p2",
        "https://freedns.controld.com/p0",
        ("null_address", "nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "cleanbrowsing_security",
        "CleanBrowsing Security",
        "CleanBrowsing",
        _SECURITY,
        "https://doh.cleanbrowsing.org/doh/security-filter/",
        _CLOUDFLARE_CONTROL,
        ("nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "mullvad_adblock",
        "Mullvad Adblock",
        "Mullvad",
        _ADS_PRIVACY,
        "https://adblock.dns.mullvad.net/dns-query",
        _MULLVAD_CONTROL,
        ("nxdomain_with_resolving_control", "ede_blocked"),
    ),
    ResolverProfile(
        "mullvad_base",
        "Mullvad Base",
        "Mullvad",
        (*_ADS_PRIVACY, DNSBlocklistCategory.MALWARE),
        "https://base.dns.mullvad.net/dns-query",
        _MULLVAD_CONTROL,
        ("nxdomain_with_resolving_control", "ede_blocked"),
    ),
)


@dataclass(frozen=True, slots=True)
class _CachedResult:
    response: DNSFilteringCheckResponse
    cached_at: float


class DNSFilteringService:
    def __init__(
        self,
        config: DNSFilteringConfig,
        *,
        profiles: tuple[ResolverProfile, ...] = RESOLVER_PROFILES,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self.profiles = profiles
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            http2=True,
            timeout=config.query_timeout_seconds,
            headers={"User-Agent": "Hyrule-Cloud-DNS-Filtering/1.0 (+https://hyrule.host)"},
        )
        self._cache: TTLCache[_CachedResult] = TTLCache(max_entries=2048)
        self._overall_counts: dict[str, int] = {}
        self._profile_counts: dict[tuple[str, str], int] = {}
        self._last_profile_status: dict[str, str] = {}
        self._profile_latency_ms_total: dict[str, float] = {}
        self._profile_latency_samples: dict[str, int] = {}

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def resolver_catalog(self) -> DNSFilteringResolversResponse:
        return filtering_resolver_catalog(
            self.config,
            profiles=self.profiles,
            statuses=self._last_profile_status,
        )

    def metrics_snapshot(self) -> dict[str, object]:
        return {
            "overall": dict(self._overall_counts),
            "profiles": {
                f"{profile_id}|{status}": count
                for (profile_id, status), count in self._profile_counts.items()
            },
            "last_profile_status": dict(self._last_profile_status),
            "profile_latency_ms_total": dict(self._profile_latency_ms_total),
            "profile_latency_samples": dict(self._profile_latency_samples),
        }

    def meets_quality_floor(self, response: DNSFilteringCheckResponse) -> bool:
        conclusive = {
            result.profile_id: result
            for result in response.profiles
            if result.status
            in {DNSFilteringProfileStatus.BLOCKED, DNSFilteringProfileStatus.ALLOWED}
        }
        if len(conclusive) < self.config.minimum_conclusive_profiles:
            return False
        categories = {
            category
            for result in conclusive.values()
            for category in result.categories
        }
        has_ads = bool(categories.intersection(_ADS_PRIVACY))
        has_security = bool(categories.intersection(_SECURITY))
        return has_ads and has_security

    async def check(self, input_domain: str) -> DNSFilteringCheckResponse:
        if not self.config.enabled:
            raise FilteringCoverageError("DNS filtering checks are disabled")
        normalized = normalize_domain(input_domain)
        cached = self._cache.get(normalized)
        if cached is not None:
            age = max(0, int(time.monotonic() - cached.cached_at))
            return cached.response.model_copy(
                update={
                    "request_id": generate_diagnostic_request_id(),
                    "input_domain": input_domain,
                    "cache_age_seconds": age,
                    "generated_at": datetime.now(UTC),
                }
            )

        response = await self._collect(input_domain, normalized)
        self._overall_counts[response.overall.value] = (
            self._overall_counts.get(response.overall.value, 0) + 1
        )
        for result in response.profiles:
            key = (result.profile_id, result.status.value)
            self._profile_counts[key] = self._profile_counts.get(key, 0) + 1
            self._last_profile_status[result.profile_id] = result.status.value
            latencies = [
                observation.latency_ms
                for observation in result.filtered
                if observation.latency_ms is not None
            ]
            if latencies:
                self._profile_latency_ms_total[result.profile_id] = (
                    self._profile_latency_ms_total.get(result.profile_id, 0.0)
                    + sum(latencies)
                )
                self._profile_latency_samples[result.profile_id] = (
                    self._profile_latency_samples.get(result.profile_id, 0)
                    + len(latencies)
                )
        if self.meets_quality_floor(response) and self.config.cache_ttl_seconds:
            self._cache.set(
                normalized,
                _CachedResult(response=response, cached_at=time.monotonic()),
                ttl_seconds=self.config.cache_ttl_seconds,
            )
        return response

    async def _collect(
        self,
        input_domain: str,
        normalized: str,
    ) -> DNSFilteringCheckResponse:
        endpoints = {
            endpoint
            for profile in self.profiles
            for endpoint in (profile.filtered_endpoint, profile.control_endpoint)
        }
        task_by_key: dict[tuple[str, str], asyncio.Task[DNSFilteringObservation]] = {}
        for endpoint in endpoints:
            for record_type in ("A", "AAAA"):
                task_by_key[(endpoint, record_type)] = asyncio.create_task(
                    self._safe_query(endpoint, normalized, record_type)
                )

        done, pending = await asyncio.wait(
            task_by_key.values(),
            timeout=self.config.overall_timeout_seconds,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        observations: dict[tuple[str, str], DNSFilteringObservation] = {}
        for key, task in task_by_key.items():
            if task in done:
                observations[key] = task.result()
            else:
                observations[key] = DNSFilteringObservation(
                    record_type=key[1], error="overall DNS filtering deadline exceeded"
                )

        control_observations = {
            key: observation
            for key, observation in observations.items()
            if key[0] in {profile.control_endpoint for profile in self.profiles}
        }
        any_control_answer = any(
            _non_null_answers(observation) for observation in control_observations.values()
        )
        any_control_dns_response = any(
            observation.rcode is not None for observation in control_observations.values()
        )
        if not any_control_answer and any_control_dns_response:
            raise DomainNotResolvableError(
                "domain has no A or AAAA answer from the control resolvers"
            )

        observed_at = datetime.now(UTC)
        results: list[DNSFilteringProfileResult] = []
        for profile in self.profiles:
            filtered = [
                observations[(profile.filtered_endpoint, record_type)]
                for record_type in ("A", "AAAA")
            ]
            control = [
                observations[(profile.control_endpoint, record_type)]
                for record_type in ("A", "AAAA")
            ]
            status, reason = _classify(filtered, control)
            results.append(
                DNSFilteringProfileResult(
                    profile_id=profile.profile_id,
                    name=profile.name,
                    provider=profile.provider,
                    categories=list(profile.categories),
                    status=status,
                    reason=reason,
                    filtered=filtered,
                    control=control,
                    observed_at=observed_at,
                )
            )

        blocked = sum(result.status == DNSFilteringProfileStatus.BLOCKED for result in results)
        allowed = sum(result.status == DNSFilteringProfileStatus.ALLOWED for result in results)
        conclusive = blocked + allowed
        if blocked and allowed:
            overall = DNSFilteringOverallStatus.MIXED
        elif blocked:
            overall = DNSFilteringOverallStatus.BLOCKED
        elif allowed:
            overall = DNSFilteringOverallStatus.ALLOWED
        else:
            overall = DNSFilteringOverallStatus.INCONCLUSIVE
        return DNSFilteringCheckResponse(
            input_domain=input_domain,
            normalized_domain=normalized,
            overall=overall,
            blocked_profile_count=blocked,
            allowed_profile_count=allowed,
            conclusive_profile_count=conclusive,
            total_profile_count=len(results),
            profiles=results,
            partial=conclusive < len(results),
            observed_at=observed_at,
        )

    async def _safe_query(
        self,
        endpoint: str,
        domain: str,
        record_type: str,
    ) -> DNSFilteringObservation:
        try:
            return await asyncio.wait_for(
                self._query_endpoint(endpoint, domain, record_type),
                timeout=self.config.query_timeout_seconds,
            )
        except TimeoutError:
            return DNSFilteringObservation(record_type=record_type, error="DNS query timed out")
        except Exception as exc:
            return DNSFilteringObservation(
                record_type=record_type,
                error=f"{type(exc).__name__}: {str(exc)[:200]}",
            )

    async def _query_endpoint(
        self,
        endpoint: str,
        domain: str,
        record_type: str,
    ) -> DNSFilteringObservation:
        query = dns.message.make_query(domain, record_type, use_edns=True)
        started = time.perf_counter()
        response = await dns.asyncquery.https(
            query,
            endpoint,
            timeout=self.config.query_timeout_seconds,
            client=self._client,
            http_version=dns.query.HTTPVersion.H2,
        )
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        answers: list[str] = []
        cname_chain: list[str] = []
        wanted = dns.rdatatype.from_text(record_type)
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname_chain.extend(rdata.target.to_text().rstrip(".") for rdata in rrset)
            elif rrset.rdtype == wanted:
                answers.extend(rdata.to_text().rstrip(".") for rdata in rrset)
        ede_codes = [
            int(option.code)
            for option in response.options
            if isinstance(option, dns.edns.EDEOption)
        ]
        return DNSFilteringObservation(
            record_type=record_type,
            rcode=dns.rcode.to_text(response.rcode()),
            answers=answers,
            cname_chain=cname_chain,
            ede_codes=ede_codes,
            authority_count=len(response.authority),
            latency_ms=latency_ms,
        )


def _non_null_answers(observation: DNSFilteringObservation) -> list[str]:
    return [
        answer
        for answer in observation.answers
        if answer not in {"0.0.0.0", "::", "0:0:0:0:0:0:0:0"}
    ]


def _classify(
    filtered: list[DNSFilteringObservation],
    control: list[DNSFilteringObservation],
) -> tuple[DNSFilteringProfileStatus, str]:
    control_resolves = any(_non_null_answers(observation) for observation in control)
    if not control_resolves:
        if all(observation.error for observation in control):
            return DNSFilteringProfileStatus.UNAVAILABLE, "control resolver was unavailable"
        return DNSFilteringProfileStatus.INCONCLUSIVE, "control resolver did not resolve the domain"

    block_signals: list[str] = []
    allowed_signals = 0
    for observation in filtered:
        if observation.error:
            continue
        answers = _non_null_answers(observation)
        null_answers = set(observation.answers) - set(answers)
        if null_answers:
            block_signals.append(f"{observation.record_type} returned a null address")
        if observation.rcode == "NXDOMAIN":
            block_signals.append(f"{observation.record_type} returned NXDOMAIN")
        if 15 in observation.ede_codes:
            block_signals.append(f"{observation.record_type} returned EDE 15 (Blocked)")
        if answers:
            allowed_signals += 1

    if block_signals and allowed_signals:
        return (
            DNSFilteringProfileStatus.INCONCLUSIVE,
            "address families produced conflicting block and allow evidence",
        )
    if block_signals:
        return DNSFilteringProfileStatus.BLOCKED, "; ".join(block_signals)
    if allowed_signals:
        return DNSFilteringProfileStatus.ALLOWED, "filtered resolver returned usable addresses"
    if all(observation.error for observation in filtered):
        return DNSFilteringProfileStatus.UNAVAILABLE, "filtered resolver was unavailable"
    return DNSFilteringProfileStatus.INCONCLUSIVE, "no documented blocking signal was observed"


def dns_filtering_enabled(config: DNSFilteringConfig | None = None) -> bool:
    if config is None:
        config = HyruleConfig().dns_filtering
    return config.enabled


def filtering_resolver_catalog(
    config: DNSFilteringConfig | None = None,
    *,
    profiles: tuple[ResolverProfile, ...] = RESOLVER_PROFILES,
    statuses: dict[str, str] | None = None,
) -> DNSFilteringResolversResponse:
    if config is None:
        config = HyruleConfig().dns_filtering
    statuses = statuses or {}
    return DNSFilteringResolversResponse(
        enabled=config.enabled,
        profiles=[
            DNSFilteringResolverInfo(
                profile_id=profile.profile_id,
                name=profile.name,
                provider=profile.provider,
                categories=list(profile.categories),
                filtered_endpoint=profile.filtered_endpoint,
                control_endpoint=profile.control_endpoint,
                blocking_signals=list(profile.blocking_signals),
                status=statuses.get(profile.profile_id, "configured"),
            )
            for profile in profiles
        ],
    )
