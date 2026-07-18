from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import Response
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.api.metrics import _render_dns_product_metrics
from hyrule_cloud.app import app
from hyrule_cloud.config import (
    DNSBlocklistConfig,
    DNSFilteringConfig,
    HyruleConfig,
    PaymentConfig,
)
from hyrule_cloud.models import (
    DNSBlocklistCategory,
    DNSBlocklistSourceOutcome,
    DNSBlocklistVerdict,
    DNSFilteringObservation,
    DNSFilteringOverallStatus,
    DNSFilteringProfileStatus,
)
from hyrule_cloud.services.dns.blocklists import (
    BLOCKLIST_SOURCES,
    BlocklistService,
    BlocklistSource,
    parse_rule_line,
)
from hyrule_cloud.services.dns.domain import normalize_domain
from hyrule_cloud.services.dns.filtering import (
    DNSFilteringService,
    DomainNotResolvableError,
    ResolverProfile,
)


def _source(
    source_id: str,
    categories: tuple[DNSBlocklistCategory, ...],
) -> BlocklistSource:
    return BlocklistSource(
        source_id=source_id,
        name=source_id.replace("_", " ").title(),
        categories=categories,
        source_url=f"https://lists.example/{source_id}.txt",
        license="MIT",
        license_url="https://lists.example/license",
        format="test",
        minimum_rules=1,
    )


def _seed_source(
    service: BlocklistService,
    source: BlocklistSource,
    rules: str,
    *,
    validated_at: datetime | None = None,
) -> None:
    now = validated_at or datetime.now(UTC)
    raw = service.data_dir / "raw" / f"{source.source_id}.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(rules, encoding="utf-8")
    state = service.data_dir / "state" / f"{source.source_id}.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        json.dumps(
            {
                "validated_at": now.isoformat(),
                "content_updated_at": now.isoformat(),
                "rule_count": len(rules.splitlines()),
                "rejected_rule_count": 0,
                "last_error": None,
            }
        ),
        encoding="utf-8",
    )


def _blocklist_service(tmp_path, *, stale_second_source: bool = False) -> BlocklistService:
    sources = (
        _source("ads", (DNSBlocklistCategory.ADS,)),
        _source("security", (DNSBlocklistCategory.MALWARE, DNSBlocklistCategory.C2)),
    )
    config = DNSBlocklistConfig(
        _env_file=None,
        data_dir=tmp_path,
        minimum_coverage=0.5 if stale_second_source else 1.0,
    )
    service = BlocklistService(config, sources=sources)
    _seed_source(
        service,
        sources[0],
        "\n".join(
            (
                "||tracker.example^",
                "@@||allowed.tracker.example^",
                "*.wild.example",
                "0.0.0.0 exact.example",
                "||browser-only.example^$third-party",
            )
        ),
    )
    validated = (
        datetime.now(UTC) - timedelta(days=8)
        if stale_second_source
        else datetime.now(UTC)
    )
    _seed_source(service, sources[1], "bad.example\n", validated_at=validated)
    service.compile_snapshot()
    return service


def test_domain_normalization_and_dns_decidable_rule_parser() -> None:
    assert normalize_domain("BÜCHER.example.") == "xn--bcher-kva.example"
    assert parse_rule_line("0.0.0.0 exact.example").match_kind == "exact"
    assert parse_rule_line("||parent.example^").match_kind == "suffix"
    assert parse_rule_line("*.wild.example").match_kind == "wildcard"
    assert parse_rule_line("@@||allowed.example^").action == "allow"
    assert parse_rule_line("||browser.example^$third-party") is None
    assert parse_rule_line("example.com/path.js") is None
    with pytest.raises(ValueError, match="not a URL"):
        normalize_domain("https://example.com/path")
    with pytest.raises(ValueError, match="IP addresses"):
        normalize_domain("192.0.2.1")


def test_hagezi_tif_medium_uses_current_dns_capable_feed() -> None:
    source = next(
        source for source in BLOCKLIST_SOURCES if source.source_id == "hagezi_tif_medium"
    )
    assert source.source_url.endswith("/adblock/tif.medium.txt")
    assert source.format == "adblock-dns"


def test_compiled_blocklist_matching_exceptions_and_wildcards(tmp_path) -> None:
    service = _blocklist_service(tmp_path)
    assert service.sources_response().ready is True

    listed = service._check_sync("sub.tracker.example", "sub.tracker.example")
    assert listed.verdict == DNSBlocklistVerdict.LISTED
    assert listed.matched_source_count == 1
    assert listed.categories == [DNSBlocklistCategory.ADS]

    excepted = service._check_sync(
        "allowed.tracker.example", "allowed.tracker.example"
    )
    ads = next(result for result in excepted.results if result.source_id == "ads")
    assert ads.outcome == DNSBlocklistSourceOutcome.EXCEPTED
    assert excepted.verdict == DNSBlocklistVerdict.NOT_LISTED

    base = service._check_sync("wild.example", "wild.example")
    assert base.verdict == DNSBlocklistVerdict.NOT_LISTED
    wildcard = service._check_sync("child.wild.example", "child.wild.example")
    assert wildcard.verdict == DNSBlocklistVerdict.LISTED


def test_hard_expired_source_makes_negative_answer_inconclusive(tmp_path) -> None:
    service = _blocklist_service(tmp_path, stale_second_source=True)
    catalog = service.sources_response()
    assert catalog.ready is True
    assert catalog.usable_source_count == 1

    result = service._check_sync("clean.example", "clean.example")
    assert result.verdict == DNSBlocklistVerdict.INCONCLUSIVE
    assert result.partial is True
    unavailable = next(item for item in result.results if item.source_id == "security")
    assert unavailable.outcome == DNSBlocklistSourceOutcome.UNAVAILABLE


_FILTER_PROFILES = (
    ResolverProfile(
        "ads",
        "Ads",
        "Test",
        (DNSBlocklistCategory.ADS, DNSBlocklistCategory.TRACKERS),
        "https://ads.test/dns-query",
        "https://control.test/dns-query",
        ("nxdomain_with_resolving_control",),
    ),
    ResolverProfile(
        "security",
        "Security",
        "Test",
        (DNSBlocklistCategory.MALWARE,),
        "https://security.test/dns-query",
        "https://control.test/dns-query",
        ("null_address",),
    ),
)


class _StubFilteringService(DNSFilteringService):
    def __init__(self, observations: dict[tuple[str, str], DNSFilteringObservation]):
        super().__init__(
            DNSFilteringConfig(
                _env_file=None,
                minimum_conclusive_profiles=2,
                cache_ttl_seconds=60,
            ),
            profiles=_FILTER_PROFILES,
        )
        self.observations = observations
        self.query_count = 0

    async def _query_endpoint(
        self, endpoint: str, domain: str, record_type: str
    ) -> DNSFilteringObservation:
        self.query_count += 1
        return self.observations[(endpoint, record_type)].model_copy(deep=True)


def _observations(*, control_resolves: bool = True) -> dict[tuple[str, str], DNSFilteringObservation]:
    control_a = DNSFilteringObservation(
        record_type="A",
        rcode="NOERROR" if control_resolves else "NXDOMAIN",
        answers=["192.0.2.10"] if control_resolves else [],
    )
    control_aaaa = DNSFilteringObservation(record_type="AAAA", rcode="NOERROR")
    return {
        ("https://control.test/dns-query", "A"): control_a,
        ("https://control.test/dns-query", "AAAA"): control_aaaa,
        ("https://ads.test/dns-query", "A"): DNSFilteringObservation(
            record_type="A", rcode="NXDOMAIN"
        ),
        ("https://ads.test/dns-query", "AAAA"): DNSFilteringObservation(
            record_type="AAAA", rcode="NXDOMAIN"
        ),
        ("https://security.test/dns-query", "A"): DNSFilteringObservation(
            record_type="A", rcode="NOERROR", answers=["198.51.100.20"]
        ),
        ("https://security.test/dns-query", "AAAA"): DNSFilteringObservation(
            record_type="AAAA", rcode="NOERROR"
        ),
    }


@pytest.mark.asyncio
async def test_filtering_matrix_classifies_mixed_and_caches() -> None:
    service = _StubFilteringService(_observations())
    try:
        first = await service.check("Example.COM.")
        assert first.overall == DNSFilteringOverallStatus.MIXED
        assert first.conclusive_profile_count == 2
        assert service.meets_quality_floor(first) is True
        assert {result.status for result in first.profiles} == {
            DNSFilteringProfileStatus.BLOCKED,
            DNSFilteringProfileStatus.ALLOWED,
        }
        queries = service.query_count

        second = await service.check("example.com")
        assert service.query_count == queries
        assert second.request_id != first.request_id
        assert second.normalized_domain == "example.com"
    finally:
        await service.close()


@pytest.mark.asyncio
async def test_filtering_matrix_rejects_non_resolving_control() -> None:
    service = _StubFilteringService(_observations(control_resolves=False))
    try:
        with pytest.raises(DomainNotResolvableError):
            await service.check("missing.example")
    finally:
        await service.close()


class _Gate:
    def __init__(self) -> None:
        self.settled = 0

    async def verify_only(self, request, amount, description="", extra_body=None):
        if not request.headers.get("X-Mock-Wallet"):
            return Response(status_code=402)
        return SimpleNamespace(amount=amount, payer=request.headers["X-Mock-Wallet"])

    async def settle_verified(self, request, verified):
        self.settled += 1
        return True


class _FailingSettlementGate(_Gate):
    async def settle_verified(self, request, verified):
        self.settled += 1
        return False


@pytest.mark.asyncio
async def test_paid_dns_blocking_routes_settle_only_delivered_results(tmp_path) -> None:
    blocklists = _blocklist_service(tmp_path / "lists")
    filtering = _StubFilteringService(_observations())
    gate = _Gate()
    config = HyruleConfig(
        _env_file=None,
        dns_blocklists=blocklists.config,
        dns_filtering=filtering.config,
        payment=PaymentConfig(_env_file=None),
    )
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=config,
        payment_gate=gate,
        dns_blocklists=blocklists,
        dns_filtering=filtering,
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            unpaid = await client.post(
                "/v1/dns/blocklists/check", json={"domain": "example.com"}
            )
            listed = await client.post(
                "/v1/dns/blocklists/check",
                headers={"X-Mock-Wallet": "0xWallet"},
                json={"domain": "sub.tracker.example"},
            )
            filtered = await client.post(
                "/v1/dns/filtering/check",
                headers={"X-Mock-Wallet": "0xWallet"},
                json={"domain": "example.com"},
            )
            blocklist_quote = await client.post(
                "/v1/dns/blocklists/check/quote", json={"domain": "example.com"}
            )
            filtering_quote = await client.post(
                "/v1/dns/filtering/check/quote", json={"domain": "example.com"}
            )
            pricing = await client.get("/v1/dns/pricing")
            capabilities = await client.get("/v1/dns/capabilities")
    finally:
        await filtering.close()
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert unpaid.status_code == 402
    assert listed.status_code == 200
    assert listed.json()["verdict"] == "listed"
    assert filtered.status_code == 200
    assert filtered.json()["overall"] == "mixed"
    assert gate.settled == 2
    assert blocklist_quote.json()["amount_usd"] == "0.003"
    assert filtering_quote.json()["amount_usd"] == "0.01"
    assert "/v1/dns/blocklists/check" in {
        endpoint["path"] for endpoint in capabilities.json()["paid_endpoints"]
    }
    assert pricing.json() == {
        "lookup_usd": "0.001",
        "blocklist_check_usd": "0.003",
        "filtering_check_usd": "0.01",
    }


@pytest.mark.asyncio
async def test_filtering_undercoverage_is_not_settled(tmp_path) -> None:
    observations = _observations()
    for key in list(observations):
        if key[0] != "https://control.test/dns-query":
            observations[key] = DNSFilteringObservation(
                record_type=key[1], error="provider unavailable"
            )
    filtering = _StubFilteringService(observations)
    gate = _Gate()
    config = HyruleConfig(
        _env_file=None,
        dns_filtering=filtering.config,
        payment=PaymentConfig(_env_file=None),
    )
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=config,
        payment_gate=gate,
        dns_filtering=filtering,
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/dns/filtering/check",
                headers={"X-Mock-Wallet": "0xWallet"},
                json={"domain": "example.com"},
            )
    finally:
        await filtering.close()
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 503
    assert gate.settled == 0


@pytest.mark.asyncio
async def test_failed_settlement_withholds_blocklist_result(tmp_path) -> None:
    blocklists = _blocklist_service(tmp_path)
    gate = _FailingSettlementGate()
    config = HyruleConfig(
        _env_file=None,
        dns_blocklists=blocklists.config,
        payment=PaymentConfig(_env_file=None),
    )
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=config,
        payment_gate=gate,
        dns_blocklists=blocklists,
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/dns/blocklists/check",
                headers={"X-Mock-Wallet": "0xWallet"},
                json={"domain": "sub.tracker.example"},
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert response.status_code == 402
    assert "verdict" not in response.json()
    assert gate.settled == 1


@pytest.mark.asyncio
async def test_dns_product_metrics_expose_catalog_and_profile_outcomes(tmp_path) -> None:
    blocklists = _blocklist_service(tmp_path)
    filtering = _StubFilteringService(_observations())
    try:
        await blocklists.check("sub.tracker.example")
        await filtering.check("example.com")
        lines: list[str] = []
        _render_dns_product_metrics(
            lines,
            SimpleNamespace(
                dns_blocklists=blocklists,
                dns_filtering=filtering,
            ),
        )
    finally:
        await filtering.close()
    rendered = "\n".join(lines)
    assert "hyrule_dns_blocklist_ready 1" in rendered
    assert 'hyrule_dns_blocklist_checks_total{verdict="listed"} 1' in rendered
    assert 'hyrule_dns_filtering_checks_total{result="mixed"} 1' in rendered
