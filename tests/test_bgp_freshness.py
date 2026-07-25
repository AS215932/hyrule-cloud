"""Freshness labelling for BGP lookups.

Regression cover for a real incident: an operator asked "is this /48 propagating?"
against RIPEstat routing-status, got a 10-hour-old batch snapshot reported as
status="ok", concluded the prefix was being filtered upstream, and filed a bug on
that false premise. The prefix was in fact live — visible in the looking-glass at
query time.

The product rule these tests encode: never report snapshot data as fresh, and
always offer a real-time path for propagation questions.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hyrule_cloud.models import BGPDataset, BGPLookupRequest, DataFreshness
from hyrule_cloud.services.bgp import lookup as bgp_lookup


def _req(datasets: list[str], value: str = "2a0c:b641:b51::/48") -> BGPLookupRequest:
    return BGPLookupRequest.model_validate(
        {"subject": {"type": "prefix", "value": value}, "datasets": datasets}
    )


@pytest.fixture(autouse=True)
def _clear_cache():
    bgp_lookup._cache._store.clear() if hasattr(bgp_lookup._cache, "_store") else None
    yield


def _stub_get_json(monkeypatch, mapping: dict[str, dict]):
    async def fake(url: str, params):
        for key, payload in mapping.items():
            if key in url:
                return payload, None
        return None, "not stubbed"

    monkeypatch.setattr(bgp_lookup, "_get_json", fake)


def test_parse_query_time_assumes_utc_when_naive():
    data = {"query_time": "2026-07-24T16:00:00"}
    parsed = bgp_lookup._parse_query_time(data)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.hour == 16


def test_old_snapshot_is_marked_stale_with_age_and_guidance():
    observed = datetime.now(UTC) - timedelta(hours=10)
    health, freshness = bgp_lookup._delayed_source_health(
        {"query_time": observed.isoformat()}, "https://example/routing-status"
    )
    assert health.status == "stale"
    assert health.age_seconds >= 10 * 3600 - 5
    # The message must point at the fix, not just state a number.
    assert "live_looking_glass" in (health.message or "")
    assert freshness["class"] == DataFreshness.DELAYED.value
    assert freshness["stale"] is True


def test_recent_snapshot_is_not_marked_stale():
    observed = datetime.now(UTC) - timedelta(minutes=2)
    health, freshness = bgp_lookup._delayed_source_health(
        {"query_time": observed.isoformat()}, "https://example/routing-status"
    )
    assert health.status == "ok"
    assert freshness["stale"] is False


def test_missing_query_time_is_unknown_not_silently_fresh():
    _health, freshness = bgp_lookup._delayed_source_health({}, "https://example/routing-status")
    assert freshness["class"] == DataFreshness.UNKNOWN.value
    assert freshness["age_seconds"] is None


@pytest.mark.asyncio
async def test_looking_glass_reports_realtime_and_extracts_origins(monkeypatch):
    _stub_get_json(
        monkeypatch,
        {
            "looking-glass": {
                "query_time": datetime.now(UTC).isoformat(),
                "rrcs": [
                    {
                        "rrc": "RRC20",
                        "location": "Zurich",
                        "peers": [{"as_path": "58057 215932"}],
                    },
                    {
                        "rrc": "RRC00",
                        "location": "Amsterdam",
                        "peers": [
                            {"as_path": "56755 215932"},
                            {"as_path": "49544 58057 215932"},
                        ],
                    },
                ],
            }
        },
    )
    result, health = await bgp_lookup._looking_glass("2a0c:b641:b51::/48")
    assert health.status == "ok"
    assert result["freshness"]["class"] == DataFreshness.REALTIME.value
    assert result["visible"] is True
    assert result["collector_count"] == 2
    assert result["peer_entry_count"] == 3
    # Origin is the last ASN in the path, deduplicated across collectors.
    assert result["origin_asns"] == [215932]


@pytest.mark.asyncio
async def test_looking_glass_absent_from_collectors_is_not_visible(monkeypatch):
    _stub_get_json(monkeypatch, {"looking-glass": {"query_time": datetime.now(UTC).isoformat(), "rrcs": []}})
    result, health = await bgp_lookup._looking_glass("2001:db8::/48")
    assert health.status == "ok"
    assert result["visible"] is False
    assert result["peer_entry_count"] == 0


@pytest.mark.asyncio
async def test_stale_snapshot_does_not_override_live_visibility(monkeypatch):
    """The incident in one test.

    routing-status is old enough to have missed the announcement; the
    looking-glass sees it live. `routed` must reflect the live observation.
    """
    stale = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
    _stub_get_json(
        monkeypatch,
        {
            "prefix-overview": {"announced": False, "asns": []},
            "routing-status": {"query_time": stale, "origins": [], "last_seen": {}},
            "looking-glass": {
                "query_time": datetime.now(UTC).isoformat(),
                "rrcs": [{"rrc": "RRC20", "peers": [{"as_path": "58057 215932"}]}],
            },
            "rpki-validation": {"status": "valid"},
        },
    )
    result = await bgp_lookup.lookup_bgp(
        _req([BGPDataset.PUBLIC_ROUTING.value, BGPDataset.LIVE_LOOKING_GLASS.value])
    )
    assert result.resolved.routed is True
    assert 215932 in result.resolved.observed_origin_asns
    assert result.sources["ripestat_routing_status"].status == "stale"
    assert result.results["looking_glass"]["vantage"] == "external_ris"


@pytest.mark.asyncio
async def test_internal_vantage_declares_itself_not_configured(monkeypatch):
    """Selecting the internal dataset must not look like a successful answer.

    It is not charged a premium tier (see test_router_tables_alone_is_not_a_premium_tier
    below), so a quiet not_configured stub can't be mistaken for a paid,
    populated result.
    """
    _stub_get_json(
        monkeypatch,
        {
            "prefix-overview": {"announced": True, "asns": []},
            "routing-status": {"query_time": datetime.now(UTC).isoformat(), "origins": []},
        },
    )
    result = await bgp_lookup.lookup_bgp(
        _req([BGPDataset.PUBLIC_ROUTING.value, BGPDataset.AS215932_ROUTER_TABLES.value])
    )
    assert result.sources["as215932_router_tables"].status == "not_configured"
    assert result.results["as215932_router_tables"]["status"] == "not_configured"
    assert result.partial is True


def test_router_tables_alone_is_not_a_premium_tier():
    """Regression: AS215932_ROUTER_TABLES isn't wired up (returns a
    not_configured stub, no additional data over the base lookup), so
    selecting it must not bill the $0.01 router-query rate — that would
    charge double for nothing."""
    from hyrule_cloud.api.bgp import _lookup_price_attr

    attr, default = _lookup_price_attr(_req([BGPDataset.AS215932_ROUTER_TABLES.value]))
    assert (attr, default) == ("price_bgp_lookup", "0.005")


def test_router_tables_combined_with_looking_glass_still_charges_looking_glass():
    from hyrule_cloud.api.bgp import _lookup_price_attr

    attr, default = _lookup_price_attr(
        _req([BGPDataset.AS215932_ROUTER_TABLES.value, BGPDataset.LIVE_LOOKING_GLASS.value])
    )
    assert (attr, default) == ("price_bgp_looking_glass", "0.01")


@pytest.mark.asyncio
async def test_as215932_status_reflects_live_visibility_despite_stale_snapshot(monkeypatch):
    """Same incident as test_stale_snapshot_does_not_override_live_visibility,
    but on the free /v1/bgp/status endpoint: it used to build its lookup
    request without live_looking_glass, so prefix_visible came solely from
    the batch routing_status snapshot and could read False for hours after a
    real announcement, on Hyrule's most public status surface."""
    stale = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
    _stub_get_json(
        monkeypatch,
        {
            "prefix-overview": {"announced": False, "asns": []},
            "routing-status": {"query_time": stale, "origins": [], "last_seen": {}},
            "looking-glass": {
                "query_time": datetime.now(UTC).isoformat(),
                "rrcs": [{"rrc": "RRC20", "peers": [{"as_path": "58057 215932"}]}],
            },
            "rpki-validation": {"status": "valid"},
        },
    )
    status = await bgp_lookup.as215932_status()
    assert status.routing["prefix_visible"] is True
    assert 215932 in status.routing["observed_origin_asns"]
    assert status.status == "ok"
    # The verdict came from the realtime looking-glass observation, not the
    # stale snapshot — the reported freshness must say so.
    assert status.routing["freshness"]["class"] == DataFreshness.REALTIME.value
