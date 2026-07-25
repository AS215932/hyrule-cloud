"""Public BGP lookup service.

This first implementation uses lightweight public APIs that are safe to call
from Hyrule Cloud synchronously. extmon adds BGPalerter, Routinator-local,
BGPStream workers, and router snapshots in later steps.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from hyrule_cloud.models import (
    BGPAssertions,
    BGPDataset,
    BGPLookupRequest,
    BGPLookupResponse,
    BGPOriginObservation,
    BGPResolvedSubject,
    BGPStatusResponse,
    BGPSubjectType,
    DataFreshness,
    SourceHealth,
)
from hyrule_cloud.services.cache import TTLCache

_RIPESTAT = "https://stat.ripe.net/data"
_cache: TTLCache[BGPLookupResponse] = TTLCache(max_entries=2048)


async def _get_json(url: str, params: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            resp = await client.get(url, params=params, headers={"User-Agent": "HyruleCloud-BGP/1.0"})
            resp.raise_for_status()
            return resp.json().get("data", {}), None
        except Exception as exc:
            return None, str(exc)


def _normalize_asn(value: str | int) -> int:
    text = str(value).strip().upper().removeprefix("AS")
    return int(text)


# A routing-status snapshot older than this is old enough that a recently
# deployed announcement would be invisible in it. Callers asking a propagation
# question against data this old are answering yesterday's question.
_STALE_AFTER_SECONDS = 3600


def _parse_query_time(data: dict[str, Any]) -> datetime | None:
    raw = data.get("query_time") or data.get("latest_time")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _delayed_source_health(data: dict[str, Any], source_url: str) -> tuple[SourceHealth, dict[str, Any]]:
    """Health + freshness block for a snapshot source.

    RIPEstat serves real-time and batch data calls from one hostname, with the
    snapshot time buried in the payload as `query_time`. Reporting a stale batch
    result as status="ok" is how a caller concludes a prefix is not announced
    when it went live minutes ago. Surface the age instead of hiding it.
    """
    observed_at = _parse_query_time(data)
    if observed_at is None:
        return (
            SourceHealth(status="ok", message="upstream returned no query_time", source_url=source_url),
            {"class": DataFreshness.UNKNOWN.value, "observed_at": None, "age_seconds": None},
        )
    age = max(0, int((datetime.now(UTC) - observed_at).total_seconds()))
    stale = age > _STALE_AFTER_SECONDS
    return (
        SourceHealth(
            status="stale" if stale else "ok",
            age_seconds=age,
            checked_at=observed_at,
            source_url=source_url,
            message=(
                f"snapshot is {age}s old; it cannot reflect announcements made since "
                f"{observed_at.isoformat()}. Use dataset live_looking_glass for a "
                "real-time answer."
                if stale
                else None
            ),
        ),
        {
            "class": DataFreshness.DELAYED.value,
            "observed_at": observed_at.isoformat(),
            "age_seconds": age,
            "stale": stale,
        },
    )


async def _looking_glass(prefix: str) -> tuple[dict[str, Any], SourceHealth]:
    """Real-time propagation view from RIS collector RIBs.

    Unlike routing-status this is computed at query time, so a prefix announced
    a minute ago shows up. This is the dataset that answers "is it live?".
    """
    source_url = f"{_RIPESTAT}/looking-glass/data.json"
    data, err = await _get_json(source_url, {"resource": prefix})
    if data is None:
        return {}, SourceHealth(status="degraded", message=err, source_url=source_url)

    rrcs = data.get("rrcs", []) or []
    peer_entries = 0
    as_paths: list[str] = []
    origin_asns: list[int] = []
    collectors: list[dict[str, Any]] = []
    for rrc in rrcs:
        peers = rrc.get("peers", []) or []
        peer_entries += len(peers)
        for peer in peers:
            path = str(peer.get("as_path") or "").strip()
            if path and path not in as_paths:
                as_paths.append(path)
            if path:
                try:
                    asn = int(path.split()[-1])
                except (ValueError, IndexError):
                    continue
                if asn not in origin_asns:
                    origin_asns.append(asn)
        collectors.append(
            {
                "rrc": rrc.get("rrc"),
                "location": rrc.get("location"),
                "peer_count": len(peers),
            }
        )

    observed_at = _parse_query_time(data) or datetime.now(UTC)
    result = {
        "freshness": {
            "class": DataFreshness.REALTIME.value,
            "observed_at": observed_at.isoformat(),
            "age_seconds": 0,
            "stale": False,
        },
        "visible": peer_entries > 0,
        "collector_count": len(rrcs),
        "peer_entry_count": peer_entries,
        "origin_asns": origin_asns,
        "as_paths": as_paths[:64],
        "collectors": collectors[:64],
    }
    return result, SourceHealth(
        status="ok",
        age_seconds=0,
        checked_at=observed_at,
        source_url=source_url,
    )


def _assertions(observed: list[int], assertions: BGPAssertions, rpki_status: str | None) -> dict[str, object]:
    result: dict[str, object] = {}
    if assertions.expected_origin_asns:
        result["expected_origin_asns"] = {
            "pass": any(asn in observed for asn in assertions.expected_origin_asns),
            "observed": observed,
            "expected": assertions.expected_origin_asns,
        }
    if assertions.expected_rpki:
        result["expected_rpki"] = {
            "pass": rpki_status == assertions.expected_rpki,
            "observed": rpki_status,
            "expected": assertions.expected_rpki,
        }
    return result


async def _prefix_lookup(req: BGPLookupRequest) -> BGPLookupResponse:
    prefix = str(req.subject.value)
    cache_key = f"prefix:{prefix}:{req.model_dump_json()}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    sources: dict[str, SourceHealth] = {}
    results: dict[str, object] = {}
    observed: list[int] = []
    origins: list[BGPOriginObservation] = []
    partial = False
    rpki_status: str | None = None
    best_prefix: str | None = prefix
    routed: bool | None = None

    overview, err = await _get_json(f"{_RIPESTAT}/prefix-overview/data.json", {"resource": prefix})
    if overview is None:
        sources["ripestat_prefix_overview"] = SourceHealth(status="degraded", message=err)
        partial = True
    else:
        sources["ripestat_prefix_overview"] = SourceHealth(status="ok")
        routed = bool(overview.get("announced"))
        for asn_obj in overview.get("asns", []) or []:
            try:
                asn = int(asn_obj.get("asn"))
            except Exception:
                continue
            if asn not in observed:
                observed.append(asn)
        results["prefix_overview"] = overview

    routing_status_url = f"{_RIPESTAT}/routing-status/data.json"
    routing, err = await _get_json(routing_status_url, {"resource": prefix})
    if routing is None:
        sources["ripestat_routing_status"] = SourceHealth(status="degraded", message=err)
        partial = True
    else:
        health, freshness = _delayed_source_health(routing, routing_status_url)
        sources["ripestat_routing_status"] = health
        routed = bool(routing.get("last_seen") or routing.get("origins"))
        best_prefix = routing.get("last_seen", {}).get("prefix") or prefix
        for origin in routing.get("origins", []) or []:
            try:
                asn = int(origin.get("origin"))
            except Exception:
                continue
            if asn not in observed:
                observed.append(asn)
        results["routing_status"] = {**routing, "freshness": freshness}

    # Real-time propagation view. Opt-in so existing callers keep their current
    # cost and latency profile, but it is the only dataset that can answer
    # "is this announcement live?" — routing_status above cannot.
    if BGPDataset.LIVE_LOOKING_GLASS in req.datasets:
        lg, lg_health = await _looking_glass(prefix)
        sources["ripestat_looking_glass"] = lg_health
        if lg:
            results["looking_glass"] = {**lg, "vantage": "external_ris"}
            if lg.get("visible"):
                routed = True
                for asn in lg.get("origin_asns", []):
                    if asn not in observed:
                        observed.append(asn)
        else:
            partial = True

    # Internal AS215932 vantage. Not wired up yet: this service has no path to
    # the routers. Say so explicitly rather than returning silence — the caller
    # is billed at the router-query rate for selecting this dataset, so a quiet
    # no-op would be charging for data we never produced.
    if BGPDataset.AS215932_ROUTER_TABLES in req.datasets:
        sources["as215932_router_tables"] = SourceHealth(
            status="not_configured",
            message=(
                "Internal AS215932 router vantage is not yet implemented. No router "
                "RIB data is included in this response."
            ),
        )
        results["as215932_router_tables"] = {
            "vantage": "as215932_internal",
            "status": "not_configured",
            "note": (
                "External vantages answer 'does the world see this prefix'. The "
                "internal vantage answers 'which upstream do our own routers pick, "
                "and where does return traffic land' — a different question."
            ),
        }
        partial = True

    for asn in observed[:5]:
        rpki, err = await _get_json(
            f"{_RIPESTAT}/rpki-validation/data.json",
            {"resource": str(asn), "prefix": prefix},
        )
        if rpki is None:
            sources[f"ripestat_rpki_{asn}"] = SourceHealth(status="degraded", message=err)
            partial = True
            origins.append(BGPOriginObservation(asn=asn, sources=["ripestat"]))
        else:
            sources[f"ripestat_rpki_{asn}"] = SourceHealth(status="ok")
            rpki_status = str(rpki.get("status") or "unknown")
            origins.append(BGPOriginObservation(asn=asn, rpki=rpki_status, sources=["ripestat"]))
            results.setdefault("rpki", {})[str(asn)] = rpki  # type: ignore[index]

    response = BGPLookupResponse(
        request_id="bgpq_contract",
        subject={"type": req.subject.type.value, "input": prefix, "normalized": prefix},
        resolved=BGPResolvedSubject(
            routed=routed,
            best_prefix=best_prefix,
            observed_origin_asns=observed,
            origins=origins,
        ),
        results=results,
        assertions=_assertions(observed, req.assertions, rpki_status),
        sources=sources,
        partial=partial,
        charged_amount_usd=None,
        generated_at=datetime.now(UTC),
    )
    _cache.set(cache_key, response, ttl_seconds=req.time.max_age_seconds or 900)
    return response


async def _asn_lookup(req: BGPLookupRequest) -> BGPLookupResponse:
    asn = _normalize_asn(req.subject.value)
    cache_key = f"asn:{asn}:{req.model_dump_json()}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached
    sources: dict[str, SourceHealth] = {}
    results: dict[str, object] = {}
    partial = False

    overview, err = await _get_json(f"{_RIPESTAT}/as-overview/data.json", {"resource": f"AS{asn}"})
    if overview is None:
        sources["ripestat_as_overview"] = SourceHealth(status="degraded", message=err)
        partial = True
    else:
        sources["ripestat_as_overview"] = SourceHealth(status="ok")
        results["as_overview"] = overview

    announced, err = await _get_json(f"{_RIPESTAT}/announced-prefixes/data.json", {"resource": f"AS{asn}"})
    if announced is None:
        sources["ripestat_announced_prefixes"] = SourceHealth(status="degraded", message=err)
        partial = True
    else:
        sources["ripestat_announced_prefixes"] = SourceHealth(status="ok")
        results["announced_prefixes"] = announced

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            pdb = await client.get(f"https://www.peeringdb.com/api/net?asn={asn}", headers={"User-Agent": "HyruleCloud-BGP/1.0"})
            pdb.raise_for_status()
            results["peeringdb"] = pdb.json()
            sources["peeringdb"] = SourceHealth(status="ok")
        except Exception as exc:
            sources["peeringdb"] = SourceHealth(status="degraded", message=str(exc))
            partial = True

    response = BGPLookupResponse(
        request_id="bgpq_contract",
        subject={"type": req.subject.type.value, "input": req.subject.value, "normalized": asn},
        resolved=BGPResolvedSubject(observed_origin_asns=[asn]),
        results=results,
        assertions={},
        sources=sources,
        partial=partial,
        generated_at=datetime.now(UTC),
    )
    _cache.set(cache_key, response, ttl_seconds=req.time.max_age_seconds or 900)
    return response


async def lookup_bgp(req: BGPLookupRequest) -> BGPLookupResponse:
    if req.subject.type == BGPSubjectType.ASN:
        return await _asn_lookup(req)
    # RIPEstat accepts both IP and prefix on prefix-overview/routing-status and
    # resolves the routed covering prefix in routing-status when available.
    return await _prefix_lookup(req)


async def as215932_status() -> BGPStatusResponse:
    # Same incident as /v1/bgp/lookup, on our most public surface: without the
    # live looking-glass dataset, prefix_visible is derived solely from
    # routing_status, a batch snapshot that can be hours behind. This free
    # status endpoint would then report our own prefix as unrouted for hours
    # after a real announcement. Opting in here costs one extra public
    # RIPEstat call per status request — this call bypasses /lookup's payment
    # gate entirely (it invokes lookup_bgp directly), so it is not billed.
    req = BGPLookupRequest.model_validate(
        {
            "subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"},
            "datasets": [BGPDataset.PUBLIC_ROUTING, BGPDataset.LIVE_LOOKING_GLASS, BGPDataset.RPKI],
            "assertions": {"expected_origin_asns": [215932], "expected_rpki": "valid"},
        }
    )
    result = await lookup_bgp(req)
    visibility: dict[str, object] = {}
    freshness: dict[str, object] = {}
    routing_status = result.results.get("routing_status")
    if isinstance(routing_status, dict):
        visibility = routing_status.get("visibility", {}) or {}
        freshness = routing_status.get("freshness", {}) or {}
    # The live looking-glass observation, when it saw the prefix, is what
    # actually decided routed=True below — report its (realtime) freshness
    # instead of the stale snapshot's, so callers see what backs the verdict.
    looking_glass = result.results.get("looking_glass")
    if isinstance(looking_glass, dict) and looking_glass.get("visible"):
        freshness = looking_glass.get("freshness", freshness) or freshness
    rpki_status = None
    for origin in result.resolved.origins:
        if origin.asn == 215932:
            rpki_status = origin.rpki
            break
    return BGPStatusResponse(
        status="ok" if result.resolved.routed and 215932 in result.resolved.observed_origin_asns and rpki_status == "valid" else "degraded",
        monitored={
            "asn": 215932,
            "prefixes": ["2a0c:b641:b50::/44"],
            "expected_origin_asns": [215932],
            "rpki_max_length": 48,
        },
        routing={
            "prefix_visible": result.resolved.routed,
            "observed_origin_asns": result.resolved.observed_origin_asns,
            "rpki_status": rpki_status or "unknown",
            "visibility": visibility,
            "freshness": freshness,
        },
        sources={name: health.status for name, health in result.sources.items()},
        updated_at=result.generated_at,
    )
