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
    BGPLookupRequest,
    BGPLookupResponse,
    BGPOriginObservation,
    BGPResolvedSubject,
    BGPStatusResponse,
    BGPSubjectType,
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

    routing, err = await _get_json(f"{_RIPESTAT}/routing-status/data.json", {"resource": prefix})
    if routing is None:
        sources["ripestat_routing_status"] = SourceHealth(status="degraded", message=err)
        partial = True
    else:
        sources["ripestat_routing_status"] = SourceHealth(status="ok")
        routed = bool(routing.get("last_seen") or routing.get("origins"))
        best_prefix = routing.get("last_seen", {}).get("prefix") or prefix
        for origin in routing.get("origins", []) or []:
            try:
                asn = int(origin.get("origin"))
            except Exception:
                continue
            if asn not in observed:
                observed.append(asn)
        results["routing_status"] = routing

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
    req = BGPLookupRequest(
        subject={"type": "prefix", "value": "2a0c:b641:b50::/44"},
        assertions={"expected_origin_asns": [215932], "expected_rpki": "valid"},
    )
    result = await lookup_bgp(req)
    visibility: dict[str, object] = {}
    routing_status = result.results.get("routing_status")
    if isinstance(routing_status, dict):
        visibility = routing_status.get("visibility", {}) or {}
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
        },
        sources={name: health.status for name, health in result.sources.items()},
        updated_at=result.generated_at,
    )
