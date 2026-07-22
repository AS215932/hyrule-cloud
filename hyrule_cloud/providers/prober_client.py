"""Prober sidecar client for x402-gated /v1/path/* active measurements.

Hyrule Cloud owns the public API and x402 payment verification. This provider
only talks to the internal `hyrule-prober` service after the route has gated
and (deliver-then-settle) verified the request. The prober executes real
ping/traceroute from AS215932 vantage points and returns per-vantage evidence.

The prober is NOT hyrule-mcp: it exposes only bounded probe/health verbs with a
bearer token, so a compromised path route can never reach ssh_run_command or a
service restart. Keep it internal-bind only.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

log = structlog.get_logger()


class ProbeUnavailableError(Exception):
    """The prober could not deliver a measurement (unreachable, no healthy
    vantage, or a 5xx). The caller must NOT settle payment — never charge for a
    measurement we failed to produce."""


class ProbeRejectedError(Exception):
    """The prober refused the request as unsafe/invalid (its own defense-in-depth
    400). The caller returns 400 and does not settle payment."""


@dataclass(frozen=True)
class VantageOutcome:
    vantage: str
    ok: bool
    duration_ms: int = 0
    error: str | None = None
    ping: dict[str, Any] | None = None
    traceroute: dict[str, Any] | None = None
    dig: dict[str, Any] | None = None
    raw_excerpt: str = ""


@dataclass(frozen=True)
class ProbeOutcome:
    target: str
    kind: str
    family: str
    resolved_addresses: list[str]
    probed_address: str | None
    results: list[VantageOutcome]


class ProberProvider:
    def __init__(
        self,
        prober_url: str = "http://127.0.0.1:8460",
        token: str = "",
        health_ttl_seconds: int = 30,
    ):
        self.prober_url = prober_url.rstrip("/")
        self.token = token
        self.health_ttl_seconds = max(1, health_ttl_seconds)
        self._client = httpx.AsyncClient(
            base_url=self.prober_url,
            timeout=45.0,
            headers=self._headers,
        )
        self._health_cache: dict[str, bool] | None = None
        self._health_expires_at = 0.0

    @property
    def _headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def configured(self) -> bool:
        """Whether a prober is deployed for this instance. An empty token means
        the operator has not provisioned the prober, so path/* stays gated."""
        return bool(self.token)

    async def close(self) -> None:
        await self._client.aclose()

    async def _get_health(self) -> dict[str, bool]:
        now = time.monotonic()
        if self._health_cache is not None and now < self._health_expires_at:
            return self._health_cache
        parsed: dict[str, bool] = {}
        try:
            resp = await self._client.get("/v1/health")
            resp.raise_for_status()
            for name, info in resp.json().get("vantages", {}).items():
                parsed[name] = bool(info.get("ok"))
        except Exception as exc:
            log.warning("prober_health_failed", exc=str(exc), prober_url=self.prober_url)
        self._health_cache = parsed
        self._health_expires_at = now + self.health_ttl_seconds
        return parsed

    async def healthy_vantage_names(self) -> set[str]:
        """Names of vantages the prober currently reports healthy (TTL-cached).

        A probe is only sent to vantages in this set so a request never fails
        with a prober-side 400 for an unknown/down vantage, and so source health
        in the response reflects fresh probe capacity rather than a stale stub.
        """
        return {name for name, ok in (await self._get_health()).items() if ok}

    async def probe(
        self,
        *,
        target: str,
        kind: str,
        family: str,
        count: int,
        vantages: list[str],
        max_hops: int = 20,
        record_type: str = "AAAA",
        timeout_s: int = 10,
    ) -> ProbeOutcome:
        if not self.configured():
            raise ProbeUnavailableError("prober is not configured")
        payload = {
            "target": target,
            "kind": kind,
            "family": family,
            "count": count,
            "max_hops": max_hops,
            "record_type": record_type,
            "vantages": vantages,
            "timeout_s": timeout_s,
        }
        try:
            resp = await self._client.post(
                "/v1/probe", json=payload, timeout=timeout_s + count + 15
            )
        except Exception as exc:
            log.warning("prober_request_failed", exc=str(exc), prober_url=self.prober_url)
            raise ProbeUnavailableError(f"prober unreachable: {exc}") from exc
        if resp.status_code == 400:
            detail = _detail(resp)
            raise ProbeRejectedError(detail)
        if resp.status_code == 429:
            raise ProbeUnavailableError("prober rate limit exceeded")
        if resp.status_code != 200:
            log.warning("prober_bad_status", status_code=resp.status_code)
            raise ProbeUnavailableError(f"prober error: HTTP {resp.status_code}")
        data = resp.json()
        results = [
            VantageOutcome(
                vantage=r.get("vantage", ""),
                ok=bool(r.get("ok")),
                duration_ms=int(r.get("duration_ms") or 0),
                error=r.get("error"),
                ping=r.get("ping"),
                traceroute=r.get("traceroute"),
                dig=r.get("dig"),
                raw_excerpt=r.get("raw_excerpt", ""),
            )
            for r in data.get("results", [])
        ]
        return ProbeOutcome(
            target=data.get("target", target),
            kind=data.get("kind", kind),
            family=data.get("family", family),
            resolved_addresses=list(data.get("resolved_addresses", [])),
            probed_address=data.get("probed_address"),
            results=results,
        )


def _detail(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("detail", "probe rejected"))
    except Exception:
        return "probe rejected"


# Process-wide active prober, set by the app lifespan so the synchronous
# discovery gate (services/path/diagnostics.path_active_probe_enabled) can learn
# whether a prober is configured without a Request or an async call. Unset in
# tests / OpenAPI generation, where prober_configured() falls back to the env.
_ACTIVE_PROBER: ProberProvider | None = None


def set_active_prober(provider: ProberProvider | None) -> None:
    global _ACTIVE_PROBER
    _ACTIVE_PROBER = provider


def active_prober() -> ProberProvider | None:
    return _ACTIVE_PROBER


def prober_configured() -> bool:
    """Fail-closed predicate: is a prober deployed for this instance?

    Prefers the lifespan-wired provider (its token may come from a .env file);
    falls back to the environment so the synchronous manifest gate answers
    correctly before AppState exists (mirrors bgpstream_worker_enabled()).
    """
    provider = _ACTIVE_PROBER
    if provider is not None:
        return provider.configured()
    return bool(os.environ.get("HYRULE_PROBER_TOKEN"))
