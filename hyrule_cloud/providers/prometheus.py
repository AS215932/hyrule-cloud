"""Thin async client for the Prometheus HTTP API on the `mon` VM.

Used by `/v1/stats/network` (Block H) to surface live fleet-truth numbers
(BGP peers, IPv6 prefixes, NAT64 sessions) on the public transparency page.
Fail-soft: every query has a short timeout and never raises into the caller —
the endpoint falls back to a static `_source: "fallback"` shape if Prometheus
is unreachable, so the homepage never serves a 500 over a missing scrape.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

log = structlog.get_logger()


class PrometheusClient:
    """Tiny Prometheus HTTP API wrapper. Async, time-bounded, reuses one client."""

    def __init__(self, base_url: str, timeout_seconds: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    def _http(self) -> httpx.AsyncClient:
        # One reused connection pool across the several queries a single
        # /stats/network request issues — cheaper than a client per query.
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def query_scalar(self, promql: str) -> float | None:
        """Run a PromQL query expected to reduce to a single scalar.

        Returns the first vector sample's value, or None on any kind of failure
        (network error, non-200, empty result, unparseable response).
        """
        try:
            resp = await self._http().get(
                f"{self.base_url}/api/v1/query",
                params={"query": promql},
            )
            if resp.status_code != 200:
                log.warning("prometheus_non_200", status=resp.status_code, query=promql)
                return None
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("prometheus_query_failed", error=repr(exc), query=promql)
            return None

        if body.get("status") != "success":
            return None
        data = body.get("data", {})
        result = data.get("result", []) if isinstance(data, dict) else []
        if not result:
            return None
        # Prometheus returns either matrix or vector; we only handle vector
        # (instant queries). vector[i] = {"metric": {...}, "value": [ts, "v"]}
        sample = result[0]
        value_pair = sample.get("value") if isinstance(sample, dict) else None
        if not value_pair or len(value_pair) != 2:
            return None
        try:
            return float(value_pair[1])
        except (TypeError, ValueError):
            return None

    async def query_dict(self, promql: str) -> dict[str, Any] | None:
        """Run a PromQL query and return the raw `data` block, or None.

        Useful when the caller wants the full vector (e.g. per-peer breakdown).
        """
        try:
            resp = await self._http().get(
                f"{self.base_url}/api/v1/query",
                params={"query": promql},
            )
            if resp.status_code != 200:
                return None
            body = resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        if body.get("status") != "success":
            return None
        return body.get("data")

    async def active_alerts(self) -> list[dict[str, Any]] | None:
        """Return Prometheus' active alert objects, or ``None`` on failure.

        The service-status API applies a strict public allow-list to this raw
        response. Keeping the transport helper generic prevents monitoring
        internals from becoming part of the provider contract.
        """
        try:
            resp = await self._http().get(f"{self.base_url}/api/v1/alerts")
            if resp.status_code != 200:
                log.warning("prometheus_alerts_non_200", status=resp.status_code)
                return None
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("prometheus_alerts_failed", error=repr(exc))
            return None

        if body.get("status") != "success":
            return None
        data = body.get("data")
        alerts = data.get("alerts") if isinstance(data, dict) else None
        if not isinstance(alerts, list):
            return None
        return [alert for alert in alerts if isinstance(alert, dict)]
