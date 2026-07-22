"""
Reverse-SSH tunnel daemon client.

Hyrule Cloud owns the public API and x402 payment verification. This provider
talks to the internal ``hyrule-tunnel-proxy`` Go daemon (co-located on the
netproxy VM) after the route has verified/charged the request. The daemon owns
the public SSH intake, allocates the token + public port, and enforces leases.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

log = structlog.get_logger()


class TunnelDaemonError(Exception):
    """Raised when the tunnel daemon cannot fulfil a control request."""

    def __init__(self, message: str, *, ports_exhausted: bool = False):
        super().__init__(message)
        self.ports_exhausted = ports_exhausted


@dataclass(frozen=True)
class LeaseResult:
    """A lease as returned by the daemon control API."""

    tunnel_id: str
    token: str | None
    port: int
    endpoint_host: str
    ssh_port: int
    status: str
    expires_at: str
    connected: bool = False
    visitor_conns: int = 0

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> LeaseResult:
        return cls(
            tunnel_id=data["lease_id"],
            token=data.get("token"),
            port=int(data["port"]),
            endpoint_host=data["endpoint_host"],
            ssh_port=int(data.get("ssh_port", 2222)),
            status=data.get("status", "active"),
            expires_at=data["expires_at"],
            connected=bool(data.get("connected", False)),
            visitor_conns=int(data.get("visitor_conns", 0)),
        )


class TunnelProvider:
    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:8452",
        token: str = "",
        health_ttl_seconds: int = 15,
    ):
        self.proxy_url = proxy_url.rstrip("/")
        self.token = token
        self.health_ttl_seconds = max(1, health_ttl_seconds)
        self._client = httpx.AsyncClient(
            base_url=self.proxy_url,
            timeout=15.0,
            headers=self._headers,
        )
        self._health_cache: bool | None = None
        self._health_cache_expires_at = 0.0

    @property
    def _headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    async def close(self) -> None:
        await self._client.aclose()

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("/v1/health")
            return resp.status_code == 200 and resp.json().get("status") == "ok"
        except Exception:
            return False

    async def health_check_cached(self) -> bool:
        """Health check with a short TTL cache, for the readiness gate."""
        now = time.monotonic()
        if self._health_cache is not None and now < self._health_cache_expires_at:
            return self._health_cache
        ok = await self.health_check()
        self._health_cache = ok
        self._health_cache_expires_at = now + self.health_ttl_seconds
        return ok

    async def create_lease(
        self,
        tunnel_id: str,
        duration_seconds: int,
        allowlist_cidrs: list[str] | None,
    ) -> LeaseResult:
        body: dict[str, Any] = {"lease_id": tunnel_id, "duration_seconds": duration_seconds}
        if allowlist_cidrs:
            body["allowlist_cidrs"] = allowlist_cidrs
        try:
            resp = await self._client.post("/v1/leases", json=body)
        except Exception as exc:  # network error to the daemon
            log.warning("tunnel_daemon_unreachable", exc=str(exc), proxy_url=self.proxy_url)
            raise TunnelDaemonError(f"tunnel daemon unreachable: {exc}") from exc
        if resp.status_code == 503:
            raise TunnelDaemonError("no free tunnel ports", ports_exhausted=True)
        if resp.status_code != 200:
            raise TunnelDaemonError(f"daemon create failed: HTTP {resp.status_code}")
        return LeaseResult.from_json(resp.json())

    async def extend_lease(self, tunnel_id: str, duration_seconds: int) -> LeaseResult:
        try:
            resp = await self._client.post(
                f"/v1/leases/{tunnel_id}/extend",
                json={"duration_seconds": duration_seconds},
            )
        except Exception as exc:
            raise TunnelDaemonError(f"tunnel daemon unreachable: {exc}") from exc
        if resp.status_code == 404:
            raise TunnelDaemonError("lease not found")
        if resp.status_code != 200:
            raise TunnelDaemonError(f"daemon extend failed: HTTP {resp.status_code}")
        return LeaseResult.from_json(resp.json())

    async def revoke_lease(self, tunnel_id: str) -> bool:
        """Delete a lease on the daemon. Returns True on success or if absent."""
        try:
            resp = await self._client.delete(f"/v1/leases/{tunnel_id}")
        except Exception as exc:
            log.warning("tunnel_revoke_failed", tunnel_id=tunnel_id, exc=str(exc))
            return False
        return resp.status_code in (204, 404)

    async def get_lease(self, tunnel_id: str) -> LeaseResult | None:
        try:
            resp = await self._client.get(f"/v1/leases/{tunnel_id}")
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        return LeaseResult.from_json(resp.json())

    async def list_leases(self) -> list[LeaseResult]:
        try:
            resp = await self._client.get("/v1/leases")
            resp.raise_for_status()
        except Exception as exc:
            log.warning("tunnel_list_failed", exc=str(exc))
            return []
        return [LeaseResult.from_json(item) for item in resp.json().get("leases", [])]
