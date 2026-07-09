"""
Network sidecar provider for agent-driven x402 micro-proxy requests.

Hyrule Cloud owns the public API and x402 payment verification. This provider
only talks to the internal `hyrule-network-proxy` Go sidecar after the route has
validated/charged the request. The sidecar performs final egress policy checks
and executes the request over direct, Tor, I2P, or Yggdrasil.
"""
from __future__ import annotations

import socket
import time
import urllib.parse
from dataclasses import dataclass
from ipaddress import ip_address

import httpx
import structlog

from hyrule_cloud.models import NetworkRequest, NetworkResponse, ProxyMode
from hyrule_cloud.providers.base import Provider

log = structlog.get_logger()

_ALLOWED_METHODS = {"GET", "HEAD", "POST"}
_ALLOWED_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class ModeStatus:
    available: bool
    reason: str | None = None


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
        return ip.is_global and not ip.is_loopback and not ip.is_multicast
    except ValueError:
        return False


class SSRFBlockedError(Exception):
    pass


class NetworkProvider(Provider):
    def __init__(
        self,
        proxy_url: str = "http://127.0.0.1:8450",
        token: str = "",
        health_ttl_seconds: int = 15,
    ):
        self.proxy_url = proxy_url.rstrip("/")
        self.token = token
        self.health_ttl_seconds = max(1, health_ttl_seconds)
        self._client = httpx.AsyncClient(
            base_url=self.proxy_url,
            timeout=65.0,
            headers=self._headers,
        )
        self._modes_cache: dict[ProxyMode, ModeStatus] | None = None
        self._modes_cache_expires_at = 0.0

    @property
    def _headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("/v1/health")
            return resp.status_code == 200 and resp.json().get("status") == "ok"
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()

    async def mode_status(self, mode: ProxyMode) -> ModeStatus:
        modes = await self._get_modes()
        return modes.get(mode, ModeStatus(False, "proxy mode is not advertised by sidecar"))

    async def _get_modes(self) -> dict[ProxyMode, ModeStatus]:
        now = time.monotonic()
        if self._modes_cache is not None and now < self._modes_cache_expires_at:
            return self._modes_cache

        try:
            resp = await self._client.get("/v1/modes")
            resp.raise_for_status()
            raw_modes = resp.json().get("modes", {})
        except Exception as exc:
            log.warning("network_proxy_modes_failed", exc=str(exc), proxy_url=self.proxy_url)
            raw_modes = {}

        parsed: dict[ProxyMode, ModeStatus] = {}
        for raw_mode, info in raw_modes.items():
            try:
                mode = ProxyMode(raw_mode)
            except ValueError:
                continue
            parsed[mode] = ModeStatus(
                available=bool(info.get("available")),
                reason=info.get("reason"),
            )
        self._modes_cache = parsed
        self._modes_cache_expires_at = now + self.health_ttl_seconds
        return parsed

    async def validate_request(self, req: NetworkRequest) -> NetworkResponse | None:
        """Pre-flight validation (method/scheme/URL/SSRF) with NO forwarding, so
        a caller can reject a bad request BEFORE charging for it. Returns the
        rejection NetworkResponse (400/403) or None when the request is allowed.
        """
        return await self._validate_request(req)

    async def execute_request(self, req: NetworkRequest) -> NetworkResponse:
        validation_error = await self._validate_request(req)
        if validation_error is not None:
            return validation_error

        try:
            resp = await self._client.post(
                "/v1/request",
                json=req.model_dump(mode="json"),
                timeout=req.timeout_seconds + 5,
            )
            resp.raise_for_status()
            return NetworkResponse.model_validate(resp.json())
        except httpx.HTTPStatusError as exc:
            log.warning(
                "network_proxy_http_error",
                status_code=exc.response.status_code,
                proxy_url=self.proxy_url,
            )
            return NetworkResponse(
                status_code=502,
                headers={},
                body="",
                elapsed_seconds=0.0,
                proxy_mode=req.proxy_mode,
                error=f"Network proxy error: HTTP {exc.response.status_code}",
            )
        except Exception as exc:
            log.warning("network_proxy_request_failed", exc=str(exc), proxy_url=self.proxy_url)
            return NetworkResponse(
                status_code=502,
                headers={},
                body="",
                elapsed_seconds=0.0,
                proxy_mode=req.proxy_mode,
                error=f"Network proxy error: {exc!s}",
            )

    async def _validate_request(self, req: NetworkRequest) -> NetworkResponse | None:
        method = req.method.upper()
        if method not in _ALLOWED_METHODS:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Unsupported HTTP method")

        parsed_url = urllib.parse.urlparse(req.url)
        if parsed_url.scheme not in _ALLOWED_SCHEMES:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Unsupported URL scheme")
        host = parsed_url.hostname
        if not host:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Invalid URL")

        host = host.lower().rstrip(".")
        is_onion = host.endswith(".onion")
        is_i2p = host.endswith(".i2p")
        if req.proxy_mode == ProxyMode.DIRECT:
            if is_onion:
                return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=".onion URLs require tor proxy_mode")
            if is_i2p:
                return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=".i2p URLs require i2p proxy_mode")
            try:
                await self._resolve_and_check_ssrf(host)
            except SSRFBlockedError as exc:
                return NetworkResponse(status_code=403, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=str(exc))
        elif req.proxy_mode == ProxyMode.TOR:
            if is_i2p:
                return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=".i2p URLs require i2p proxy_mode")
            if not is_onion:
                try:
                    await self._resolve_and_check_ssrf(host)
                except SSRFBlockedError as exc:
                    return NetworkResponse(status_code=403, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=str(exc))
        elif req.proxy_mode == ProxyMode.I2P:
            if not is_i2p:
                return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="i2p proxy_mode requires .i2p URLs")
        elif req.proxy_mode == ProxyMode.YGGDRASIL:
            if is_onion or is_i2p:
                return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="yggdrasil proxy_mode requires Yggdrasil IPv6/host targets")
        return None

    async def _resolve_and_check_ssrf(self, host: str) -> None:
        if host in {"localhost", "localhost.localdomain"}:
            raise SSRFBlockedError(f"Host {host} is disallowed")
        try:
            addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = {info[4][0] for info in addr_info}
        except socket.gaierror:
            return
        for ip in ips:
            if not is_public_ip(ip):
                log.warning("ssrf_blocked", host=host, ip=ip)
                raise SSRFBlockedError(f"Host {host} resolves to disallowed IP {ip}")
