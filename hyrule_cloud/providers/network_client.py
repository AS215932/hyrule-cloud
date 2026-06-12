"""
Network client provider for agent-driven micro-proxy requests.

Provides a unified interface for dispatching HTTP requests via:
- Direct local outbound access
- Tor network (SOCKS5 proxy)
- (Future) Residential proxies

Includes strict SSRF mitigation to prevent autonomous agents from
scanning internal networks or metadata services via the proxy endpoint.
"""
from __future__ import annotations

import socket
import urllib.parse
from ipaddress import ip_address

import httpx
import structlog

from hyrule_cloud.models import NetworkRequest, NetworkResponse, ProxyMode
from hyrule_cloud.providers.base import Provider

log = structlog.get_logger()

_ALLOWED_METHODS = {"GET", "HEAD", "POST"}
_ALLOWED_SCHEMES = {"http", "https"}
_MAX_RESPONSE_BYTES = 65536
_REDACT_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-payment",
}

def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
        return ip.is_global and not ip.is_loopback and not ip.is_multicast
    except ValueError:
        return False

class SSRFBlockedError(Exception):
    pass

class NetworkProvider(Provider):
    def __init__(self, tor_proxy_url: str = "socks5://tor:9050"):
        self.tor_proxy_url = tor_proxy_url
        self._direct_client = httpx.AsyncClient(timeout=30.0)
        self._tor_client = httpx.AsyncClient(proxy=self.tor_proxy_url, timeout=60.0)

    async def health_check(self) -> bool:
        try:
            resp = await self._direct_client.get("https://cloudflare.com/cdn-cgi/trace")
            return resp.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        await self._direct_client.aclose()
        await self._tor_client.aclose()

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

    async def execute_request(self, req: NetworkRequest) -> NetworkResponse:
        method = req.method.upper()
        if method not in _ALLOWED_METHODS:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Unsupported HTTP method")

        parsed_url = urllib.parse.urlparse(req.url)
        if parsed_url.scheme not in _ALLOWED_SCHEMES:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Unsupported URL scheme")
        host = parsed_url.hostname
        if not host:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Invalid URL")

        is_onion = host.endswith(".onion")
        if is_onion and req.proxy_mode != ProxyMode.TOR:
            return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=".onion URLs require tor proxy_mode")

        if req.proxy_mode == ProxyMode.DIRECT:
            if is_onion:
                return NetworkResponse(status_code=400, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=".onion URLs require tor proxy_mode")
            try:
                await self._resolve_and_check_ssrf(host)
            except SSRFBlockedError as e:
                return NetworkResponse(status_code=403, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=str(e))
            client = self._direct_client
        elif req.proxy_mode == ProxyMode.TOR:
            if not is_onion:
                try:
                    await self._resolve_and_check_ssrf(host)
                except SSRFBlockedError as e:
                    return NetworkResponse(status_code=403, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error=str(e))
            client = self._tor_client
        else:
            return NetworkResponse(status_code=501, headers={}, body="", elapsed_seconds=0.0, proxy_mode=req.proxy_mode, error="Residential proxy not configured")

        start_time = httpx._utils.time.perf_counter()
        try:
            resp = await client.request(
                method=method,
                url=req.url,
                headers=req.headers,
                content=req.body.encode("utf-8") if req.body else None,
                follow_redirects=True,
                timeout=req.timeout_seconds
            )
            elapsed = httpx._utils.time.perf_counter() - start_time
            resp_headers = {
                k: v for k, v in resp.headers.items() if k.lower() not in _REDACT_HEADERS
            }
            body_bytes = resp.content[:_MAX_RESPONSE_BYTES]
            body = body_bytes.decode(resp.encoding or "utf-8", errors="replace")
            if len(resp.content) > _MAX_RESPONSE_BYTES:
                resp_headers["x-hyrule-truncated"] = "true"
            return NetworkResponse(status_code=resp.status_code, headers=resp_headers, body=body, elapsed_seconds=elapsed, proxy_mode=req.proxy_mode)
        except httpx.RequestError as exc:
            elapsed = httpx._utils.time.perf_counter() - start_time
            log.warning("network_request_failed", exc=str(exc), url=req.url, proxy_mode=req.proxy_mode)
            return NetworkResponse(status_code=502, headers={}, body="", elapsed_seconds=elapsed, proxy_mode=req.proxy_mode, error=f"Network error: {exc!s}")
