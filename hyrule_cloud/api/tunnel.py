"""Reverse-SSH tunnel API.

A host behind NAT pays per hour (x402) and receives a public TCP port it can be
reached on via `ssh -R`. Hyrule Cloud verifies/settles payment and mints the
lease through the internal hyrule-tunnel-proxy daemon.

Payment model:
  * create  -> verify_only -> provision on daemon -> settle_verified.
    Provisioning before settling means a daemon failure never charges the caller;
    a settle failure revokes the freshly-minted lease so it is never paid-for-free.
  * extend  -> check_payment (settle-first): the lease already exists, so there
    is no delivery risk and settle-first is correct.
"""
from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request, Response

from hyrule_cloud.api._contract import config_from_request, not_implemented, payment_price, quote
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import ReverseTunnelRow
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.models import (
    CapabilityEndpoint,
    PaidEndpointQuote,
    ProductCapabilityResponse,
    TunnelCreateRequest,
    TunnelExtendRequest,
    TunnelPricingResponse,
    TunnelResponse,
)
from hyrule_cloud.providers.tunnel_client import TunnelDaemonError
from hyrule_cloud.services.tunnel.readiness import tunnel_service_ready
from hyrule_cloud.services.tunnel.service import TunnelService, new_tunnel_id

log = structlog.get_logger()

router = APIRouter(prefix="/v1/tunnel", tags=["Reverse SSH Tunnel"])


# In-flight x402 authorizations for create (verify_only defers settlement, so a
# concurrent replay of the same authorization could mint two leases before
# either settles). Mirrors the network-proxy route guard.
_tunnel_inflight_auth: set[str] = set()


@asynccontextmanager
async def _tunnel_authorization_guard(request: Request) -> AsyncIterator[None]:
    key = request.headers.get("payment-signature") or request.headers.get("x-payment")
    if not key:
        yield
        return
    if key in _tunnel_inflight_auth:
        raise HTTPException(409, "payment authorization already in flight")
    _tunnel_inflight_auth.add(key)
    try:
        yield
    finally:
        _tunnel_inflight_auth.discard(key)


def _state(request: Request) -> Any:
    return getattr(request.app.state, "_typed_state", None)


def _gate(request: Request) -> Any:
    state = _state(request)
    return getattr(state, "payment_gate", None)


def _service(request: Request) -> TunnelService | None:
    state = _state(request)
    return getattr(state, "tunnel_service", None)


def _ssh_command(token: str, endpoint_host: str, ssh_port: int) -> str:
    return f"ssh -N -R 0:localhost:22 {token}@{endpoint_host} -p {ssh_port}"


def _to_response(
    row: ReverseTunnelRow,
    *,
    token: str | None = None,
    connected: bool = False,
    visitor_conns: int = 0,
) -> TunnelResponse:
    shown_token = token if token is not None else "<your-token>"
    return TunnelResponse(
        tunnel_id=row.tunnel_id,
        token=token,
        endpoint_host=row.endpoint_host,
        ssh_port=row.ssh_port,
        public_port=row.allocated_port,
        ssh_command=_ssh_command(shown_token, row.endpoint_host, row.ssh_port),
        status=row.status,
        expires_at=row.expires_at,
        connected=connected,
        visitor_conns=visitor_conns,
    )


@router.get("/capabilities", response_model=ProductCapabilityResponse)
async def get_tunnel_capabilities() -> ProductCapabilityResponse:
    return ProductCapabilityResponse(
        service="tunnel",
        purpose=(
            "Make a host behind NAT publicly reachable over a raw TCP port via "
            "reverse SSH (ssh -R). The x402 lease token is the SSH username."
        ),
        separation_of_concerns=(
            "/v1/tunnel provisions per-hour reverse-tunnel leases; the SSH intake "
            "and public data ports are served by the hyrule-tunnel-proxy daemon."
        ),
        free_endpoints=[
            CapabilityEndpoint(path="/v1/tunnel/capabilities", method="GET", description="Tunnel capabilities"),
            CapabilityEndpoint(path="/v1/tunnel/pricing", method="GET", description="Tunnel pricing"),
            CapabilityEndpoint(path="/v1/tunnel/quote", method="POST", description="Quote a tunnel lease"),
            CapabilityEndpoint(path="/v1/tunnel/{tunnel_id}/status", method="GET", description="Live lease status (owner token)"),
            CapabilityEndpoint(path="/v1/tunnel/{tunnel_id}", method="DELETE", description="Tear down a tunnel early (owner token)"),
        ],
        paid_endpoints=[
            CapabilityEndpoint(path="/v1/tunnel/create", method="POST", paid=True, description="Provision a reverse-SSH tunnel"),
            CapabilityEndpoint(path="/v1/tunnel/{tunnel_id}/extend", method="POST", paid=True, description="Extend a tunnel lease"),
        ],
    )


@router.get("/pricing", response_model=TunnelPricingResponse)
async def get_tunnel_pricing(request: Request) -> TunnelPricingResponse:
    cfg = config_from_request(request)
    return TunnelPricingResponse(
        hourly_usd=str(payment_price(request, "price_tunnel_hourly", "0.05")),
        min_hours=cfg.tunnel_min_hours,
        max_hours=cfg.tunnel_max_hours,
    )


@router.post("/quote", response_model=PaidEndpointQuote)
async def quote_tunnel(request: Request, body: TunnelCreateRequest) -> PaidEndpointQuote:
    hourly = payment_price(request, "price_tunnel_hourly", "0.05")
    return quote(hourly, "tunnel_hour", "/v1/tunnel/create", quantity=body.hours)


@router.post("/create", response_model=TunnelResponse)
async def create_tunnel(body: TunnelCreateRequest, request: Request) -> TunnelResponse | Response:
    if not tunnel_service_ready():
        return not_implemented("tunnel", "Reverse-SSH tunnel service is not configured.")
    gate = _gate(request)
    svc = _service(request)
    if gate is None or svc is None:
        return not_implemented("tunnel", "Tunnel service is not wired.")

    cfg = config_from_request(request)
    _require_hours_in_bounds(body.hours, cfg)
    amount = payment_price(request, "price_tunnel_hourly", "0.05") * body.hours
    description = f"Reverse SSH tunnel for {body.hours}h"
    extra_body = {"hours": body.hours}

    async with _tunnel_authorization_guard(request):
        verified = await gate.verify_only(request, amount=amount, description=description, extra_body=extra_body)
        if isinstance(verified, Response):
            return verified

        tunnel_id = new_tunnel_id()
        try:
            row, lease = await svc.provision(
                tunnel_id=tunnel_id,
                hours=body.hours,
                allowlist_cidrs=body.allowlist_cidrs,
                owner_wallet=verified.payer,
                owner_account_id=None,
            )
        except TunnelDaemonError as exc:
            # Not provisioned -> never settle -> no charge.
            if exc.ports_exhausted:
                raise HTTPException(503, "no free tunnel ports available") from exc
            raise HTTPException(502, "tunnel provisioning failed") from exc

        # Delivered a live tunnel: settle. On settle failure the lease is durable
        # and revocable, so revoke it rather than hand out a paid-for-free tunnel.
        if not await gate.settle_verified(request, verified):
            if not await svc.revoke(tunnel_id):
                # The daemon revoke also failed; the lease self-expires at its
                # lease time and the worker sweep retries. Log for visibility.
                log.error("tunnel_settle_failed_revoke_failed", tunnel_id=tunnel_id)
            raise HTTPException(402, "payment settlement failed")

        # Payment is final and the tunnel is live. The payment_tx stamp is
        # bookkeeping — a failure there must NOT hide the one-time token, or the
        # paid tunnel becomes unmanageable, so record best-effort and always
        # return the credential.
        try:
            await svc.mark_settled(tunnel_id, getattr(request.state, "payment_tx", "") or "")
        except Exception:
            log.error("tunnel_mark_settled_failed", tunnel_id=tunnel_id, exc_info=True)
        return _to_response(row, token=lease.token)


@router.post("/{tunnel_id}/extend", response_model=TunnelResponse)
async def extend_tunnel(tunnel_id: str, body: TunnelExtendRequest, request: Request) -> TunnelResponse | Response:
    await _tunnel_for_management(tunnel_id, request)  # owner-token gate
    gate = _gate(request)
    svc = _service(request)
    if gate is None or svc is None:
        return not_implemented("tunnel", "Tunnel service is not wired.")

    cfg = config_from_request(request)
    _require_hours_in_bounds(body.hours, cfg)
    amount = payment_price(request, "price_tunnel_hourly", "0.05") * body.hours

    # Deliver-before-charge: verify the payment, apply the extension on the
    # daemon, then settle. If the daemon is unreachable or the lease is gone,
    # the payment is never settled so the customer is not charged for time they
    # did not receive.
    async with _tunnel_authorization_guard(request):
        verified = await gate.verify_only(
            request,
            amount=amount,
            description=f"Extend tunnel {tunnel_id} by {body.hours}h",
            extra_body={"tunnel_id": tunnel_id, "hours": body.hours},
        )
        if isinstance(verified, Response):
            return verified

        try:
            updated = await svc.extend(tunnel_id, body.hours)
        except TunnelDaemonError as exc:
            raise HTTPException(502, "tunnel extend failed") from exc
        if updated is None:
            raise HTTPException(404, "tunnel not found")

        # Extension delivered: settle now.
        if not await gate.settle_verified(request, verified):
            raise HTTPException(402, "payment settlement failed")
        return _to_response(updated)


@router.delete("/{tunnel_id}")
async def revoke_tunnel(tunnel_id: str, request: Request) -> dict[str, str]:
    """Tear down a tunnel before expiry (free, owner-token gated)."""
    await _tunnel_for_management(tunnel_id, request)  # 404s if svc is None
    svc = _service(request)
    assert svc is not None
    # Strict: only report success once the daemon confirms teardown. The row is
    # retained on daemon failure so the owner can retry the emergency teardown.
    if not await svc.revoke(tunnel_id):
        raise HTTPException(502, "tunnel daemon revoke failed; retry")
    return {"status": "revoked", "tunnel_id": tunnel_id}


@router.get("/{tunnel_id}/status", response_model=TunnelResponse)
async def tunnel_status(tunnel_id: str, request: Request) -> TunnelResponse:
    row = await _tunnel_for_management(tunnel_id, request)
    svc = _service(request)
    connected, visitors = False, 0
    if svc is not None:
        stats = await svc.live_stats(tunnel_id)
        if stats is not None:
            connected, visitors = stats.connected, stats.visitor_conns
    return _to_response(row, connected=connected, visitor_conns=visitors)


async def _tunnel_for_management(tunnel_id: str, request: Request) -> ReverseTunnelRow:
    """Owner gate: the lease token (the SSH username) is the management credential.

    Presented via `X-Tunnel-Token`. A missing/wrong token is indistinguishable
    from a missing tunnel (404) so we never confirm a tunnel exists to a
    non-owner.
    """
    svc = _service(request)
    if svc is None:
        raise HTTPException(404, "tunnel not found")
    row = await svc.get(tunnel_id)
    presented = request.headers.get("x-tunnel-token", "")
    # Only the token hash is stored; compare hashes in constant time.
    if (
        row is None
        or not presented
        or not secrets.compare_digest(hash_anon_token(presented), row.token_hash)
    ):
        raise HTTPException(404, "tunnel not found")
    return row


def _require_hours_in_bounds(hours: int, cfg: HyruleConfig) -> None:
    """Enforce the *configured* lease bounds, not just the schema's outer cap.

    Pricing advertises tunnel_min_hours/tunnel_max_hours from config, so a
    deployment that tightens them must reject out-of-policy requests here.
    """
    if hours < cfg.tunnel_min_hours or hours > cfg.tunnel_max_hours:
        raise HTTPException(
            422,
            f"hours must be between {cfg.tunnel_min_hours} and {cfg.tunnel_max_hours}",
        )
