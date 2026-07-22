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

import hashlib
import json
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
from hyrule_cloud.services.tunnel.service import (
    TunnelIdempotencyConflictError,
    TunnelReconcileError,
    TunnelService,
    new_tunnel_id,
)

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
    # Apply the same configured bounds as create, so a quote is never issued for
    # a duration create would reject.
    _require_hours_in_bounds(body.hours, config_from_request(request))
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

    idem = _idempotency_key(request)

    async with _tunnel_authorization_guard(request):
        # Idempotent replay: a prior attempt with this exact payment authorization
        # already provisioned a tunnel. Recover its one-time token from the daemon
        # (create is idempotent on tunnel_id) so a client that lost the original
        # response can retry without paying again or leaking a port.
        if idem is not None:
            existing = await svc.find_by_idempotency_key(idem)
            if existing is not None:
                return await _replay_create(request, gate, svc, existing, amount, description, extra_body)

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
                idempotency_key=idem,
            )
        except TunnelIdempotencyConflictError:
            # A concurrent replica won the idempotency race; recover the winner.
            existing = await svc.find_by_idempotency_key(idem) if idem else None
            if existing is None:
                raise HTTPException(409, "concurrent create; retry") from None
            return await _replay_create(request, gate, svc, existing, amount, description, extra_body)
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

        # Persist the settlement stamp + replayable header so a retry recovers a
        # settlement-proof response and the sweep never treats this paid lease as
        # provisional.
        await svc.mark_settled(tunnel_id, getattr(request.state, "payment_tx", "") or "", _settlement_header(request))
        return _to_response(row, token=lease.token)


async def _replay_create(
    request: Request,
    gate: Any,
    svc: TunnelService,
    existing: ReverseTunnelRow,
    amount: Any,
    description: str,
    extra_body: dict[str, Any],
) -> TunnelResponse | Response:
    """Return an idempotent-replay response for an existing create attempt."""
    try:
        recovered = await svc.recover_lease(existing.tunnel_id)
    except TunnelDaemonError as exc:
        # Operational failure recovering the credential — retryable, not gone.
        raise HTTPException(503, "tunnel control plane unavailable; retry") from exc
    if recovered is None or not recovered.token:
        raise HTTPException(410, "tunnel no longer available")
    if existing.payment_tx is not None:
        # Already settled (payment_tx may be "" when the facilitator returns no
        # tx string — still settled). Replay the original settlement header so an
        # x402 client sees payment proof; do NOT settle again.
        if existing.settlement_header:
            request.state.payment_response_headers = json.loads(existing.settlement_header)
        return _to_response(existing, token=recovered.token)
    # Provisioned but interrupted before settlement: complete it now.
    verified = await gate.verify_only(request, amount=amount, description=description, extra_body=extra_body)
    if isinstance(verified, Response):
        return verified
    if not await gate.settle_verified(request, verified):
        raise HTTPException(402, "payment settlement failed")
    await svc.mark_settled(existing.tunnel_id, getattr(request.state, "payment_tx", "") or "", _settlement_header(request))
    return _to_response(existing, token=recovered.token)


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

    async with _tunnel_authorization_guard(request):
        # Pre-flight: confirm the daemon still has this lease and is reachable
        # BEFORE charging, so a daemon-down / lease-gone extend never charges for
        # time that can't be delivered.
        try:
            stats = await svc.live_stats(tunnel_id)
        except TunnelDaemonError as exc:
            raise HTTPException(502, "tunnel control plane unavailable; not charged") from exc
        if stats is None:
            raise HTTPException(404, "tunnel not found on daemon; not charged")

        # Settle first so extra time is never delivered before it is paid for.
        result = await gate.check_payment(
            request,
            amount=amount,
            description=f"Extend tunnel {tunnel_id} by {body.hours}h",
            extra_body={"tunnel_id": tunnel_id, "hours": body.hours},
        )
        if isinstance(result, Response):
            return result
        payer = result  # check_payment returns the payer wallet on success

        # Apply the extension. The pre-flight makes a post-settlement failure
        # rare; if it still happens (daemon error, or daemon succeeded but the DB
        # write failed and the sweep would revoke early), record a refund.
        try:
            updated = await svc.extend(tunnel_id, body.hours)
        except (TunnelDaemonError, TunnelReconcileError) as exc:
            raise await _extend_failed_after_payment(request, gate, tunnel_id, amount, payer, 502) from exc
        if updated is None:
            raise await _extend_failed_after_payment(request, gate, tunnel_id, amount, payer, 500)
        return _to_response(updated)


async def _extend_failed_after_payment(
    request: Request, gate: Any, tunnel_id: str, amount: Any, payer: str | None, status: int
) -> HTTPException:
    """Record a refund for a paid extension the daemon couldn't deliver, and
    build an HTTPException whose message reflects whether the refund obligation
    was durably recorded (so we never falsely claim a refund was recorded)."""
    recorded = await _record_extend_refund(request, gate, tunnel_id, amount, payer)
    if recorded:
        return HTTPException(status, "extend failed after payment; a refund has been recorded")
    log.critical("tunnel_extend_refund_not_recorded", tunnel_id=tunnel_id, amount=str(amount), payer=payer)
    return HTTPException(status, "extend failed after payment; a refund is owed and has been logged for manual processing")


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
        # Distinguish "daemon says the lease is gone" (404 -> not connected) from
        # "control plane unavailable" (503), rather than reporting a healthy-
        # looking 200 when the daemon is actually unreachable.
        try:
            stats = await svc.live_stats(tunnel_id)
        except TunnelDaemonError as exc:
            raise HTTPException(503, "tunnel control plane unavailable") from exc
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


def _idempotency_key(request: Request) -> str | None:
    """Derive a stable idempotency key from the x402 payment authorization, so a
    client retry of a settled create recovers the same tunnel rather than paying
    again. Unpaid/dev-bypass probes (no auth header) get no key.
    """
    auth = request.headers.get("payment-signature") or request.headers.get("x-payment")
    if not auth:
        return None
    return hashlib.sha256(auth.encode("utf-8")).hexdigest()


def _settlement_header(request: Request) -> str | None:
    """Serialize the x402 settlement response headers (set by the gate) so they
    can be replayed on an idempotent retry."""
    headers = getattr(request.state, "payment_response_headers", None)
    return json.dumps(headers) if headers else None


async def _record_extend_refund(
    request: Request, gate: Any, tunnel_id: str, amount: Any, payer: str | None
) -> bool:
    """Record a refund obligation when an extension is charged but the daemon
    then fails to apply it. Returns whether the obligation was durably recorded
    (so the caller never falsely claims a refund when the ledger write failed)."""
    from hyrule_cloud.services.refunds import RefundService

    try:
        return await RefundService(getattr(gate, "ledger", None)).record_owed(
            resource_path=f"/v1/tunnel/{tunnel_id}/extend",
            payer=payer,
            amount=amount,
            original_tx=getattr(request.state, "payment_tx", None),
            reason="tunnel_extend_failed_after_settlement",
            network=getattr(request.state, "payment_network", None),
            asset=getattr(request.state, "payment_asset", None),
            extra={"tunnel_id": tunnel_id},
        )
    except Exception:
        log.error("tunnel_extend_refund_record_failed", tunnel_id=tunnel_id, exc_info=True)
        return False
