"""Block H: MCP payment surface tools.

Three pure-wrapper tools that let an AI agent drive the full crypto payment
flow without touching the HTTP API directly:
  - list_payment_networks → GET /v1/payments/networks
  - create_crypto_intent  → POST /v1/intent/create
  - get_intent_status     → GET /v1/intent/{id}

These tools must:
  1. Format their output as agent-readable text (not raw JSON dumps).
  2. Surface the management_token from a PROVISIONED intent exactly once.
  3. Map HyruleError → a single-line error string (not re-raise).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from hyrule_cloud.client import HyruleError


@asynccontextmanager
async def _mock_client_cm(stub):
    """Async-context wrapper around a stub object so the `async with _client()`
    pattern in mcp_server.py works without spinning up real HTTP."""
    yield stub


def _patch_client_factory(monkeypatch, stub):
    from hyrule_cloud import mcp_server
    monkeypatch.setattr(mcp_server, "_client", lambda: _mock_client_cm(stub))


# --- list_payment_networks ---


@pytest.mark.asyncio
async def test_list_payment_networks_lists_evm_and_svm(monkeypatch):
    from hyrule_cloud.mcp_server import list_payment_networks

    class _Stub:
        async def payment_networks(self):
            return {
                "networks": [
                    {
                        "key": "base", "display_name": "Base", "family": "evm",
                        "caip2": "eip155:8453",
                        "token_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                        "token_decimals": 6,
                    },
                    {
                        "key": "solana", "display_name": "Solana", "family": "svm",
                        "caip2": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                        "token_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                        "token_decimals": 6,
                    },
                ],
                "receiver_address": "0xabc",
                "facilitator_url": "https://x402.org/facilitator",
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_payment_networks()

    # Surface both families with their CAIP-2 + family tag so the agent can
    # branch by family without guessing.
    assert "(evm)" in out and "(svm)" in out
    assert "eip155:8453" in out
    assert "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" in out
    assert "0xabc" in out  # receiver shown


@pytest.mark.asyncio
async def test_list_payment_networks_handles_error(monkeypatch):
    from hyrule_cloud.mcp_server import list_payment_networks

    class _Stub:
        async def payment_networks(self):
            raise HyruleError(503, "facilitator unreachable")

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_payment_networks()
    # _err() formatter must produce a single-line digestible message
    assert "facilitator unreachable" in out


@pytest.mark.asyncio
async def test_list_payment_networks_empty(monkeypatch):
    from hyrule_cloud.mcp_server import list_payment_networks

    class _Stub:
        async def payment_networks(self):
            return {"networks": []}

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_payment_networks()
    assert "No payment networks" in out


# --- create_crypto_intent ---


@pytest.mark.asyncio
async def test_create_crypto_intent_returns_address_amount_qr(monkeypatch):
    from hyrule_cloud.mcp_server import create_crypto_intent

    captured: dict = {}

    class _Stub:
        async def create_crypto_intent(self, **kwargs):
            captured.update(kwargs)
            return {
                "intent_id": "ci_abc123",
                "asset": "BTC",
                "status": "WAITING_PAYMENT",
                "amount_crypto": "0.00012345",
                "amount_usd": "5.00",
                "address": "bc1qexample",
                "rate_valid_until": "2026-05-17T12:50:00+00:00",
                "qr_code_uri": "bitcoin:bc1qexample?amount=0.00012345",
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await create_crypto_intent(
        asset="BTC",
        amount_usd="5.00",
        order_payload={"size": "xs", "duration_days": 7, "ssh_pubkey": "ssh-ed25519 AAA"},
        client_order_id="my-idem-key",
    )

    # Idempotency key reaches the client
    assert captured["client_order_id"] == "my-idem-key"
    assert captured["asset"] == "BTC"

    # Output surfaces the must-have fields
    assert "ci_abc123" in out
    assert "0.00012345 BTC" in out
    assert "bc1qexample" in out
    assert "bitcoin:bc1qexample" in out
    assert "Rate valid until" in out


@pytest.mark.asyncio
async def test_create_crypto_intent_idempotency_key_optional(monkeypatch):
    from hyrule_cloud.mcp_server import create_crypto_intent

    captured: dict = {}

    class _Stub:
        async def create_crypto_intent(self, **kwargs):
            captured.update(kwargs)
            return {
                "intent_id": "ci_xyz",
                "asset": "XMR",
                "status": "CREATED",
                "amount_crypto": "0.025",
                "address": "44Examp...",
            }

    _patch_client_factory(monkeypatch, _Stub())
    await create_crypto_intent(
        asset="XMR", amount_usd="5.00", order_payload={"size": "xs"}
    )
    # When None, idempotency key is omitted from the request body (so the
    # backend treats every call as fresh).
    assert captured["client_order_id"] is None


# --- get_intent_status ---


@pytest.mark.asyncio
async def test_get_intent_status_surfaces_vm_id_and_management_token(monkeypatch):
    """The PROVISIONED branch must expose the management_token so the agent
    can persist it — same one-time-reveal contract as the HTTP flow."""
    from hyrule_cloud.mcp_server import get_intent_status

    class _Stub:
        async def get_crypto_intent(self, intent_id):
            assert intent_id == "ci_abc123"
            return {
                "intent_id": "ci_abc123",
                "status": "PROVISIONED",
                "confirmations": 3,
                "amount_received_crypto": "0.00012345",
                "asset": "BTC",
                "vm_id": "vm_AbcDefGhi",
                "management_token": "hyr_vm_xyzxyzxyzxyzxyz",
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await get_intent_status("ci_abc123")

    assert "PROVISIONED" in out
    assert "vm_AbcDefGhi" in out
    assert "hyr_vm_xyzxyzxyzxyzxyz" in out
    assert "save once" in out.lower()


@pytest.mark.asyncio
async def test_get_intent_status_pending_omits_vm_fields(monkeypatch):
    from hyrule_cloud.mcp_server import get_intent_status

    class _Stub:
        async def get_crypto_intent(self, intent_id):
            return {
                "intent_id": intent_id,
                "status": "WAITING_PAYMENT",
                "confirmations": 0,
                "asset": "BTC",
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await get_intent_status("ci_pending")
    assert "WAITING_PAYMENT" in out
    assert "Confirmations: 0" in out
    # No leak of fields not present in the response
    assert "vm_" not in out
    assert "management" not in out.lower()


@pytest.mark.asyncio
async def test_get_intent_status_handles_404(monkeypatch):
    from hyrule_cloud.mcp_server import get_intent_status

    class _Stub:
        async def get_crypto_intent(self, intent_id):
            raise HyruleError(404, "intent not found")

    _patch_client_factory(monkeypatch, _Stub())
    out = await get_intent_status("ci_missing")
    assert "intent not found" in out


@pytest.mark.asyncio
async def test_diagnostic_tools_always_registered_for_remote_client():
    """The MCP server is a thin REMOTE client (documented mode:
    HYRULE_API_URL=https://cloud.hyrule.host), so it can't know the hosted API's
    source state locally — it must NOT gate tool registration on its own
    package's stub predicates, or a diagnostic that is live on the API would be
    unreachable. All diagnostic tools stay registered; the API's response (incl.
    a 501) is the source of truth."""
    from hyrule_cloud import mcp_server

    names = {t.name for t in await mcp_server.mcp.list_tools()}
    for tool in ("path_report", "threat_reputation_lookup", "voip_number_lookup", "voip_sip_check"):
        assert tool in names
    assert "ip_sources" in names
    assert "network_probe_manifest" in names
    assert "network_environment_check" in names
    assert "network_check_report" in names
    # Licensed resale has a stricter dark-launch requirement than the legacy
    # diagnostic stubs: the paid tool is absent unless the deployment sets the
    # explicit MCP switch after the API entitlement is live.
    assert "ip_quality" not in names


def test_err_surfaces_clear_not_live_message_for_501():
    """A gated diagnostic 501s before charging. _err must turn that into an
    honest, non-charging 'not available yet' message rather than a raw error, so
    the agent knows nothing was paid and the endpoint simply isn't live yet."""
    from hyrule_cloud.client import HyruleError
    from hyrule_cloud.mcp_server import _err

    msg = _err(HyruleError(501, "path.report source_not_configured"))
    assert "isn't available yet" in msg
    assert "No payment was taken" in msg
