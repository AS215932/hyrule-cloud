"""Block D: MCP auth + API-key surface tools.

Wrappers that let an MCP agent drive the full account lifecycle:
  - register_account → POST /v1/auth/register (with_api_key=True by default)
  - whoami           → GET  /v1/me
  - list_my_vms      → GET  /v1/me/vms
  - claim_vm         → POST /v1/me/vms/{vm_id}/claim
  - list_api_keys    → GET  /v1/me/api-keys
  - create_api_key   → POST /v1/me/api-keys
  - revoke_api_key   → DELETE /v1/me/api-keys/{key_id}

Same fixture pattern as test_mcp_payment_tools.py: stub `_client()` with an
async context wrapper. No HTTP, no DB — these are surface tests for the
agent-readable text formatting and error mapping.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from hyrule_cloud.client import HyruleError


@asynccontextmanager
async def _mock_client_cm(stub):
    yield stub


def _patch_client_factory(monkeypatch, stub):
    from hyrule_cloud import mcp_server
    monkeypatch.setattr(mcp_server, "_client", lambda: _mock_client_cm(stub))


# --- register_account ---


@pytest.mark.asyncio
async def test_register_account_with_key_surfaces_cleartext_once(monkeypatch):
    from hyrule_cloud.mcp_server import register_account

    captured: dict = {}

    class _Stub:
        async def register(self, password, *, with_api_key=False, api_key_name=None):
            captured["password"] = password
            captured["with_api_key"] = with_api_key
            captured["api_key_name"] = api_key_name
            return {
                "account_id": "H1234567890",
                "recovery_code": "hyr-rec-abcdefghij",
                "api_key": "hyr_sk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "api_key_id": "key-uuid-1",
                "api_key_scopes": [
                    "account:read", "vm:read", "vm:power", "vm:extend", "vm:logs",
                ],
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await register_account("correct horse battery staple", api_key_name="laptop")

    assert "H1234567890" in out
    assert "hyr-rec-abcdefghij" in out
    assert "hyr_sk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in out
    assert "HYRULE_API_KEY" in out  # bootstrap hint
    # MCP default is with_api_key=True
    assert captured["with_api_key"] is True
    assert captured["api_key_name"] == "laptop"


@pytest.mark.asyncio
async def test_register_account_without_key_explains_browser_path(monkeypatch):
    from hyrule_cloud.mcp_server import register_account

    class _Stub:
        async def register(self, password, *, with_api_key=False, api_key_name=None):
            return {
                "account_id": "H0000000001",
                "recovery_code": "hyr-rec-xxxxxxxxxx",
                "api_key": None,
                "api_key_id": None,
                "api_key_scopes": None,
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await register_account("correct horse battery staple", with_api_key=False)
    assert "H0000000001" in out
    assert "hyr-rec-xxxxxxxxxx" in out
    assert "hyr_sk_" not in out  # no key was issued
    assert "browser session" in out  # tells the agent how to get one


@pytest.mark.asyncio
async def test_register_account_maps_error(monkeypatch):
    from hyrule_cloud.mcp_server import register_account

    class _Stub:
        async def register(self, password, **_):
            raise HyruleError(429, "rate limited; try again in an hour")

    _patch_client_factory(monkeypatch, _Stub())
    out = await register_account("correct horse battery staple")
    assert "rate limited" in out


# --- whoami ---


@pytest.mark.asyncio
async def test_whoami_formats_profile(monkeypatch):
    from hyrule_cloud.mcp_server import whoami

    class _Stub:
        async def me(self):
            return {
                "account_id": "H1234567890",
                "created_at": "2026-05-01T00:00:00+00:00",
                "last_login_at": "2026-05-18T12:00:00+00:00",
                "vm_count": 3,
                "is_admin": False,
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await whoami()
    assert "H1234567890" in out
    assert "VMs: 3" in out
    assert "Admin: False" in out


@pytest.mark.asyncio
async def test_whoami_maps_unauthenticated(monkeypatch):
    from hyrule_cloud.mcp_server import whoami

    class _Stub:
        async def me(self):
            raise HyruleError(401, "Authentication required")

    _patch_client_factory(monkeypatch, _Stub())
    out = await whoami()
    assert "Authentication required" in out


# --- list_my_vms ---


@pytest.mark.asyncio
async def test_list_my_vms_empty(monkeypatch):
    from hyrule_cloud.mcp_server import list_my_vms

    class _Stub:
        async def my_vms(self):
            return {"vms": []}

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_my_vms()
    assert "No VMs" in out


@pytest.mark.asyncio
async def test_list_my_vms_populates_one_line_per_vm(monkeypatch):
    from hyrule_cloud.mcp_server import list_my_vms

    class _Stub:
        async def my_vms(self):
            return {"vms": [
                {"vm_id": "vm_a", "status": "READY", "os": "debian-13",
                 "hostname": "a.deploy", "expires_at": "2026-06-01T00:00:00+00:00"},
                {"vm_id": "vm_b", "status": "DESTROYED", "os": "alpine-3.21",
                 "hostname": None, "expires_at": None},
            ]}

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_my_vms()
    assert "2 VM(s)" in out
    assert "vm_a" in out and "vm_b" in out
    assert "READY" in out and "DESTROYED" in out


# --- claim_vm ---


@pytest.mark.asyncio
async def test_claim_vm_success(monkeypatch):
    from hyrule_cloud.mcp_server import claim_vm

    captured: dict = {}

    class _Stub:
        async def claim_vm_by_token(self, vm_id, token):
            captured["vm_id"] = vm_id
            captured["token"] = token
            return {"vm_id": vm_id, "owner_account_id": "H1234567890"}

    _patch_client_factory(monkeypatch, _Stub())
    out = await claim_vm("vm_aBcDeFgHiJkLmNoPqRsTuV", "hyr_vm_xxxxx")
    assert "vm_aBcDeFgHiJkLmNoPqRsTuV" in out
    assert "H1234567890" in out
    assert captured["token"] == "hyr_vm_xxxxx"


@pytest.mark.asyncio
async def test_claim_vm_wrong_token(monkeypatch):
    from hyrule_cloud.mcp_server import claim_vm

    class _Stub:
        async def claim_vm_by_token(self, vm_id, token):
            raise HyruleError(403, "Invalid management token")

    _patch_client_factory(monkeypatch, _Stub())
    out = await claim_vm("vm_x", "wrong-token")
    assert "Invalid management token" in out


# --- list_api_keys / create_api_key / revoke_api_key ---


@pytest.mark.asyncio
async def test_list_api_keys_empty(monkeypatch):
    from hyrule_cloud.mcp_server import list_api_keys

    class _Stub:
        async def list_api_keys(self):
            return {"keys": []}

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_api_keys()
    assert "No API keys" in out


@pytest.mark.asyncio
async def test_list_api_keys_renders_summary(monkeypatch):
    from hyrule_cloud.mcp_server import list_api_keys

    class _Stub:
        async def list_api_keys(self):
            return {"keys": [
                {"key_id": "k1", "name": "laptop", "scopes": ["vm:read", "account:read"],
                 "created_at": "2026-05-01T00:00:00+00:00",
                 "last_used_at": "2026-05-17T00:00:00+00:00",
                 "expires_at": None},
            ]}

    _patch_client_factory(monkeypatch, _Stub())
    out = await list_api_keys()
    assert "laptop" in out
    assert "k1" in out
    assert "vm:read" in out


@pytest.mark.asyncio
async def test_create_api_key_returns_cleartext_with_warning(monkeypatch):
    from hyrule_cloud.mcp_server import create_api_key

    captured: dict = {}

    class _Stub:
        async def create_api_key(self, *, name, scopes=None, expires_at=None):
            captured["name"] = name
            captured["scopes"] = scopes
            return {
                "key_id": "k-new",
                "key": "hyr_sk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "name": name,
                "scopes": scopes or [],
                "created_at": "2026-05-18T00:00:00+00:00",
                "expires_at": None,
            }

    _patch_client_factory(monkeypatch, _Stub())
    out = await create_api_key("ci-runner", scopes="vm:read,vm:logs")
    assert "hyr_sk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in out
    assert "k-new" in out
    # The cleartext-once warning must be there so an agent doesn't expect retrieval.
    assert "once" in out.lower() or "save" in out.lower()
    # The MCP tool splits the comma-separated scopes string before calling the client.
    assert captured["scopes"] == ["vm:read", "vm:logs"]


@pytest.mark.asyncio
async def test_create_api_key_unknown_scope_error(monkeypatch):
    from hyrule_cloud.mcp_server import create_api_key

    class _Stub:
        async def create_api_key(self, **_):
            raise HyruleError(400, "Unknown scopes: vm:nuke")

    _patch_client_factory(monkeypatch, _Stub())
    out = await create_api_key("typo", scopes="vm:nuke")
    assert "Unknown scopes" in out


@pytest.mark.asyncio
async def test_revoke_api_key_success(monkeypatch):
    from hyrule_cloud.mcp_server import revoke_api_key

    class _Stub:
        async def revoke_api_key(self, key_id):
            return {"status": "ok", "key_id": key_id}

    _patch_client_factory(monkeypatch, _Stub())
    out = await revoke_api_key("k1")
    assert "k1" in out


@pytest.mark.asyncio
async def test_revoke_api_key_404(monkeypatch):
    from hyrule_cloud.mcp_server import revoke_api_key

    class _Stub:
        async def revoke_api_key(self, key_id):
            raise HyruleError(404, "API key not found")

    _patch_client_factory(monkeypatch, _Stub())
    out = await revoke_api_key("k-missing")
    assert "API key not found" in out
