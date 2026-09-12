"""Real provisioning events behind `GET /v1/vm/{vm_id}/logs`.

Before this, `/logs` returned one hardcoded `provisioning_started` entry no
matter what happened, so an agent that passed a `setup_script` had no way to
learn whether its deployment got anywhere. These tests pin the durable event
sequence, the terminal failure event, the sanitization guarantee (nothing about
our infrastructure reaches the customer), and the rule that an observability
write can never fail a paid customer's VM.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import IPv6Network
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import yaml
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, VMEventRow, VMRow
from hyrule_cloud.middleware.anon_token import hash_anon_token
from hyrule_cloud.models import VMEventKey, VMSize, VMStatus
from hyrule_cloud.orchestrator import Orchestrator, VMCapacityError
from hyrule_cloud.providers.network_config import prefix_for_index, vm_address_for_prefix
from hyrule_cloud.providers.xcpng import XOError
from hyrule_cloud.services.guest_result import GuestResult, accept_guest_result
from hyrule_cloud.services.vm_events import (
    FAILURE_CAPACITY,
    FAILURE_DNS,
    FAILURE_INTERNAL,
    FAILURE_TIMEOUT,
    ProvisioningFailedError,
    customer_failure_message,
)

# Internal identifiers that must never reach a customer-visible surface.
TEMPLATE_UUID = "b1946ac9-4f2b-4d1c-9c86-c4c0e1a0aa11"
XO_HOST = "xo.mgmt.servify.network"
XO_VM_UUID = "8f14e45f-ceea-467a-9a1b-6f3a4b6a1d55"
INTERNAL_GATEWAY = "2a0c:b641:b51::1"  # customer_ipv6_gateway — our router, not theirs
TOKEN = "hyr_vm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

SUPERNET = "2a0c:b641:b51::/48"  # HyruleConfig.customer_ipv6_supernet default
CUSTOMER_PREFIX = str(prefix_for_index(IPv6Network(SUPERNET), 5))
CUSTOMER_IPV6 = str(vm_address_for_prefix(IPv6Network(CUSTOMER_PREFIX)))


def _now() -> datetime:
    return datetime.now(UTC)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _vm(
    vm_id: str,
    *,
    os_name: str = "debian-13",
    setup_script: str | None = None,
    prefix_index: int = 5,
) -> VMRow:
    # Each VM owns a distinct customer /64 (the column is uniquely indexed).
    prefix = str(prefix_for_index(IPv6Network(SUPERNET), prefix_index))
    return VMRow(
        vm_id=vm_id,
        owner_wallet="0x" + "ab" * 20,
        anon_management_token_hash=hash_anon_token(TOKEN),
        status=VMStatus.PROVISIONING,
        size=VMSize.XS,
        vcpu=1,
        memory_mb=1024,
        disk_gb=10,
        os=os_name,
        hostname=f"{vm_id}.deploy.hyrule.host",
        ssh_pubkey="ssh-ed25519 AAAA test",
        open_ports=[22, 80, 443],
        setup_script=setup_script,
        ipv6_prefix=prefix,
        ipv6_prefix_index=prefix_index,
        expires_at=_now() + timedelta(days=1),
        cost_total=Decimal("0.05"),
    )


def _real_orchestrator(session_factory, monkeypatch) -> Orchestrator:
    """An Orchestrator on the real provisioning path with faked providers."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    config = HyruleConfig()
    config.xcpng.templates = {"debian-13": TEMPLATE_UUID}
    orch = Orchestrator(config, session_factory)
    orch.xcpng.find_vm_ids_by_name_label = AsyncMock(return_value=[])
    orch.xcpng.get_vm_power_state = AsyncMock(return_value="Running")
    async def create_with_guest_completion(**kwargs):
        config_data = yaml.safe_load(kwargs["cloud_init_config"])
        report = json.loads(next(
            entry["content"] for entry in config_data["write_files"]
            if entry["path"] == "/var/lib/hyrule-guest-result/config.json"
        ))
        vm_id = report["url"].rsplit("/", 3)[1]
        async with session_factory() as session:
            await accept_guest_result(
                session, vm_id, report["url"].rsplit("/", 1)[1], report["token"],
                GuestResult(outcome="succeeded", stage="cloud_init", exit_code=0),
            )
            await session.commit()
        return XO_VM_UUID

    orch.xcpng.create_vm = AsyncMock(side_effect=create_with_guest_completion)
    orch.dns.create_aaaa = AsyncMock(return_value=None)
    orch.dns.verify_aaaa = AsyncMock(return_value=True)
    orch._wait_for_ipv6 = AsyncMock(return_value=CUSTOMER_IPV6)
    orch._probe_ssh = AsyncMock(return_value=True)
    return orch


async def _events(session_factory, vm_id: str) -> list[VMEventRow]:
    async with session_factory() as session:
        result = await session.execute(
            select(VMEventRow)
            .where(VMEventRow.vm_id == vm_id)
            .order_by(VMEventRow.created_at, VMEventRow.event_id)
        )
        return list(result.scalars())


async def _keys(session_factory, vm_id: str) -> list[str]:
    return [event.event for event in await _events(session_factory, vm_id)]


# --- Successful provision ---


@pytest.mark.asyncio
async def test_successful_provision_records_the_full_sequence(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    async with session_factory() as session:
        session.add(_vm("vm_ok"))
        await session.commit()

    await orch._provision_vm("vm_ok")

    assert await _keys(session_factory, "vm_ok") == [
        VMEventKey.PROVISIONING_STARTED,
        VMEventKey.CLOUD_INIT_PREPARED,
        VMEventKey.VM_CREATED,
        VMEventKey.NETWORK_READY,
        VMEventKey.DNS_CREATED,
        VMEventKey.SSH_REACHABLE,
        VMEventKey.READY,
    ]
    events = {e.event: e for e in await _events(session_factory, "vm_ok")}
    # The terminal event carries the delivery facts an agent needs.
    ready = events[VMEventKey.READY]
    assert ready.detail["hostname"] == "vm_ok.deploy.hyrule.host"
    assert ready.detail["ipv6"] == CUSTOMER_IPV6
    assert ready.detail["dns_aaaa_verified"] is True
    assert ready.detail["ssh_reachable"] is True
    # Resources are the customer's own order, not hypervisor placement detail.
    assert events[VMEventKey.VM_CREATED].detail == {
        "vcpu": 1,
        "ram_mb": 1024,
        "disk_gb": 10,
    }


@pytest.mark.asyncio
async def test_events_are_chronological_and_survive_a_new_orchestrator(
    session_factory, monkeypatch
) -> None:
    """Events are durable rows, not in-process state: a fresh Orchestrator (as
    after a restart) reads back the same ordered history."""
    orch = _real_orchestrator(session_factory, monkeypatch)
    async with session_factory() as session:
        session.add(_vm("vm_durable"))
        await session.commit()
    await orch._provision_vm("vm_durable")

    from hyrule_cloud.services.vm_events import list_vm_events

    rows = await list_vm_events(session_factory, "vm_durable")
    assert [r.event for r in rows] == await _keys(session_factory, "vm_durable")
    timestamps = [r.created_at for r in rows]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_ssh_unreachable_is_reported_without_failing_the_vm(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    orch._probe_ssh = AsyncMock(return_value=False)
    async with session_factory() as session:
        session.add(_vm("vm_nossh"))
        await session.commit()

    await orch._provision_vm("vm_nossh")

    keys = await _keys(session_factory, "vm_nossh")
    assert VMEventKey.SSH_UNREACHABLE in keys
    from hyrule_cloud.services.vm_events import list_vm_events

    rows = await list_vm_events(session_factory, "vm_nossh")
    warning = next(row for row in rows if row.event == VMEventKey.SSH_UNREACHABLE)
    assert "Delivery is pending guest initialization verification" in warning.message
    assert "still delivered" not in warning.message
    assert keys[-1] == VMEventKey.READY
    async with session_factory() as session:
        assert (await session.get(VMRow, "vm_nossh")).status == VMStatus.READY


# --- setup_script observability (and its honest limits) ---


@pytest.mark.asyncio
async def test_setup_script_injection_requires_verified_completion(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    async with session_factory() as session:
        session.add(_vm("vm_script", setup_script="#!/bin/sh\napt-get install -y nginx\n"))
        await session.commit()

    await orch._provision_vm("vm_script")

    events = {e.event: e for e in await _events(session_factory, "vm_script")}
    injected = events[VMEventKey.SETUP_SCRIPT_INJECTED]
    # Injection does not claim success; READY follows the separate receipt.
    assert "Completion must be verified" in injected.message
    assert "/var/log/hyrule-setup.log" in injected.message
    # Detailed script output remains inside the guest, not a new public event.
    assert not any("setup_script_completed" in key for key in events)
    # The script body is the customer's, but there is no reason to echo it back.
    assert "nginx" not in json.dumps([e.message for e in await _events(session_factory, "vm_script")])


@pytest.mark.asyncio
async def test_no_setup_script_means_no_setup_script_event(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    async with session_factory() as session:
        session.add(_vm("vm_noscript"))
        await session.commit()

    await orch._provision_vm("vm_noscript")

    assert VMEventKey.SETUP_SCRIPT_INJECTED not in await _keys(session_factory, "vm_noscript")


# --- Failed provision ---


@pytest.mark.asyncio
async def test_failed_provision_ends_in_provisioning_failed_with_safe_message(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    orch.xcpng.create_vm = AsyncMock(
        side_effect=XOError(
            "VM.create",
            {
                "message": "SR_BACKEND_FAILURE_44",
                "template": TEMPLATE_UUID,
                "host": XO_HOST,
                "vm": XO_VM_UUID,
            },
        )
    )
    async with session_factory() as session:
        session.add(_vm("vm_boom"))
        await session.commit()

    await orch._provision_vm("vm_boom")

    keys = await _keys(session_factory, "vm_boom")
    assert keys[-1] == VMEventKey.PROVISIONING_FAILED
    assert VMEventKey.READY not in keys
    failure = (await _events(session_factory, "vm_boom"))[-1]
    assert failure.message == FAILURE_INTERNAL
    async with session_factory() as session:
        row = await session.get(VMRow, "vm_boom")
        assert row.status == VMStatus.FAILED
        # row.error is customer-visible (management view + public launch proof),
        # so it holds the sanitized message, never the provider payload.
        assert row.error == FAILURE_INTERNAL


@pytest.mark.asyncio
async def test_dns_failure_maps_to_the_dns_message(session_factory, monkeypatch) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    orch.xcpng.suspend_vm = AsyncMock()
    # Models recovery after provider stop succeeded but the FAILED commit was
    # lost: an already-halted guest must advance without replaying vm.stop.
    orch.xcpng.get_vm_power_state = AsyncMock(return_value="Halted")
    orch.dns.create_aaaa = AsyncMock(
        side_effect=RuntimeError("DNS update failed: SERVFAIL from ns1.servify.network")
    )
    async with session_factory() as session:
        session.add(_vm("vm_dns"))
        await session.commit()

    await orch._provision_vm("vm_dns")

    events = await _events(session_factory, "vm_dns")
    assert events[-1].event == VMEventKey.PROVISIONING_FAILED
    assert events[-1].message == FAILURE_DNS
    assert "SERVFAIL" not in events[-1].message
    assert "ns1.servify.network" not in events[-1].message
    orch.xcpng.suspend_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_boot_timeout_maps_to_the_timeout_message(session_factory, monkeypatch) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    orch.xcpng.suspend_vm = AsyncMock()
    orch._wait_for_ipv6 = AsyncMock(return_value=None)
    async with session_factory() as session:
        session.add(_vm("vm_slow"))
        await session.commit()

    await orch._provision_vm("vm_slow")

    events = await _events(session_factory, "vm_slow")
    assert events[-1].event == VMEventKey.PROVISIONING_FAILED
    assert events[-1].message == FAILURE_TIMEOUT
    # The internal wait target (the VM's expected address) is not narrated back
    # as raw error text.
    assert "within 120s" not in events[-1].message
    orch.xcpng.suspend_vm.assert_awaited_once_with(XO_VM_UUID)


@pytest.mark.asyncio
async def test_mark_vm_failed_emits_a_terminal_event_and_sanitizes_row_error(
    session_factory, monkeypatch
) -> None:
    """The pre-provisioner failure path (paid create that dies before the
    background task) must also be visible — and must not persist the caller's
    internal reason string on the row."""
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True
    )
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_vm("vm_early"))
        await session.commit()

    await orch.mark_vm_failed(
        "vm_early", f"create failed post-charge: XOError on {XO_HOST}/{XO_VM_UUID}"
    )

    events = await _events(session_factory, "vm_early")
    assert [e.event for e in events] == [VMEventKey.PROVISIONING_FAILED]
    assert events[0].message == FAILURE_INTERNAL
    async with session_factory() as session:
        row = await session.get(VMRow, "vm_early")
        assert row.status == VMStatus.FAILED
        assert XO_HOST not in (row.error or "")
        assert row.error == FAILURE_INTERNAL


# --- Leak audit over the whole customer-visible surface ---


@pytest.mark.asyncio
async def test_no_internal_identifiers_leak_into_customer_visible_output(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    successful_create = orch.xcpng.create_vm
    orch.xcpng.create_vm = AsyncMock(
        side_effect=XOError(
            "VM.create",
            {
                "message": f"clone of {TEMPLATE_UUID} failed on {XO_HOST}",
                "vm": XO_VM_UUID,
                "token": "xo-session-abcdef0123456789",
                "traceback": "Traceback (most recent call last): ...",
            },
        )
    )
    async with session_factory() as session:
        session.add(_vm("vm_leak", setup_script="echo hi"))
        await session.commit()

    await orch._provision_vm("vm_leak")
    # And a successful one, so the audit covers the happy path too.
    orch.xcpng.create_vm = successful_create
    async with session_factory() as session:
        session.add(_vm("vm_leak_ok", setup_script="echo hi", prefix_index=6))
        await session.commit()
    await orch._provision_vm("vm_leak_ok")

    payload = json.dumps(
        [
            {"event": e.event, "message": e.message, "detail": e.detail}
            for vm_id in ("vm_leak", "vm_leak_ok")
            for e in await _events(session_factory, vm_id)
        ]
    )
    for forbidden in (
        TEMPLATE_UUID,
        XO_HOST,
        XO_VM_UUID,
        INTERNAL_GATEWAY,
        "xo-session-abcdef0123456789",
        "Traceback",
        "SR_BACKEND_FAILURE",
        "xcpng",
        "XOError",
    ):
        assert forbidden not in payload, f"leaked {forbidden!r} into customer events"
    # The customer's own address is theirs to see.
    assert CUSTOMER_IPV6 in payload


def test_customer_failure_message_never_echoes_internal_text() -> None:
    internal = f"XOError VM.create {{'host': '{XO_HOST}', 'uuid': '{XO_VM_UUID}'}}"
    assert customer_failure_message(RuntimeError(internal)) == FAILURE_INTERNAL
    # Plain strings (legacy callers) collapse to the generic message too.
    assert customer_failure_message(internal) == FAILURE_INTERNAL
    assert customer_failure_message(None) == FAILURE_INTERNAL
    assert customer_failure_message(TimeoutError("expected 2a0c:... within 120s")) == (
        FAILURE_TIMEOUT
    )
    assert customer_failure_message(VMCapacityError("insufficient vCPU capacity")) == (
        FAILURE_CAPACITY
    )
    assert customer_failure_message(ProvisioningFailedError(FAILURE_DNS)) == FAILURE_DNS


# --- Simulated provisioning ---


@pytest.mark.asyncio
async def test_simulated_provisioning_is_marked_simulated(session_factory) -> None:
    """Default (non-real) provisioning must never look like a real launch."""
    orch = Orchestrator(HyruleConfig(), session_factory)
    async with session_factory() as session:
        session.add(_vm("vm_sim"))
        await session.commit()

    await orch._provision_vm("vm_sim")

    events = await _events(session_factory, "vm_sim")
    assert [e.event for e in events] == [
        VMEventKey.PROVISIONING_STARTED,
        VMEventKey.PROVISIONING_SIMULATED,
        VMEventKey.READY,
    ]
    assert events[1].detail == {"simulated": True}
    assert "SIMULATED" in events[1].message
    assert events[-1].detail["simulated"] is True
    assert "SIMULATED" in events[-1].message


# --- Observability must never break provisioning ---


@pytest.mark.asyncio
async def test_event_write_failure_does_not_break_provisioning(
    session_factory, monkeypatch
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)

    class _ExplodingEventRow:
        def __init__(self, **kwargs: object) -> None:
            raise RuntimeError("vm_events table is gone")

    monkeypatch.setattr("hyrule_cloud.services.vm_events.VMEventRow", _ExplodingEventRow)
    async with session_factory() as session:
        session.add(_vm("vm_noevents"))
        await session.commit()

    await orch._provision_vm("vm_noevents")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_noevents")
        assert row.status == VMStatus.READY
        assert row.ipv6 == CUSTOMER_IPV6
        assert row.error is None
    assert await _keys(session_factory, "vm_noevents") == []


# --- Route: management-gated read-back ---


class _StubNetwork:
    key = "base"
    caip2 = "eip155:8453"
    asset = "USDC"
    chain_id = 8453


class _StubPayment:
    dev_bypass_secret = ""

    def enabled_networks(self):
        return [_StubNetwork()]


class _StubCfg:
    payment = _StubPayment()
    blocked_ports = [25]
    deploy_domain = "deploy.hyrule.host"
    max_paid_active_vms = 0
    vm_grace_period_hours = 1


class _StubOrch:
    """Only what /logs needs: the session factory and get_vm."""

    def __init__(self, session_factory) -> None:
        self.db = session_factory

    async def get_vm(self, vm_id: str) -> VMRow | None:
        async with self.db() as session:
            return await session.get(VMRow, vm_id)

    async def get_quote_for_vm(self, vm_id: str):
        return None


@pytest_asyncio.fixture
async def logs_client(session_factory):
    from hyrule_cloud.state import AppState

    prev = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_StubCfg(),
        orchestrator=_StubOrch(session_factory),
        payment_gate=AsyncMock(),
        network_provider=None,
        session_factory=session_factory,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c
    app.state._typed_state = prev


@pytest.mark.asyncio
async def test_logs_route_returns_persisted_events_with_management_token(
    session_factory, monkeypatch, logs_client
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    async with session_factory() as session:
        session.add(_vm("vm_route", setup_script="echo hi"))
        await session.commit()
    await orch._provision_vm("vm_route")

    res = await logs_client.get(
        "/v1/vm/vm_route/logs", headers={"Authorization": f"Bearer {TOKEN}"}
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["vm_id"] == "vm_route"
    assert body["status"] == VMStatus.READY
    keys = [e["event"] for e in body["events"]]
    assert keys == [
        VMEventKey.PROVISIONING_STARTED,
        VMEventKey.CLOUD_INIT_PREPARED,
        VMEventKey.SETUP_SCRIPT_INJECTED,
        VMEventKey.VM_CREATED,
        VMEventKey.NETWORK_READY,
        VMEventKey.DNS_CREATED,
        VMEventKey.SSH_REACHABLE,
        VMEventKey.READY,
    ]
    assert [e["ts"] for e in body["events"]] == sorted(e["ts"] for e in body["events"])
    assert all(e["message"] for e in body["events"])
    # Nothing about our infrastructure travelled with the response.
    for forbidden in (TEMPLATE_UUID, XO_HOST, XO_VM_UUID, INTERNAL_GATEWAY):
        assert forbidden not in res.text


@pytest.mark.asyncio
async def test_logs_route_requires_the_management_token(session_factory, logs_client) -> None:
    async with session_factory() as session:
        session.add(_vm("vm_gated"))
        await session.commit()

    unauthenticated = await logs_client.get("/v1/vm/vm_gated/logs")
    wrong = await logs_client.get(
        "/v1/vm/vm_gated/logs",
        headers={"Authorization": "Bearer hyr_vm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
    )

    # 404, not 403 — vm_id existence must not leak (Block A0 contract).
    assert unauthenticated.status_code == 404
    assert wrong.status_code == 404


@pytest.mark.asyncio
async def test_logs_route_falls_back_for_vms_with_no_stored_events(
    session_factory, logs_client
) -> None:
    """Back-compat: VMs provisioned before this feature keep the old single
    `provisioning_started` entry instead of returning an empty log."""
    async with session_factory() as session:
        row = _vm("vm_legacy")
        row.created_at = _now()
        session.add(row)
        await session.commit()

    res = await logs_client.get(
        "/v1/vm/vm_legacy/logs", headers={"Authorization": f"Bearer {TOKEN}"}
    )

    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) == 1
    assert events[0]["event"] == VMEventKey.PROVISIONING_STARTED


@pytest.mark.asyncio
async def test_logs_route_surfaces_the_failure_event_and_sanitized_error(
    session_factory, monkeypatch, logs_client
) -> None:
    orch = _real_orchestrator(session_factory, monkeypatch)
    orch.xcpng.create_vm = AsyncMock(
        side_effect=XOError("VM.create", {"host": XO_HOST, "vm": XO_VM_UUID})
    )
    async with session_factory() as session:
        session.add(_vm("vm_route_failed"))
        await session.commit()
    await orch._provision_vm("vm_route_failed")

    res = await logs_client.get(
        "/v1/vm/vm_route_failed/logs", headers={"Authorization": f"Bearer {TOKEN}"}
    )

    assert res.status_code == 200
    body = res.json()
    assert body["status"] == VMStatus.FAILED
    assert body["events"][-1]["event"] == VMEventKey.PROVISIONING_FAILED
    assert body["events"][-1]["message"] == FAILURE_INTERNAL
    assert body["error"] == FAILURE_INTERNAL
    assert XO_HOST not in res.text and XO_VM_UUID not in res.text
