from __future__ import annotations

from decimal import Decimal
from ipaddress import IPv6Network

import pytest
import pytest_asyncio
import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import Base, VMRow
from hyrule_cloud.models import VMSize, VMStatus
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.network_config import (
    prefix_for_index,
    render_debian_network_config,
    supports_static_network_config,
    validate_customer_network_settings,
    vm_address_for_prefix,
)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


def test_customer_prefix_index_maps_to_expected_64_and_address():
    supernet = IPv6Network("2a0c:b641:b51::/48")
    prefix = prefix_for_index(supernet, 1)

    assert str(prefix) == "2a0c:b641:b51:1::/64"
    assert str(vm_address_for_prefix(prefix)) == "2a0c:b641:b51:1::2"


def test_debian_network_config_uses_on_link_gateway():
    rendered = render_debian_network_config(
        address="2a0c:b641:b51:1::2",
        prefix="2a0c:b641:b51:1::/64",
        gateway="2a0c:b641:b51::1",
        dns_servers=["2a0c:b641:b51::1"],
        customer_supernet=IPv6Network("2a0c:b641:b51::/48"),
    )

    body = yaml.safe_load(rendered)
    iface = body["ethernets"]["enX0"]
    assert iface["addresses"] == ["2a0c:b641:b51:1::2/64"]
    assert iface["nameservers"]["addresses"] == ["2a0c:b641:b51::1"]
    assert iface["routes"] == [{"to": "::/0", "via": "2a0c:b641:b51::1", "on-link": True}]


def test_debian_network_config_rejects_non_64_prefix():
    with pytest.raises(ValueError, match="/64"):
        render_debian_network_config(
            address="2a0c:b641:b51:1::2",
            prefix="2a0c:b641:b51::/48",
            gateway="2a0c:b641:b51::1",
            dns_servers=["2a0c:b641:b51::1"],
        )


def test_debian_network_config_rejects_address_outside_prefix():
    with pytest.raises(ValueError, match="not inside"):
        render_debian_network_config(
            address="2a0c:b641:b51:2::2",
            prefix="2a0c:b641:b51:1::/64",
            gateway="2a0c:b641:b51::1",
            dns_servers=["2a0c:b641:b51::1"],
        )


def test_debian_network_config_rejects_gateway_outside_customer_supernet():
    with pytest.raises(ValueError, match="gateway"):
        render_debian_network_config(
            address="2a0c:b641:b51:1::2",
            prefix="2a0c:b641:b51:1::/64",
            gateway="2001:db8::1",
            dns_servers=["2a0c:b641:b51::1"],
            customer_supernet=IPv6Network("2a0c:b641:b51::/48"),
        )


def test_static_network_config_support_is_debian_first():
    assert supports_static_network_config("debian-13")
    assert not supports_static_network_config("openbsd-7.8")


@pytest.mark.asyncio
async def test_allocator_skips_existing_reserved_prefix(session_factory, monkeypatch):
    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    monkeypatch.setattr("hyrule_cloud.orchestrator.prefix_index_candidate", lambda *_: 1)

    async with session_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_existing",
                owner_wallet="wallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ipv6_prefix_index=1,
                ipv6_prefix="2a0c:b641:b51:1::/64",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()

        prefix_index, prefix = await orch._allocate_customer_prefix(session, "vm_new")

    assert prefix_index == 2
    assert str(prefix) == "2a0c:b641:b51:2::/64"


@pytest.mark.asyncio
async def test_wait_for_ipv6_requires_expected_address(session_factory):
    class StubXCPNG:
        def __init__(self) -> None:
            self.calls = 0

        async def get_vm_ipv6(self, vm_uuid: str) -> str | None:
            self.calls += 1
            return "2a0c:b641:b51:1::2"

    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    orch.xcpng = StubXCPNG()

    assert (
        await orch._wait_for_ipv6(
            "vm-uuid",
            timeout=1,
            expected_ipv6="2a0c:b641:b51:1::2",
        )
        == "2a0c:b641:b51:1::2"
    )


@pytest.mark.asyncio
async def test_restarted_provisioner_replaces_untracked_exact_label_clone(
    session_factory, monkeypatch
):
    """A crash after XO cloned but before its UUID commit cannot duplicate a VM."""
    monkeypatch.setattr("hyrule_cloud.services.launch_proof.use_real_provisioning", lambda: True)

    class StubXCPNG:
        def __init__(self) -> None:
            self.destroyed: list[str] = []
            self.created: list[dict] = []

        async def find_vm_ids_by_name_label(self, name_label: str) -> list[str]:
            assert name_label == "hyrule-vm_recover_clone"
            return ["orphan-clone"]

        async def destroy_vm(self, uuid: str) -> None:
            self.destroyed.append(uuid)

        async def create_vm(self, **kwargs) -> str:
            self.created.append(kwargs)
            return "fresh-clone"

        async def get_vm_ipv6(self, vm_uuid: str) -> str | None:
            assert vm_uuid == "fresh-clone"
            return "2a0c:b641:b51:9::2"

    class StubDNS:
        def __init__(self) -> None:
            self.created: list[tuple[str, str]] = []

        async def create_aaaa(self, subdomain: str, ipv6: str) -> None:
            self.created.append((subdomain, ipv6))

        async def verify_aaaa(self, subdomain: str, ipv6: str) -> bool:
            return True

    cfg = HyruleConfig()
    cfg.xcpng.templates["debian-13"] = "template"
    orch = Orchestrator(cfg, session_factory)
    xcpng = StubXCPNG()
    dns = StubDNS()
    orch.xcpng = xcpng
    orch.dns = dns

    async def probe_ssh(ipv6: str) -> bool:
        return True

    monkeypatch.setattr(orch, "_probe_ssh", probe_ssh)
    async with session_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_recover_clone",
                owner_wallet="0x" + "1" * 40,
                status=VMStatus.PROVISIONING,
                size=VMSize.XS,
                os="debian-13",
                ipv6_prefix_index=9,
                ipv6_prefix="2a0c:b641:b51:9::/64",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()

    await orch._provision_vm("vm_recover_clone")

    async with session_factory() as session:
        recovered = await session.get(VMRow, "vm_recover_clone")
    assert xcpng.destroyed == ["orphan-clone"]
    assert len(xcpng.created) == 1
    assert recovered.xcpng_uuid == "fresh-clone"
    assert recovered.status == VMStatus.READY
    assert recovered.ipv6 == "2a0c:b641:b51:9::2"


def test_debian_network_config_allows_off_supernet_dns():
    """Public/DNS64 resolvers outside the customer allocation are a normal
    production configuration — only the gateway must be on-link."""
    rendered = render_debian_network_config(
        address="2a0c:b641:b51:1::2",
        prefix="2a0c:b641:b51:1::/64",
        gateway="2a0c:b641:b51::1",
        dns_servers=["2001:4860:4860::8888"],
        customer_supernet=IPv6Network("2a0c:b641:b51::/48"),
    )
    body = yaml.safe_load(rendered)
    assert body["ethernets"]["enX0"]["nameservers"]["addresses"] == ["2001:4860:4860::8888"]


def test_validate_customer_network_settings_accepts_defaults():
    cfg = HyruleConfig()
    validate_customer_network_settings(
        supernet=cfg.customer_ipv6_supernet,
        gateway=cfg.customer_ipv6_gateway,
        dns=cfg.customer_ipv6_dns,
    )


def test_validate_customer_network_settings_accepts_off_net_dns():
    validate_customer_network_settings(
        supernet="2a0c:b641:b51::/48",
        gateway="2a0c:b641:b51::1",
        dns="2001:4860:4860::8888,2a0c:b641:b51::1",
    )


def test_validate_customer_network_settings_rejects_single_64_pool():
    with pytest.raises(ValueError, match="no usable"):
        validate_customer_network_settings(
            supernet="2a0c:b641:b51::/64",
            gateway="2a0c:b641:b51::1",
            dns="2a0c:b641:b51::1",
        )


def test_validate_customer_network_settings_rejects_off_net_gateway():
    with pytest.raises(ValueError, match="gateway"):
        validate_customer_network_settings(
            supernet="2a0c:b641:b51::/48",
            gateway="2001:db8::1",
            dns="2a0c:b641:b51::1",
        )


def test_validate_customer_network_settings_rejects_malformed_dns():
    with pytest.raises(ValueError):
        validate_customer_network_settings(
            supernet="2a0c:b641:b51::/48",
            gateway="2a0c:b641:b51::1",
            dns="not-an-ip",
        )


@pytest.mark.asyncio
async def test_destroy_releases_customer_prefix(session_factory):
    """Destroyed rows must free their /64 (unique index would otherwise pin
    it forever) so churn cannot exhaust the customer pool."""

    class StubXCPNG:
        async def destroy_vm(self, uuid: str) -> None:
            pass

    class StubDNS:
        async def delete_aaaa(self, subdomain: str) -> None:
            pass

    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    orch.xcpng = StubXCPNG()
    orch.dns = StubDNS()

    async with session_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_release",
                owner_wallet="wallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ipv6_prefix_index=7,
                ipv6_prefix="2a0c:b641:b51:7::/64",
                hostname="rel.deploy.hyrule.host",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()

    assert await orch.destroy_vm("vm_release") is True

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_release")
        assert row.status == VMStatus.DESTROYED
        assert row.ipv6_prefix_index is None
        assert row.ipv6_prefix is None

        # The freed index is allocatable again.
        session.add(
            VMRow(
                vm_id="vm_next",
                owner_wallet="wallet",
                status=VMStatus.PROVISIONING,
                size=VMSize.XS,
                os="debian-13",
                ipv6_prefix_index=7,
                ipv6_prefix="2a0c:b641:b51:7::/64",
                ssh_pubkey="ssh-ed25519 AAAA test",
                open_ports=[22],
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()


def test_vm_order_validation_rejects_unsupported_os_in_real_mode(monkeypatch):
    """Both payment entry points (x402 create and BTC/XMR intent create) run
    this validator, so an unsupported OS is rejected before any charge."""
    from fastapi import HTTPException

    from hyrule_cloud.api import routes
    from hyrule_cloud.models import VMCreateRequest

    monkeypatch.setattr(routes, "_real_provisioning_enabled", lambda: True)
    order = VMCreateRequest(
        duration_days=1,
        os="openbsd-7.8",
        ssh_pubkey="ssh-ed25519 AAAA test",
    )

    class _Cfg:
        blocked_ports = [25]

    with pytest.raises(HTTPException) as exc:
        routes._validate_vm_order(order, _Cfg())
    assert exc.value.status_code == 400
    assert "not supported" in exc.value.detail


@pytest.mark.asyncio
async def test_create_vm_refuses_unsupported_os_before_persisting(session_factory, monkeypatch):
    """Defense in depth: even a pre-validation settled intent cannot create a
    paid VM row for an OS real provisioning cannot deliver."""
    from sqlalchemy import func, select

    from hyrule_cloud.models import VMCreateRequest
    from hyrule_cloud.services import launch_proof

    monkeypatch.setattr(launch_proof, "_LAUNCH_PROOF_REAL", True)
    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)

    with pytest.raises(ValueError, match=r"OS template|Unknown OS"):
        await orch.create_vm(
            VMCreateRequest(duration_days=1, os="openbsd-7.8", ssh_pubkey="ssh-ed25519 AAAA t"),
            owner_wallet="0xWALLET",
        )

    async with session_factory() as session:
        count = (await session.execute(select(func.count()).select_from(VMRow))).scalar_one()
    assert count == 0


def test_validate_customer_network_settings_rejects_oversized_supernet():
    """Indexes persist in a 32-bit column; supernets shorter than /33 overflow."""
    with pytest.raises(ValueError, match="32-bit"):
        validate_customer_network_settings(
            supernet="2a00::/32",
            gateway="2a00::1",
            dns="2a00::1",
        )


def test_vm_order_validation_requires_configured_template(monkeypatch):
    """Real mode: an OS with static-config support but no template UUID must be
    rejected before payment, not inside create_vm after the charge."""
    from fastapi import HTTPException

    from hyrule_cloud.api import routes
    from hyrule_cloud.models import VMCreateRequest

    monkeypatch.setattr(routes, "_real_provisioning_enabled", lambda: True)

    class _XCPNG:
        templates = {"debian-13": ""}  # name known, UUID unconfigured

    class _Cfg:
        blocked_ports = [25]
        xcpng = _XCPNG()

    order = VMCreateRequest(duration_days=1, os="debian-13", ssh_pubkey="ssh-ed25519 AAAA t")
    with pytest.raises(HTTPException) as exc:
        routes._validate_vm_order(order, _Cfg())
    assert exc.value.status_code == 400
    assert "not available" in exc.value.detail


@pytest.mark.asyncio
async def test_prefix_capacity_enforced_before_payment(session_factory):
    """A full /64 pool must refuse new orders with 503 BEFORE the payment gate
    runs — allocation happens post-charge in create_vm."""
    from fastapi import HTTPException

    from hyrule_cloud.api.routes import _enforce_prefix_capacity

    class _Cfg:
        customer_ipv6_supernet = "2a0c:b641:b51::/63"  # usable = 1 (index 0 reserved)

    class _Orch:
        def __init__(self, db):
            self.db = db

    orch = _Orch(session_factory)
    await _enforce_prefix_capacity(orch, _Cfg())  # empty pool: fine

    async with session_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_full",
                owner_wallet="wallet",
                status=VMStatus.READY,
                size=VMSize.XS,
                os="debian-13",
                ipv6_prefix_index=1,
                ipv6_prefix="2a0c:b641:b51:1::/64",
                ssh_pubkey="ssh-ed25519 AAAA t",
                open_ports=[22],
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()

    with pytest.raises(HTTPException) as exc:
        await _enforce_prefix_capacity(orch, _Cfg())
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_simulated_ipv6_stays_inside_assigned_prefix(session_factory):
    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)

    async with session_factory() as session:
        session.add(
            VMRow(
                vm_id="vm_sim",
                owner_wallet="wallet",
                status=VMStatus.PROVISIONING,
                size=VMSize.XS,
                os="debian-13",
                ipv6_prefix_index=3,
                ipv6_prefix="2a0c:b641:b51:3::/64",
                ssh_pubkey="ssh-ed25519 AAAA t",
                open_ports=[22],
                cost_total=Decimal("0.05"),
            )
        )
        await session.commit()

    await orch._simulate_provisioning("vm_sim")

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_sim")
        assert row.ipv6 == "2a0c:b641:b51:3::2"
        assert row.status == VMStatus.READY


class _StubXCPNGDestroy:
    async def destroy_vm(self, uuid: str) -> None:
        pass


class _StubDNSDelete:
    async def delete_aaaa(self, subdomain: str) -> None:
        pass


class _FailingDomains:
    async def detach_vm(self, account_id: str, domain: str, vm_id: str) -> None:
        raise RuntimeError("managed DNS control down")


class _OkDomains:
    def __init__(self) -> None:
        self.detached: list[tuple[str, str, str]] = []

    async def detach_vm(self, account_id: str, domain: str, vm_id: str) -> None:
        self.detached.append((account_id, domain, vm_id))


def _vm_row(vm_id: str, *, prefix_index: int, **overrides) -> VMRow:
    from hyrule_cloud.models import DomainMode

    defaults = dict(
        vm_id=vm_id,
        owner_wallet="wallet",
        status=VMStatus.READY,
        size=VMSize.XS,
        os="debian-13",
        ipv6_prefix_index=prefix_index,
        ipv6_prefix=f"2a0c:b641:b51:{prefix_index:x}::/64",
        hostname=f"{vm_id}.deploy.hyrule.host",
        ssh_pubkey="ssh-ed25519 AAAA t",
        open_ports=[22],
        cost_total=Decimal("0.05"),
        domain_mode=DomainMode.AUTO,
        xcpng_uuid="xcp-uuid",
    )
    defaults.update(overrides)
    return VMRow(**defaults)


@pytest.mark.asyncio
async def test_destroy_quarantines_prefix_when_custom_dns_cleanup_fails(session_factory):
    from hyrule_cloud.models import DomainMode

    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    orch.xcpng = _StubXCPNGDestroy()
    orch.dns = _StubDNSDelete()
    orch.domains = _FailingDomains()

    async with session_factory() as session:
        session.add(
            _vm_row(
                "vm_cd",
                prefix_index=9,
                domain_mode=DomainMode.CUSTOM,
                domain="cust.dev",
                owner_account_id="H1234567890",
            )
        )
        await session.commit()

    assert await orch.destroy_vm("vm_cd") is True

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_cd")
        assert row.status == VMStatus.DESTROYED
        # Custom AAAA may still resolve to ::2 — the /64 stays quarantined.
        assert row.ipv6_prefix_index == 9


@pytest.mark.asyncio
async def test_destroy_releases_prefix_after_custom_dns_cleanup(session_factory):
    from hyrule_cloud.models import DomainMode

    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    orch.xcpng = _StubXCPNGDestroy()
    orch.dns = _StubDNSDelete()
    domains = _OkDomains()
    orch.domains = domains

    async with session_factory() as session:
        session.add(
            _vm_row(
                "vm_cd2",
                prefix_index=10,
                domain_mode=DomainMode.CUSTOM,
                domain="cust2.dev",
                owner_account_id="H1234567890",
            )
        )
        await session.commit()

    assert await orch.destroy_vm("vm_cd2") is True
    assert domains.detached == [("H1234567890", "cust2.dev", "vm_cd2")]

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_cd2")
        assert row.ipv6_prefix_index is None


@pytest.mark.asyncio
async def test_destroy_quarantines_prefix_for_uuidless_provisioning_row(session_factory):
    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    orch.xcpng = _StubXCPNGDestroy()
    orch.dns = _StubDNSDelete()

    async with session_factory() as session:
        session.add(
            _vm_row("vm_race", prefix_index=11, status=VMStatus.PROVISIONING, xcpng_uuid=None)
        )
        await session.commit()

    assert await orch.destroy_vm("vm_race") is True

    async with session_factory() as session:
        row = await session.get(VMRow, "vm_race")
        # The clone may still appear on this prefix — keep it quarantined.
        assert row.ipv6_prefix_index == 11


@pytest.mark.asyncio
async def test_reservation_lifecycle(session_factory, monkeypatch):
    """reserve → release frees the /64; reserve → activate attaches payment
    and starts provisioning."""
    from hyrule_cloud.models import VMCreateRequest

    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    spawned: list[str] = []
    monkeypatch.setattr(orch, "_spawn_provisioning", spawned.append)

    order = VMCreateRequest(duration_days=1, os="debian-13", ssh_pubkey="ssh-ed25519 AAAA t")

    reserved, token = await orch.reserve_vm(order)
    assert reserved.owner_wallet == ""
    assert reserved.ipv6_prefix_index is not None
    assert token.startswith("hyr_vm_")
    assert spawned == []  # reservations must not provision

    await orch.release_vm_reservation(reserved.vm_id)
    async with session_factory() as session:
        assert await session.get(VMRow, reserved.vm_id) is None

    reserved2, _ = await orch.reserve_vm(order)
    activated = await orch.activate_vm_reservation(
        reserved2.vm_id, owner_wallet="0xPAYER", payment_tx="0xTX"
    )
    assert activated.owner_wallet == "0xPAYER"
    assert activated.payment_tx == "0xTX"
    assert spawned == [reserved2.vm_id]

    # Paid rows are not releasable as reservations.
    await orch.release_vm_reservation(reserved2.vm_id)
    async with session_factory() as session:
        assert await session.get(VMRow, reserved2.vm_id) is not None


@pytest.mark.asyncio
async def test_expiry_sweep_purges_abandoned_reservations(session_factory):
    from datetime import UTC, datetime, timedelta

    cfg = HyruleConfig()
    orch = Orchestrator(cfg, session_factory)
    orch.xcpng = _StubXCPNGDestroy()
    orch.dns = _StubDNSDelete()

    stale = datetime.now(UTC) - timedelta(minutes=30)
    async with session_factory() as session:
        old_res = _vm_row(
            "vm_stale_res",
            prefix_index=12,
            owner_wallet="",
            status=VMStatus.PROVISIONING,
            xcpng_uuid=None,
            expires_at=None,
        )
        old_res.created_at = stale
        fresh_res = _vm_row(
            "vm_fresh_res",
            prefix_index=13,
            owner_wallet="",
            status=VMStatus.PROVISIONING,
            xcpng_uuid=None,
            expires_at=None,
        )
        session.add_all([old_res, fresh_res])
        await session.commit()

    await orch.check_expiries()

    async with session_factory() as session:
        assert await session.get(VMRow, "vm_stale_res") is None
        assert await session.get(VMRow, "vm_fresh_res") is not None
