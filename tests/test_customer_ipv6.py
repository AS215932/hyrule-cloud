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
    assert iface["routes"] == [
        {"to": "::/0", "via": "2a0c:b641:b51::1", "on-link": True}
    ]


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

    assert await orch._wait_for_ipv6(
        "vm-uuid",
        timeout=1,
        expected_ipv6="2a0c:b641:b51:1::2",
    ) == "2a0c:b641:b51:1::2"
