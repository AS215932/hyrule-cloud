from __future__ import annotations

import pytest

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.providers.dns import DNSProvider


class CaptureDNSProvider(DNSProvider):
    def __init__(self) -> None:
        cfg = HyruleConfig(dns_tsig_key="abcd", deploy_domain="deploy.hyrule.host")
        super().__init__(cfg)
        self.commands: list[tuple] = []

    async def _send(self, commands: list[tuple[str, ...]]) -> None:
        self.commands.extend(commands)


@pytest.mark.asyncio
async def test_create_aaaa_uses_absolute_name_for_zone_update():
    provider = CaptureDNSProvider()

    await provider.create_aaaa("vm1", "2a0c:b641:b51:1::2")

    assert provider.commands == [
        ("delete", "vm1.deploy.hyrule.host.", 28),
        ("add", "vm1.deploy.hyrule.host.", 300, 28, "2a0c:b641:b51:1::2"),
    ]


@pytest.mark.asyncio
async def test_create_record_uses_absolute_name_for_zone_update():
    provider = CaptureDNSProvider()

    await provider.create_record("example.deploy.hyrule.host", "AAAA", "2a0c:b641:b51:2::2")

    assert provider.commands == [
        ("delete", "example.deploy.hyrule.host.", 28),
        ("add", "example.deploy.hyrule.host.", 300, 28, "2a0c:b641:b51:2::2"),
    ]
