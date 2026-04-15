"""
DNS provider for managing records on the authoritative nameserver.

Uses RFC 2136 (DNS UPDATE) via dnspython, authenticated with TSIG.
Works with BIND, Knot, PowerDNS, and NSD.

For the auto-subdomain case (*.deploy.servify.network), we create AAAA
records pointing to the VM's IPv6 address.
"""

from __future__ import annotations

import asyncio
from functools import partial

import dns.name
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.query
import structlog

from hyrule_cloud.config import HyruleConfig

log = structlog.get_logger()


class DNSProvider:
    """Manage DNS records via RFC 2136 dynamic updates."""

    def __init__(self, config: HyruleConfig) -> None:
        self.config = config
        self.server = config.dns_server
        self.zone = config.deploy_domain
        self.keyring = dns.tsigkeyring.from_text({
            "hyrule-dns": config.dns_tsig_key,
        })
        self.tsig_algo = config.dns_tsig_algo

    def _make_update(self, commands: list[tuple[str, ...]]) -> dns.update.Update:
        """Build a dns.update.Update message from a list of command tuples."""
        update = dns.update.Update(
            self.zone,
            keyring=self.keyring,
            keyalgorithm=self.tsig_algo,
        )
        for cmd in commands:
            action, *args = cmd
            if action == "delete":
                update.delete(*args)
            elif action == "add":
                update.add(*args)
        return update

    async def _send(self, commands: list[tuple[str, ...]]) -> None:
        """Build and send an RFC 2136 update over TCP."""
        if not self.server:
            log.warning("dns_update_skipped", reason="no dns_server configured")
            return

        update = self._make_update(commands)
        log.debug("dns_update", commands=commands)

        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None, partial(dns.query.tcp, update, self.server, timeout=10)
        )

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            log.error("dns_update_failed", rcode=dns.rcode.to_text(rcode))
            raise RuntimeError(f"DNS update failed: {dns.rcode.to_text(rcode)}")

        log.info("dns_update_success", commands=commands)

    async def create_aaaa(self, subdomain: str, ipv6_address: str, ttl: int = 300) -> None:
        """Create an AAAA record under the deploy zone."""
        fqdn = f"{subdomain}.{self.zone}"
        await self._send([
            ("delete", fqdn, dns.rdatatype.AAAA),
            ("add", fqdn, ttl, dns.rdatatype.AAAA, ipv6_address),
        ])
        log.info("dns_aaaa_created", fqdn=fqdn, ipv6=ipv6_address)

    async def delete_aaaa(self, subdomain: str) -> None:
        """Remove AAAA record for a subdomain."""
        fqdn = f"{subdomain}.{self.zone}"
        await self._send([
            ("delete", fqdn, dns.rdatatype.AAAA),
        ])
        log.info("dns_aaaa_deleted", fqdn=fqdn)

    async def create_record(
        self,
        fqdn: str,
        rtype: str,
        value: str,
        ttl: int = 300,
    ) -> None:
        """Create an arbitrary DNS record."""
        rdtype = dns.rdatatype.from_text(rtype)
        await self._send([
            ("delete", fqdn, rdtype),
            ("add", fqdn, ttl, rdtype, value),
        ])

    async def delete_record(self, fqdn: str, rtype: str) -> None:
        """Delete a DNS record."""
        rdtype = dns.rdatatype.from_text(rtype)
        await self._send([
            ("delete", fqdn, rdtype),
        ])
