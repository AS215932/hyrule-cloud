"""
DNS provider for managing records on the authoritative nameserver.

Uses RFC 2136 (DNS UPDATE) via the `nsupdate` command, authenticated
with TSIG. This works with BIND, Knot, PowerDNS, and NSD.

For the auto-subdomain case (*.deploy.hyrule.cloud), we create AAAA
records pointing to the VM's IPv6 address.
"""

from __future__ import annotations

import asyncio
import tempfile

import structlog

from hyrule_cloud.config import HyruleConfig

log = structlog.get_logger()


class DNSProvider:
    """Manage DNS records via nsupdate (RFC 2136)."""

    def __init__(self, config: HyruleConfig) -> None:
        self.config = config
        self.server = config.dns_server
        self.tsig_key = config.dns_tsig_key
        self.tsig_algo = config.dns_tsig_algo
        self.zone = config.deploy_domain

    async def _nsupdate(self, commands: list[str]) -> None:
        """
        Execute nsupdate commands.

        Writes a temporary script and runs nsupdate with TSIG auth.
        """
        script_lines = [
            f"server {self.server}",
            f"zone {self.zone}",
            *commands,
            "send",
            "quit",
        ]
        script = "\n".join(script_lines) + "\n"

        log.debug("nsupdate_script", commands=commands)

        # Write TSIG key file
        key_content = (
            f"key \"hyrule-dns\" {{\n"
            f"  algorithm {self.tsig_algo};\n"
            f"  secret \"{self.tsig_key}\";\n"
            f"}};\n"
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=True) as kf:
            kf.write(key_content)
            kf.flush()

            proc = await asyncio.create_subprocess_exec(
                "nsupdate", "-k", kf.name,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await proc.communicate(script.encode())

        if proc.returncode != 0:
            log.error(
                "nsupdate_failed",
                returncode=proc.returncode,
                stderr=stderr.decode(),
            )
            raise RuntimeError(f"nsupdate failed: {stderr.decode()}")

        log.info("nsupdate_success", commands=commands)

    async def create_aaaa(self, subdomain: str, ipv6_address: str, ttl: int = 300) -> None:
        """Create an AAAA record under the deploy zone."""
        fqdn = f"{subdomain}.{self.zone}"
        await self._nsupdate([
            f"update delete {fqdn} AAAA",
            f"update add {fqdn} {ttl} AAAA {ipv6_address}",
        ])
        log.info("dns_aaaa_created", fqdn=fqdn, ipv6=ipv6_address)

    async def delete_aaaa(self, subdomain: str) -> None:
        """Remove AAAA record for a subdomain."""
        fqdn = f"{subdomain}.{self.zone}"
        await self._nsupdate([
            f"update delete {fqdn} AAAA",
        ])
        log.info("dns_aaaa_deleted", fqdn=fqdn)

    async def create_record(
        self,
        fqdn: str,
        rtype: str,
        value: str,
        ttl: int = 300,
    ) -> None:
        """Create an arbitrary DNS record. Used for custom domain DNS management."""
        # For custom domains, the zone will be different.
        # This is a simplified version; production would need zone detection.
        await self._nsupdate([
            f"update delete {fqdn} {rtype}",
            f"update add {fqdn} {ttl} {rtype} {value}",
        ])

    async def delete_record(self, fqdn: str, rtype: str) -> None:
        """Delete a DNS record."""
        await self._nsupdate([
            f"update delete {fqdn} {rtype}",
        ])
