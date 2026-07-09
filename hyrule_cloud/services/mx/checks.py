"""MXToolbox-compatible diagnostic checks implemented by Hyrule."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime

import httpx

from hyrule_cloud.models import (
    DNSLookupRecordType,
    DNSLookupRequest,
    IPLookupRequest,
    IPLookupView,
    MXCheckRequest,
    MXCheckResponse,
    MXFinding,
    MXStatus,
    MXTool,
    RegistrySubject,
    RegistrySubjectType,
    WhoisLookupRequest,
)
from hyrule_cloud.services.dns.lookup import lookup as dns_lookup
from hyrule_cloud.services.intel.ip import lookup_ip
from hyrule_cloud.services.registry.lookup import whois_lookup
from hyrule_cloud.services.safety import UnsafeTargetError, resolve_public_addresses, safe_url


class MXInputError(ValueError):
    pass


def normalize_request(req: MXCheckRequest) -> tuple[MXTool, str]:
    if req.command:
        tool_text, sep, target = req.command.partition(":")
        if not sep or not tool_text or not target:
            raise MXInputError("command must be in SuperTool form, e.g. mx:example.com")
        return MXTool(tool_text.strip().lower()), target.strip()
    if req.tool is None or not req.target:
        raise MXInputError("tool and target are required when command is not supplied")
    return req.tool, req.target.strip()


def _finding(severity: MXStatus, code: str, message: str, recommendation: str | None = None, **evidence: object) -> MXFinding:
    return MXFinding(
        severity=severity,
        code=code,
        message=message,
        evidence=evidence,
        recommendation=recommendation,
    )


def _overall(findings: list[MXFinding]) -> MXStatus:
    order = [MXStatus.ERROR, MXStatus.CRITICAL, MXStatus.WARNING, MXStatus.INFO, MXStatus.OK]
    severities = {f.severity for f in findings}
    for severity in order:
        if severity in severities:
            return severity
    return MXStatus.OK


def _mx_exchange_is_root(value: str) -> bool:
    """Whether an MX record's exchange is the root label (``.``)."""
    return value.split()[-1].rstrip(".") == ""


def _mx_preference(value: str) -> int | None:
    """The numeric preference of an MX record (``10`` in ``10 mail.``), or None
    if it can't be parsed."""
    parts = value.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[0])
    except ValueError:
        return None


def _is_null_mx(values: list[str]) -> bool:
    """RFC 7505 null MX: exactly one record ``0 .`` — preference 0 with the root
    (``.``) exchange — signalling the domain explicitly accepts no mail. A
    root exchange at a non-zero preference (e.g. ``10 .``) is malformed, not a
    valid null MX, so it does not qualify here."""
    if len(values) != 1:
        return False
    return _mx_exchange_is_root(values[0]) and _mx_preference(values[0]) == 0


def _dns_summary(tool: MXTool, target: str, values: list[str]) -> str:
    if values:
        return f"{tool.value.upper()} lookup for {target} returned {len(values)} record(s)."
    return f"No {tool.value.upper()} records found for {target}."


async def _dns_record(tool: MXTool, target: str, rtype: DNSLookupRecordType) -> MXCheckResponse:
    resp = await dns_lookup(DNSLookupRequest(name=target, type=rtype))
    values = [answer.value for answer in resp.answers]
    findings = [
        _finding(MXStatus.OK, f"{tool.value}_present", f"Found {len(values)} {rtype.value} record(s).", records=values)
    ] if values else [
        _finding(MXStatus.WARNING, f"{tool.value}_missing", f"No {rtype.value} records were found.")
    ]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=tool,
        target=target,
        status=_overall(findings),
        summary=_dns_summary(tool, target, values),
        findings=findings,
        raw={"dns": resp.model_dump(mode="json")},
        sources={"dns": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _mx(target: str) -> MXCheckResponse:
    resp = await dns_lookup(DNSLookupRequest(name=target, type=DNSLookupRecordType.MX))
    values = [answer.value for answer in resp.answers]
    findings: list[MXFinding] = []
    if not values:
        findings.append(_finding(MXStatus.CRITICAL, "mx_missing", "No MX records found.", "Publish MX records for inbound mail delivery."))
    elif _is_null_mx(values):
        # RFC 7505: a single "0 ." record means the domain explicitly accepts
        # no mail. That is a valid, deliberate configuration — a clean finding,
        # not an error (and there is no exchange host to resolve).
        findings.append(_finding(MXStatus.INFO, "mx_null", "Domain publishes a null MX (RFC 7505): it explicitly accepts no mail.", records=values))
    elif len(values) == 1 and _mx_exchange_is_root(values[0]):
        # A single root-exchange MX with a non-zero preference is a malformed
        # null MX: RFC 7505 requires preference 0. Warn rather than pass it off
        # as a clean "accepts no mail" signal (or trying to resolve an empty
        # exchange host, which would raise).
        findings.append(_finding(MXStatus.WARNING, "mx_null_bad_preference", "Domain publishes a root (null) MX exchange with a non-zero preference; RFC 7505 requires preference 0.", "Publish the null MX as '0 .' or configure a real mail exchanger.", records=values))
    else:
        findings.append(_finding(MXStatus.OK, "mx_present", f"Found {len(values)} MX record(s).", records=values))
        for mx_value in values:
            host = mx_value.split()[-1].rstrip(".")
            if not host:
                # A null exchange (".") mixed with real MX records is malformed:
                # RFC 7505 requires the null MX to be the only record. Report it
                # rather than resolving an empty DNS name (which would raise).
                findings.append(_finding(MXStatus.WARNING, "mx_null_mixed", "A null MX (.) is mixed with other MX records; RFC 7505 requires it to be the only record.", record=mx_value))
                continue
            a = await dns_lookup(DNSLookupRequest(name=host, type=DNSLookupRecordType.A))
            aaaa = await dns_lookup(DNSLookupRequest(name=host, type=DNSLookupRecordType.AAAA))
            if not a.answers and not aaaa.answers:
                findings.append(_finding(MXStatus.CRITICAL, "mx_host_no_address", f"MX host {host} has no A/AAAA records.", host=host))
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.MX,
        target=target,
        status=_overall(findings),
        summary=f"MX check for {target}: {len(values)} record(s).",
        findings=findings,
        raw={"records": values},
        sources={"dns": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _spf(target: str) -> MXCheckResponse:
    txt = await dns_lookup(DNSLookupRequest(name=target, type=DNSLookupRecordType.TXT))
    records = [a.value.strip('"') for a in txt.answers if a.value.strip('"').lower().startswith("v=spf1")]
    findings: list[MXFinding] = []
    if not records:
        findings.append(_finding(MXStatus.WARNING, "spf_missing", "No SPF record found.", "Publish a TXT record beginning with v=spf1."))
    elif len(records) > 1:
        findings.append(_finding(MXStatus.CRITICAL, "spf_multiple", "Multiple SPF records found.", "Publish exactly one SPF record.", records=records))
    else:
        record = records[0]
        lookup_count = sum(record.count(token) for token in ["include:", " a", " mx", "ptr", "exists:", "redirect="])
        severity = MXStatus.WARNING if lookup_count > 10 else MXStatus.OK
        findings.append(_finding(severity, "spf_record", f"SPF record found with estimated {lookup_count} DNS lookup(s).", "Reduce SPF mechanisms/includes to <=10 lookups." if lookup_count > 10 else None, record=record, lookup_count=lookup_count))
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.SPF,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw={"records": records},
        sources={"dns": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _txt_policy(tool: MXTool, target: str, name: str, prefix: str) -> MXCheckResponse:
    resp = await dns_lookup(DNSLookupRequest(name=name, type=DNSLookupRecordType.TXT))
    records = [a.value.strip('"') for a in resp.answers if a.value.strip('"').lower().startswith(prefix.lower())]
    if records:
        findings = [_finding(MXStatus.OK, f"{tool.value}_present", f"{tool.value.upper()} record found.", records=records)]
    else:
        findings = [_finding(MXStatus.WARNING, f"{tool.value}_missing", f"No {tool.value.upper()} record found at {name}.")]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=tool,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw={"lookup_name": name, "records": records},
        sources={"dns": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _dkim(target: str, selectors: list[str]) -> MXCheckResponse:
    selectors = selectors or ["default", "selector1", "selector2", "google", "mail"]
    findings: list[MXFinding] = []
    raw: dict[str, object] = {}
    for selector in selectors:
        name = f"{selector}._domainkey.{target}"
        resp = await dns_lookup(DNSLookupRequest(name=name, type=DNSLookupRecordType.TXT))
        records = [a.value.strip('"') for a in resp.answers if "v=DKIM1" in a.value.upper()]
        raw[selector] = records
        if records:
            findings.append(_finding(MXStatus.OK, "dkim_selector_present", f"DKIM selector {selector} exists.", selector=selector))
    if not findings:
        findings.append(_finding(MXStatus.WARNING, "dkim_missing", "No DKIM records found for common selectors.", "Pass explicit dkim_selectors when your selector is known."))
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.DKIM,
        target=target,
        status=_overall(findings),
        summary=f"DKIM checked {len(selectors)} selector(s).",
        findings=findings,
        raw=raw,
        sources={"dns": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _dns_health(target: str) -> MXCheckResponse:
    checks = {
        "NS": await dns_lookup(DNSLookupRequest(name=target, type=DNSLookupRecordType.NS, dnssec=True)),
        "SOA": await dns_lookup(DNSLookupRequest(name=target, type=DNSLookupRecordType.SOA)),
    }
    findings: list[MXFinding] = []
    if checks["NS"].answers:
        findings.append(_finding(MXStatus.OK, "ns_present", "Authoritative NS records found.", records=[a.value for a in checks["NS"].answers]))
    else:
        findings.append(_finding(MXStatus.CRITICAL, "ns_missing", "No NS records found."))
    if checks["SOA"].answers:
        findings.append(_finding(MXStatus.OK, "soa_present", "SOA record found."))
    else:
        findings.append(_finding(MXStatus.WARNING, "soa_missing", "No SOA record found."))
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.DNS,
        target=target,
        status=_overall(findings),
        summary=f"DNS health check for {target}: {len(findings)} finding(s).",
        findings=findings,
        raw={k: v.model_dump(mode="json") for k, v in checks.items()},
        sources={"dns": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _http(tool: MXTool, target: str) -> MXCheckResponse:
    url = safe_url(target, default_scheme=tool.value)
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        try:
            resp = await client.get(url, headers={"User-Agent": "HyruleCloud-MXDiag/1.0"})
            status = MXStatus.OK if resp.status_code < 500 else MXStatus.WARNING
            findings = [_finding(status, f"{tool.value}_reachable", f"{url} returned HTTP {resp.status_code}.", status_code=resp.status_code)]
        except Exception as exc:
            findings = [_finding(MXStatus.CRITICAL, f"{tool.value}_failed", f"{url} failed: {exc}")]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=tool,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw=None,
        sources={"http": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _mta_sts(target: str) -> MXCheckResponse:
    txt_result = await _txt_policy(MXTool.MTA_STS, target, f"_mta-sts.{target}", "v=STSv1")
    policy_url = f"https://mta-sts.{target}/.well-known/mta-sts.txt"
    findings = list(txt_result.findings)
    raw = dict(txt_result.raw or {})
    try:
        url = safe_url(policy_url)
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "HyruleCloud-MXDiag/1.0"})
        raw["policy_status_code"] = resp.status_code
        raw["policy"] = resp.text[:4096]
        findings.append(_finding(MXStatus.OK if resp.status_code == 200 else MXStatus.WARNING, "mta_sts_policy_fetch", f"MTA-STS policy returned HTTP {resp.status_code}."))
    except Exception as exc:
        findings.append(_finding(MXStatus.WARNING, "mta_sts_policy_fetch_failed", f"MTA-STS policy fetch failed: {exc}"))
    txt_result.findings = findings
    txt_result.status = _overall(findings)
    txt_result.summary = f"MTA-STS check for {target}: {len(findings)} finding(s)."
    txt_result.raw = raw
    return txt_result


async def _tcp(target: str, port: int | None, tool: MXTool = MXTool.TCP) -> MXCheckResponse:
    host = target
    if ":" in target and not target.startswith("[") and target.count(":") == 1:
        host, port_text = target.rsplit(":", 1)
        if port is None:
            port = int(port_text)
    port = port or (25 if tool == MXTool.SMTP else 443)
    addresses = await asyncio.to_thread(resolve_public_addresses, host)
    addr = addresses[0]
    try:
        await asyncio.to_thread(_connect_once, addr, port, 10)
        findings = [_finding(MXStatus.OK, "tcp_connect_ok", f"Connected to {host}:{port}.", address=addr, port=port)]
    except Exception as exc:
        findings = [_finding(MXStatus.CRITICAL, "tcp_connect_failed", f"Could not connect to {host}:{port}: {exc}", address=addr, port=port)]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=tool,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw=None,
        sources={"tcp": "ok"},
        generated_at=datetime.now(UTC),
    )


def _connect_once(addr: str, port: int, timeout: float) -> None:
    with socket.create_connection((addr, port), timeout=timeout):
        return


async def _smtp(target: str) -> MXCheckResponse:
    # Accept domain or MX hostname. If a domain has MX records, test the first MX host.
    host = target
    mx = await dns_lookup(DNSLookupRequest(name=target, type=DNSLookupRecordType.MX))
    if mx.answers:
        host = sorted([a.value for a in mx.answers])[0].split()[-1].rstrip(".")
    tcp = await _tcp(host, 25, MXTool.SMTP)
    findings = list(tcp.findings)
    if tcp.status == MXStatus.OK:
        try:
            banner = await asyncio.to_thread(_smtp_banner, host, 25)
            findings.append(_finding(MXStatus.OK, "smtp_banner", "SMTP banner received.", banner=banner[:512]))
        except Exception as exc:
            findings.append(_finding(MXStatus.WARNING, "smtp_banner_failed", f"SMTP banner read failed: {exc}"))
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.SMTP,
        target=target,
        status=_overall(findings),
        summary=f"SMTP check for {target} via {host}: {len(findings)} finding(s).",
        findings=findings,
        raw={"mx_host": host},
        sources={"dns": "ok", "tcp": "ok"},
        generated_at=datetime.now(UTC),
    )


def _smtp_banner(host: str, port: int) -> str:
    addresses = resolve_public_addresses(host)
    with socket.create_connection((addresses[0], port), timeout=10) as sock:
        sock.settimeout(10)
        banner = sock.recv(1024).decode("utf-8", errors="replace")
        try:
            sock.sendall(b"EHLO hyrule.cloud\r\nQUIT\r\n")
            banner += sock.recv(2048).decode("utf-8", errors="replace")
        except Exception:
            pass
        return banner


async def _blacklist(target: str) -> MXCheckResponse:
    host = target
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        addresses = await asyncio.to_thread(resolve_public_addresses, host)
        ip = ipaddress.ip_address(addresses[0])
    if ip.version != 4:
        findings = [_finding(MXStatus.INFO, "blacklist_ipv6_limited", "DNSBL check currently supports IPv4 DNSBL zones only.")]
    else:
        reversed_ip = ".".join(reversed(str(ip).split(".")))
        zones = ["zen.spamhaus.org", "bl.spamcop.net"]
        listings: list[str] = []
        for zone in zones:
            check_name = f"{reversed_ip}.{zone}"
            resp = await dns_lookup(DNSLookupRequest(name=check_name, type=DNSLookupRecordType.A))
            if resp.answers:
                listings.append(zone)
        findings = [_finding(MXStatus.CRITICAL if listings else MXStatus.OK, "blacklist_result", "Listed on DNSBL(s)." if listings else "No DNSBL listings found in configured providers.", listings=listings)]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.BLACKLIST,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw=None,
        sources={"dnsbl": "ok"},
        generated_at=datetime.now(UTC),
    )


async def _ip_asn(target: str) -> MXCheckResponse:
    result = await lookup_ip(IPLookupRequest(address=target, views=[IPLookupView.ASN, IPLookupView.RDNS]))
    network = result.network
    if network and network.asn:
        findings = [_finding(MXStatus.OK, "asn_found", f"{target} maps to AS{network.asn}.", asn=network.asn, prefix=network.prefix, registry=network.registry)]
    else:
        findings = [_finding(MXStatus.WARNING, "asn_not_found", "ASN could not be determined.")]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=MXTool.ASN,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw={"ip": result.model_dump(mode="json")},
        sources=result.sources,
        generated_at=datetime.now(UTC),
    )


async def _whois(target: str, tool: MXTool = MXTool.WHOIS) -> MXCheckResponse:
    subject_type = RegistrySubjectType.DOMAIN
    value = target
    try:
        ipaddress.ip_address(target.split("/", 1)[0])
        subject_type = RegistrySubjectType.PREFIX if "/" in target else RegistrySubjectType.IP
    except ValueError:
        pass
    result = await whois_lookup(WhoisLookupRequest(subject=RegistrySubject(type=subject_type, value=value), include_raw=False))
    ok = "error" not in result.parsed
    findings = [_finding(MXStatus.OK if ok else MXStatus.WARNING, "whois_result", "WHOIS data found." if ok else "WHOIS lookup failed or returned no parsed data.", parsed=result.parsed)]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=tool,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw={"whois": result.model_dump(mode="json")},
        sources={"whois": "ok" if ok else "degraded"},
        generated_at=datetime.now(UTC),
    )


async def _subprocess_probe(tool: MXTool, target: str) -> MXCheckResponse:
    addresses = await asyncio.to_thread(resolve_public_addresses, target)
    address = addresses[0]
    command = ["ping", "-c", "4", "-W", "2", address] if tool == MXTool.PING else ["traceroute", "-m", "20", address]
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        ok = proc.returncode == 0
        output = (stdout or stderr).decode("utf-8", errors="replace")[-4096:]
        findings = [_finding(MXStatus.OK if ok else MXStatus.WARNING, f"{tool.value}_result", f"{tool.value} exited with code {proc.returncode}.", output=output)]
    except FileNotFoundError:
        findings = [_finding(MXStatus.WARNING, f"{tool.value}_unavailable", f"{tool.value} binary is not installed on this vantage point.")]
    except Exception as exc:
        findings = [_finding(MXStatus.WARNING, f"{tool.value}_failed", f"{tool.value} failed: {exc}")]
    return MXCheckResponse(
        request_id="mxq_contract",
        tool=tool,
        target=target,
        status=_overall(findings),
        summary=findings[0].message,
        findings=findings,
        raw=None,
        sources={"active_probe": "ok"},
        generated_at=datetime.now(UTC),
    )


async def run_check(req: MXCheckRequest) -> MXCheckResponse:
    try:
        tool, target = normalize_request(req)
        if tool == MXTool.A:
            return await _dns_record(tool, target, DNSLookupRecordType.A)
        if tool == MXTool.AAAA:
            return await _dns_record(tool, target, DNSLookupRecordType.AAAA)
        if tool == MXTool.CNAME:
            return await _dns_record(tool, target, DNSLookupRecordType.CNAME)
        if tool == MXTool.TXT:
            return await _dns_record(tool, target, DNSLookupRecordType.TXT)
        if tool == MXTool.SOA:
            return await _dns_record(tool, target, DNSLookupRecordType.SOA)
        if tool == MXTool.PTR:
            from hyrule_cloud.services.dns.lookup import reverse

            ptr = await reverse(target)
            findings = [_finding(MXStatus.OK if ptr.answers else MXStatus.WARNING, "ptr_result", "PTR records found." if ptr.answers else "No PTR records found.", records=[a.value for a in ptr.answers])]
            return MXCheckResponse(request_id="mxq_contract", tool=tool, target=target, status=_overall(findings), summary=findings[0].message, findings=findings, raw={"dns": ptr.model_dump(mode="json")}, sources={"dns": "ok"}, generated_at=datetime.now(UTC))
        if tool == MXTool.MX:
            return await _mx(target)
        if tool == MXTool.SPF:
            return await _spf(target)
        if tool == MXTool.DMARC:
            return await _txt_policy(tool, target, f"_dmarc.{target}", "v=DMARC1")
        if tool == MXTool.TLSRPT:
            return await _txt_policy(tool, target, f"_smtp._tls.{target}", "v=TLSRPTv1")
        if tool == MXTool.BIMI:
            return await _txt_policy(tool, target, f"default._bimi.{target}", "v=BIMI1")
        if tool == MXTool.DKIM:
            return await _dkim(target, req.options.dkim_selectors)
        if tool == MXTool.DNS:
            return await _dns_health(target)
        if tool == MXTool.HTTP:
            return await _http(tool, target)
        if tool == MXTool.HTTPS:
            return await _http(tool, target)
        if tool == MXTool.MTA_STS:
            return await _mta_sts(target)
        if tool == MXTool.TCP:
            return await _tcp(target, req.options.port)
        if tool == MXTool.SMTP:
            return await _smtp(target)
        if tool == MXTool.BLACKLIST:
            return await _blacklist(target)
        if tool == MXTool.ASN:
            return await _ip_asn(target)
        if tool in {MXTool.WHOIS, MXTool.ARIN}:
            return await _whois(target, tool)
        if tool in {MXTool.PING, MXTool.TRACE}:
            return await _subprocess_probe(tool, target)
    except (MXInputError, UnsafeTargetError, ValueError, ssl.SSLError) as exc:
        tool_value = req.tool or MXTool.DNS
        target_value = req.target or req.command or ""
        finding = _finding(MXStatus.ERROR, "invalid_or_unsafe_target", str(exc))
        return MXCheckResponse(
            request_id="mxq_contract",
            tool=tool_value,
            target=target_value,
            status=MXStatus.ERROR,
            summary=str(exc),
            findings=[finding],
            raw=None,
            sources={},
            generated_at=datetime.now(UTC),
        )
    raise MXInputError(f"unsupported MX tool: {req.tool}")
