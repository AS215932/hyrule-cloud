"""RDAP and WHOIS lookup services."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime
from typing import Any

import httpx

from hyrule_cloud.models import (
    RDAPLookupRequest,
    RDAPLookupResponse,
    RegistrySubject,
    RegistrySubjectType,
    WhoisLookupRequest,
    WhoisLookupResponse,
)
from hyrule_cloud.services.cache import TTLCache

_rdap_cache: TTLCache[RDAPLookupResponse] = TTLCache(max_entries=2048)
_whois_cache: TTLCache[WhoisLookupResponse] = TTLCache(max_entries=2048)


def _rdap_url(subject: RegistrySubject) -> str:
    typ = subject.type
    value = str(subject.value).removeprefix("AS").removeprefix("as")
    if typ == RegistrySubjectType.DOMAIN:
        return f"https://rdap.org/domain/{value}"
    if typ == RegistrySubjectType.IP:
        return f"https://rdap.org/ip/{value}"
    if typ == RegistrySubjectType.PREFIX:
        ip = value.split("/", 1)[0]
        return f"https://rdap.org/ip/{ip}"
    if typ == RegistrySubjectType.ASN:
        return f"https://rdap.org/autnum/{value}"
    if typ == RegistrySubjectType.ENTITY:
        return f"https://rdap.org/entity/{value}"
    raise ValueError(f"unsupported RDAP subject type: {typ}")


def _parse_rdap(raw: dict[str, Any]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key in ["objectClassName", "handle", "ldhName", "name", "type", "country", "status"]:
        if key in raw:
            parsed[key] = raw[key]
    if "startAddress" in raw or "endAddress" in raw:
        parsed["range"] = {"start": raw.get("startAddress"), "end": raw.get("endAddress")}
    if "port43" in raw:
        parsed["whois_server"] = raw["port43"]
    if "nameservers" in raw:
        parsed["nameservers"] = [ns.get("ldhName") for ns in raw.get("nameservers", []) if ns.get("ldhName")]
    if "entities" in raw:
        parsed["entities"] = [entity.get("handle") for entity in raw.get("entities", []) if entity.get("handle")]
    return parsed


async def rdap_lookup(req: RDAPLookupRequest) -> RDAPLookupResponse:
    key = f"{req.subject.type}:{req.subject.value}:{req.include_raw}"
    cached = _rdap_cache.get(key)
    if cached is not None:
        return cached

    url = _rdap_url(req.subject)
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            response = await client.get(url, headers={"User-Agent": "HyruleCloud-RDAP/1.0"})
            response.raise_for_status()
            raw = response.json()
            parsed = _parse_rdap(raw)
            registry = raw.get("port43") or raw.get("handle")
        except Exception as exc:
            raw = {"error": str(exc)}
            parsed = {"error": str(exc)}
            registry = None

    result = RDAPLookupResponse(
        request_id="rdapq_contract",
        subject=req.subject,
        registry=registry,
        bootstrap_url=url,
        parsed=parsed,
        raw=raw if req.include_raw else None,
        generated_at=datetime.now(UTC),
    )
    _rdap_cache.set(key, result, ttl_seconds=req.max_age_seconds or 86400)
    return result


def _whois_query_sync(server: str, query: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _extract_whois_server(raw: str) -> str | None:
    for line in raw.splitlines():
        lower = line.lower()
        if lower.startswith("whois:") or lower.startswith("refer:"):
            _, _, value = line.partition(":")
            value = value.strip()
            if value:
                return value
        if "whois server:" in lower:
            _, _, value = line.partition(":")
            value = value.strip()
            if value:
                return value
    return None


def _parse_whois(raw: str) -> dict[str, object]:
    fields: dict[str, object] = {}
    wanted = {
        "registrar",
        "creation date",
        "created",
        "registry expiry date",
        "expiry date",
        "updated date",
        "name server",
        "nserver",
        "netname",
        "org-name",
        "orgname",
        "country",
        "originas",
        "route",
        "route6",
        "inetnum",
        "netrange",
    }
    nameservers: list[str] = []
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_l = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key_l in {"name server", "nserver"}:
            ns = value.split()[0].rstrip(".").lower()
            if ns not in nameservers:
                nameservers.append(ns)
        elif key_l in wanted and key_l not in fields:
            fields[key_l.replace(" ", "_").replace("-", "_")] = value
    if nameservers:
        fields["nameservers"] = nameservers
    return fields


def _whois_lookup_sync(req: WhoisLookupRequest) -> WhoisLookupResponse:
    key = f"{req.subject.type}:{req.subject.value}:{req.include_raw}"
    cached = _whois_cache.get(key)
    if cached is not None:
        return cached

    value = str(req.subject.value).removeprefix("AS").removeprefix("as")
    query = f"AS{value}" if req.subject.type == RegistrySubjectType.ASN else value
    server = "whois.iana.org"
    raw = ""
    try:
        first = _whois_query_sync(server, query)
        referral = _extract_whois_server(first)
        if referral and referral != server:
            server = referral
            raw = _whois_query_sync(server, query)
            if not raw.strip():
                raw = first
        else:
            raw = first
        parsed = _parse_whois(raw)
    except Exception as exc:
        parsed = {"error": str(exc)}
        raw = str(exc)

    result = WhoisLookupResponse(
        request_id="whoisq_contract",
        subject=req.subject,
        registry=server,
        server=server,
        parsed=parsed,
        raw=raw if req.include_raw else None,
        redacted="REDACTED" in raw.upper() or "GDPR" in raw.upper(),
        generated_at=datetime.now(UTC),
    )
    _whois_cache.set(key, result, ttl_seconds=req.max_age_seconds or 86400)
    return result


async def whois_lookup(req: WhoisLookupRequest) -> WhoisLookupResponse:
    return await asyncio.to_thread(_whois_lookup_sync, req)
