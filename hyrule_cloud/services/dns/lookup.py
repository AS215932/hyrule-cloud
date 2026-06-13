"""DNS resolver service for read-only /v1/dns and MX diagnostics."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import dns.exception
import dns.resolver
import dns.reversename

from hyrule_cloud.models import (
    DNSLookupRecordType,
    DNSLookupRequest,
    DNSLookupResponse,
    DNSQuestion,
    DNSRecordAnswer,
    DNSSECResult,
)
from hyrule_cloud.services.cache import TTLCache

_cache: TTLCache[DNSLookupResponse] = TTLCache(max_entries=4096)


def _record_value(rdata: object) -> str:
    return rdata.to_text() if hasattr(rdata, "to_text") else str(rdata)


def _answers(answer: dns.resolver.Answer) -> list[DNSRecordAnswer]:
    ttl = getattr(getattr(answer, "rrset", None), "ttl", None)
    rdtype = dns.rdatatype.to_text(answer.rdtype)
    return [
        DNSRecordAnswer(
            name=answer.canonical_name.to_text(),
            type=rdtype,
            ttl=ttl,
            value=_record_value(rdata),
        )
        for rdata in answer
    ]


def _resolve_sync(req: DNSLookupRequest) -> DNSLookupResponse:
    key = f"{req.name}|{req.type}|{req.resolver}|{req.dnssec}|{req.trace}"
    cached = _cache.get(key)
    if cached is not None:
        return cached

    resolver = dns.resolver.Resolver(configure=req.resolver == "system")
    if req.resolver not in {"system", "default"}:
        resolver.nameservers = [req.resolver]
    resolver.lifetime = req.timeout_ms / 1000
    resolver.timeout = min(req.timeout_ms / 1000, 5)

    name = req.name.rstrip(".") + "."
    rcode = "NOERROR"
    answers: list[DNSRecordAnswer] = []
    authority: list[DNSRecordAnswer] = []
    additional: list[DNSRecordAnswer] = []
    trace: list[dict[str, object]] = []
    dnssec: DNSSECResult | None = None

    try:
        answer = resolver.resolve(name, req.type.value, raise_on_no_answer=False)
        if answer.rrset is None:
            rcode = "NODATA"
        else:
            answers = _answers(answer)
    except dns.resolver.NXDOMAIN:
        rcode = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        rcode = "NODATA"
    except dns.resolver.NoNameservers as exc:
        rcode = "SERVFAIL"
        authority.append(DNSRecordAnswer(name=name, type="ERROR", value=str(exc)))
    except dns.exception.Timeout:
        rcode = "TIMEOUT"
    except Exception as exc:
        rcode = "ERROR"
        authority.append(DNSRecordAnswer(name=name, type="ERROR", value=str(exc)))

    if req.dnssec:
        dnssec = DNSSECResult(
            validated=None,
            chain_status="unknown",
            detail="DNSSEC validation is reported by resolver support in a later implementation step.",
        )
        try:
            ds_answer = resolver.resolve(name, "DS", raise_on_no_answer=False)
            if ds_answer.rrset is not None:
                dnssec.chain_status = "signed_or_delegated"
        except Exception:
            pass

    if req.trace:
        labels = name.strip(".").split(".")
        for i in range(len(labels)):
            zone = ".".join(labels[i:]) + "."
            try:
                ns_answer = resolver.resolve(zone, "NS", raise_on_no_answer=False)
                trace.append({"zone": zone, "ns": [_record_value(r) for r in ns_answer]})
            except Exception as exc:
                trace.append({"zone": zone, "error": str(exc)})

    resp = DNSLookupResponse(
        request_id="dnsq_contract",
        question=DNSQuestion(name=name, type=req.type.value),
        answers=answers,
        authority=authority,
        additional=additional,
        rcode=rcode,
        dnssec=dnssec,
        resolver=req.resolver,
        trace=trace,
        generated_at=datetime.now(UTC),
    )
    _cache.set(key, resp, ttl_seconds=60)
    return resp


async def lookup(req: DNSLookupRequest) -> DNSLookupResponse:
    return await asyncio.to_thread(_resolve_sync, req)


async def reverse(address: str, *, timeout_ms: int = 3000) -> DNSLookupResponse:
    ptr = dns.reversename.from_address(address).to_text()
    return await lookup(
        DNSLookupRequest(name=ptr, type=DNSLookupRecordType.PTR, timeout_ms=timeout_ms)
    )


async def lookup_values(name: str, record_type: DNSLookupRecordType | str) -> list[str]:
    rtype = record_type if isinstance(record_type, DNSLookupRecordType) else DNSLookupRecordType(record_type)
    resp = await lookup(DNSLookupRequest(name=name, type=rtype))
    return [answer.value for answer in resp.answers]
