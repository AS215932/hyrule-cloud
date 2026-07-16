"""Strict input validation for registrable names and managed DNS records."""

from __future__ import annotations

import re
from ipaddress import ip_address

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.models import DNSRRSet

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_LABEL = re.compile(r"^(?:\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$")
_FQDN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)


def normalize_registrable_domain(value: str) -> tuple[str, str, str]:
    """Return ``(label, tld, fqdn)`` for one ASCII second-level name."""
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DomainProblem(
            422,
            "idn_not_supported",
            "Internationalized domain names are not supported in this release.",
        ) from exc
    fqdn = value.strip().lower().rstrip(".")
    if len(fqdn) > 253 or fqdn.count(".") != 1:
        raise DomainProblem(
            422,
            "invalid_domain",
            "Use one second-level ASCII domain, for example example.dev.",
        )
    label, tld = fqdn.split(".", 1)
    if not _LABEL.fullmatch(label) or not _LABEL.fullmatch(tld):
        raise DomainProblem(422, "invalid_domain", "The domain name is not valid.")
    if label.startswith("xn--") or tld.startswith("xn--"):
        raise DomainProblem(
            422,
            "idn_not_supported",
            "Punycode and internationalized domains are not supported in this release.",
        )
    return label, tld, fqdn


def normalize_fqdn(value: str, *, field: str = "name") -> str:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DomainProblem(422, "invalid_nameserver", f"{field} must be an ASCII hostname.") from exc
    fqdn = value.strip().lower().rstrip(".")
    if not _FQDN.fullmatch(fqdn):
        raise DomainProblem(422, "invalid_nameserver", f"{field} must be a valid hostname.")
    return fqdn


def validate_nameservers(values: list[str]) -> list[str]:
    normalized = [normalize_fqdn(value, field="nameserver") for value in values]
    if len(set(normalized)) != len(normalized):
        raise DomainProblem(422, "duplicate_nameserver", "Nameservers must be unique.")
    return normalized


def normalize_record_name(name: str, zone: str) -> str:
    name = name.strip().lower().rstrip(".") or "@"
    if name == zone:
        return "@"
    suffix = f".{zone}"
    if name.endswith(suffix):
        name = name[: -len(suffix)] or "@"
    if name == "@":
        return name
    labels = name.split(".")
    if any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise DomainProblem(422, "invalid_dns_name", "The DNS record name is invalid.")
    if any(label == "*" for label in labels[1:]):
        raise DomainProblem(422, "invalid_dns_name", "A wildcard is only valid as the first label.")
    return name


def validate_rrset(rrset: DNSRRSet, zone: str) -> DNSRRSet:
    """Validate one RRset with dnspython and return its normalized form."""
    name = normalize_record_name(rrset.name, zone)
    if name == "@" and rrset.type.value in {"CNAME", "NS"}:
        raise DomainProblem(
            422,
            "protected_apex_record",
            "Apex CNAME and NS records are managed by Hyrule and cannot be changed.",
        )
    origin = dns.name.from_text(f"{zone}.")
    values: list[str] = []
    for raw_value in rrset.values:
        value = raw_value.strip()
        if not value or any(ord(char) < 32 and char not in "\t" for char in value):
            raise DomainProblem(422, "invalid_dns_value", "A DNS value contains invalid characters.")
        if "\n" in value or "\r" in value or len(value) > 4096:
            raise DomainProblem(422, "invalid_dns_value", "A DNS value is too long or multiline.")
        try:
            if rrset.type.value in {"A", "AAAA"}:
                parsed = ip_address(value)
                if parsed.version != (4 if rrset.type.value == "A" else 6):
                    raise ValueError("address family mismatch")
                normalized = str(parsed)
            else:
                rdata = dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.from_text(rrset.type.value),
                    value,
                    origin=origin,
                    relativize=False,
                )
                normalized = rdata.to_text(origin=origin, relativize=False)
        except (ValueError, dns.exception.DNSException) as exc:
            raise DomainProblem(
                422,
                "invalid_dns_value",
                f"A {rrset.type.value} record value is invalid.",
            ) from exc
        if normalized not in values:
            values.append(normalized)
    return rrset.model_copy(update={"name": name, "values": values})
