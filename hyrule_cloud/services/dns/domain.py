"""Canonical validation shared by DNS domain-intelligence products."""

from __future__ import annotations

import ipaddress
import re

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Return a lower-case IDNA A-label domain or raise ``ValueError``.

    These products intentionally accept public host/domain names, not URLs,
    IP literals, local search suffixes, or arbitrary DNS owner names.
    """

    candidate = value.strip().rstrip(".")
    if not candidate:
        raise ValueError("domain must not be empty")
    if "://" in candidate or any(char in candidate for char in "/?#@"):
        raise ValueError("submit a domain name, not a URL")
    try:
        ipaddress.ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported")

    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc

    labels = normalized.split(".")
    if len(labels) < 2:
        raise ValueError("a public domain must contain at least two labels")
    if len(normalized) > 253:
        raise ValueError("domain exceeds 253 characters")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("domain contains an invalid DNS label")
    return normalized


def domain_suffixes(domain: str) -> list[str]:
    """Return candidate suffixes, excluding the single-label public suffix."""

    labels = domain.split(".")
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]
