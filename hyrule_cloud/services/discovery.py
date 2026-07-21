"""Curated x402 launch catalog and its machine-readable projections.

The catalog in this module is the single source of truth for everything Hyrule
advertises as a payable agent resource:

* x402 annotations on payable operations in the complete ``/openapi.json``
* ``/.well-known/x402.json`` (Hyrule compatibility manifest)
* Bazaar declarations attached to runtime 402 challenges
* the pre-validation unpaid challenge middleware

Only launch-ready, independently payable operations belong in this catalog.
The canonical OpenAPI document still describes every public, authenticated,
management, and worker operation; the catalog controls only which operations
receive x402 metadata and appear in the x402 manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal

from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError
from starlette.routing import compile_path
from x402.extensions.bazaar import OutputConfig, declare_discovery_extension

from hyrule_cloud import models
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.middleware.auth import require_account, require_browser_session

if TYPE_CHECKING:
    from fastapi import FastAPI


PriceMode = Literal["fixed", "dynamic"]


@dataclass(frozen=True, slots=True)
class PriceSpec:
    """Configuration-backed OpenAPI and preflight price metadata."""

    mode: PriceMode
    fields: tuple[tuple[str, str], ...]
    bounded: bool = True

    def values(self, payment: PaymentConfig) -> tuple[Decimal, ...]:
        return tuple(
            Decimal(str(getattr(payment, field, default))) for field, default in self.fields
        )

    def minimum(self, payment: PaymentConfig) -> Decimal:
        return min(self.values(payment))

    def maximum(self, payment: PaymentConfig) -> Decimal | None:
        if self.mode != "dynamic" or not self.bounded:
            return None
        return max(self.values(payment))

    def openapi(self, payment: PaymentConfig) -> dict[str, str]:
        if self.mode == "fixed":
            return {
                "mode": "fixed",
                "currency": "USD",
                "amount": str(self.minimum(payment)),
            }
        result = {
            "mode": "dynamic",
            "currency": "USD",
            "min": str(self.minimum(payment)),
        }
        maximum = self.maximum(payment)
        if maximum is not None:
            result["max"] = str(maximum)
        return result


# Bazaar resource tags per catalog area (spec: <=5 tags, each <=32 ASCII).
_TAG_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/v1/vm", ("compute", "vps")),
    ("/v1/network", ("proxy", "tor", "anonymity")),
    ("/v1/bgp", ("network-intel", "bgp")),
    ("/v1/ip", ("network-intel", "ip")),
    ("/v1/dns", ("network-intel", "dns")),
    ("/v1/rdap", ("network-intel", "registry")),
    ("/v1/whois", ("network-intel", "registry")),
    ("/v1/web", ("network-intel", "tls")),
    ("/v1/mx", ("network-intel", "email")),
    ("/v1/path", ("network-intel", "looking-glass")),
    ("/v1/ports", ("network-intel", "reachability")),
    ("/v1/nat", ("network-intel", "reachability")),
    ("/v1/threat", ("network-intel", "reputation")),
    ("/v1/voip", ("network-intel", "voip")),
)

_INTENT_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "/v1/vm",
        (
            "deploy an IPv6-native VPS",
            "provision a virtual machine for an AI agent",
        ),
    ),
    (
        "/v1/network",
        (
            "make an HTTP request through Tor, I2P, or Yggdrasil",
            "fetch a URL through a privacy network",
        ),
    ),
    (
        "/v1/bgp",
        (
            "investigate BGP routes and ASNs",
            "check route origin and RPKI status",
        ),
    ),
    (
        "/v1/ip",
        ("look up an IP address, ASN, reverse DNS, RDAP, or WHOIS",),
    ),
    (
        "/v1/dns",
        ("query DNS and DNSSEC", "check DNS propagation"),
    ),
    (
        "/v1/rdap",
        ("look up structured RDAP data for a domain, IP, prefix, or ASN",),
    ),
    (
        "/v1/whois",
        ("look up WHOIS data for a domain, IP, prefix, or ASN",),
    ),
    (
        "/v1/web",
        (
            "check whether a website is down",
            "inspect a website TLS certificate and security headers",
        ),
    ),
    (
        "/v1/mx",
        (
            "check MX configuration and mail deliverability",
            "diagnose an SMTP rejection or mail bounce",
        ),
    ),
    (
        "/v1/path",
        ("trace a network path and collect routing evidence",),
    ),
    (
        "/v1/ports",
        ("test whether a public TCP or UDP port is reachable",),
    ),
    (
        "/v1/nat",
        ("diagnose NAT, CGNAT, or port-forward reachability",),
    ),
    (
        "/v1/threat",
        ("check public threat and reputation evidence",),
    ),
    (
        "/v1/voip",
        ("diagnose SIP, SIP TLS, STUN, or TURN connectivity",),
    ),
)

_CAPABILITY_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/v1/vm", ("compute.ipv6", "vps.provision")),
    ("/v1/network", ("http.proxy", "privacy.networks")),
    ("/v1/bgp", ("network.bgp", "network.rpki")),
    ("/v1/ip", ("network.ip-intelligence",)),
    ("/v1/dns", ("dns.lookup", "dns.diagnostics")),
    ("/v1/rdap", ("registry.rdap",)),
    ("/v1/whois", ("registry.whois",)),
    ("/v1/web", ("web.reachability", "web.tls")),
    ("/v1/mx", ("mail.deliverability",)),
    ("/v1/path", ("network.path",)),
    ("/v1/ports", ("network.port-reachability",)),
    ("/v1/nat", ("network.nat-cgnat",)),
    ("/v1/threat", ("security.reputation",)),
    ("/v1/voip", ("network.voip-sip",)),
)


def _default_tags(path: str) -> tuple[str, ...]:
    for prefix, tags in _TAG_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return tags
    return ()


def _prefixed_values(
    path: str,
    table: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[str, ...]:
    for prefix, values in table:
        if path == prefix or path.startswith(prefix + "/"):
            return values
    return ()


def _capability_id(path: str) -> str:
    return "hyrule." + ".".join(
        segment.replace("{", "").replace("}", "")
        for segment in path.removeprefix("/v1/").split("/")
    )


@dataclass(frozen=True, slots=True)
class PaidOperation:
    method: str
    path: str
    description: str
    price: PriceSpec
    declaration: dict[str, Any]
    request_model: type[BaseModel] | None
    input_schema: dict[str, Any] | None
    input_example: dict[str, Any] | None
    output_example: Any
    path_examples: dict[str, Any]
    gate: str = "always"
    tags: tuple[str, ...] = ()
    capability_id: str = ""
    intents: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return self.method, self.path

    def accepts_input(self, value: Any) -> bool:
        """Whether a parsed body can safely reach its exact-price handler."""

        if self.request_model is None:
            return False
        try:
            self.request_model.model_validate(value)
        except ValidationError:
            return False
        return True


def _inline_defs(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve internal ``#/$defs/...`` references by substitution.

    Bazaar nests a route schema below its own extension schema. Root-relative
    Pydantic references would otherwise point at the wrong document root.
    """

    defs: dict[str, Any] = schema.get("$defs", {})

    def resolve(node: Any, seen: frozenset[str]) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                name = ref.removeprefix("#/$defs/")
                if name in seen:
                    return node
                target = resolve(defs.get(name, {}), seen | {name})
                return {**target, **{k: v for k, v in node.items() if k != "$ref"}}
            return {k: resolve(v, seen) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(item, seen) for item in node]
        return node

    resolved: dict[str, Any] = resolve(
        {k: v for k, v in schema.items() if k != "$defs"},
        frozenset(),
    )
    return resolved


def _flat_subject_schema(
    model_cls: type[BaseModel],
    *,
    type_description: str,
    value_description: str,
) -> dict[str, Any]:
    """Advertise a scalar subject form that discovery UIs can render.

    The request models accept both this form and the original nested
    ``subject`` object.  Keeping the Bazaar schema scalar avoids unusable
    marketplace rows such as ``subject | object | null`` while preserving
    backwards compatibility for existing clients.
    """

    schema = _inline_defs(model_cls.model_json_schema())
    properties = dict(schema.get("properties", {}))
    subject = properties.pop("subject", {})
    subject_properties = subject.get("properties", {})
    subject_type = dict(subject_properties.get("type", {"type": "string"}))
    subject_value = dict(subject_properties.get("value", {"type": "string"}))
    subject_type.update(
        {
            "title": "Subject Type",
            "description": type_description,
        }
    )
    subject_value.update(
        {
            "title": "Subject Value",
            "description": value_description,
        }
    )
    schema["properties"] = {
        "subject_type": subject_type,
        "subject_value": subject_value,
        **properties,
    }
    required = [name for name in schema.get("required", []) if name != "subject"]
    schema["required"] = ["subject_type", "subject_value", *required]
    return schema


def _json_body(
    model_cls: type[BaseModel],
    example: dict[str, Any],
    input_schema: dict[str, Any],
    output_model: type[BaseModel],
    output_example: Any,
) -> dict[str, Any]:
    # Keep examples executable, not merely illustrative. An invalid example is
    # especially harmful here because discovery clients may use it verbatim.
    model_cls.model_validate(example)
    output_model.model_validate(output_example)
    return declare_discovery_extension(
        input=example,
        input_schema=input_schema,
        body_type="json",
        output=OutputConfig(
            example=output_example,
            schema=_inline_defs(output_model.model_json_schema()),
        ),
    )


def _body_operation(
    path: str,
    description: str,
    price: PriceSpec,
    request_model: type[BaseModel],
    input_example: dict[str, Any],
    output_model: type[BaseModel],
    output_example: Any,
    *,
    gate: str = "always",
    input_schema: dict[str, Any] | None = None,
) -> PaidOperation:
    resolved_input_schema = input_schema or _inline_defs(request_model.model_json_schema())
    return PaidOperation(
        method="POST",
        path=path,
        description=description,
        price=price,
        declaration=_json_body(
            request_model,
            input_example,
            resolved_input_schema,
            output_model,
            output_example,
        ),
        request_model=request_model,
        input_schema=resolved_input_schema,
        input_example=input_example,
        output_example=output_example,
        path_examples={},
        gate=gate,
        tags=_default_tags(path),
        capability_id=_capability_id(path),
        intents=_prefixed_values(path, _INTENT_PREFIXES),
        capabilities=_prefixed_values(path, _CAPABILITY_PREFIXES),
    )


def _download_operation(
    path: str,
    description: str,
    price: PriceSpec,
    *,
    gate: str = "always",
) -> PaidOperation:
    path_examples = {"snapshot_id": "bgpsnap_a1b2c3d4"}
    input_schema = {
        "type": "object",
        "properties": {
            "snapshot_id": {
                "type": "string",
                "description": "Router-table snapshot identifier",
            }
        },
        "required": ["snapshot_id"],
    }
    output_example = "<gzip-compressed normalized JSONL>"
    declaration = declare_discovery_extension(
        path_params_schema=input_schema,
        output=OutputConfig(
            example=output_example,
            schema={"type": "string", "format": "binary"},
        ),
    )
    return PaidOperation(
        method="GET",
        path=path,
        description=description,
        price=price,
        declaration=declaration,
        request_model=None,
        input_schema=input_schema,
        input_example=path_examples,
        output_example=output_example,
        path_examples=path_examples,
        gate=gate,
        tags=_default_tags(path),
        capability_id=_capability_id(path),
        intents=_prefixed_values(path, _INTENT_PREFIXES),
        capabilities=_prefixed_values(path, _CAPABILITY_PREFIXES),
    )


def _fixed(field: str, default: str) -> PriceSpec:
    return PriceSpec("fixed", ((field, default),))


_VM_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_vm_xs", "0.20"),
        ("price_vm_sm", "0.40"),
        ("price_vm_md", "0.60"),
        ("price_vm_lg", "0.80"),
    ),
    # Duration and an optional registrar quote make a truthful upper bound
    # impossible at discovery time.
    bounded=False,
)
_PROXY_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_proxy_direct", "0.01"),
        ("price_proxy_tor", "0.05"),
        ("price_proxy_i2p", "0.05"),
        ("price_proxy_yggdrasil", "0.03"),
    ),
)
_BGP_LOOKUP_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_bgp_lookup", "0.005"),
        ("price_bgp_router_query", "0.01"),
    ),
)
_BGP_JOB_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_bgpstream_hour", "0.05"),
        ("price_bgpstream_rib", "0.10"),
    ),
)

_GENERATED_AT = "2026-07-15T00:00:00Z"


def _diagnostic_output(
    target: str,
    target_type: str,
    summary: str = "Diagnostic completed",
) -> dict[str, Any]:
    return {
        "request_id": "diag_a1b2c3d4",
        "status": "ok",
        "summary": summary,
        "target": {
            "input": target,
            "normalized": target,
            "type": target_type,
        },
        "findings": [{"severity": "ok", "code": "example", "message": "No issue found"}],
        "sources": {},
        "partial": False,
        "generated_at": _GENERATED_AT,
    }


_BGP_LOOKUP_OUTPUT = {
    "request_id": "bgp_a1b2c3d4",
    "subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"},
    "resolved": {
        "routed": True,
        "best_prefix": "2a0c:b641:b50::/44",
        "observed_origin_asns": [215932],
        "origins": [{"asn": 215932, "rpki": "valid", "sources": ["as215932"]}],
    },
    "results": {},
    "assertions": {},
    "sources": {},
    "partial": False,
    "charged_amount_usd": "0.005",
    "generated_at": _GENERATED_AT,
}
_IP_LOOKUP_OUTPUT = {
    "request_id": "ip_a1b2c3d4",
    "address": "2a0c:b641:b50::1",
    "network": {
        "asn": 215932,
        "asn_name": "Hyrule Networks",
        "prefix": "2a0c:b641:b50::/44",
        "registry": "RIPE",
    },
    "reverse_dns": [],
    "sources": {},
    "partial": False,
    "generated_at": _GENERATED_AT,
}
_DNS_LOOKUP_OUTPUT = {
    "request_id": "dns_a1b2c3d4",
    "question": {"name": "example.com", "type": "AAAA"},
    "answers": [
        {
            "name": "example.com",
            "type": "AAAA",
            "ttl": 300,
            "value": "2001:db8::1",
        }
    ],
    "authority": [],
    "additional": [],
    "rcode": "NOERROR",
    "resolver": "system",
    "trace": [],
    "generated_at": _GENERATED_AT,
}
_MX_CHECK_OUTPUT = {
    "request_id": "mx_a1b2c3d4",
    "tool": "mx",
    "target": "example.com",
    "status": "ok",
    "summary": "Mail exchanger records resolved",
    "findings": [],
    "sources": {},
    "generated_at": _GENERATED_AT,
}
_BGP_JOB_OUTPUT = {
    "job_id": "bgpj_a1b2c3d4",
    "job_access_token": "hyr_bgp_job_…",
    "status": "queued",
    "charged_amount_usd": "0.05",
    "status_url": "/v1/bgp/jobs/bgpj_a1b2c3d4",
    "created_at": _GENERATED_AT,
}
_MX_JOB_OUTPUT = {
    "job_id": "mxj_a1b2c3d4",
    "status": "completed",
    "target": "example.com",
    "profile": "mail_delivery",
    "results": [],
    "created_at": _GENERATED_AT,
}


PAID_OPERATIONS: tuple[PaidOperation, ...] = (
    _body_operation(
        "/v1/vm/create",
        "Provision an IPv6-native bare VM with SSH access",
        _VM_PRICE,
        models.VMCreateRequest,
        {
            "duration_days": 7,
            "size": "sm",
            "os": "debian-13",
            "ssh_pubkey": "ssh-ed25519 AAAA…",
            "domain_mode": "auto",
            "open_ports": [80, 443],
        },
        models.VMCreateResponse,
        {
            "vm_id": "vm_a1b2c3d4e5f6",
            "status": "provisioning",
            "status_url": "/v1/vm/vm_a1b2c3d4e5f6/status",
        },
        gate="real_vm",
    ),
    # Domain registration is intentionally absent. Its provider/readiness fix
    # is deferred to a separate PR and will opt the operation back in here.
    _body_operation(
        "/v1/network/request",
        "Make a micro-proxy network request over Direct, Tor, I2P, or Yggdrasil",
        _PROXY_PRICE,
        models.NetworkRequest,
        {
            "url": "https://example.com",
            "method": "GET",
            "proxy_mode": "direct",
            "timeout_seconds": 15,
        },
        models.NetworkResponse,
        {
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "body": "<html>…</html>",
            "elapsed_seconds": 0.12,
            "proxy_mode": "direct",
        },
    ),
    _body_operation(
        "/v1/bgp/lookup",
        "Paid BGP/routing lookup by prefix, IP, ASN, or AS215932 router-table dataset",
        _BGP_LOOKUP_PRICE,
        models.BGPLookupRequest,
        {
            "subject_type": "prefix",
            "subject_value": "2a0c:b641:b50::/44",
            "datasets": ["public_routing", "rpki"],
            "views": ["origins", "rpki"],
            "sources": ["auto"],
            "limit": 500,
        },
        models.BGPLookupResponse,
        _BGP_LOOKUP_OUTPUT,
        input_schema=_flat_subject_schema(
            models.BGPLookupRequest,
            type_description="Lookup subject kind: prefix, IP address, or ASN",
            value_description="CIDR prefix, IP address, or ASN/AS-prefixed ASN",
        ),
    ),
    _body_operation(
        "/v1/bgp/jobs",
        "Paid historical BGPStream job over RouteViews and RIPE RIS collectors",
        _BGP_JOB_PRICE,
        models.BGPStreamJobRequest,
        {
            "subject_type": "prefix",
            "subject_value": "2a0c:b641:b50::/44",
            "projects": ["routeviews", "ris"],
            "record_type": "updates",
            "collectors": [],
            "limit": 100000,
        },
        models.BGPJobResponse,
        _BGP_JOB_OUTPUT,
        gate="bgpstream_worker",
        input_schema=_flat_subject_schema(
            models.BGPStreamJobRequest,
            type_description="Historical BGP subject kind: prefix, IP address, or ASN",
            value_description="CIDR prefix, IP address, or ASN/AS-prefixed ASN",
        ),
    ),
    _download_operation(
        "/v1/bgp/snapshots/router/{snapshot_id}/download",
        "Paid AS215932 active router table snapshot download",
        _fixed("price_bgp_router_table", "0.10"),
        gate="bgp_router_snapshot_download",
    ),
    _body_operation(
        "/v1/ip/lookup",
        "Paid IP ASN/ISP, reverse DNS, RDAP/WHOIS, and BGP-context lookup",
        _fixed("price_ip_lookup", "0.003"),
        models.IPLookupRequest,
        {
            "address": "2a0c:b641:b50::1",
            "views": ["asn", "rdns", "rdap", "whois", "bgp"],
            "max_age_seconds": 3600,
        },
        models.IPLookupResponse,
        _IP_LOOKUP_OUTPUT,
    ),
    _body_operation(
        "/v1/dns/lookup",
        "Paid read-only DNS lookup, reverse lookup, resolver-validated DNSSEC (AD/DS), and trace diagnostics",
        _fixed("price_dns_lookup", "0.001"),
        models.DNSLookupRequest,
        {
            "name": "example.com",
            "type": "AAAA",
            "resolver": "system",
            "dnssec": False,
            "trace": False,
            "timeout_ms": 3000,
        },
        models.DNSLookupResponse,
        _DNS_LOOKUP_OUTPUT,
    ),
    _body_operation(
        "/v1/dns/propagation",
        "Paid DNS propagation comparison across public recursive resolvers",
        _fixed("price_dns_lookup", "0.001"),
        models.DNSPropagationRequest,
        {
            "name": "example.com",
            "type": "A",
            "expected": [],
            "resolvers": ["cloudflare", "google", "quad9", "system"],
            "authoritative": True,
            "timeout_ms": 3000,
        },
        models.DNSDiagnosticResponse,
        _diagnostic_output("example.com", "domain", "DNS propagation compared"),
    ),
    _body_operation(
        "/v1/rdap/lookup",
        "Paid structured RDAP lookup for domains, IPs, prefixes, ASNs, and entities",
        _fixed("price_rdap_lookup", "0.003"),
        models.RDAPLookupRequest,
        {
            "subject_type": "domain",
            "subject_value": "example.com",
            "include_raw": False,
            "max_age_seconds": 86400,
        },
        models.RDAPLookupResponse,
        {
            "request_id": "rdap_a1b2c3d4",
            "subject": {"type": "domain", "value": "example.com"},
            "registry": "Verisign",
            "parsed": {},
            "generated_at": _GENERATED_AT,
        },
        input_schema=_flat_subject_schema(
            models.RDAPLookupRequest,
            type_description="Registry subject kind: domain, IP, prefix, ASN, or entity",
            value_description="Domain, IP address, CIDR prefix, ASN, or entity handle",
        ),
    ),
    _body_operation(
        "/v1/whois/lookup",
        "Paid legacy WHOIS lookup for domains, IPs, prefixes/network blocks, and ASNs",
        _fixed("price_whois_lookup", "0.005"),
        models.WhoisLookupRequest,
        {
            "subject_type": "domain",
            "subject_value": "example.com",
            "include_raw": False,
            "max_age_seconds": 86400,
        },
        models.WhoisLookupResponse,
        {
            "request_id": "whois_a1b2c3d4",
            "subject": {"type": "domain", "value": "example.com"},
            "registry": "Verisign",
            "server": "whois.verisign-grs.com",
            "parsed": {},
            "redacted": True,
            "generated_at": _GENERATED_AT,
        },
        input_schema=_flat_subject_schema(
            models.WhoisLookupRequest,
            type_description="Registry subject kind: domain, IP, prefix, ASN, or entity",
            value_description="Domain, IP address, CIDR prefix, ASN, or entity handle",
        ),
    ),
    _body_operation(
        "/v1/web/check",
        "Paid web reachability, HTTP/HTTPS, TLS certificate, security headers, and CDN/WAF diagnostic check",
        _fixed("price_web_check", "0.005"),
        models.WebCheckRequest,
        {
            "target": "https://example.com",
            "checks": ["dns", "http", "tls", "cert", "headers", "cdn_waf"],
            "vantages": ["extmon"],
            "timeout_ms": 10000,
            "include_raw": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("https://example.com", "url", "Web diagnostic completed"),
    ),
    _body_operation(
        "/v1/web/tls/deep",
        "Paid deep TLS protocol, certificate, and negotiated-cipher scan with grade",
        _fixed("price_web_tls_deep", "0.10"),
        models.WebTLSDeepRequest,
        {
            "host": "example.com",
            "port": 443,
            "scan_profile": "ssl_labs_style",
            "checks": [
                "protocol_versions",
                "cipher_suites",
                "certificate_chain",
                "ocsp",
                "hsts",
                "caa",
                "security_headers",
            ],
            "include_raw": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "host", "Deep TLS scan completed"),
    ),
    _body_operation(
        "/v1/mx/check",
        "Paid MXToolbox-compatible diagnostic check for mail, DNS, blacklist, SMTP, and domain troubleshooting",
        _fixed("price_mx_check", "0.005"),
        models.MXCheckRequest,
        {"tool": "mx", "target": "example.com"},
        models.MXCheckResponse,
        _MX_CHECK_OUTPUT,
    ),
    _body_operation(
        "/v1/mx/bounce/parse",
        "Paid mail bounce/rejection parser and likely-cause classifier",
        _fixed("price_mx_check", "0.005"),
        models.MailBounceParseRequest,
        {"message": "550 5.7.26 unauthenticated email rejected"},
        models.MailBounceParseResponse,
        {
            "status": "warning",
            "classification": "auth_failure",
            "recommended_actions": ["Check SPF, DKIM, and DMARC alignment"],
        },
    ),
    _body_operation(
        "/v1/mx/jobs",
        "Paid full mail-delivery diagnostic report (synchronous, results returned inline)",
        _fixed("price_mx_report", "0.03"),
        models.MXJobRequest,
        {
            "profile": "mail_delivery",
            "target": "example.com",
            "checks": [],
        },
        models.MXJobResponse,
        _MX_JOB_OUTPUT,
    ),
    _body_operation(
        "/v1/path/report",
        "Paid routing/path evidence pack using extmon, AS215932, BGP/RPKI, and optional multi-vantage sources",
        _fixed("price_path_report", "0.05"),
        models.PathReportRequest,
        {
            "target": "example.com",
            "address_family": "auto",
            "vantages": ["extmon", "as215932", "globalping"],
            "checks": ["ping", "traceroute", "mtr", "bgp", "rpki", "router_table"],
            "max_duration_seconds": 60,
            "include_raw": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "host", "Path evidence pack completed"),
        gate="path_report",
    ),
    _body_operation(
        "/v1/path/ping",
        "Paid ping/path probe from approved Hyrule diagnostic vantages",
        _fixed("price_path_probe", "0.005"),
        models.PathProbeRequest,
        {
            "target": "example.com",
            "probe": "ping",
            "address_family": "auto",
            "vantages": ["extmon"],
            "count": 4,
            "timeout_ms": 10000,
        },
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "host", "Path probe completed"),
        gate="path_probe",
    ),
    _body_operation(
        "/v1/ports/check",
        "Paid outside-in single declared service reachability check with strict port allowlist",
        _fixed("price_port_check", "0.003"),
        models.PortCheckRequest,
        {
            "target": "example.com",
            "port": 443,
            "protocol": "tcp",
            "profile": "https",
            "vantage": "extmon",
            "timeout_ms": 5000,
            "include_banner": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("example.com:443", "host", "Port is reachable"),
    ),
    _body_operation(
        "/v1/nat/port-forward/check",
        "Paid outside-in NAT port-forward reachability check for one declared service",
        _fixed("price_nat_port_forward_check", "0.005"),
        models.NATPortForwardCheckRequest,
        {
            "target": "example.com",
            "port": 443,
            "protocol": "tcp",
            "profile": "https",
            "vantage": "extmon",
            "timeout_ms": 5000,
            "include_banner": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("example.com:443", "host", "Port forward is reachable"),
    ),
    _body_operation(
        "/v1/threat/lookup",
        "Paid open-source-first threat/reputation lookup with licensed provider adapters disabled until configured",
        _fixed("price_threat_lookup", "0.01"),
        models.ThreatLookupRequest,
        {
            "subject_type": "domain",
            "subject_value": "example.com",
            "views": ["rbl", "ct", "rdap", "whois", "dns", "reputation"],
            "include_raw": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "domain", "Threat lookup completed"),
        gate="threat",
        input_schema=_flat_subject_schema(
            models.ThreatLookupRequest,
            type_description="Threat subject kind: domain, IP, certificate, or URL",
            value_description="Domain, IP address, certificate identifier, or URL",
        ),
    ),
    _body_operation(
        "/v1/voip/check",
        "Paid SIP DNS, SIP TLS, OPTIONS, STUN/TURN diagnostic check",
        _fixed("price_voip_check", "0.01"),
        models.VoIPCheckRequest,
        {
            "target": "sip.example.com",
            "checks": ["sip_dns", "sip_tls"],
            "sip_port": 5061,
            "timeout_ms": 10000,
            "include_raw": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output("sip.example.com", "host", "SIP diagnostic completed"),
    ),
    _body_operation(
        "/v1/voip/number/lookup",
        "Paid pluggable number carrier/CNAM/spam/E911 lookup",
        _fixed("price_voip_number_lookup", "0.05"),
        models.VoIPNumberLookupRequest,
        {
            "number": "+31201234567",
            "country": "NL",
            "checks": ["number_intel", "cnam", "spam_reputation", "e911"],
            "include_raw": False,
        },
        models.DiagnosticResponse,
        _diagnostic_output(
            "+31201234567",
            "phone_number",
            "Number intelligence lookup completed",
        ),
        gate="voip_number",
    ),
)


_OPERATIONS_BY_KEY = {operation.key: operation for operation in PAID_OPERATIONS}
_PATH_MATCHERS = tuple(
    (operation, compile_path(operation.path)[0]) for operation in PAID_OPERATIONS
)

# Compatibility export used by PaymentGate and existing integration tests.
DISCOVERY: dict[tuple[str, str], dict[str, Any]] = {
    operation.key: operation.declaration for operation in PAID_OPERATIONS
}


def _gate_enabled(gate: str) -> bool:
    if gate == "always":
        return True
    if gate == "real_vm":
        from hyrule_cloud.services.launch_proof import use_real_provisioning

        return use_real_provisioning()
    if gate in {"path_probe", "path_report"}:
        from hyrule_cloud.services.path.diagnostics import path_active_probe_enabled

        vantages = (
            models.PATH_PROBE_DEFAULT_VANTAGES
            if gate == "path_probe"
            else models.PATH_REPORT_DEFAULT_VANTAGES
        )
        return path_active_probe_enabled(vantages)
    if gate == "threat":
        from hyrule_cloud.services.threat.lookup import threat_intel_enabled

        return threat_intel_enabled()
    if gate == "voip_number":
        from hyrule_cloud.services.voip.diagnostics import number_intel_enabled

        return number_intel_enabled()
    if gate == "bgpstream_worker":
        from hyrule_cloud.services.bgp.stream import bgpstream_worker_enabled

        return bgpstream_worker_enabled()
    if gate == "bgp_router_snapshot_download":
        from hyrule_cloud.services.bgp.snapshots import router_snapshot_download_enabled

        return router_snapshot_download_enabled()
    raise ValueError(f"Unknown paid-operation gate: {gate}")


def enabled_paid_operations() -> tuple[PaidOperation, ...]:
    """Return the launch catalog after applying deployment readiness gates."""

    return tuple(operation for operation in PAID_OPERATIONS if _gate_enabled(operation.gate))


def discovery_for(method: str, path: str) -> dict[str, Any] | None:
    operation = _OPERATIONS_BY_KEY.get((method.upper(), path))
    if operation is None or not _gate_enabled(operation.gate):
        return None
    return operation.declaration


def match_enabled_operation(method: str, concrete_path: str) -> PaidOperation | None:
    """Match a request URL to an enabled catalog path template."""

    wanted_method = method.upper()
    normalized_path = concrete_path.rstrip("/") or "/"
    for operation, path_regex in _PATH_MATCHERS:
        if operation.method != wanted_method or not _gate_enabled(operation.gate):
            continue
        if path_regex.fullmatch(normalized_path):
            return operation
    return None


def match_enabled_operation_any_method(concrete_path: str) -> PaidOperation | None:
    """Match a request path to an enabled operation regardless of method.

    Catalog paths are method-unique, so this is unambiguous; used where only
    the URL survives (402 resource-metadata construction in PaymentGate).
    """
    normalized_path = concrete_path.rstrip("/") or "/"
    for operation, path_regex in _PATH_MATCHERS:
        if not _gate_enabled(operation.gate):
            continue
        if path_regex.fullmatch(normalized_path):
            return operation
    return None


_CATALOG_PHRASES: tuple[tuple[str, str], ...] = (
    ("/v1/vm", "IPv6-native compute"),
    ("/v1/network", "outbound requests over Direct, Tor, I2P, or Yggdrasil"),
    ("/v1/bgp", "BGP/routing intelligence"),
    ("/v1/ip", "IP/ASN intelligence"),
    ("/v1/dns", "DNS diagnostics"),
    ("/v1/rdap", "RDAP/WHOIS registry lookups"),
    ("/v1/whois", "RDAP/WHOIS registry lookups"),
    ("/v1/web", "web and deep TLS checks"),
    ("/v1/mx", "mail deliverability"),
    ("/v1/path", "multi-vantage path evidence"),
    ("/v1/ports", "outside-in port reachability"),
    ("/v1/nat", "NAT port-forward checks"),
    ("/v1/threat", "threat/reputation lookups"),
    ("/v1/voip", "VoIP/SIP diagnostics"),
)


def service_overview() -> str:
    """Marketplace-ready capability copy assembled from enabled routes only.

    Generated from live gate state so a product that is gated off (VM
    simulation, missing prober/worker/provider) can never appear in
    manifest/OpenAPI marketing copy.
    """
    enabled_paths = [operation.path for operation in enabled_paid_operations()]
    phrases: list[str] = []
    for prefix, phrase in _CATALOG_PHRASES:
        if phrase in phrases:
            continue
        if any(path == prefix or path.startswith(prefix + "/") for path in enabled_paths):
            phrases.append(phrase)
    return (
        "Hyrule Cloud is pay-per-use infrastructure for AI agents on AS215932: "
        + ", ".join(phrases)
        + ". Calls settle in USDC via x402."
    )


def catalog_description() -> str:
    """Public catalog description plus current launch-scope caveats."""

    return f"{service_overview()} Domain registration is deferred from this launch catalog."


def marketplace_resource_description(operation: PaidOperation) -> str:
    """Make any endpoint safe for a marketplace to select as service copy.

    Agentic Market currently derives its service overview from one endpoint's
    resource description.  Prefixing every indexed resource with the real
    service scope prevents an arbitrary route (for example MX diagnostics)
    from being mistaken for the whole product.
    """

    endpoint = operation.description.rstrip(".")
    return f"{service_overview()} This endpoint: {endpoint}."


def build_x402_manifest(config: HyruleConfig) -> dict[str, Any]:
    public_base_url = str(getattr(config, "public_base_url", "https://cloud.hyrule.host")).rstrip(
        "/"
    )
    resources: list[dict[str, Any]] = []
    for operation in enabled_paid_operations():
        resource: dict[str, Any] = {
            "id": operation.capability_id,
            "path": operation.path,
            "method": operation.method,
            "description": operation.description,
            "minPrice": str(operation.price.minimum(config.payment)),
            "price": operation.price.openapi(config.payment),
            "networks": getattr(config.payment, "networks", []),
            "discoverable": True,
            "intents": list(operation.intents),
            "capabilities": list(operation.capabilities),
            "inputSchema": operation.input_schema or {},
            "inputExample": operation.input_example or {},
            "documentationUrl": f"{public_base_url}/openapi.json",
        }
        maximum = operation.price.maximum(config.payment)
        if maximum is not None:
            resource["maxPrice"] = str(maximum)
        resources.append(resource)
    return {
        "x402Version": 2,
        "name": "Hyrule Cloud",
        "description": catalog_description(),
        "intents": sorted(
            {intent for operation in enabled_paid_operations() for intent in operation.intents}
        ),
        "capabilities": sorted(
            {
                capability
                for operation in enabled_paid_operations()
                for capability in operation.capabilities
            }
        ),
        "resources": resources,
        "facilitator": getattr(config.payment, "facilitator_url", ""),
        "contact": "https://github.com/AS215932",
    }


_PAYMENT_REQUIRED_SCHEMA = {
    "type": "object",
    "required": ["x402Version", "accepts", "payment_required"],
    "properties": {
        "x402Version": {"type": "integer", "const": 2},
        "accepts": {"type": "array", "items": {"type": "object"}, "minItems": 1},
        "payment_required": {"type": "boolean", "const": True},
        "resource": {"type": "object"},
        "extensions": {"type": "object"},
        "error": {"type": "string"},
        "amount": {"type": "string"},
        "description": {"type": "string"},
    },
    "additionalProperties": True,
}

_SECURITY_SCHEMES = {
    "HyruleApiKey": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "hyr_sk_<secret>",
        "description": (
            "Scoped Hyrule account API key. Each scoped operation publishes its required "
            "key scopes in x-hyrule-required-api-key-scopes."
        ),
    },
    "HyruleSession": {
        "type": "apiKey",
        "in": "cookie",
        "name": "hyr_sess",
        "description": "Opaque Hyrule browser session cookie.",
    },
    "HyruleBGPIngestToken": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Hyrule-BGP-Ingest-Token",
        "description": "Internal BGP worker credential.",
    },
}


def _dependency_metadata(route: APIRoute) -> tuple[set[Any], set[str]]:
    calls: set[Any] = set()
    scopes: set[str] = set()

    def visit(dependant: Any) -> None:
        for dependency in getattr(dependant, "dependencies", []):
            call = getattr(dependency, "call", None)
            if call is not None:
                calls.add(call)
                required = getattr(call, "__hyrule_required_scopes__", ())
                if isinstance(required, (tuple, list, set, frozenset)):
                    scopes.update(scope for scope in required if isinstance(scope, str))
            visit(dependency)

    visit(route.dependant)
    return calls, scopes


def _annotate_security(schema: dict[str, Any], application: FastAPI) -> None:
    components = schema.setdefault("components", {})
    components.setdefault("securitySchemes", {}).update(_SECURITY_SCHEMES)
    for route in application.routes:
        if not isinstance(route, APIRoute) or not route.include_in_schema:
            continue
        calls, required_scopes = _dependency_metadata(route)
        security: list[dict[str, list[str]]]
        if route.path.startswith("/v1/internal/bgp"):
            security = [{"HyruleBGPIngestToken": []}]
        elif require_browser_session in calls:
            security = [{"HyruleSession": []}]
        elif require_account in calls:
            security = [{"HyruleApiKey": []}, {"HyruleSession": []}]
        else:
            continue
        path_item = schema.get("paths", {}).get(route.path, {})
        for method in route.methods or set():
            operation = path_item.get(method.lower())
            if isinstance(operation, dict):
                operation["security"] = security
                if required_scopes:
                    operation["x-hyrule-required-api-key-scopes"] = sorted(required_scopes)


def _annotate_operation(
    schema: dict[str, Any],
    operation: PaidOperation,
    payment: PaymentConfig,
) -> None:
    openapi_operation = schema["paths"][operation.path][operation.method.lower()]
    openapi_operation["security"] = []
    openapi_operation["x-payment-info"] = {
        "price": operation.price.openapi(payment),
        "protocols": [{"x402": {}}],
    }
    openapi_operation["x-hyrule-capability-id"] = operation.capability_id
    openapi_operation["x-hyrule-intents"] = list(operation.intents)
    openapi_operation["x-hyrule-capabilities"] = list(operation.capabilities)
    openapi_operation.setdefault("summary", operation.description)
    openapi_operation.setdefault("description", operation.description)

    request_body = openapi_operation.get("requestBody")
    if operation.input_example is not None and isinstance(request_body, dict):
        json_content = request_body.get("content", {}).get("application/json")
        if isinstance(json_content, dict):
            if operation.input_schema is not None:
                json_content["schema"] = operation.input_schema
            json_content["example"] = operation.input_example

    for parameter in openapi_operation.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        name = parameter.get("name")
        if name in operation.path_examples:
            parameter["required"] = True
            parameter["example"] = operation.path_examples[name]

    responses = openapi_operation.setdefault("responses", {})
    responses["402"] = {
        "description": "Payment Required",
        "headers": {
            "Payment-Required": {
                "description": "Base64-encoded x402 v2 payment requirements",
                "schema": {"type": "string"},
            }
        },
        "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/X402PaymentRequired"}}
        },
    }

    for status, response in responses.items():
        if not str(status).startswith("2") or not isinstance(response, dict):
            continue
        content = response.get("content")
        if not isinstance(content, dict) or not content:
            continue
        for media in content.values():
            if isinstance(media, dict):
                media.setdefault("example", operation.output_example)


def build_full_openapi(application: FastAPI, config: HyruleConfig) -> dict[str, Any]:
    """Generate the complete API contract and annotate its payable subset."""

    enabled = enabled_paid_operations()
    schema = get_openapi(
        title=application.title,
        version=application.version,
        openapi_version=application.openapi_version,
        summary=application.summary,
        description=application.description,
        routes=application.routes,
        tags=application.openapi_tags,
        servers=application.servers,
        terms_of_service=application.terms_of_service,
        contact=application.contact,
        license_info=application.license_info,
        separate_input_output_schemas=bool(
            getattr(application, "separate_input_output_schemas", True)
        ),
        external_docs=application.openapi_external_docs,
    )
    schema["info"]["x-guidance"] = (
        "This is the complete Hyrule Cloud API contract. Operations carrying "
        "x-payment-info are independently payable x402 v2 resources; call one "
        "without payment to receive Payment-Required, then retry the same "
        "request with Payment-Signature. Operations without x-payment-info may "
        "be free, authenticated, account-scoped, or readiness-gated."
    )
    schema["info"]["x-hyrule-x402-manifest"] = "/.well-known/x402.json"
    schema.setdefault("components", {}).setdefault("schemas", {})["X402PaymentRequired"] = (
        _PAYMENT_REQUIRED_SCHEMA
    )
    _annotate_security(schema, application)

    for operation in enabled:
        _annotate_operation(schema, operation, config.payment)

    return schema
