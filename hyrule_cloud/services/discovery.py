"""Curated x402 launch catalog and its machine-readable projections.

The catalog in this module is the single source of truth for everything Hyrule
advertises as a payable agent resource:

* ``/openapi.json`` (x402scan's canonical discovery source)
* ``/.well-known/x402.json`` (Hyrule compatibility manifest)
* Bazaar declarations attached to runtime 402 challenges
* the pre-validation unpaid challenge middleware

Only launch-ready, independently payable operations belong here. Callable
management, identity, internal, convenience, and contract-only routes remain
outside the catalog and therefore outside the curated OpenAPI document.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal

from cryptography.fernet import Fernet
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError
from starlette.routing import compile_path
from x402.extensions.bazaar import OutputConfig, declare_discovery_extension

from hyrule_cloud import models
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.domains.models import AgentDomainOrderRequest, AgentDomainOrderResponse
from hyrule_cloud.mail.models import (
    MailAccountCreateRequest,
    MailAccountResponse,
    MailSendRequest,
    MailSendResponse,
)

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
            Decimal(str(getattr(payment, field, default)))
            for field, default in self.fields
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
    ("/v1/mail", ("email", "agent-mail")),
    ("/v1/domains/agent", ("domains", "identity")),
    ("/v1/path", ("network-intel", "looking-glass")),
    ("/v1/ports", ("network-intel", "reachability")),
    ("/v1/nat", ("network-intel", "reachability")),
    ("/v1/threat", ("network-intel", "reputation")),
    ("/v1/voip", ("network-intel", "voip")),
)


def _default_tags(path: str) -> tuple[str, ...]:
    for prefix, tags in _TAG_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return tags
    return ()


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
    )


def _download_operation(
    path: str,
    description: str,
    price: PriceSpec,
    *,
    gate: str = "always",
) -> PaidOperation:
    path_examples = {"snapshot_id": "bgpsnap_a1b2c3d4"}
    output_example = "<gzip-compressed normalized JSONL>"
    declaration = declare_discovery_extension(
        path_params_schema={
            "type": "object",
            "properties": {
                "snapshot_id": {
                    "type": "string",
                    "description": "Router-table snapshot identifier",
                }
            },
            "required": ["snapshot_id"],
        },
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
        input_schema=None,
        input_example=None,
        output_example=output_example,
        path_examples=path_examples,
        gate=gate,
        tags=_default_tags(path),
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
_MAIL_ACTIVATION_PRICE = PriceSpec(
    "dynamic",
    (("price_mail_activation", "1.00"),),
    # A combined domain + mailbox checkout includes a live registrar quote.
    bounded=False,
)
_AGENT_DOMAIN_PRICE = PriceSpec(
    "dynamic",
    (("price_domain_markup", "1.00"),),
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
        "findings": [
            {"severity": "ok", "code": "example", "message": "No issue found"}
        ],
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
        "Provision a bare VM with SSH access",
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
    _body_operation(
        "/v1/domains/agent/orders",
        "Buy a managed domain without creating a Hyrule account",
        _AGENT_DOMAIN_PRICE,
        AgentDomainOrderRequest,
        {
            "quote_id": "dq_a1b2c3d4",
            "terms_version": "2026-07-15",
        },
        AgentDomainOrderResponse,
        {
            "order_id": "do_a1b2c3d4",
            "domain": "prompttoproof.dev",
            "action": "register",
            "status": "queued",
            "amount_usd": "13.00",
            "payment_method": "usdc",
            "management_token": "hyr_dom_…",
            "status_url": "/v1/domains/agent/orders/do_a1b2c3d4",
            "created_at": _GENERATED_AT,
            "updated_at": _GENERATED_AT,
        },
        gate="agent_domains",
    ),
    _body_operation(
        "/v1/mail/accounts",
        "Activate an API-only agent mailbox for 30 days, optionally with a new domain",
        _MAIL_ACTIVATION_PRICE,
        MailAccountCreateRequest,
        {"quote_id": "mailq_a1b2c3d4"},
        MailAccountResponse,
        {
            "mailbox_id": "mbx_a1b2c3d4",
            "address": "agent@prompttoproof.dev",
            "mode": "domain_and_mailbox",
            "status": "pending_domain",
            "management_token": "hyr_identity_…",
            "status_url": "/v1/mail/accounts/mbx_a1b2c3d4",
            "messages_url": "/v1/mail/accounts/mbx_a1b2c3d4/messages",
            "send_quote_url": "/v1/mail/messages/send/quote",
            "domain_order_id": "do_a1b2c3d4",
            "domain_status_url": "/v1/domains/agent/orders/do_a1b2c3d4",
            "charged_amount_usd": "14.00",
            "auto_renew": False,
        },
        gate="mail",
    ),
    _body_operation(
        "/v1/mail/messages/send",
        "Send one conversation-safe Agent Mail message to one recipient",
        _fixed("price_mail_send", "0.01"),
        MailSendRequest,
        {"quote_id": "mailq_send_a1b2c3d4"},
        MailSendResponse,
        {
            "send_id": "send_a1b2c3d4",
            "mailbox_id": "mbx_a1b2c3d4",
            "message_id": "jmap_message_id",
            "status": "accepted",
            "recipient": "proof-recipient@example.net",
            "accepted_at": _GENERATED_AT,
            "charged_amount_usd": "0.01",
            "delivery_is_final": False,
        },
        gate="mail",
    ),
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
    if gate == "mail":
        return HyruleConfig().mail.public_ready
    if gate == "agent_domains":
        config = HyruleConfig()
        provider = config.openprovider
        try:
            Fernet(config.domain.agent_order_fernet_key.encode())
        except (TypeError, ValueError):
            return False
        return bool(
            config.domain.enabled
            and config.domain.agent_purchases_enabled
            and config.domain.legal_approved
            and config.domain.tax_approved
            and config.domain.dns_control_url
            and config.domain.dns_control_secret
            and config.domain.agent_order_fernet_key
            and provider.username
            and provider.password
            and provider.owner_handle
            and provider.admin_handle
            and provider.tech_handle
            and provider.billing_handle
        )
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
    ("/v1/mail", "API-only email accounts for agents"),
    ("/v1/domains/agent", "wallet-native managed domains"),
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

    return service_overview()


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
    resources: list[dict[str, Any]] = []
    for operation in enabled_paid_operations():
        resource: dict[str, Any] = {
            "path": operation.path,
            "method": operation.method,
            "description": operation.description,
            "minPrice": str(operation.price.minimum(config.payment)),
            "networks": getattr(config.payment, "networks", []),
            "discoverable": True,
        }
        maximum = operation.price.maximum(config.payment)
        if maximum is not None:
            resource["maxPrice"] = str(maximum)
        resources.append(resource)
    return {
        "x402Version": 2,
        "name": "Hyrule Cloud",
        "description": catalog_description(),
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
    openapi_operation.setdefault("summary", operation.description)

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
            "application/json": {
                "schema": {"$ref": "#/components/schemas/X402PaymentRequired"}
            }
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


def build_curated_openapi(application: FastAPI, config: HyruleConfig) -> dict[str, Any]:
    """Generate the sole OpenAPI document from enabled launch operations."""

    enabled = enabled_paid_operations()
    enabled_keys = {operation.key for operation in enabled}
    selected_routes = [
        route
        for route in application.routes
        if isinstance(route, APIRoute)
        and any((method.upper(), route.path) in enabled_keys for method in route.methods)
    ]
    schema = get_openapi(
        title=application.title,
        version=application.version,
        openapi_version=application.openapi_version,
        summary=application.summary,
        description=(
            f"{catalog_description()} This OpenAPI document intentionally contains only "
            "the launch-ready, independently payable agent surface."
        ),
        routes=selected_routes,
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
        "Every operation in this document is an independently payable x402 v2 "
        "resource. Call it without payment to receive the Payment-Required "
        "challenge, then retry the same method, URL, and input with a valid "
        "payment signature. Routes omitted from this document are not part of "
        "the agent launch catalog."
    )
    schema.setdefault("components", {}).setdefault("schemas", {})[
        "X402PaymentRequired"
    ] = _PAYMENT_REQUIRED_SCHEMA

    for operation in enabled:
        _annotate_operation(schema, operation, config.payment)

    # Be exact even if a future APIRoute gains more than one method.
    for path, path_item in list(schema.get("paths", {}).items()):
        for method in list(path_item):
            if method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}:
                if (method.upper(), path) not in enabled_keys:
                    del path_item[method]
        if not any((method.upper(), path) in enabled_keys for method in path_item):
            del schema["paths"][path]

    return schema
