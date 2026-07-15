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

from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.routing import compile_path
from x402.extensions.bazaar import OutputConfig, declare_discovery_extension

from hyrule_cloud import models
from hyrule_cloud.config import HyruleConfig, PaymentConfig

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


@dataclass(frozen=True, slots=True)
class PaidOperation:
    method: str
    path: str
    description: str
    price: PriceSpec
    declaration: dict[str, Any]
    input_example: dict[str, Any] | None
    output_example: Any
    path_examples: dict[str, Any]
    gate: str = "always"

    @property
    def key(self) -> tuple[str, str]:
        return self.method, self.path


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


def _json_body(
    model_cls: type[BaseModel],
    example: dict[str, Any],
    output_model: type[BaseModel],
    output_example: Any,
) -> dict[str, Any]:
    # Keep examples executable, not merely illustrative. An invalid example is
    # especially harmful here because discovery clients may use it verbatim.
    model_cls.model_validate(example)
    output_model.model_validate(output_example)
    return declare_discovery_extension(
        input=example,
        input_schema=_inline_defs(model_cls.model_json_schema()),
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
) -> PaidOperation:
    return PaidOperation(
        method="POST",
        path=path,
        description=description,
        price=price,
        declaration=_json_body(
            request_model,
            input_example,
            output_model,
            output_example,
        ),
        input_example=input_example,
        output_example=output_example,
        path_examples={},
        gate=gate,
    )


def _download_operation(
    path: str,
    description: str,
    price: PriceSpec,
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
        input_example=None,
        output_example=output_example,
        path_examples=path_examples,
    )


def _fixed(field: str, default: str) -> PriceSpec:
    return PriceSpec("fixed", ((field, default),))


_VM_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_vm_xs", "0.05"),
        ("price_vm_sm", "0.10"),
        ("price_vm_md", "0.20"),
        ("price_vm_lg", "0.40"),
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
    # Domain registration is intentionally absent. Its provider/readiness fix
    # is deferred to a separate PR and will opt the operation back in here.
    _body_operation(
        "/v1/network/request",
        "Make a micro-proxy network request over Direct, Tor, I2P, or Yggdrasil",
        _PROXY_PRICE,
        models.NetworkRequest,
        {"url": "https://example.com", "method": "GET", "proxy_mode": "direct"},
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
        {"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}},
        models.BGPLookupResponse,
        _BGP_LOOKUP_OUTPUT,
    ),
    _body_operation(
        "/v1/bgp/jobs",
        "Paid historical BGPStream job over RouteViews and RIPE RIS collectors",
        _BGP_JOB_PRICE,
        models.BGPStreamJobRequest,
        {
            "subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"},
            "record_type": "updates",
        },
        models.BGPJobResponse,
        _BGP_JOB_OUTPUT,
    ),
    _download_operation(
        "/v1/bgp/snapshots/router/{snapshot_id}/download",
        "Paid AS215932 active router table snapshot download",
        _fixed("price_bgp_router_table", "0.10"),
    ),
    _body_operation(
        "/v1/ip/lookup",
        "Paid IP geolocation, ASN/ISP, reverse DNS, RDAP/WHOIS, reputation, and BGP-context lookup",
        _fixed("price_ip_lookup", "0.003"),
        models.IPLookupRequest,
        {"address": "2a0c:b641:b50::1"},
        models.IPLookupResponse,
        _IP_LOOKUP_OUTPUT,
    ),
    _body_operation(
        "/v1/dns/lookup",
        "Paid read-only DNS lookup, reverse lookup, DNSSEC, and trace diagnostics",
        _fixed("price_dns_lookup", "0.001"),
        models.DNSLookupRequest,
        {"name": "example.com", "type": "AAAA"},
        models.DNSLookupResponse,
        _DNS_LOOKUP_OUTPUT,
    ),
    _body_operation(
        "/v1/dns/propagation",
        "Paid DNS propagation comparison across public recursive resolvers",
        _fixed("price_dns_lookup", "0.001"),
        models.DNSPropagationRequest,
        {"name": "example.com", "type": "A"},
        models.DNSDiagnosticResponse,
        _diagnostic_output("example.com", "domain", "DNS propagation compared"),
    ),
    _body_operation(
        "/v1/dns/recommend-records",
        "Paid DNS record recommendations for web, mail, SIP, verification, and reverse DNS workflows",
        _fixed("price_dns_lookup", "0.001"),
        models.DNSRecordRecommendationRequest,
        {
            "domain": "example.com",
            "use_case": "web",
            "ipv6": "2a0c:b641:b50::1",
        },
        models.DNSDiagnosticResponse,
        _diagnostic_output("example.com", "domain", "DNS records recommended"),
    ),
    _body_operation(
        "/v1/rdap/lookup",
        "Paid structured RDAP lookup for domains, IPs, prefixes, ASNs, and entities",
        _fixed("price_rdap_lookup", "0.003"),
        models.RDAPLookupRequest,
        {"subject": {"type": "domain", "value": "example.com"}},
        models.RDAPLookupResponse,
        {
            "request_id": "rdap_a1b2c3d4",
            "subject": {"type": "domain", "value": "example.com"},
            "registry": "Verisign",
            "parsed": {},
            "generated_at": _GENERATED_AT,
        },
    ),
    _body_operation(
        "/v1/whois/lookup",
        "Paid legacy WHOIS lookup for domains, IPs, prefixes/network blocks, and ASNs",
        _fixed("price_whois_lookup", "0.005"),
        models.WhoisLookupRequest,
        {"subject": {"type": "domain", "value": "example.com"}},
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
    ),
    _body_operation(
        "/v1/web/check",
        "Paid web reachability, HTTP/HTTPS, TLS certificate, security headers, and CDN/WAF diagnostic check",
        _fixed("price_web_check", "0.005"),
        models.WebCheckRequest,
        {"target": "https://example.com"},
        models.DiagnosticResponse,
        _diagnostic_output("https://example.com", "url", "Web diagnostic completed"),
    ),
    _body_operation(
        "/v1/web/tls/deep",
        "Paid Hyrule-native SSL Labs-style deep TLS scanner and grade",
        _fixed("price_web_tls_deep", "0.10"),
        models.WebTLSDeepRequest,
        {"host": "example.com", "port": 443},
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
        "/v1/mx/recommend-records",
        "Paid SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and BIMI recommendation engine",
        _fixed("price_mx_check", "0.005"),
        models.MailRecordRecommendationRequest,
        {"domain": "example.com", "provider": "custom"},
        models.MailRecordRecommendationResponse,
        {"domain": "example.com", "provider": "custom", "records": []},
    ),
    _body_operation(
        "/v1/mx/jobs",
        "Paid full mail-delivery diagnostic report (synchronous, results returned inline)",
        _fixed("price_mx_report", "0.03"),
        models.MXJobRequest,
        {"profile": "mail_delivery", "target": "example.com"},
        models.MXJobResponse,
        _MX_JOB_OUTPUT,
    ),
    _body_operation(
        "/v1/path/report",
        "Paid routing/path evidence pack using extmon, AS215932, BGP/RPKI, and optional multi-vantage sources",
        _fixed("price_path_report", "0.05"),
        models.PathReportRequest,
        {"target": "example.com"},
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "host", "Path evidence pack completed"),
        gate="path_report",
    ),
    _body_operation(
        "/v1/path/ping",
        "Paid ping/path probe from approved Hyrule diagnostic vantages",
        _fixed("price_path_probe", "0.005"),
        models.PathProbeRequest,
        {"target": "example.com"},
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "host", "Path probe completed"),
        gate="path_probe",
    ),
    _body_operation(
        "/v1/ports/check",
        "Paid outside-in single declared service reachability check with strict port allowlist",
        _fixed("price_port_check", "0.003"),
        models.PortCheckRequest,
        {"target": "example.com", "port": 443},
        models.DiagnosticResponse,
        _diagnostic_output("example.com:443", "host", "Port is reachable"),
    ),
    _body_operation(
        "/v1/nat/lookup",
        "Paid server-only CGNAT/NAT hint report from caller and customer WAN/LAN evidence",
        _fixed("price_nat_lookup", "0.003"),
        models.NATLookupRequest,
        {"customer_reported_wan_ip": "100.64.1.1"},
        models.NATLookupResponse,
        {
            "cgnat_likely": True,
            "evidence": ["Customer WAN address is inside 100.64.0.0/10"],
        },
    ),
    _body_operation(
        "/v1/nat/port-forward/check",
        "Paid outside-in NAT port-forward reachability check for one declared service",
        _fixed("price_nat_port_forward_check", "0.005"),
        models.NATPortForwardCheckRequest,
        {"target": "example.com", "port": 443},
        models.DiagnosticResponse,
        _diagnostic_output("example.com:443", "host", "Port forward is reachable"),
    ),
    _body_operation(
        "/v1/threat/lookup",
        "Paid open-source-first threat/reputation lookup with licensed provider adapters disabled until configured",
        _fixed("price_threat_lookup", "0.01"),
        models.ThreatLookupRequest,
        {"subject": {"type": "domain", "value": "example.com"}},
        models.DiagnosticResponse,
        _diagnostic_output("example.com", "domain", "Threat lookup completed"),
        gate="threat",
    ),
    _body_operation(
        "/v1/voip/check",
        "Paid SIP DNS, SIP TLS, OPTIONS, STUN/TURN diagnostic check",
        _fixed("price_voip_check", "0.01"),
        models.VoIPCheckRequest,
        {"target": "sip.example.com"},
        models.DiagnosticResponse,
        _diagnostic_output("sip.example.com", "host", "SIP diagnostic completed"),
    ),
    _body_operation(
        "/v1/voip/number/lookup",
        "Paid pluggable number carrier/CNAM/spam/E911 lookup",
        _fixed("price_voip_number_lookup", "0.05"),
        models.VoIPNumberLookupRequest,
        {"number": "+31201234567"},
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
    for operation, path_regex in _PATH_MATCHERS:
        if operation.method != wanted_method or not _gate_enabled(operation.gate):
            continue
        if path_regex.fullmatch(concrete_path):
            return operation
    return None


_MANIFEST_DESCRIPTION = (
    "Launch-ready, first-party network infrastructure for AI agents on AS215932: "
    "IPv6-native compute, BGP/routing, IP/ASN and reputation, DNS diagnostics, "
    "RDAP/WHOIS, web and TLS, mail deliverability, port/NAT/CGNAT, VoIP/SIP, "
    "and outbound requests over Direct, Tor, I2P, or Yggdrasil. Pay per request "
    "in USDC via x402. Domain registration is deferred from this launch catalog."
)


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
        "description": _MANIFEST_DESCRIPTION,
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
        media = content.get("application/json") or next(iter(content.values()))
        if isinstance(media, dict):
            media.setdefault("example", operation.output_example)
        break


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
            f"{application.description} This OpenAPI document intentionally contains only "
            "the launch-ready, independently payable agent surface."
        ),
        routes=selected_routes,
        tags=application.openapi_tags,
        servers=application.servers,
        terms_of_service=application.terms_of_service,
        contact=application.contact,
        license_info=application.license_info,
        separate_input_output_schemas=application.separate_input_output_schemas,
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
