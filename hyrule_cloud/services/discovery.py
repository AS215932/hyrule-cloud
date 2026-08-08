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
from pydantic import BaseModel, ValidationError
from starlette.routing import compile_path
from x402.extensions.bazaar import OutputConfig, declare_discovery_extension

from hyrule_cloud import models
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.domains import models as domain_models

if TYPE_CHECKING:
    from fastapi import FastAPI


PriceMode = Literal["fixed", "dynamic"]


@dataclass(frozen=True, slots=True)
class PriceSpec:
    """Configuration-backed OpenAPI and preflight price metadata."""

    mode: PriceMode
    fields: tuple[tuple[str, str], ...]
    bounded: bool = True
    literal_min: Decimal | None = None

    def values(self, payment: PaymentConfig) -> tuple[Decimal, ...]:
        return tuple(
            Decimal(str(getattr(payment, field, default)))
            for field, default in self.fields
        )

    def minimum(self, payment: PaymentConfig) -> Decimal:
        if self.literal_min is not None:
            return self.literal_min
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
    ("/v1/domains", ("domains", "registration")),
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
    ("/v1/tunnel", ("tunnel", "ssh", "nat-traversal")),
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


@dataclass(frozen=True, slots=True)
class SupportingOperation:
    """A free route the curated OpenAPI publishes alongside the paid catalog.

    Paid operations alone are not a usable contract: an agent that reads only
    ``/openapi.json`` must also see the unpaid routes that complete each
    workflow (quotes, status polling, pricing, template catalog). These carry
    no 402 challenge and no Bazaar declaration — the manifest stays paid-only.
    """

    method: str
    path: str
    description: str
    gate: str = "always"

    @property
    def key(self) -> tuple[str, str]:
        return self.method, self.path


SUPPORTING_OPERATIONS: tuple[SupportingOperation, ...] = (
    SupportingOperation("GET", "/v1/pricing", "Current price list for all resources"),
    SupportingOperation(
        "GET", "/v1/products/vms", "Machine-readable VM catalog with customization pricing"
    ),
    SupportingOperation("GET", "/v1/os/list", "Available OS templates"),
    SupportingOperation(
        "GET",
        "/v1/payments/networks",
        "Enabled payment networks, receiver address, and facilitator",
    ),
    SupportingOperation(
        "POST",
        "/v1/vm/quote",
        "Lock a durable VM price quote (free; pass quote_id to POST /v1/vm/create)",
        gate="real_vm",
    ),
    SupportingOperation(
        "GET", "/v1/vm/quote/{quote_id}", "Reload a previously locked VM quote", gate="real_vm"
    ),
    SupportingOperation(
        "GET",
        "/v1/vm/{vm_id}/status",
        "Public provisioning and launch-proof status poll",
        gate="real_vm",
    ),
    SupportingOperation(
        "GET",
        "/v1/vm/{vm_id}",
        "Full VM view including SSH target (management token required)",
        gate="real_vm",
    ),
    SupportingOperation(
        "GET",
        "/v1/vm/{vm_id}/logs",
        "Provisioning log events (management token required)",
        gate="real_vm",
    ),
    SupportingOperation(
        "POST",
        "/v1/vm/{vm_id}/reboot",
        "Hard reboot a VM (management token required)",
        gate="real_vm",
    ),
    SupportingOperation(
        "DELETE",
        "/v1/vm/{vm_id}",
        "Destroy a VM permanently (management token required)",
        gate="real_vm",
    ),
)


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
_PROXY_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_proxy_direct", "0.01"),
        ("price_proxy_tor", "0.05"),
        ("price_proxy_i2p", "0.05"),
        ("price_proxy_yggdrasil", "0.03"),
    ),
)
_TUNNEL_PRICE = PriceSpec(
    "dynamic",
    (("price_tunnel_hourly", "0.05"),),
    # Total is hours * hourly (1-720h), so a truthful upper bound is impossible
    # at discovery time; advertise the per-hour minimum, like the VM price.
    bounded=False,
)
_BGP_LOOKUP_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_bgp_lookup", "0.005"),
        ("price_bgp_looking_glass", "0.01"),
        # price_bgp_router_query intentionally absent: /lookup never charges it
        # (see api/bgp.py::_lookup_price_attr) until the router vantage exists.
    ),
)
_BGP_JOB_PRICE = PriceSpec(
    "dynamic",
    (
        ("price_bgpstream_hour", "0.05"),
        ("price_bgpstream_rib", "0.10"),
    ),
)
_DOMAIN_REGISTRATION_PRICE = PriceSpec(
    "dynamic",
    (),
    bounded=False,
    # The provider component varies by TLD and live availability. Hyrule's
    # configured fee floor is a guaranteed lower bound for discovery.
    literal_min=Decimal("3.00"),
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
_DNS_BLOCKLIST_OUTPUT = {
    "request_id": "diag_a1b2c3d4",
    "input_domain": "example.com",
    "normalized_domain": "example.com",
    "verdict": "not_listed",
    "categories": [],
    "checked_source_count": 16,
    "matched_source_count": 0,
    "required_source_count": 16,
    "results": [
        {
            "source_id": "easylist",
            "source_name": "EasyList",
            "categories": ["ads"],
            "outcome": "not_listed",
            "source_status": "ok",
            "source_age_seconds": 300,
        }
    ],
    "catalog_version": "blcat_a1b2c3d4",
    "snapshot_id": "blsnap_20260719T000000-a1b2c3d4",
    "partial": False,
    "generated_at": _GENERATED_AT,
}
_DNS_FILTERING_OUTPUT = {
    "request_id": "diag_a1b2c3d4",
    "input_domain": "example.com",
    "normalized_domain": "example.com",
    "vantage": "hyrule",
    "overall": "allowed",
    "blocked_profile_count": 0,
    "allowed_profile_count": 8,
    "conclusive_profile_count": 8,
    "total_profile_count": 8,
    "profiles": [
        {
            "profile_id": "cloudflare_security",
            "name": "Cloudflare Malware Blocking",
            "provider": "Cloudflare",
            "categories": ["phishing", "malware"],
            "status": "allowed",
            "reason": "filtered resolver returned usable addresses",
            "filtered": [
                {
                    "record_type": "A",
                    "rcode": "NOERROR",
                    "answers": ["93.184.216.34"],
                    "latency_ms": 18.2,
                }
            ],
            "control": [
                {
                    "record_type": "A",
                    "rcode": "NOERROR",
                    "answers": ["93.184.216.34"],
                    "latency_ms": 16.4,
                }
            ],
            "observed_at": _GENERATED_AT,
        }
    ],
    "partial": False,
    "observed_at": _GENERATED_AT,
    "cache_age_seconds": 0,
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
        "/v1/domains/registrations",
        "Register an eligible domain for one year, owned by the x402 payer wallet",
        _DOMAIN_REGISTRATION_PRICE,
        domain_models.DomainRegistrationRequest,
        {
            "domain": "agent-example.xyz",
            "client_order_id": "agent-order-20260719-0001",
            "accept_terms": True,
            "max_price_usd": "10.00",
        },
        domain_models.DomainRegistrationResponse,
        {
            "registration_id": "dr_a1b2c3d4e5f6g7h8i9j0kl",
            "order_id": "do_a1b2c3d4e5f6g7h8i9j0kl",
            "domain": "agent-example.xyz",
            "status": "queued",
            "amount_usd": "6.15",
            "owner_wallet": "0x1111111111111111111111111111111111111111",
            "terms_version": "2026-07-19",
            "status_url": "/v1/domains/registrations/status/ds_a1b2c3d4e5f6g7h8i9j0kl",
            "management_url": "/v1/domains/agent-example.xyz",
            "operation_id": "dop_a1b2c3d4e5f6g7h8i9j0k",
            "created_at": _GENERATED_AT,
            "updated_at": _GENERATED_AT,
        },
        gate="domain_marketplace",
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
        "/v1/tunnel/create",
        "Expose a host behind NAT on a public TCP port via reverse SSH (ssh -R), leased by the hour",
        _TUNNEL_PRICE,
        models.TunnelCreateRequest,
        {"hours": 1},
        models.TunnelResponse,
        {
            "tunnel_id": "rtun_a1b2c3d4e5f6a7b8",
            "token": "abcdefghijklmnopqrstuvwxyz234567",
            "endpoint_host": "tun.hyrule.host",
            "ssh_port": 2222,
            "public_port": 10234,
            "ssh_command": "ssh -N -R 0:localhost:22 abcdefghijklmnopqrstuvwxyz234567@tun.hyrule.host -p 2222",
            "status": "active",
            "expires_at": "2026-07-22T18:00:00Z",
            "connected": False,
            "visitor_conns": 0,
        },
        gate="tunnel",
    ),
    _body_operation(
        "/v1/bgp/lookup",
        (
            "BGP/routing lookup by prefix, IP, or ASN. Every result is labelled with "
            "its data freshness, so you can tell a live observation from a snapshot. "
            "Choose the dataset by the question you are asking: "
            "`live_looking_glass` ($0.01) queries RIS collector RIBs at request time "
            "and is the ONLY dataset that can answer 'is this prefix propagating right "
            "now?' — use it after any announcement, withdrawal, or filter change. "
            "`public_routing` ($0.005) is a periodically-recomputed snapshot that can "
            "be many hours stale; it is fine for 'who normally originates this?' but "
            "will report a freshly-announced prefix as invisible. Responses carry "
            "results.<source>.freshness{class,observed_at,age_seconds,stale} and mark "
            "sources stale rather than silently returning old data. "
            "`rpki` adds origin validation. `as215932_router_tables` is the internal "
            "AS215932 vantage (not yet implemented; reports not_configured)."
        ),
        _BGP_LOOKUP_PRICE,
        models.BGPLookupRequest,
        {
            "subject_type": "prefix",
            "subject_value": "2a0c:b641:b50::/44",
            "datasets": ["live_looking_glass", "public_routing", "rpki"],
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
        "/v1/dns/blocklists/check",
        "Paid domain membership check across Hyrule's maintained catalog of common DNS-capable ad, privacy, and security blocklists",
        _fixed("price_dns_blocklist_check", "0.003"),
        models.DNSDomainCheckRequest,
        {"domain": "example.com"},
        models.DNSBlocklistCheckResponse,
        _DNS_BLOCKLIST_OUTPUT,
        gate="dns_blocklists",
    ),
    _body_operation(
        "/v1/dns/filtering/check",
        "Paid live DNS filtering comparison across curated public security and ads/tracking resolver profiles from Hyrule's vantage",
        _fixed("price_dns_filtering_check", "0.01"),
        models.DNSDomainCheckRequest,
        {"domain": "example.com"},
        models.DNSFilteringCheckResponse,
        _DNS_FILTERING_OUTPUT,
        gate="dns_filtering",
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


def _gate_enabled(gate: str, config: HyruleConfig | None = None) -> bool:
    if gate == "always":
        return True
    if gate == "domain_marketplace":
        configured = config or HyruleConfig()
        domain = getattr(configured, "domain", None)
        provider = getattr(configured, "openprovider", None)
        if domain is None or provider is None:
            # Lightweight config doubles used by unrelated paid endpoints predate
            # domain sales. Missing domain settings must fail closed, not break
            # discovery or request middleware for those endpoints.
            return False
        payment = getattr(configured, "payment", None)
        return bool(
            getattr(domain, "enabled", False)
            and getattr(domain, "purchases_enabled", False)
            and getattr(domain, "marketplace_sales_enabled", False)
            and getattr(domain, "legal_approved", False)
            and getattr(domain, "tax_approved", False)
            and not getattr(domain, "marketplace_payer_allowlist", ())
            and (
                getattr(domain, "allow_all_eligible_tlds", False)
                or getattr(domain, "tld_allowlist", ())
            )
            and getattr(domain, "dns_control_url", "")
            and getattr(domain, "dns_control_secret", "")
            and getattr(provider, "username", "")
            and getattr(provider, "password", "")
            and getattr(provider, "owner_handle", "")
            and getattr(provider, "admin_handle", "")
            and getattr(provider, "tech_handle", "")
            and getattr(provider, "billing_handle", "")
            # The gate is the fail-closed launch-readiness decision: every
            # other flag can be on while checkout is still structurally
            # unable to settle a 402 (no receiver configured, or every
            # payment network disabled) and every attempt 503s.
            and payment is not None
            and getattr(payment, "receiver_address", "")
            and payment.enabled_networks()
        )
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
    if gate == "tunnel":
        from hyrule_cloud.services.tunnel.readiness import tunnel_service_ready

        return tunnel_service_ready()
    if gate == "dns_blocklists":
        from hyrule_cloud.services.dns.blocklists import blocklist_catalog_ready

        return blocklist_catalog_ready()
    if gate == "dns_filtering":
        from hyrule_cloud.services.dns.filtering import dns_filtering_enabled

        return dns_filtering_enabled()
    raise ValueError(f"Unknown paid-operation gate: {gate}")


def enabled_paid_operations(
    config: HyruleConfig | None = None,
) -> tuple[PaidOperation, ...]:
    """Return the launch catalog after applying deployment readiness gates."""

    return tuple(
        operation
        for operation in PAID_OPERATIONS
        if _gate_enabled(operation.gate, config)
    )


def enabled_supporting_operations() -> tuple[SupportingOperation, ...]:
    """Free workflow routes whose readiness gate passes."""

    return tuple(
        operation for operation in SUPPORTING_OPERATIONS if _gate_enabled(operation.gate)
    )


def discovery_for(
    method: str,
    path: str,
    config: HyruleConfig | None = None,
) -> dict[str, Any] | None:
    operation = _OPERATIONS_BY_KEY.get((method.upper(), path))
    if operation is None or not _gate_enabled(operation.gate, config):
        return None
    return operation.declaration


def match_enabled_operation(
    method: str,
    concrete_path: str,
    config: HyruleConfig | None = None,
) -> PaidOperation | None:
    """Match a request URL to an enabled catalog path template."""

    wanted_method = method.upper()
    normalized_path = concrete_path.rstrip("/") or "/"
    for operation, path_regex in _PATH_MATCHERS:
        if operation.method != wanted_method or not _gate_enabled(
            operation.gate, config
        ):
            continue
        if not path_regex.fullmatch(normalized_path):
            continue
        return operation if _gate_enabled(operation.gate) else None
    return None


def match_enabled_operation_any_method(
    concrete_path: str,
    config: HyruleConfig | None = None,
) -> PaidOperation | None:
    """Match a request path to an enabled operation regardless of method.

    Catalog paths are method-unique, so this is unambiguous; used where only
    the URL survives (402 resource-metadata construction in PaymentGate).
    """
    normalized_path = concrete_path.rstrip("/") or "/"
    for operation, path_regex in _PATH_MATCHERS:
        if not _gate_enabled(operation.gate, config):
            continue
        if path_regex.fullmatch(normalized_path):
            return operation
    return None


_CATALOG_PHRASES: tuple[tuple[str, str], ...] = (
    ("/v1/vm", "IPv6-native compute"),
    ("/v1/domains", "one-year domain registration"),
    ("/v1/network", "outbound requests over Direct, Tor, I2P, or Yggdrasil"),
    ("/v1/bgp", "BGP/routing intelligence"),
    ("/v1/ip", "IP/ASN intelligence"),
    # Keyed to each operation's actual path rather than the whole /v1/dns
    # prefix: /v1/dns/lookup is ungated, but blocklist membership and
    # filtering evidence each have their own readiness gate
    # (dns_blocklists / dns_filtering) and must not be advertised just
    # because DNS diagnostics happens to be live.
    ("/v1/dns/lookup", "DNS diagnostics"),
    ("/v1/dns/propagation", "DNS diagnostics"),
    ("/v1/dns/blocklists", "blocklist membership checks"),
    ("/v1/dns/filtering", "filtering evidence"),
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


def service_overview(config: HyruleConfig | None = None) -> str:
    """Marketplace-ready capability copy assembled from enabled routes only.

    Generated from live gate state so a product that is gated off (VM
    simulation, missing prober/worker/provider) can never appear in
    manifest/OpenAPI marketing copy.
    """
    enabled_paths = [operation.path for operation in enabled_paid_operations(config)]
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


def catalog_description(config: HyruleConfig | None = None) -> str:
    """Public catalog description plus current launch-scope caveats."""

    overview = service_overview(config)
    if any(
        operation.path == "/v1/domains/registrations"
        for operation in enabled_paid_operations(config)
    ):
        return overview
    return f"{overview} Domain registration is deferred from this launch catalog."


def marketplace_resource_description(
    operation: PaidOperation,
    config: HyruleConfig | None = None,
) -> str:
    """Make any endpoint safe for a marketplace to select as service copy.

    Agentic Market currently derives its service overview from one endpoint's
    resource description.  Prefixing every indexed resource with the real
    service scope prevents an arbitrary route (for example MX diagnostics)
    from being mistaken for the whole product.
    """

    endpoint = operation.description.rstrip(".")
    return f"{service_overview(config)} This endpoint: {endpoint}."


def build_x402_manifest(config: HyruleConfig) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    for operation in enabled_paid_operations(config):
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
        "description": catalog_description(config),
        "resources": resources,
        "facilitator": getattr(config.payment, "facilitator_url", ""),
        "contact": "https://github.com/AS215932",
    }


# A2A skill groups for the agent card, matched by catalog path prefix. A group
# with no enabled operation is omitted entirely, so gated-off products can
# never be advertised as skills (Block G).
@dataclass(frozen=True, slots=True)
class _SkillGroup:
    id: str
    name: str
    blurb: str
    prefixes: tuple[str, ...]
    tags: tuple[str, ...]


_SKILL_GROUPS: tuple[_SkillGroup, ...] = (
    _SkillGroup(
        id="compute",
        name="IPv6-native compute (VPS)",
        blurb="Provision bare IPv6-native VMs with SSH access and automatic HTTPS subdomains.",
        prefixes=("/v1/vm",),
        tags=("compute", "vps", "ssh"),
    ),
    _SkillGroup(
        id="domains-dns",
        name="Domain registration & DNS",
        blurb="Register domains owned by the paying x402 wallet, with managed DNS on AS215932.",
        prefixes=("/v1/domains",),
        tags=("domains", "dns", "registration"),
    ),
    _SkillGroup(
        id="network-intelligence",
        name="Network intelligence",
        blurb=(
            "BGP/routing, IP/ASN, DNS, RDAP/WHOIS, web/TLS, mail deliverability, "
            "port/NAT reachability, threat, and VoIP diagnostics."
        ),
        prefixes=(
            "/v1/bgp",
            "/v1/ip",
            "/v1/dns",
            "/v1/rdap",
            "/v1/whois",
            "/v1/web",
            "/v1/mx",
            "/v1/path",
            "/v1/ports",
            "/v1/nat",
            "/v1/threat",
            "/v1/voip",
        ),
        tags=("network-intel", "bgp", "dns", "tls", "email"),
    ),
    _SkillGroup(
        id="network-proxy",
        name="Network proxy & tunnels",
        blurb=(
            "Outbound requests over Direct, Tor, I2P, or Yggdrasil, and reverse-SSH "
            "tunnels exposing NATed hosts on a public port."
        ),
        prefixes=("/v1/network", "/v1/tunnel"),
        tags=("proxy", "tor", "tunnel"),
    ),
)

# a2a-x402 payments extension (A2A extension URI, not a fetchable document).
_A2A_X402_EXTENSION_URI = "https://github.com/google-agentic-commerce/a2a-x402/v0.1"


def _price_phrase(operation: PaidOperation, payment: PaymentConfig) -> str:
    minimum = operation.price.minimum(payment)
    if operation.price.mode == "fixed":
        return f"${minimum}"
    maximum = operation.price.maximum(payment)
    if maximum is not None:
        return f"${minimum}-${maximum}"
    return f"from ${minimum}"


def _summary(operation: PaidOperation) -> str:
    """First sentence of the catalog description, for compact skill listings."""

    return operation.description.split(". ")[0].rstrip(".")


def build_agent_card(config: HyruleConfig) -> dict[str, Any]:
    """A2A AgentCard built from the enabled catalog only.

    This card is a capability/payment declaration for discovery: Hyrule Cloud
    is an x402 REST API plus an MCP server, and does NOT expose an A2A
    JSON-RPC transport. Skills mirror the live service groups; a readiness
    gate that disables a group removes its skill entirely (Block G).
    """

    from hyrule_cloud import __version__

    base = config.public_base_url.rstrip("/")
    enabled = enabled_paid_operations(config)
    skills: list[dict[str, Any]] = []
    for group in _SKILL_GROUPS:
        operations = [
            operation
            for operation in enabled
            if any(
                operation.path == prefix or operation.path.startswith(prefix + "/")
                for prefix in group.prefixes
            )
        ]
        if not operations:
            continue
        listing = "; ".join(
            f"{operation.method} {operation.path} "
            f"({_price_phrase(operation, config.payment)} USD) — {_summary(operation)}"
            for operation in operations
        )
        skills.append(
            {
                "id": group.id,
                "name": group.name,
                "description": f"{group.blurb} Live x402-payable operations: {listing}.",
                "tags": list(group.tags),
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        )
    return {
        "protocolVersion": "0.3.0",
        "name": "Hyrule Cloud",
        "description": (
            "This agent card is a discovery and payment-capability declaration for "
            f"Hyrule Cloud, an x402 (HTTP 402) REST API at {base} plus an MCP server "
            "(pypi: hyrule-cloud). There is no A2A JSON-RPC transport; invoke skills "
            f"via the REST operations in {base}/openapi.json and pay per request in "
            f"USDC via x402. {catalog_description(config)}"
        ),
        "url": base,
        "documentationUrl": "https://hyrule.host/agents",
        "version": __version__,
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
            "extensions": [
                {
                    "uri": _A2A_X402_EXTENSION_URI,
                    "description": (
                        "Payable operations reply HTTP 402 with x402 v2 payment "
                        "requirements; retry with a signed payment to settle in USDC."
                    ),
                    "required": False,
                    "params": {
                        "x402Version": 2,
                        "networks": [
                            network.caip2 for network in config.payment.enabled_networks()
                        ],
                    },
                }
            ],
        },
        "skills": skills,
    }


def build_llms_txt(config: HyruleConfig) -> str:
    """Agent-facing plaintext guide, generated from the enabled catalog only.

    Everything advertised here derives from ``enabled_paid_operations`` and
    live payment config, so a gated-off operation can never appear (Block G).
    """

    base = config.public_base_url.rstrip("/")
    networks = ", ".join(
        f"{network.display_name} ({network.caip2})"
        for network in config.payment.enabled_networks()
    )
    lines = [
        "# Hyrule Cloud — x402-payable network services for AI agents",
        "",
        catalog_description(config),
        "",
        f"Machine-readable catalog: {base}/.well-known/x402.json",
        f"OpenAPI (payable surface only): {base}/openapi.json",
        f"A2A agent card (capability/payment declaration; no A2A JSON-RPC transport): {base}/.well-known/agent-card.json",
        "Payment: HTTP 402 challenge (x402 v2), USDC; accepted networks at "
        f"{base}/v1/payments/networks"
        + (f" — currently {networks}" if networks else ""),
        "",
        "Golden path (402 challenge -> pay -> retry):",
        f"  curl -s -X POST {base}/v1/dns/lookup \\",
        "    -H 'Content-Type: application/json' -d '{\"name\":\"example.com\",\"type\":\"AAAA\"}'",
        "  -> HTTP 402 with payment requirements (JSON body + Payment-Required header).",
        "  Pay the challenge with an x402 client, then retry the same method, URL, and",
        "  body with the X-PAYMENT header; the response settles and carries settlement headers.",
        "",
        "Paid operations (method path — min USD — description):",
    ]
    for operation in enabled_paid_operations(config):
        price = operation.price.minimum(config.payment)
        lines.append(
            f"  {operation.method} {operation.path} — ${price} — {operation.description}"
        )
    lines += [
        "",
        "MCP server (pypi: hyrule-cloud) — client config:",
        "  {",
        '    "mcpServers": {',
        '      "hyrule-cloud": {',
        '        "command": "python",',
        '        "args": ["-m", "hyrule_cloud.mcp_server"],',
        f'        "env": {{"HYRULE_API_URL": "{base}"}}',
        "      }",
        "    }",
        "  }",
        "  Optional: set HYRULE_API_KEY (bootstrap one with the register_account tool)",
        "  to authenticate subsequent calls.",
        "",
        "More Hyrule services: https://hyrule.host/llms.txt",
    ]
    return "\n".join(lines) + "\n"


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

    enabled = enabled_paid_operations(config)
    enabled_keys = {operation.key for operation in enabled}
    supporting = enabled_supporting_operations()
    supporting_keys = {operation.key for operation in supporting}
    documented_keys = enabled_keys | supporting_keys
    selected_routes = [
        route
        for route in application.routes
        if isinstance(route, APIRoute)
        and any((method.upper(), route.path) in documented_keys for method in route.methods)
    ]
    schema = get_openapi(
        title=application.title,
        version=application.version,
        openapi_version=application.openapi_version,
        summary=application.summary,
        description=(
            f"{catalog_description(config)} This OpenAPI document contains the launch-ready, "
            "independently payable agent surface plus the free supporting routes "
            "(quotes, status polling, pricing, template catalog) required to complete "
            "those workflows."
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
        "Operations whose x-payment-info carries a price are independently "
        "payable x402 v2 resources: call one without payment to receive the "
        "Payment-Required challenge, then retry the same method, URL, and "
        "input with a valid payment signature. Operations marked "
        '{"price": {"mode": "free"}} are unpaid supporting routes for those '
        "workflows. Routes omitted from this document are not part of the "
        "agent launch catalog."
    )
    schema.setdefault("components", {}).setdefault("schemas", {})[
        "X402PaymentRequired"
    ] = _PAYMENT_REQUIRED_SCHEMA

    for operation in enabled:
        _annotate_operation(schema, operation, config.payment)
    for supporting_operation in supporting:
        _annotate_supporting_operation(schema, supporting_operation)

    # Be exact even if a future APIRoute gains more than one method.
    for path, path_item in list(schema.get("paths", {}).items()):
        for method in list(path_item):
            if method.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}:
                if (method.upper(), path) not in documented_keys:
                    del path_item[method]
        if not any((method.upper(), path) in documented_keys for method in path_item):
            del schema["paths"][path]

    return schema


def _annotate_supporting_operation(
    schema: dict[str, Any],
    operation: SupportingOperation,
) -> None:
    openapi_operation = schema["paths"][operation.path][operation.method.lower()]
    openapi_operation["security"] = []
    openapi_operation["x-payment-info"] = {"price": {"mode": "free"}}
    openapi_operation.setdefault("summary", operation.description)
    openapi_operation["description"] = (
        f"{operation.description}. Free supporting route — no x402 payment required."
    )
