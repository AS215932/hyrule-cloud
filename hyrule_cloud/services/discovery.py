"""x402 Bazaar discovery declarations for paid endpoints.

Coinbase's Bazaar indexes a resource when the CDP facilitator settles a
payment whose 402 challenge carried a `bazaar` discovery extension. This
module declares, per (method, path), how the endpoint is called — example
body, JSON Schema (reused from the pydantic request models), and a sample
response — and PaymentGate attaches the declaration to every 402 it emits.

Only endpoints with a real backend belong here: the declaration IS the
advertisement.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from x402.extensions.bazaar import OutputConfig, declare_discovery_extension

from hyrule_cloud import models


def _inline_defs(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve internal ``#/$defs/...`` references by substitution.

    ``model_json_schema()`` emits ``$defs`` at the schema root, but the SDK
    nests our schema under the extension's ``body`` property while the
    ``$ref`` pointers keep targeting the (now wrong) document root — Bazaar
    validation then rejects the extension as unresolvable. Our request models
    are non-recursive (enums + small nested models), so full inlining is safe.
    """
    defs: dict[str, Any] = schema.get("$defs", {})

    def resolve(node: Any, seen: frozenset[str]) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                name = ref.removeprefix("#/$defs/")
                if name in seen:  # cycle guard: leave the ref rather than loop
                    return node
                target = resolve(defs.get(name, {}), seen | {name})
                # Sibling keys next to $ref (e.g. default) merge over the target.
                return {**target, **{k: v for k, v in node.items() if k != "$ref"}}
            return {k: resolve(v, seen) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(item, seen) for item in node]
        return node

    resolved: dict[str, Any] = resolve(
        {k: v for k, v in schema.items() if k != "$defs"}, frozenset()
    )
    return resolved


def _json_body(
    model_cls: type[BaseModel],
    example: dict[str, Any],
    output_example: dict[str, Any],
) -> dict[str, Any]:
    return declare_discovery_extension(
        input=example,
        input_schema=_inline_defs(model_cls.model_json_schema()),
        body_type="json",
        output=OutputConfig(example=output_example),
    )


_DIAG_OUTPUT = {
    "status": "ok",
    "summary": "…",
    "findings": [{"severity": "ok", "code": "…", "message": "…"}],
}

# (method, path) → declared bazaar extension. Paths are the FastAPI route
# paths; PaymentGate looks requests up via request.scope["route"].path so
# call sites don't need changing.
DISCOVERY: dict[tuple[str, str], dict[str, Any]] = {
    ("POST", "/v1/vm/create"): _json_body(
        models.VMCreateRequest,
        {
            "duration_days": 7,
            "size": "sm",
            "os": "debian-13",
            "ssh_pubkey": "ssh-ed25519 AAAA…",
            "domain_mode": "auto",
            "open_ports": [80, 443],
        },
        {
            "vm_id": "vm_a1b2c3d4e5f6",
            "status": "provisioning",
            "status_url": "https://cloud.hyrule.host/v1/vm/vm_a1b2c3d4e5f6",
        },
    ),
    ("POST", "/v1/domain/register"): _json_body(
        models.DomainRegisterRequest,
        {"name": "mysite", "extension": "dev", "duration_years": 1},
        {"domain": "mysite.dev", "status": "active"},
    ),
    ("POST", "/v1/network/request"): _json_body(
        models.NetworkRequest,
        {"url": "https://example.com", "method": "GET", "proxy_mode": "tor"},
        {"status_code": 200, "body": "<html>…</html>", "proxy_mode": "tor"},
    ),
    ("POST", "/v1/dns/lookup"): _json_body(
        models.DNSLookupRequest,
        {"name": "example.com", "type": "AAAA"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/ip/lookup"): _json_body(
        models.IPLookupRequest,
        {"address": "2a0c:b641:b50::1"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/bgp/lookup"): _json_body(
        models.BGPLookupRequest,
        {"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/rdap/lookup"): _json_body(
        models.RDAPLookupRequest,
        {"subject": {"type": "domain", "value": "example.com"}},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/whois/lookup"): _json_body(
        models.WhoisLookupRequest,
        {"subject": {"type": "domain", "value": "example.com"}},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/web/check"): _json_body(
        models.WebCheckRequest,
        {"target": "https://example.com"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/mx/check"): _json_body(
        models.MXCheckRequest,
        {"tool": "mx", "target": "example.com"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/path/ping"): _json_body(
        models.PathProbeRequest,
        {"target": "example.com"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/ports/check"): _json_body(
        models.PortCheckRequest,
        {"target": "example.com", "port": 443},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/nat/lookup"): _json_body(
        models.NATLookupRequest,
        {"customer_reported_wan_ip": "100.64.1.1"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/threat/lookup"): _json_body(
        models.ThreatLookupRequest,
        {"subject": {"type": "domain", "value": "example.com"}},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/voip/check"): _json_body(
        models.VoIPCheckRequest,
        {"target": "sip.example.com"},
        _DIAG_OUTPUT,
    ),
    ("POST", "/v1/voip/number/lookup"): _json_body(
        models.VoIPNumberLookupRequest,
        {"number": "+31201234567"},
        _DIAG_OUTPUT,
    ),
}


def _gated_discovery_enabled(path: str) -> bool:
    """A gated diagnostic must not be advertised in Bazaar discovery any more
    than in the x402 manifest: its default example request 501s before charging
    until the backing source is configured, so an agent copying the declared
    extension would be handed an unusable request. Returns True when the route is
    safe to advertise — mirroring the manifest/MCP enablement predicates (gated
    on each endpoint's OWN default vantages for path)."""
    from hyrule_cloud.services.path.diagnostics import path_active_probe_enabled
    from hyrule_cloud.services.threat.lookup import threat_intel_enabled
    from hyrule_cloud.services.voip.diagnostics import number_intel_enabled

    if path == "/v1/path/ping":
        return path_active_probe_enabled(
            models.PathProbeRequest.model_fields["vantages"].default_factory()
        )
    if path == "/v1/threat/lookup":
        return threat_intel_enabled()
    if path == "/v1/voip/number/lookup":
        return number_intel_enabled()
    return True


def discovery_for(method: str, path: str) -> dict[str, Any] | None:
    decl = DISCOVERY.get((method.upper(), path))
    if decl is None or not _gated_discovery_enabled(path):
        return None
    return decl
