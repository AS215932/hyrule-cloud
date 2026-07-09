from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.models import BGPLookupRequest, BGPSubjectType


def test_bgp_prefix_lookup_contract_does_not_require_asn():
    req = BGPLookupRequest(subject={"type": "prefix", "value": "2a0c:b641:b50::/44"})
    assert req.subject.type == BGPSubjectType.PREFIX
    assert req.subject.value == "2a0c:b641:b50::/44"
    assert req.assertions.expected_origin_asns == []


def test_openapi_exposes_network_intelligence_contracts():
    paths = app.openapi()["paths"]
    for path in [
        "/v1/bgp/status",
        "/v1/bgp/lookup",
        "/v1/ip/lookup",
        "/v1/dns/lookup",
        "/v1/dns/resolve",
        "/v1/dns/propagation",
        "/v1/dns/recommend-records",
        "/v1/dns/authority-vs-recursive",
        "/v1/dns/resolver-detect",
        "/v1/dns/dnssec/report",
        "/v1/rdap/lookup",
        "/v1/whois/lookup",
        "/v1/web/check",
        "/v1/web/reports",
        "/v1/web/tls/deep",
        "/v1/mx/check",
        "/v1/mx/bounce/parse",
        "/v1/mx/recommend-records",
        "/v1/mx/reports/mail-delivery",
        "/v1/mx/jobs",
        "/v1/path/report",
        "/v1/path/ping",
        "/v1/path/jobs",
        "/v1/ports/check",
        "/v1/nat/ip",
        "/v1/nat/lookup",
        "/v1/nat/port-forward/check",
        "/v1/threat/lookup",
        "/v1/threat/domain/{domain}",
        "/v1/threat/rbl",
        "/v1/voip/check",
        "/v1/voip/number/lookup",
        "/v1/voip/jobs",
        "/v1/speedtest",
        "/v1/speedtest/jobs",
        "/v1/mail/accounts",
        "/v1/mail/messages/send",
    ]:
        assert path in paths


@pytest.mark.asyncio
async def test_dns_capabilities_state_read_only_separation():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/dns/capabilities")
    assert res.status_code == 200
    body = res.json()
    assert body["service"] == "dns"
    assert "never registers domains" in body["separation_of_concerns"]
    assert "never mutates authoritative zone records" in body["separation_of_concerns"]


@pytest.mark.asyncio
async def test_mx_tools_include_full_supertool_contract():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/mx/tools")
    assert res.status_code == 200
    tools = {item["tool"] for item in res.json()["tools"]}
    assert tools == {
        "a",
        "aaaa",
        "arin",
        "asn",
        "bimi",
        "blacklist",
        "cname",
        "dkim",
        "dmarc",
        "dns",
        "http",
        "https",
        "mta-sts",
        "mx",
        "ping",
        "ptr",
        "smtp",
        "soa",
        "spf",
        "tcp",
        "tlsrpt",
        "trace",
        "txt",
        "whois",
    }


@pytest.mark.asyncio
async def test_paid_network_intel_endpoints_fail_closed_without_payment():
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            dns = await client.post("/v1/dns/lookup", json={"name": "example.com", "type": "A"})
            dns_prop = await client.post("/v1/dns/propagation", json={"name": "example.com", "type": "A"})
            web = await client.post("/v1/web/check", json={"target": "https://example.com"})
            mx = await client.post("/v1/mx/check", json={"tool": "mx", "target": "example.com"})
            bounce = await client.post("/v1/mx/bounce/parse", json={"message": "550 5.7.26 auth failed"})
            port = await client.post("/v1/ports/check", json={"target": "example.com", "port": 443})
            nat = await client.post("/v1/nat/lookup", json={"customer_reported_wan_ip": "100.64.1.1"})
            voip = await client.post("/v1/voip/check", json={"target": "example.com"})
            bgp = await client.post("/v1/bgp/lookup", json={"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
    assert dns.status_code == 402
    assert dns_prop.status_code == 402
    assert web.status_code == 402
    assert mx.status_code == 402
    assert bounce.status_code == 402
    assert port.status_code == 402
    assert nat.status_code == 402
    assert voip.status_code == 402
    assert bgp.status_code == 402


@pytest.mark.asyncio
async def test_unbuilt_paid_endpoints_return_501_before_charging():
    """Endpoints without a real backend must refuse with 501 *before* the payment
    gate runs — a 402 here would mean an agent can pay for a dead end."""
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            responses = {
                "/v1/mail/accounts": await client.post(
                    "/v1/mail/accounts",
                    json={"plan": "agent-basic", "duration_days": 1, "local_part": "a", "domain": "agentmail.hyrule.host"},
                ),
                "/v1/mail/messages/send": await client.post(
                    "/v1/mail/messages/send",
                    json={
                        "mailbox_id": "mb_x",
                        "from": "agent@agentmail.hyrule.host",
                        "to": ["a@example.com"],
                        "subject": "s",
                        "text": "t",
                    },
                ),
                "/v1/web/reports": await client.post("/v1/web/reports", json={"target": "https://example.com"}),
                "/v1/path/jobs": await client.post("/v1/path/jobs", json={"target": "example.com"}),
                "/v1/speedtest": await client.post("/v1/speedtest", json={"target": "hyrule"}),
                "/v1/speedtest/jobs": await client.post("/v1/speedtest/jobs", json={"target": "hyrule"}),
                "/v1/voip/report": await client.post("/v1/voip/report", json={"target": "example.com"}),
                "/v1/voip/jobs": await client.post("/v1/voip/jobs", json={"target": "example.com"}),
                # Diagnostics whose real data source isn't configured must also
                # refuse before charging (contract-only responses otherwise).
                "/v1/threat/lookup": await client.post(
                    "/v1/threat/lookup", json={"subject": {"type": "domain", "value": "example.com"}}
                ),
                "/v1/voip/number/lookup": await client.post(
                    "/v1/voip/number/lookup", json={"number": "+31201234567"}
                ),
                "/v1/path/ping": await client.post("/v1/path/ping", json={"target": "example.com"}),
                "/v1/path/report": await client.post("/v1/path/report", json={"target": "example.com"}),
            }
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
    for endpoint, res in responses.items():
        assert res.status_code == 501, f"{endpoint} returned {res.status_code}, expected 501 before any charge"
        assert res.json()["error"] == "not_implemented", endpoint


@pytest.mark.asyncio
async def test_voip_check_stub_only_checks_501_before_charge():
    """/v1/voip/check runs real SIP DNS/TLS work by default, but SIP_OPTIONS and
    STUN_TURN only emit contract findings. A request (or quote) limited to those
    must 501 before charging; any request that includes a live check still
    charges (402)."""
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            options_only = await client.post("/v1/voip/check", json={"target": "example.com", "checks": ["sip_options"]})
            stun_only = await client.post("/v1/voip/check", json={"target": "example.com", "checks": ["stun_turn"]})
            both_stub = await client.post("/v1/voip/check", json={"target": "example.com", "checks": ["sip_options", "stun_turn"]})
            quote_stub = await client.post("/v1/voip/check/quote", json={"target": "example.com", "checks": ["stun_turn"]})
            # Default (SIP_DNS + SIP_TLS) and mixed requests keep real work → charge.
            default_checks = await client.post("/v1/voip/check", json={"target": "example.com"})
            mixed = await client.post("/v1/voip/check", json={"target": "example.com", "checks": ["sip_dns", "sip_options"]})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
    for res in (options_only, stun_only, both_stub, quote_stub):
        assert res.status_code == 501, res.status_code
        assert res.json()["error"] == "not_implemented"
    assert default_checks.status_code == 402
    assert mixed.status_code == 402


@pytest.mark.asyncio
async def test_x402_manifest_lists_network_intel_resources():
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig())
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/.well-known/x402.json")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
    assert res.status_code == 200
    paths = {resource["path"] for resource in res.json()["resources"]}
    assert "/v1/bgp/lookup" in paths
    assert "/v1/ip/lookup" in paths
    assert "/v1/dns/lookup" in paths
    assert "/v1/dns/propagation" in paths
    assert "/v1/dns/recommend-records" in paths
    assert "/v1/rdap/lookup" in paths
    assert "/v1/whois/lookup" in paths
    assert "/v1/web/check" in paths
    assert "/v1/web/tls/deep" in paths
    assert "/v1/mx/check" in paths
    assert "/v1/mx/bounce/parse" in paths
    assert "/v1/mx/recommend-records" in paths
    assert "/v1/ports/check" in paths
    assert "/v1/nat/lookup" in paths
    assert "/v1/voip/check" in paths
    # Unbuilt services must never be advertised in the discovery manifest:
    # they 501 before charging, so listing them would advertise dead ends.
    assert "/v1/speedtest" not in paths
    assert "/v1/speedtest/jobs" not in paths
    assert "/v1/mail/accounts" not in paths
    # Diagnostics with no configured data source 501 before charging, so they
    # are filtered out of discovery until a source is wired up.
    assert "/v1/threat/lookup" not in paths
    assert "/v1/voip/number/lookup" not in paths
    assert "/v1/path/ping" not in paths
    assert "/v1/path/report" not in paths
    assert "/v1/mail/messages/send" not in paths
    assert "/v1/web/reports" not in paths
    assert "/v1/path/jobs" not in paths
    assert "/v1/voip/report" not in paths
    assert "/v1/voip/jobs" not in paths


@pytest.mark.asyncio
async def test_quotes_for_unbuilt_endpoints_return_501():
    """A quote whose paid_endpoint always 501s is itself a dead end: clients
    on the quote→pay→create flow would be handed a payable-looking order
    that can never succeed."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        mail_quote = await client.post(
            "/v1/mail/accounts/quote",
            json={
                "plan": "agent-basic",
                "duration_days": 30,
                "local_part": "agent-123",
                "domain": "agentmail.hyrule.host",
            },
        )
        speedtest_quote = await client.post("/v1/speedtest/quote", json={"target": "hyrule"})
        web_report_quote = await client.post(
            "/v1/web/reports/quote", json={"target": "https://example.com"}
        )
    for res in (mail_quote, speedtest_quote, web_report_quote):
        assert res.status_code == 501
        assert res.json()["error"] == "not_implemented"


def test_diagnostic_enablement_predicates_default_off():
    """With no external data source configured, the pluggable diagnostics report
    disabled — this is what makes their routes 501 before charging."""
    from hyrule_cloud.services.path.diagnostics import path_active_probe_enabled
    from hyrule_cloud.services.threat.lookup import threat_intel_enabled
    from hyrule_cloud.services.voip.diagnostics import number_intel_enabled

    assert threat_intel_enabled() is False
    assert number_intel_enabled() is False
    assert path_active_probe_enabled() is False


@pytest.mark.asyncio
async def test_threat_lookup_readvertises_and_charges_once_source_configured(monkeypatch):
    """Configuring a real source must flip the route from 501-before-charge to a
    normal paid endpoint, and bring it back into the discovery manifest — the
    gate is data-driven, not a permanent removal."""
    import hyrule_cloud.services.threat.lookup as threat_service
    from hyrule_cloud.services.diagnostics.sources import source_ok

    # Configure one licensed source. threat_intel_enabled() reads threat_sources()
    # through the module global, so this reaches both the route and the manifest.
    configured = threat_service.threat_sources()
    configured["spamhaus_commercial"] = source_ok()
    monkeypatch.setattr(threat_service, "threat_sources", lambda: configured)
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            lookup = await client.post(
                "/v1/threat/lookup", json={"subject": {"type": "domain", "value": "example.com"}}
            )
        app.state._typed_state = SimpleNamespace(config=HyruleConfig())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            manifest = await client.get("/.well-known/x402.json")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")
    # No payment header + a configured source => 402 (chargeable), not 501.
    assert lookup.status_code == 402
    paths = {resource["path"] for resource in manifest.json()["resources"]}
    assert "/v1/threat/lookup" in paths


@pytest.mark.asyncio
async def test_manifest_advertises_path_endpoints_by_their_default_request(monkeypatch):
    """Even with an active prober configured, only endpoints whose DEFAULT
    request actually probes may be advertised. /v1/path/report defaults to a
    vantage set that includes globalping, but the ping-family defaults to extmon
    (never probes), so it must stay out of the manifest — an agent following
    discovery with defaults would otherwise hit a 501."""
    import hyrule_cloud.services.path.diagnostics as pd
    from hyrule_cloud.models import DiagnosticVantage
    from hyrule_cloud.services.diagnostics.sources import source_ok

    real_sources = pd._sources

    def fake_sources(vantages):
        out = real_sources(vantages)
        for v in vantages:
            if v == DiagnosticVantage.GLOBALPING:
                out[v.value] = source_ok()  # pretend Globalping is configured
        return out

    monkeypatch.setattr(pd, "_sources", fake_sources)
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        app.state._typed_state = SimpleNamespace(config=HyruleConfig())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            manifest = await client.get("/.well-known/x402.json")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")
    paths = {resource["path"] for resource in manifest.json()["resources"]}
    assert "/v1/path/report" in paths  # default vantages include globalping
    assert "/v1/path/ping" not in paths  # default is extmon-only -> 501
    assert "/v1/path/trace" not in paths


def test_source_usable_only_accepts_configured_working_statuses():
    from hyrule_cloud.models import SourceHealth, SourceStatus
    from hyrule_cloud.services.diagnostics.sources import (
        source_degraded,
        source_disabled,
        source_error,
        source_not_configured,
        source_ok,
        source_unavailable,
        source_usable,
    )

    assert source_usable(source_ok()) is True
    assert source_usable(source_degraded("slow")) is True  # serves partial data
    # Configured-but-not-answering statuses must not enable a paid route.
    assert source_usable(source_disabled()) is False
    assert source_usable(source_error("boom")) is False
    assert source_usable(source_unavailable("down")) is False
    assert source_usable(source_not_configured()) is False
    # RATE_LIMITED is configured but can't return fresh data right now, so it
    # must not keep a paid route advertised/chargeable.
    assert source_usable(SourceHealth(status=SourceStatus.RATE_LIMITED, message="quota")) is False


@pytest.mark.asyncio
async def test_path_capabilities_gated_per_endpoint_default_vantages(monkeypatch):
    """With globalping configured, /v1/path/capabilities advertises the report
    (its default vantages include globalping) but NOT the ping-family (default
    [extmon] 501s) — mirroring the manifest's per-endpoint gate."""
    import hyrule_cloud.services.path.diagnostics as pd
    from hyrule_cloud.api.path import get_path_capabilities
    from hyrule_cloud.models import DiagnosticVantage
    from hyrule_cloud.services.diagnostics.sources import source_ok

    real_sources = pd._sources

    def fake_sources(vantages):
        out = real_sources(vantages)
        for v in vantages:
            if v == DiagnosticVantage.GLOBALPING:
                out[v.value] = source_ok()
        return out

    monkeypatch.setattr(pd, "_sources", fake_sources)
    caps = await get_path_capabilities()
    paid = {e.path for e in caps.paid_endpoints}
    free = {e.path for e in caps.free_endpoints}
    assert "/v1/path/report" in paid
    assert "/v1/path/report/quote" in free
    assert "/v1/path/ping" not in paid
    assert "/v1/path/trace" not in paid


def test_threat_predicate_rejects_configured_but_unhealthy_source(monkeypatch):
    import hyrule_cloud.services.threat.lookup as tl
    from hyrule_cloud.services.diagnostics.sources import source_disabled

    base = tl.threat_sources()
    base["spamhaus_commercial"] = source_disabled()  # present but not usable
    monkeypatch.setattr(tl, "threat_sources", lambda: dict(base))
    assert tl.threat_intel_enabled() is False


def test_path_gate_is_per_requested_vantage(monkeypatch):
    import hyrule_cloud.services.path.diagnostics as pd
    from hyrule_cloud.models import DiagnosticVantage
    from hyrule_cloud.services.diagnostics.sources import source_ok

    real_sources = pd._sources

    def fake_sources(vantages):
        out = real_sources(vantages)
        for v in vantages:
            if v == DiagnosticVantage.GLOBALPING:
                out[v.value] = source_ok()  # pretend Globalping is configured
        return out

    monkeypatch.setattr(pd, "_sources", fake_sources)

    # A request for only built-in vantages can't produce probe data => gated,
    # even though an active prober is configured process-wide.
    assert pd.path_active_probe_enabled([DiagnosticVantage.EXTMON]) is False
    assert pd.path_active_probe_enabled([DiagnosticVantage.GLOBALPING]) is True
    assert pd.path_active_probe_enabled() is True


@pytest.mark.asyncio
async def test_gated_quote_routes_501_before_charging():
    old_state = getattr(app.state, "_typed_state", None)
    if hasattr(app.state, "_typed_state"):
        delattr(app.state, "_typed_state")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            responses = {
                "/v1/threat/lookup/quote": await client.post(
                    "/v1/threat/lookup/quote",
                    json={"subject": {"type": "domain", "value": "example.com"}},
                ),
                "/v1/voip/number/lookup/quote": await client.post(
                    "/v1/voip/number/lookup/quote", json={"number": "+31201234567"}
                ),
                "/v1/path/report/quote": await client.post(
                    "/v1/path/report/quote", json={"target": "example.com"}
                ),
            }
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
    for endpoint, res in responses.items():
        assert res.status_code == 501, f"{endpoint} -> {res.status_code}"
        assert res.json()["error"] == "not_implemented", endpoint


@pytest.mark.asyncio
async def test_capabilities_hide_gated_paid_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        threat = (await client.get("/v1/threat/capabilities")).json()
        voip = (await client.get("/v1/voip/capabilities")).json()
        path = (await client.get("/v1/path/capabilities")).json()

    assert {e["path"] for e in threat["paid_endpoints"]} == set()
    voip_paid = {e["path"] for e in voip["paid_endpoints"]}
    assert "/v1/voip/check" in voip_paid  # real SIP work stays advertised
    assert "/v1/voip/number/lookup" not in voip_paid  # gated
    assert {e["path"] for e in path["paid_endpoints"]} == set()
    # The gated quote also disappears from the free list.
    assert not any(e["path"] == "/v1/path/report/quote" for e in path["free_endpoints"])


def test_bazaar_discovery_hides_gated_diagnostics_by_default():
    """The Bazaar discovery extension must mirror the manifest gate: with no
    diagnostic source configured (default), the gated routes are not declared, so
    an agent can't copy an extension whose default example 501s. Ungated routes
    still declare."""
    from hyrule_cloud.services.discovery import discovery_for

    # Gated diagnostics: no declaration until their source is configured.
    assert discovery_for("POST", "/v1/path/ping") is None
    assert discovery_for("POST", "/v1/threat/lookup") is None
    assert discovery_for("POST", "/v1/voip/number/lookup") is None
    # An ungated diagnostic is still advertised.
    assert discovery_for("POST", "/v1/dns/lookup") is not None
    assert discovery_for("POST", "/v1/mx/check") is not None
