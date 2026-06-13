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
            web = await client.post("/v1/web/check", json={"target": "https://example.com"})
            mx = await client.post("/v1/mx/check", json={"tool": "mx", "target": "example.com"})
            bounce = await client.post("/v1/mx/bounce/parse", json={"message": "550 5.7.26 auth failed"})
            bgp = await client.post("/v1/bgp/lookup", json={"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
    assert dns.status_code == 402
    assert web.status_code == 402
    assert mx.status_code == 402
    assert bounce.status_code == 402
    assert bgp.status_code == 402


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
    assert "/v1/rdap/lookup" in paths
    assert "/v1/whois/lookup" in paths
    assert "/v1/web/check" in paths
    assert "/v1/web/tls/deep" in paths
    assert "/v1/mx/check" in paths
    assert "/v1/mail/accounts" in paths


@pytest.mark.asyncio
async def test_mail_account_quote_contract():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/v1/mail/accounts/quote",
            json={
                "plan": "agent-basic",
                "duration_days": 30,
                "local_part": "agent-123",
                "domain": "agentmail.hyrule.host",
            },
        )
    assert res.status_code == 200
    body = res.json()
    assert body["paid_endpoint"] == "/v1/mail/accounts"
    assert body["billable_units"][0]["name"] == "mail_account_agent_basic_day"
    assert body["billable_units"][0]["quantity"] == 30
