"""Agent-discovery surfaces: A2A agent card, robots.txt, llms.txt, MCP registry.

Every surface must derive from ``enabled_paid_operations()`` / live config so a
gated-off operation, group, or chain can never be advertised (Block G).
"""

from __future__ import annotations

import io
import json
import logging
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud import __version__
from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, PaymentConfig
from hyrule_cloud.services.discovery import build_agent_card, build_llms_txt
from tests.test_x402_openapi_discovery import _enable_all_catalog_gates

_REPO_ROOT = Path(__file__).resolve().parents[1]

_AGENT_BOTS = (
    "ClaudeBot",
    "GPTBot",
    "OAI-SearchBot",
    "PerplexityBot",
    "Google-Extended",
)


def test_agent_card_has_required_a2a_fields_and_x402_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_all_catalog_gates(monkeypatch)
    config = HyruleConfig()
    card = build_agent_card(config)

    for field in (
        "protocolVersion",
        "name",
        "description",
        "url",
        "documentationUrl",
        "version",
        "defaultInputModes",
        "defaultOutputModes",
        "capabilities",
        "skills",
    ):
        assert field in card, field

    assert card["name"] == "Hyrule Cloud"
    assert card["url"] == config.public_base_url.rstrip("/")
    assert card["documentationUrl"] == "https://hyrule.host/agents"
    assert card["version"] == __version__
    assert card["defaultInputModes"] == ["application/json"]
    assert card["defaultOutputModes"] == ["application/json"]
    # The card is a discovery/payment declaration only; never imply an A2A
    # JSON-RPC endpoint exists.
    assert "no A2A JSON-RPC transport" in card["description"]
    assert "x402" in card["description"]

    extensions = card["capabilities"]["extensions"]
    assert len(extensions) == 1
    extension = extensions[0]
    assert extension["uri"] == "https://github.com/google-agentic-commerce/a2a-x402/v0.1"
    assert extension["required"] is False
    assert extension["params"]["x402Version"] == 2
    assert extension["params"]["networks"] == [
        network.caip2 for network in config.payment.enabled_networks()
    ]

    # With every readiness gate open, all four service groups are skills.
    assert [skill["id"] for skill in card["skills"]] == [
        "compute",
        "domains-dns",
        "network-intelligence",
        "network-proxy",
    ]
    for skill in card["skills"]:
        assert skill["name"]
        assert skill["description"]
        assert skill["tags"]

    # Skills list live operations with their prices.
    compute = card["skills"][0]
    assert "POST /v1/vm/create" in compute["description"]
    assert "$0.20" in compute["description"]


def test_agent_card_drops_skill_groups_whose_gate_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_all_catalog_gates(monkeypatch)
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning",
        lambda: False,
    )
    card = build_agent_card(HyruleConfig())
    skill_ids = [skill["id"] for skill in card["skills"]]
    assert "compute" not in skill_ids
    assert "network-intelligence" in skill_ids
    assert "/v1/vm/create" not in json.dumps(card)


@pytest.mark.asyncio
async def test_agent_card_route_serves_the_generated_card() -> None:
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig())
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get("/.well-known/agent-card.json")
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert res.status_code == 200
    card = res.json()
    assert card["name"] == "Hyrule Cloud"
    assert card["skills"]
    assert card["capabilities"]["extensions"][0]["params"]["x402Version"] == 2


@pytest.mark.asyncio
async def test_robots_txt_welcomes_agent_crawlers() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/robots.txt")

    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/plain")
    text = res.text
    assert "User-agent: *\nAllow: /" in text
    for bot in _AGENT_BOTS:
        assert f"User-agent: {bot}" in text, bot
    assert "Disallow" not in text
    # The API host has no sitemap; hyrule.host carries the site surface.
    assert "Sitemap" not in text


def test_llms_txt_lists_live_operations_and_never_gated_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Close two gates a deployment can flip: simulated VM provisioning and the
    # DNS filtering product. Neither may appear anywhere in the guide.
    monkeypatch.setattr(
        "hyrule_cloud.services.launch_proof.use_real_provisioning",
        lambda: False,
    )
    monkeypatch.setattr(
        "hyrule_cloud.services.dns.filtering.dns_filtering_enabled",
        lambda: False,
    )
    config = HyruleConfig(payment=PaymentConfig(_env_file=None))
    text = build_llms_txt(config)

    # A live, always-on operation appears with its USD price.
    assert f"POST /v1/dns/lookup — ${config.payment.price_dns_lookup} — " in text
    # Gated-off operations never appear on any advertised surface.
    assert "/v1/vm/create" not in text
    assert "/v1/dns/filtering/check" not in text

    base = config.public_base_url.rstrip("/")
    assert f"{base}/.well-known/x402.json" in text
    assert f"{base}/openapi.json" in text
    assert f"{base}/.well-known/agent-card.json" in text
    assert "HTTP 402" in text and "X-PAYMENT" in text  # golden path
    assert '"mcpServers"' in text and "hyrule_cloud.mcp_server" in text
    assert "https://hyrule.host/llms.txt" in text
    assert "HYRULE_DEV_BYPASS" not in text

    # Reopening a gate republishes the operation.
    monkeypatch.setattr(
        "hyrule_cloud.services.dns.filtering.dns_filtering_enabled",
        lambda: True,
    )
    assert "/v1/dns/filtering/check" in build_llms_txt(config)


def test_server_json_matches_package_metadata() -> None:
    raw = (_REPO_ROOT / "server.json").read_text()
    server = json.loads(raw)
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text())

    assert server["$schema"].endswith("/server.schema.json")
    assert server["name"] == "host.hyrule/hyrule-cloud"
    assert server["version"] == pyproject["project"]["version"] == __version__

    package = server["packages"][0]
    assert package["registryType"] == "pypi"
    assert package["identifier"] == "hyrule-cloud"
    assert package["transport"] == {"type": "stdio"}

    env_names = {var["name"] for var in package["environmentVariables"]}
    assert env_names == {"HYRULE_API_URL", "HYRULE_API_KEY"}
    api_key = next(v for v in package["environmentVariables"] if v["name"] == "HYRULE_API_KEY")
    assert api_key["isSecret"] is True and api_key["isRequired"] is False
    # The dev bypass must never be advertised to registry users.
    assert "HYRULE_DEV_BYPASS" not in raw

    # Registry ownership marker for the PyPI/README validation step.
    assert "mcp-name: host.hyrule/hyrule-cloud" in (_REPO_ROOT / "README.md").read_text()


def test_x402_sdk_logger_is_bridged_to_stdout_as_json() -> None:
    """The SDK's settle-response records (EXTENSION-RESPONSES header — our
    Bazaar indexing signal) log via stdlib logger "x402"; importing the app
    must bridge them to a stdout stream handler emitting JSON lines."""

    logger = logging.getLogger("x402")
    assert logger.getEffectiveLevel() <= logging.INFO
    handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
    assert handlers, "logger 'x402' has no stream handler bridged"
    handler = handlers[0]

    # Emit through the real wired handler, swapping only the stream so the
    # assertion is independent of pytest's stdout capture layers.
    buffer = io.StringIO()
    old_stream = handler.setStream(buffer)
    try:
        logger.info("settle response extension-responses: bazaar")
    finally:
        assert old_stream is not None
        handler.setStream(old_stream)

    record = json.loads(buffer.getvalue())
    assert record["event"] == "settle response extension-responses: bazaar"
    assert record["level"] == "info"
    assert "ts" in record
