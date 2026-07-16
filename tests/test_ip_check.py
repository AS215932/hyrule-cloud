from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio
from eth_account import Account
from eth_account.messages import encode_defunct
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig, IPCheckConfig
from hyrule_cloud.db import Base, IPCheckObservationRow, IPCheckSessionRow
from hyrule_cloud.models import (
    IPCheckAgentFingerprintRequest,
    IPCheckBrowserFingerprintRequest,
    IPCheckBrowserObservationRequest,
    IPCheckDNSObservationRequest,
    IPCheckSessionCreateRequest,
)
from hyrule_cloud.services.ip_check import (
    _agent_identity_challenge,
    cleanup_expired_ip_checks,
    create_ip_check_session,
    get_ip_check_report,
    observe_browser_candidates,
    observe_dns_resolver,
    observe_https_address,
    verify_agent_wallet_signature,
    verify_dns_observer_signature,
)


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _config(**updates: object) -> IPCheckConfig:
    values: dict[str, object] = {
        "enabled": True,
        "dns_observer_secret": "observer-secret",
        "session_ttl_seconds": 900,
    }
    values.update(updates)
    return IPCheckConfig(**values)


@pytest.mark.asyncio
async def test_session_stores_only_token_hash_and_returns_probe_targets(session_factory) -> None:
    created = await create_ip_check_session(
        session_factory,
        _config(),
        IPCheckSessionCreateRequest(),
    )
    async with session_factory() as session:
        row = await session.get(IPCheckSessionRow, created.session_id)
    assert row is not None
    assert row.token_hash == hashlib.sha256(created.token.encode()).hexdigest()
    assert created.token not in row.token_hash
    assert created.ipv4_probe_url.startswith("https://v4.check.hyrule.host/")
    assert created.ipv6_probe_url.startswith("https://v6.check.hyrule.host/")
    assert created.dns_probe_hostname.endswith(".dns.check.hyrule.host")
    assert created.retention_seconds == 900


@pytest.mark.asyncio
async def test_webrtc_compares_only_public_candidates_to_https_observations(
    session_factory,
) -> None:
    config = _config()
    created = await create_ip_check_session(
        session_factory, config, IPCheckSessionCreateRequest()
    )
    await observe_https_address(
        session_factory,
        session_id=created.session_id,
        token=created.token,
        address="8.8.8.8",
    )
    await observe_browser_candidates(
        session_factory,
        session_id=created.session_id,
        token=created.token,
        observation=IPCheckBrowserObservationRequest(
            status="collected", public_addresses=["8.8.8.8"]
        ),
    )
    report = await get_ip_check_report(
        session_factory,
        config,
        session_id=created.session_id,
        token=created.token,
    )
    assert report.webrtc_leak_status == "no_leak"

    await observe_browser_candidates(
        session_factory,
        session_id=created.session_id,
        token=created.token,
        observation=IPCheckBrowserObservationRequest(
            status="collected", public_addresses=["1.1.1.1"]
        ),
    )
    report = await get_ip_check_report(
        session_factory,
        config,
        session_id=created.session_id,
        token=created.token,
    )
    assert report.webrtc_leak_status == "possible_leak"

    await observe_browser_candidates(
        session_factory,
        session_id=created.session_id,
        token=created.token,
        observation=IPCheckBrowserObservationRequest(status="blocked"),
    )
    report = await get_ip_check_report(
        session_factory,
        config,
        session_id=created.session_id,
        token=created.token,
    )
    assert report.webrtc_leak_status == "inconclusive"


def test_private_or_mdns_like_webrtc_values_are_rejected() -> None:
    with pytest.raises(ValueError, match="only public"):
        IPCheckBrowserObservationRequest(
            status="collected", public_addresses=["192.168.1.20"]
        )


def test_browser_high_entropy_traits_require_explicit_consent() -> None:
    with pytest.raises(ValueError, match="high_entropy_consent"):
        IPCheckBrowserFingerprintRequest(
            timezone="Europe/Amsterdam",
            canvas_sha256="a" * 64,
        )
    accepted = IPCheckBrowserFingerprintRequest(
        timezone="Europe/Amsterdam",
        canvas_sha256="a" * 64,
        high_entropy_consent=True,
    )
    assert accepted.canvas_sha256 == "a" * 64


def test_agent_wallet_proof_is_session_bound_and_model_claim_is_declared() -> None:
    expires_at = datetime(2026, 7, 16, 12, tzinfo=UTC)
    account = Account.create()
    challenge = _agent_identity_challenge("ipc_test", expires_at)
    signature = Account.sign_message(
        encode_defunct(text=challenge), account.key
    ).signature.hex()
    request = IPCheckAgentFingerprintRequest(
        runtime="Codex",
        protocol="mcp",
        model_vendor_claim="OpenAI",
        model_name_claim="self-declared-model",
        wallet_address=account.address,
        wallet_signature=signature,
    )
    assert request.model_name_claim == "self-declared-model"
    assert verify_agent_wallet_signature(
        session_id="ipc_test",
        expires_at=expires_at,
        wallet_address=account.address,
        wallet_signature=signature,
    )
    assert not verify_agent_wallet_signature(
        session_id="ipc_other",
        expires_at=expires_at,
        wallet_address=account.address,
        wallet_signature=signature,
    )
    with pytest.raises(ValueError, match="IP addresses"):
        IPCheckBrowserObservationRequest(
            status="collected", public_addresses=["host-123.local"]
        )


@pytest.mark.asyncio
async def test_dns_is_not_called_a_leak_without_an_explicit_expectation(
    session_factory,
) -> None:
    config = _config()
    unscoped = await create_ip_check_session(
        session_factory, config, IPCheckSessionCreateRequest()
    )
    label = unscoped.dns_probe_hostname.split(".", 1)[0]
    assert await observe_dns_resolver(
        session_factory,
        IPCheckDNSObservationRequest(dns_label=label, resolver_address="1.1.1.1"),
    )
    report = await get_ip_check_report(
        session_factory,
        config,
        session_id=unscoped.session_id,
        token=unscoped.token,
    )
    assert report.dns_leak_status == "not_assessed"
    assert report.dns_expectation_configured is False

    scoped = await create_ip_check_session(
        session_factory,
        config,
        IPCheckSessionCreateRequest(expected_dns_resolvers=["8.8.8.0/24"]),
    )
    label = scoped.dns_probe_hostname.split(".", 1)[0]
    await observe_dns_resolver(
        session_factory,
        IPCheckDNSObservationRequest(dns_label=label, resolver_address="8.8.8.8"),
    )
    report = await get_ip_check_report(
        session_factory,
        config,
        session_id=scoped.session_id,
        token=scoped.token,
    )
    assert report.dns_leak_status == "no_leak"
    await observe_dns_resolver(
        session_factory,
        IPCheckDNSObservationRequest(dns_label=label, resolver_address="1.1.1.1"),
    )
    report = await get_ip_check_report(
        session_factory,
        config,
        session_id=scoped.session_id,
        token=scoped.token,
    )
    assert report.dns_leak_status == "possible_leak"


def test_dns_observer_hmac_is_body_bound_and_time_bounded() -> None:
    config = _config()
    body = b'{"dns_label":"abc12345","resolver_address":"1.1.1.1"}'
    timestamp = str(int(time.time()))
    signature = hmac.new(
        config.dns_observer_secret.encode(),
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    assert verify_dns_observer_signature(
        config, timestamp=timestamp, signature=signature, body=body
    )
    assert not verify_dns_observer_signature(
        config, timestamp=timestamp, signature=signature, body=body + b" "
    )
    assert not verify_dns_observer_signature(
        config,
        timestamp=str(int(timestamp) - 600),
        signature=signature,
        body=body,
    )


@pytest.mark.asyncio
async def test_cleanup_enforces_fifteen_minute_maximum(session_factory) -> None:
    created = await create_ip_check_session(
        session_factory, _config(), IPCheckSessionCreateRequest()
    )
    async with session_factory() as session:
        row = await session.get(IPCheckSessionRow, created.session_id)
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(
            IPCheckObservationRow(
                session_id=created.session_id,
                kind="dns",
                address="1.1.1.1",
                observed_at=datetime.now(UTC) - timedelta(minutes=16),
            )
        )
        await session.commit()
        await cleanup_expired_ip_checks(session)
        await session.commit()
    async with session_factory() as session:
        assert await session.get(IPCheckSessionRow, created.session_id) is None
        observations = list((await session.scalars(select(IPCheckObservationRow))).all())
    assert observations == []


@pytest.mark.asyncio
async def test_disabled_api_refuses_before_creating_session() -> None:
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(config=HyruleConfig(), session_factory=None)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/ip-check/sessions", json={})
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")
    assert response.status_code == 501


@pytest.mark.asyncio
async def test_api_records_dual_stack_probe_and_hmac_dns_observation(
    session_factory,
) -> None:
    config = _config()
    old_state = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=HyruleConfig(ip_check=config),
        session_factory=session_factory,
    )
    transport = ASGITransport(app=app, client=("8.8.8.8", 44321))
    try:
        async with AsyncClient(
            transport=transport, base_url="https://v4.check.hyrule.host"
        ) as client:
            created_response = await client.post("/v1/ip-check/sessions", json={})
            assert created_response.status_code == 200
            created = created_response.json()
            auth = {"Authorization": f"Bearer {created['token']}"}
            observed = await client.post(
                f"/v1/ip-check/sessions/{created['session_id']}/observe/http",
                headers=auth,
            )
            assert observed.status_code == 200
            assert observed.json()["family"] == 4

            dns_body = json.dumps(
                {
                    "dns_label": created["dns_probe_hostname"].split(".", 1)[0],
                    "resolver_address": "1.1.1.1",
                },
                separators=(",", ":"),
            ).encode()
            timestamp = str(int(time.time()))
            signature = hmac.new(
                config.dns_observer_secret.encode(),
                timestamp.encode() + b"." + dns_body,
                hashlib.sha256,
            ).hexdigest()
            dns_response = await client.post(
                "/v1/internal/ip-check/dns-observations",
                content=dns_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hyrule-Timestamp": timestamp,
                    "X-Hyrule-Signature": signature,
                },
            )
            assert dns_response.status_code == 202
            report = await client.get(
                f"/v1/ip-check/sessions/{created['session_id']}", headers=auth
            )
    finally:
        if old_state is not None:
            app.state._typed_state = old_state
        elif hasattr(app.state, "_typed_state"):
            delattr(app.state, "_typed_state")

    assert report.status_code == 200
    assert report.json()["https_ipv4_addresses"] == ["8.8.8.8"]
    assert report.json()["dns_resolver_addresses"] == ["1.1.1.1"]
    assert report.json()["dns_leak_status"] == "not_assessed"
