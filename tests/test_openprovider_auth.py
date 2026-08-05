"""OpenProvider bearer-token lifecycle.

OpenProvider answers a rejected bearer with HTTP 500 and API code 196
("Authentication/Authorization Failed") instead of a 401. A client that keys
its refresh off 401 alone stays wedged on a dead token for the lifetime of the
process, which is how the domain catalog sync went from healthy to failing on
every pass without a single re-authentication attempt.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from hyrule_cloud.config import OpenproviderConfig
from hyrule_cloud.providers.openprovider import (
    OpenproviderClient,
    OpenproviderError,
    _is_auth_rejection,
)

AUTH_REJECTED_BODY = {"code": 196, "desc": "Authentication/Authorization Failed"}


def _config() -> OpenproviderConfig:
    return OpenproviderConfig(
        api_url="https://api.openprovider.test/v1beta",
        username="reseller",
        password="hunter2",
    )


class _FakeOpenprovider:
    """Scripted OpenProvider that can expire the bearer it handed out."""

    def __init__(self, *, tlds_response: list[dict[str, Any]] | None = None) -> None:
        self.issued: list[str] = []
        self.live_token: str | None = None
        self.logins = 0
        self.calls: list[tuple[str, str, str | None]] = []
        self._tlds = tlds_response if tlds_response is not None else [{"name": "dev"}]

    def expire_current_token(self) -> None:
        self.live_token = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        bearer = request.headers.get("Authorization", "").removeprefix("Bearer ") or None
        self.calls.append((request.method, request.url.path, bearer))

        if request.url.path.endswith("/auth/login"):
            self.logins += 1
            token = f"token-{self.logins}"
            self.issued.append(token)
            self.live_token = token
            return httpx.Response(200, json={"code": 0, "data": {"token": token}})

        if bearer != self.live_token:
            # The exact shape observed from the live API for a dead bearer.
            return httpx.Response(500, json=AUTH_REJECTED_BODY)

        return httpx.Response(200, json={"code": 0, "data": {"results": self._tlds}})

    def client(self) -> OpenproviderClient:
        client = OpenproviderClient(_config())
        client._http = httpx.AsyncClient(
            base_url=_config().api_url,
            transport=httpx.MockTransport(self.handler),
        )
        return client

    @property
    def business_calls(self) -> list[tuple[str, str, str | None]]:
        return [call for call in self.calls if not call[1].endswith("/auth/login")]


def test_is_auth_rejection_accepts_int_and_string_codes() -> None:
    assert _is_auth_rejection(196)
    assert _is_auth_rejection("196")
    assert not _is_auth_rejection(500)
    assert not _is_auth_rejection(None)
    assert not _is_auth_rejection("not-a-code")


@pytest.mark.asyncio
async def test_expired_bearer_is_refreshed_and_the_safe_call_succeeds() -> None:
    """The catalog sync must heal itself instead of failing on every pass."""
    provider = _FakeOpenprovider()
    client = provider.client()
    try:
        assert await client.list_tlds() == [{"name": "dev"}]
        assert provider.logins == 1

        # The bearer dies server-side between two scheduled syncs.
        provider.expire_current_token()

        assert await client.list_tlds() == [{"name": "dev"}]
    finally:
        await client.close()

    assert provider.logins == 2
    assert client._token == provider.issued[-1]


@pytest.mark.asyncio
async def test_repeated_syncs_keep_working_after_every_expiry() -> None:
    provider = _FakeOpenprovider()
    client = provider.client()
    try:
        for _ in range(4):
            provider.expire_current_token()
            assert await client.list_tlds() == [{"name": "dev"}]
    finally:
        await client.close()

    # One login to open the client, then one per subsequent expiry.
    assert provider.logins == 4


@pytest.mark.asyncio
async def test_rejected_bearer_is_dropped_even_when_the_call_is_not_replayed() -> None:
    """A non-idempotent call fails, but never on a token known to be dead."""
    provider = _FakeOpenprovider()
    client = provider.client()
    try:
        await client.list_tlds()
        provider.expire_current_token()

        with pytest.raises(OpenproviderError):
            await client._request("POST", "/domains", safe_retry=False, json={})

        # The next call re-authenticates rather than reusing the dead bearer.
        assert await client.list_tlds() == [{"name": "dev"}]
    finally:
        await client.close()

    assert provider.logins == 2


@pytest.mark.asyncio
async def test_registration_is_never_replayed_after_an_auth_rejection() -> None:
    """Code 196 rides on a 500, so it must not trigger a blind re-submit."""
    provider = _FakeOpenprovider()
    client = provider.client()
    try:
        await client.list_tlds()
        provider.expire_current_token()

        with pytest.raises(OpenproviderError):
            await client._request("POST", "/domains", safe_retry=False, json={})
    finally:
        await client.close()

    registrations = [call for call in provider.business_calls if call[1].endswith("/domains")]
    assert len(registrations) == 1


@pytest.mark.asyncio
async def test_http_401_still_refreshes_and_replays() -> None:
    """Regression guard on the pre-existing 401 contract."""
    responses = [
        httpx.Response(401, json={"desc": "expired"}),
        httpx.Response(200, json={"code": 0, "data": {"results": []}}),
    ]
    logins = 0
    business_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal logins, business_calls
        if request.url.path.endswith("/auth/login"):
            logins += 1
            return httpx.Response(200, json={"code": 0, "data": {"token": f"t{logins}"}})
        business_calls += 1
        return responses.pop(0)

    client = OpenproviderClient(_config())
    client._http = httpx.AsyncClient(
        base_url=_config().api_url,
        transport=httpx.MockTransport(handler),
    )
    try:
        replayed = await client._request("POST", "/domains", safe_retry=False, json={})
        assert replayed == {"results": []}
    finally:
        await client.close()

    assert logins == 2
    assert business_calls == 2


@pytest.mark.asyncio
async def test_concurrent_rejections_refresh_the_bearer_once() -> None:
    """In-flight callers must not stampede /auth/login with the same refresh."""
    provider = _FakeOpenprovider()
    client = provider.client()
    try:
        await client.list_tlds()
        provider.expire_current_token()

        results = await asyncio.gather(*(client.list_tlds() for _ in range(5)))
    finally:
        await client.close()

    assert all(result == [{"name": "dev"}] for result in results)
    assert provider.logins == 2
