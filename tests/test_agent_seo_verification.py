from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from hyrule_cloud.app import app
from hyrule_cloud.config import HyruleConfig


@pytest.mark.asyncio
async def test_agent_seo_http_ownership_proof_is_static_and_optional() -> None:
    previous = getattr(app.state, "_typed_state", None)
    app.state._typed_state = SimpleNamespace(
        config=HyruleConfig(agent_seo_verification_token="claim-token")
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/.well-known/agent-seo-verification")
    finally:
        if previous is None:
            delattr(app.state, "_typed_state")
        else:
            app.state._typed_state = previous

    assert response.status_code == 200
    assert response.text == "claim-token"
    assert "X-Agent-SEO-Revision" not in response.headers
