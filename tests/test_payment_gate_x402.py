from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from fastapi import Response
from starlette.requests import Request
from x402.http import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    X_PAYMENT_HEADER,
    X_PAYMENT_RESPONSE_HEADER,
    encode_payment_signature_header,
)
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.schemas import (
    PaymentPayload,
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
    VerifyResponse,
)

from hyrule_cloud.config import PaymentConfig
from hyrule_cloud.middleware.x402 import (
    LEGACY_PAYMENT_REQUIRED_HEADER,
    CdpFacilitatorAuthProvider,
    PaymentGate,
    _facilitator_config,
)

RECEIVER = "0xFf4555af30A1066A889324a3Fe88c76796159f15"
PAYER = "0xFBD95291e4b9C901E084a8856eA184d3F7A232ed"
ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def _request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [
        (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/vm/create",
            "query_string": b"",
            "headers": [(b"host", b"testserver"), *raw_headers],
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )


class _FakeServer:
    def __init__(self, *, valid: bool = True, settle_success: bool = True) -> None:
        self.valid = valid
        self.settle_success = settle_success
        self.initialized = False
        self.verify_payment_calls = 0
        self.settle_payment_calls = 0
        self.last_resource: ResourceInfo | None = None
        self.last_extensions: dict | None = None
        self.requirements = [
            PaymentRequirements(
                scheme="exact",
                network="eip155:8453",
                asset=ASSET,
                amount="50000",
                pay_to=RECEIVER,
                max_timeout_seconds=300,
                extra={"name": "USD Coin", "version": "2"},
            )
        ]

    def initialize(self) -> None:
        self.initialized = True

    def build_payment_requirements(self, config: Any) -> list[PaymentRequirements]:
        return self.requirements

    def create_payment_required_response(
        self,
        requirements: list[PaymentRequirements],
        resource: ResourceInfo | None = None,
        error: str | None = None,
        extensions: dict | None = None,
    ) -> PaymentRequired:
        self.last_resource = resource
        self.last_extensions = extensions
        return PaymentRequired(
            x402_version=2,
            error=error,
            resource=resource,
            accepts=requirements,
            extensions=extensions,
        )

    def enrich_extensions(self, declared: dict, transport_context: object) -> dict:
        from x402.extensions.bazaar import bazaar_resource_server_extension

        return {
            key: bazaar_resource_server_extension.enrich_declaration(value, transport_context)
            if key == "bazaar"
            else value
            for key, value in declared.items()
        }

    def find_matching_requirements(
        self,
        available: list[PaymentRequirements],
        payload: PaymentPayload,
    ) -> PaymentRequirements | None:
        for req in available:
            if payload.accepted == req:
                return req
        return None

    async def verify_payment(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        self.verify_payment_calls += 1
        return VerifyResponse(
            is_valid=self.valid,
            invalid_reason=None if self.valid else "invalid_signature",
            payer=PAYER if self.valid else None,
        )

    async def settle_payment(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse:
        self.settle_payment_calls += 1
        return SettleResponse(
            success=self.settle_success,
            error_reason=None if self.settle_success else "insufficient_funds",
            payer=PAYER,
            transaction="0xSETTLED" if self.settle_success else "",
            network="eip155:8453",
            amount=requirements.amount,
        )


class _AsyncPaymentRequiredServer(_FakeServer):
    async def create_payment_required_response(
        self,
        requirements: list[PaymentRequirements],
        resource: ResourceInfo | None = None,
        error: str | None = None,
        extensions: dict | None = None,
    ) -> PaymentRequired:
        return super().create_payment_required_response(requirements, resource, error, extensions)


class _FailingInitServer(_FakeServer):
    def initialize(self) -> None:
        raise RuntimeError("facilitator down")


def _gate(server: _FakeServer, public_base_url: str = "") -> PaymentGate:
    gate = PaymentGate(
        PaymentConfig(
            receiver_address=RECEIVER,
            facilitator_url="https://facilitator.payai.network",
        ),
        public_base_url=public_base_url,
    )
    gate.server = server  # type: ignore[assignment]
    return gate


def _payment_header(req: PaymentRequirements | None = None) -> str:
    accepted = req or _FakeServer().requirements[0]
    payload = PaymentPayload(
        x402_version=2,
        accepted=accepted,
        payload={
            "authorization": {
                "from": PAYER,
                "to": accepted.pay_to,
                "value": accepted.amount,
                "validAfter": "0",
                "validBefore": "9999999999",
                "nonce": "0x" + "11" * 32,
            },
            "signature": "0x" + "22" * 65,
        },
    )
    return encode_payment_signature_header(payload)


def test_sdk_accepts_dollar_prefixed_money_price() -> None:
    parsed = ExactEvmServerScheme().parse_price("$0.05", "eip155:8453")

    assert parsed.amount == "50000"
    assert parsed.asset == ASSET


def test_unknown_facilitator_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported x402 facilitator host"):
        _facilitator_config(
            PaymentConfig(
                receiver_address=RECEIVER,
                facilitator_url="https://example.internal",
            )
        )


@pytest.mark.parametrize(
    "facilitator_url",
    [
        "https://facilitator.payai.network",
        "https://pay.openfacilitator.io",
    ],
)
def test_non_cdp_facilitator_does_not_attach_cdp_auth(monkeypatch: pytest.MonkeyPatch, facilitator_url: str) -> None:
    monkeypatch.setenv("CDP_API_KEY_ID", "organizations/test/apiKeys/key-id")
    monkeypatch.setenv("CDP_API_KEY_SECRET", "not-used-for-public-facilitator")

    config = _facilitator_config(
        PaymentConfig(
            receiver_address=RECEIVER,
            facilitator_url=facilitator_url,
        )
    )

    assert config.auth_provider is None


def test_cdp_auth_provider_generates_endpoint_scoped_bearer_jwts() -> None:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    provider = CdpFacilitatorAuthProvider(
        "organizations/test/apiKeys/key-id",
        private_pem,
        "https://api.cdp.coinbase.com/platform/v2/x402",
    )

    token = provider.get_auth_headers().supported["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})

    assert claims["iss"] == "organizations/test/apiKeys/key-id"
    assert claims["uri"] == "GET api.cdp.coinbase.com/platform/v2/x402/supported"


@pytest.mark.asyncio
async def test_no_payment_returns_standard_and_legacy_payment_required_headers() -> None:
    server = _FakeServer()
    gate = _gate(server)

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert PAYMENT_REQUIRED_HEADER in result.headers
    assert LEGACY_PAYMENT_REQUIRED_HEADER in result.headers
    assert result.headers[PAYMENT_REQUIRED_HEADER] == result.headers[LEGACY_PAYMENT_REQUIRED_HEADER]
    assert server.initialized is True


@pytest.mark.asyncio
async def test_402_resource_url_prefers_public_base_url() -> None:
    """Behind the TLS proxy the raw request URL is http://<backend>; the 402
    resource URL must be the canonical public origin so Bazaar/x402scan index
    the right identity."""
    server = _FakeServer()
    gate = _gate(server, public_base_url="https://cloud.hyrule.host")

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert server.last_resource is not None
    assert server.last_resource.url == "https://cloud.hyrule.host/v1/vm/create"


@pytest.mark.asyncio
async def test_402_resource_url_falls_back_to_request_url() -> None:
    server = _FakeServer()
    gate = _gate(server)

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert server.last_resource is not None
    assert server.last_resource.url == "http://testserver/v1/vm/create"


@pytest.mark.asyncio
async def test_no_payment_awaits_async_payment_required_builder() -> None:
    gate = _gate(_AsyncPaymentRequiredServer())

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert PAYMENT_REQUIRED_HEADER in result.headers


@pytest.mark.asyncio
async def test_standard_payment_signature_header_verifies_and_settles() -> None:
    server = _FakeServer()
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})
    gate = _gate(server)

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == PAYER
    assert server.verify_payment_calls == 1
    assert server.settle_payment_calls == 1
    assert req.state.payment_tx == "0xSETTLED"
    assert req.state.payment_response_headers[PAYMENT_RESPONSE_HEADER]
    assert req.state.payment_response_headers[X_PAYMENT_RESPONSE_HEADER]


@pytest.mark.asyncio
async def test_legacy_x_payment_header_verifies_and_settles() -> None:
    server = _FakeServer()
    req = _request({X_PAYMENT_HEADER: _payment_header(server.requirements[0])})
    gate = _gate(server)

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert result == PAYER
    assert server.verify_payment_calls == 1
    assert server.settle_payment_calls == 1


@pytest.mark.asyncio
async def test_invalid_payment_returns_402_not_502() -> None:
    server = _FakeServer(valid=False)
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})
    gate = _gate(server)

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert server.verify_payment_calls == 1
    assert server.settle_payment_calls == 0


@pytest.mark.asyncio
async def test_settlement_failure_returns_402_with_payment_response_headers() -> None:
    server = _FakeServer(settle_success=False)
    req = _request({PAYMENT_SIGNATURE_HEADER: _payment_header(server.requirements[0])})
    gate = _gate(server)

    result = await gate.check_payment(req, Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert PAYMENT_RESPONSE_HEADER in result.headers
    assert X_PAYMENT_RESPONSE_HEADER in result.headers


@pytest.mark.asyncio
async def test_facilitator_initialization_failure_returns_503() -> None:
    gate = _gate(_FailingInitServer())

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 503


@pytest.mark.asyncio
async def test_app_middleware_propagates_payment_response_headers() -> None:
    from hyrule_cloud.app import attach_payment_response_headers

    req = _request()

    async def call_next(request: Request) -> Response:
        request.state.payment_response_headers = {
            PAYMENT_RESPONSE_HEADER: "standard",
            X_PAYMENT_RESPONSE_HEADER: "legacy",
        }
        return Response("ok")

    result = await attach_payment_response_headers(req, call_next)

    assert result.headers[PAYMENT_RESPONSE_HEADER] == "standard"
    assert result.headers[X_PAYMENT_RESPONSE_HEADER] == "legacy"
    exposed = result.headers["Access-Control-Expose-Headers"]
    assert PAYMENT_RESPONSE_HEADER in exposed
    assert X_PAYMENT_RESPONSE_HEADER in exposed


@pytest.mark.asyncio
async def test_402_carries_bazaar_discovery_extension_for_declared_route() -> None:
    server = _FakeServer()
    gate = _gate(server)

    result = await gate.check_payment(_request(), Decimal("0.05"), "VM creation")

    assert isinstance(result, Response)
    assert result.status_code == 402
    assert server.last_extensions is not None
    bazaar = server.last_extensions["bazaar"]
    # The server extension must have enriched the declaration with the method.
    assert bazaar["info"]["input"]["method"] == "POST"
    assert bazaar["info"]["input"]["bodyType"] == "json"
    assert "duration_days" in bazaar["info"]["input"]["body"]


@pytest.mark.asyncio
async def test_402_has_no_extensions_for_undeclared_route() -> None:
    server = _FakeServer()
    gate = _gate(server)
    req = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/vm/quote",
            "query_string": b"",
            "headers": [(b"host", b"testserver")],
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
    )

    result = await gate.check_payment(req, Decimal("0.05"), "quote")

    assert isinstance(result, Response)
    assert server.last_extensions is None


def test_discovery_registry_only_declares_real_endpoints() -> None:
    """Declaring an endpoint IS advertising it — unbuilt services must not appear."""
    from hyrule_cloud.services.discovery import DISCOVERY

    declared_paths = {path for _, path in DISCOVERY}
    for dead in ("/v1/mail/accounts", "/v1/mail/messages/send", "/v1/speedtest", "/v1/web/reports", "/v1/voip/report", "/v1/path/jobs"):
        assert dead not in declared_paths
