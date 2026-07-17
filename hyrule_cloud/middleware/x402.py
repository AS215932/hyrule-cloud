"""
x402 payment integration using the official Coinbase SDK.

The official PaymentMiddlewareASGI works for static per-route pricing,
but our endpoints have dynamic pricing (VM size * duration). So we use
the SDK's lower-level primitives:

- x402ResourceServer + exact EVM/SVM schemes for verify/settle
- HTTPFacilitatorClient for facilitator communication
- PaymentRequirements / PaymentRequired models for response formatting

Route handlers call `check_payment()` with a computed amount and get
back either a 402 Response or the verified payment details.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import structlog
from fastapi import Request, Response
from x402.extensions.bazaar import bazaar_resource_server_extension
from x402.http import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    X_PAYMENT_HEADER,
    X_PAYMENT_RESPONSE_HEADER,
    AuthHeaders,
    FacilitatorConfig,
    HTTPFacilitatorClient,
    decode_payment_signature_header,
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.mechanisms.svm.exact import ExactSvmServerScheme
from x402.schemas import PaymentPayload, PaymentRequirements, ResourceConfig, ResourceInfo
from x402.server import x402ResourceServer

from hyrule_cloud.config import PaymentConfig

if TYPE_CHECKING:
    from hyrule_cloud.services.payments_ledger import PaymentLedger

log = structlog.get_logger()

LEGACY_PAYMENT_REQUIRED_HEADER = "X-PAYMENT-REQUIRED"
_OPENFACILITATOR_HOST = "pay.openfacilitator.io"
_PAYAI_FACILITATOR_HOST = "facilitator.payai.network"
_CDP_FACILITATOR_HOST = "api.cdp.coinbase.com"
_ALLOWED_FACILITATOR_HOSTS = {
    _OPENFACILITATOR_HOST,
    _PAYAI_FACILITATOR_HOST,
    _CDP_FACILITATOR_HOST,
}


class CdpFacilitatorAuthProvider:
    """Generate short-lived CDP REST JWT auth headers for x402 facilitator calls."""

    def __init__(self, api_key_id: str, api_key_secret: str, facilitator_url: str) -> None:
        self.api_key_id = api_key_id
        self.api_key_secret = api_key_secret.replace("\\n", "\n")
        parsed = urlparse(facilitator_url)
        self.host = parsed.netloc or _CDP_FACILITATOR_HOST
        self.base_path = parsed.path.rstrip("/")

    def _jwt_for(self, method: str, suffix: str) -> str:
        import jwt

        now = int(time.time())
        path = f"{self.base_path}/{suffix.lstrip('/')}"
        uri = f"{method.upper()} {self.host}{path}"
        # Claim shape must match coinbase/cdp-sdk generate_jwt: `iss` is the
        # literal "cdp" (the key id goes in sub/kid only) and the endpoint
        # scope is a `uris` list. CDP rejects iss=<key id> with a plain 401.
        payload = {
            "iss": "cdp",
            "sub": self.api_key_id,
            "nbf": now,
            "exp": now + 120,
            "uris": [uri],
        }
        headers = {"kid": self.api_key_id, "nonce": secrets.token_hex(16)}
        return jwt.encode(payload, self.api_key_secret, algorithm="ES256", headers=headers)

    def _bearer(self, method: str, suffix: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._jwt_for(method, suffix)}"}

    def get_auth_headers(self) -> AuthHeaders:
        return AuthHeaders(
            verify=self._bearer("POST", "verify"),
            settle=self._bearer("POST", "settle"),
            supported=self._bearer("GET", "supported"),
        )


def _dotenv_value(key: str) -> str:
    try:
        for raw_line in open(".env", encoding="utf-8"):
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() == key:
                return value.strip().strip('"').strip("'")
    except OSError:
        return ""
    return ""


def _env_or_dotenv(key: str) -> str:
    return os.environ.get(key, "") or _dotenv_value(key)


def _facilitator_config(config: PaymentConfig) -> FacilitatorConfig:
    auth_provider = None
    facilitator_host = urlparse(config.facilitator_url).hostname or ""
    if facilitator_host not in _ALLOWED_FACILITATOR_HOSTS:
        raise ValueError(f"Unsupported x402 facilitator host: {facilitator_host}")
    if facilitator_host == _CDP_FACILITATOR_HOST:
        api_key_id = _env_or_dotenv("CDP_API_KEY_ID")
        api_key_secret = _env_or_dotenv("CDP_API_KEY_SECRET")
        if not (api_key_id and api_key_secret):
            # CDP requires auth on every endpoint (401 otherwise), and the
            # vault render hook does not treat these keys as required — fail
            # at boot rather than 401 on every paid request.
            raise ValueError(
                "CDP facilitator configured but CDP_API_KEY_ID/CDP_API_KEY_SECRET are unset"
            )
        auth_provider = CdpFacilitatorAuthProvider(
            api_key_id,
            api_key_secret,
            config.facilitator_url,
        )
    return FacilitatorConfig(url=config.facilitator_url, auth_provider=auth_provider)


@dataclass
class VerifiedPayment:
    """A payment that passed verification but has NOT been settled yet.

    Returned by ``PaymentGate.verify_only``. Hand it to
    ``PaymentGate.settle_verified`` once the paid resource has actually been
    delivered, so a post-payment delivery failure (a proxy 5xx, a provisioning
    error) never moves the customer's money.
    """

    payer: str
    amount: Decimal
    payment_payload: PaymentPayload | None = None
    matching_requirements: PaymentRequirements | None = None
    dev_bypass: bool = False


class PaymentGate:
    """
    Handles x402 payment verification for dynamically-priced endpoints.

    Uses the official x402 SDK for all protocol-level operations.
    Route handlers call `check_payment()` which either returns
    a 402 Response (no/bad payment) or the payer's wallet address.
    """

    def __init__(
        self,
        config: PaymentConfig,
        public_base_url: str = "",
        ledger: PaymentLedger | None = None,
    ) -> None:
        self.config = config
        self.public_base_url = public_base_url.rstrip("/")
        self.ledger = ledger
        self._facilitator_host = urlparse(config.facilitator_url).hostname or ""
        self.facilitator = HTTPFacilitatorClient(_facilitator_config(config))
        self.server = x402ResourceServer(self.facilitator)
        # Bazaar discovery: enriches declared extensions with the HTTP method
        # so CDP can index the endpoint at settlement time.
        self.server.register_extension(bazaar_resource_server_extension)
        for network in self.config.enabled_networks():
            if network.family == "evm":
                scheme = ExactEvmServerScheme()
            elif network.family == "svm":
                scheme = ExactSvmServerScheme()
            else:  # PaymentConfig rejects this; keep the gate fail-closed too.
                raise ValueError(f"Unsupported payment network family: {network.family}")
            self.server.register(network.caip2, scheme)
        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def _ensure_initialized(self) -> bool:
        """Lazily fetch facilitator support once for SDK requirement building."""
        if self._initialized:
            return True
        async with self._init_lock:
            if self._initialized:
                return True
            try:
                await asyncio.to_thread(self.server.initialize)
            except Exception:
                log.error("payment_facilitator_initialization_failed", exc_info=True)
                return False
            self._initialized = True
            return True

    @staticmethod
    def _json_response(
        status_code: int, body: dict[str, Any], headers: dict[str, str] | None = None
    ) -> Response:
        response_headers = {"Content-Type": "application/json"}
        if headers:
            response_headers.update(headers)
        return Response(
            status_code=status_code,
            content=json.dumps(body),
            headers=response_headers,
        )

    def _supported_networks(self) -> list[Any]:
        """Configured networks the initialized facilitator can actually settle."""
        get_supported = getattr(self.server, "get_supported_kind", None)
        if get_supported is None:
            # Compatibility for deterministic SDK test doubles.
            return self.config.enabled_networks()

        supported = []
        for network in self.config.enabled_networks():
            if not self.config.receiver_for(network):
                log.error("payment_receiver_missing", network=network.caip2)
                continue
            kind = get_supported(2, network.caip2, "exact")
            if kind is None:
                continue
            if network.family == "svm" and not (getattr(kind, "extra", None) or {}).get("feePayer"):
                log.error("svm_facilitator_missing_fee_payer", network=network.caip2)
                continue
            supported.append(network)
        return supported

    async def supported_network_keys(self) -> set[str]:
        """Return only networks safe to advertise to clients."""
        if not await self._ensure_initialized():
            return set()
        return {network.key for network in self._supported_networks()}

    def _resource_configs(self, amount: Decimal) -> list[ResourceConfig]:
        return [
            ResourceConfig(
                scheme="exact",
                network=network.caip2,
                pay_to=self.config.receiver_for(network),
                price=f"${amount}",
            )
            for network in self._supported_networks()
        ]

    def _build_requirements(self, amount: Decimal) -> list[PaymentRequirements]:
        requirements: list[PaymentRequirements] = []
        for resource_cfg in self._resource_configs(amount):
            requirements.extend(self.server.build_payment_requirements(resource_cfg))
        if not requirements:
            raise RuntimeError("No configured payment network is supported by the facilitator")
        return requirements

    def _discovery_extensions(
        self,
        request: Request,
        *,
        route_path: str | None = None,
    ) -> dict[str, Any] | None:
        """Look up and enrich the Bazaar discovery declaration for this route."""
        from hyrule_cloud.services.discovery import discovery_for

        route = request.scope.get("route")
        path = route_path or getattr(route, "path", None) or request.url.path
        declared = discovery_for(request.method, path)
        if not declared:
            return None
        enrich = getattr(self.server, "enrich_extensions", None)
        if enrich is None:
            return declared
        try:
            return enrich(declared, SimpleNamespace(method=request.method))
        except Exception:
            log.warning("bazaar_extension_enrich_failed", exc_info=True)
            return declared

    def _resource_info(self, request_url: str | None, description: str | None) -> ResourceInfo:
        """Bazaar resource metadata for the 402 challenge.

        The CDP quality score weighs metadata completeness, so when the URL
        maps to an enabled catalog operation the challenge carries service
        name, tags, mime type, and icon — not just url+description.
        """
        from urllib.parse import urlsplit

        from hyrule_cloud.services.discovery import (
            marketplace_resource_description,
            match_enabled_operation_any_method,
        )

        operation = None
        if request_url:
            operation = match_enabled_operation_any_method(urlsplit(request_url).path)
        if operation is None:
            return ResourceInfo(url=request_url or "", description=description or None)
        return ResourceInfo(
            url=request_url or "",
            description=marketplace_resource_description(operation),
            mime_type="application/json",
            service_name="Hyrule Cloud",
            tags=list(operation.tags),
            icon_url=(f"{self.public_base_url}/icon-192.png" if self.public_base_url else None),
        )

    async def _payment_required_response(
        self,
        requirements: list[PaymentRequirements],
        amount: Decimal,
        description: str,
        extra_body: dict[str, Any] | None,
        request_url: str | None = None,
        error: str | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> Response:
        resource = self._resource_info(request_url, description)
        payment_required = self.server.create_payment_required_response(
            requirements,
            resource=resource,
            error=error,
            extensions=extensions,
        )
        if inspect.isawaitable(payment_required):
            payment_required = await payment_required
        encoded = encode_payment_required_header(payment_required)

        # Header and body must describe the same challenge. Serializing the SDK
        # model preserves resource metadata and extensions (especially Bazaar),
        # which the previous hand-built body accidentally dropped.
        body: dict[str, Any] = dict(extra_body or {})
        body.update(payment_required.model_dump(by_alias=True, exclude_none=True))
        body.update(
            {
                # Hyrule compatibility fields retained alongside canonical v2.
                "payment_required": True,
                "amount": str(amount),
                "description": description,
                "networks": [requirement.network for requirement in requirements],
            }
        )

        return self._json_response(
            402,
            body,
            headers={
                PAYMENT_REQUIRED_HEADER: encoded,
                LEGACY_PAYMENT_REQUIRED_HEADER: encoded,
            },
        )

    async def build_402_response(
        self,
        amount: Decimal,
        description: str = "",
        extra_body: dict[str, Any] | None = None,
        request_url: str | None = None,
        error: str | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> Response:
        """
        Build a Payment Required response using x402 SDK types.

        The response includes the standard x402 v2 header (`PAYMENT-REQUIRED`)
        plus Hyrule's legacy compatibility header (`X-PAYMENT-REQUIRED`).
        """
        configured = self.config.enabled_networks()
        has_receiver = any(self.config.receiver_for(network) for network in configured)
        if not configured or not has_receiver:
            log.error(
                "payment_config_unavailable",
                has_receiver=has_receiver,
                networks=len(configured),
            )
            return self._json_response(503, {"error": "Payment facilitator unavailable"})

        if not await self._ensure_initialized():
            return self._json_response(503, {"error": "Payment facilitator unavailable"})

        try:
            requirements = self._build_requirements(amount)
        except Exception:
            log.error("payment_requirement_build_failed", exc_info=True)
            return self._json_response(503, {"error": "Payment facilitator unavailable"})

        return await self._payment_required_response(
            requirements,
            amount,
            description,
            extra_body,
            request_url=request_url,
            error=error,
            extensions=extensions,
        )

    @staticmethod
    def _payment_header(request: Request) -> str | None:
        return request.headers.get(PAYMENT_SIGNATURE_HEADER) or request.headers.get(
            X_PAYMENT_HEADER
        )

    def has_payment_credentials(self, request: Request) -> bool:
        """True when this request will actually be charged if valid — a
        payment header is present, or the dev bypass matches. Routes use this
        to reserve scarce resources only for paying requests, not for the
        unpaid discovery round-trip that just fetches the 402."""
        if self._payment_header(request):
            return True
        return bool(
            self.config.dev_bypass_secret
            and request.headers.get("X-DEV-BYPASS") == self.config.dev_bypass_secret
        )

    # Ledger writes are best-effort observability: a slow/exhausted payments
    # DB must never hold a settled response hostage. Writes that exceed this
    # bound are dropped with a warning.
    _LEDGER_WRITE_TIMEOUT_SECONDS = 2.0

    async def _record(
        self, event_type: str, request: Request, amount: Decimal, **kwargs: Any
    ) -> None:
        """Bounded ledger write; no-op without a ledger, never raises."""
        if self.ledger is None:
            return
        try:
            await asyncio.wait_for(
                self.ledger.record(
                    event_type=event_type,
                    request=request,
                    amount=amount,
                    facilitator_host=self._facilitator_host,
                    **kwargs,
                ),
                timeout=self._LEDGER_WRITE_TIMEOUT_SECONDS,
            )
        except Exception:
            log.warning("payment_ledger_write_dropped", event_type=event_type, exc_info=True)

    def _canonical_url(self, request: Request) -> str:
        """Resource URL for 402 responses. Behind the TLS proxy the raw request
        URL is http://<backend-host>; discovery indexers key on the canonical
        public URL, so prefer the configured public origin."""
        if not self.public_base_url:
            return str(request.url)
        query = f"?{request.url.query}" if request.url.query else ""
        return f"{self.public_base_url}{request.url.path}{query}"

    async def challenge_payment(
        self,
        request: Request,
        amount: Decimal,
        description: str,
        *,
        route_path: str | None = None,
        extra_body: dict[str, Any] | None = None,
    ) -> Response:
        """Issue an unpaid challenge before FastAPI request validation.

        ``route_path`` is the catalog template matched by the outer middleware;
        routing has not populated ``request.scope['route']`` at that point.
        This method never verifies or settles a payment.
        """

        response = await self.build_402_response(
            amount,
            description,
            extra_body,
            request_url=self._canonical_url(request),
            extensions=self._discovery_extensions(request, route_path=route_path),
        )
        if response.status_code == 402:
            await self._record("required_402", request, amount)
        return response

    async def check_payment(
        self,
        request: Request,
        amount: Decimal,
        description: str = "",
        extra_body: dict[str, Any] | None = None,
    ) -> Response | str:
        """
        Check if request contains a valid x402 payment.

        Returns:
            - A 402 Response if no payment or invalid payment
            - The payer's wallet address (str) if payment is valid

        Usage in route handler:
            result = await payment_gate.check_payment(request, total, "VM creation")
            if isinstance(result, Response):
                return result
            wallet_address = result
        """
        # Dev bypass for testing (never enable in production)
        if self.config.dev_bypass_secret:
            bypass = request.headers.get("X-DEV-BYPASS")
            if bypass == self.config.dev_bypass_secret:
                log.warning("dev_bypass_payment", amount=str(amount))
                request.state.payment_tx = "dev_bypass_0x0"
                request.state.payment_network = "dev-bypass"
                request.state.payment_asset = "USDC"
                await self._record(
                    "dev_bypass",
                    request,
                    amount,
                    payer="0xDEV_TEST_WALLET",
                    tx_hash="dev_bypass_0x0",
                    extra=extra_body,
                )
                return "0xDEV_TEST_WALLET"

        # Bazaar discovery declaration for this route (None when undeclared);
        # attached to every 402 so CDP indexes the endpoint at settlement.
        extensions = self._discovery_extensions(request)

        payment_header = self._payment_header(request)
        if not payment_header:
            response = await self.build_402_response(
                amount,
                description,
                extra_body,
                request_url=self._canonical_url(request),
                extensions=extensions,
            )
            # Only a real 402 counts as a challenge issued: a facilitator
            # outage yields a 503 here, and recording it as required_402
            # would corrupt the conversion funnel.
            if response.status_code == 402:
                await self._record("required_402", request, amount)
            return response

        if not await self._ensure_initialized():
            return self._json_response(503, {"error": "Payment facilitator unavailable"})

        try:
            requirements = self._build_requirements(amount)
            try:
                payment_payload = decode_payment_signature_header(payment_header)
            except Exception:
                # Malformed header (bad base64/JSON — scanners, broken wallets):
                # a verification failure, not a server error. Record it so
                # /metrics doesn't undercount, and answer with a fresh 402.
                await self._record(
                    "verify_failed", request, amount, error="Malformed payment header"
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error="Malformed payment header",
                    extensions=extensions,
                )
            if not isinstance(payment_payload, PaymentPayload):
                await self._record(
                    "verify_failed", request, amount, error="Unsupported payment payload version"
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error="Unsupported payment payload version",
                    extensions=extensions,
                )

            matching_requirements = self.server.find_matching_requirements(
                requirements,
                payment_payload,
            )
            if matching_requirements is None:
                await self._record(
                    "verify_failed", request, amount, error="No matching payment requirements"
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error="No matching payment requirements",
                    extensions=extensions,
                )

            verification = await self.server.verify_payment(
                payment_payload,
                matching_requirements,
            )
            if not verification.is_valid:
                log.warning(
                    "payment_verification_failed",
                    invalid_reason=verification.invalid_reason,
                    invalid_message=verification.invalid_message,
                )
                await self._record(
                    "verify_failed",
                    request,
                    amount,
                    network=matching_requirements.network,
                    payer=verification.payer,
                    error=verification.invalid_reason or "Payment verification failed",
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error=verification.invalid_reason or "Payment verification failed",
                    extensions=extensions,
                )

            settlement = await self.server.settle_payment(
                payment_payload,
                matching_requirements,
            )
            settlement_header = encode_payment_response_header(settlement)
            settlement_headers = {
                PAYMENT_RESPONSE_HEADER: settlement_header,
                X_PAYMENT_RESPONSE_HEADER: settlement_header,
            }

            if not settlement.success:
                log.warning(
                    "payment_settlement_failed",
                    error_reason=settlement.error_reason,
                    error_message=settlement.error_message,
                )
                await self._record(
                    "settle_failed",
                    request,
                    amount,
                    network=matching_requirements.network,
                    asset=matching_requirements.asset,
                    payer=settlement.payer or verification.payer,
                    error=settlement.error_reason or "Payment settlement failed",
                )
                return self._json_response(
                    402,
                    {"error": settlement.error_reason or "Payment settlement failed"},
                    headers=settlement_headers,
                )

            wallet = settlement.payer or verification.payer or self._extract_wallet(payment_header)
            tx_hash = settlement.transaction or ""

            log.info(
                "payment_settled",
                wallet=wallet,
                amount=str(amount),
                tx_hash=tx_hash,
            )
            await self._record(
                "settled",
                request,
                amount,
                network=matching_requirements.network,
                asset=matching_requirements.asset,
                payer=wallet,
                tx_hash=tx_hash,
                extra=extra_body,
            )

            request.state.payment_tx = tx_hash
            request.state.payment_network = matching_requirements.network
            request.state.payment_asset = matching_requirements.asset
            request.state.payment_response_headers = settlement_headers
            return wallet or "unknown"

        except Exception:
            log.error("payment_processing_error", exc_info=True)
            return self._json_response(502, {"error": "Payment processing error"})

    async def verify_only(
        self,
        request: Request,
        amount: Decimal,
        description: str = "",
        extra_body: dict[str, Any] | None = None,
    ) -> Response | VerifiedPayment:
        """Verify a payment WITHOUT settling it.

        For endpoints that must deliver before charging: call this first, run
        the work, then call ``settle_verified`` only on success. Returns a
        ``VerifiedPayment`` handle when the payment is valid, or a ``Response``
        (402 challenge / 503 / 502) to return to the client otherwise. No money
        moves until ``settle_verified`` is called.
        """
        # Dev bypass for testing (never enable in production). Settlement is
        # deferred to settle_verified so a failed delivery isn't recorded.
        if self.config.dev_bypass_secret:
            bypass = request.headers.get("X-DEV-BYPASS")
            if bypass == self.config.dev_bypass_secret:
                log.warning("dev_bypass_payment", amount=str(amount))
                return VerifiedPayment(payer="0xDEV_TEST_WALLET", amount=amount, dev_bypass=True)

        extensions = self._discovery_extensions(request)
        payment_header = self._payment_header(request)
        if not payment_header:
            response = await self.build_402_response(
                amount,
                description,
                extra_body,
                request_url=self._canonical_url(request),
                extensions=extensions,
            )
            if response.status_code == 402:
                await self._record("required_402", request, amount)
            return response

        if not await self._ensure_initialized():
            return self._json_response(503, {"error": "Payment facilitator unavailable"})

        try:
            requirements = self._build_requirements(amount)
            try:
                payment_payload = decode_payment_signature_header(payment_header)
            except Exception:
                await self._record(
                    "verify_failed", request, amount, error="Malformed payment header"
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error="Malformed payment header",
                    extensions=extensions,
                )
            if not isinstance(payment_payload, PaymentPayload):
                await self._record(
                    "verify_failed", request, amount, error="Unsupported payment payload version"
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error="Unsupported payment payload version",
                    extensions=extensions,
                )

            matching_requirements = self.server.find_matching_requirements(
                requirements,
                payment_payload,
            )
            if matching_requirements is None:
                await self._record(
                    "verify_failed", request, amount, error="No matching payment requirements"
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error="No matching payment requirements",
                    extensions=extensions,
                )

            verification = await self.server.verify_payment(
                payment_payload,
                matching_requirements,
            )
            if not verification.is_valid:
                log.warning(
                    "payment_verification_failed",
                    invalid_reason=verification.invalid_reason,
                    invalid_message=verification.invalid_message,
                )
                await self._record(
                    "verify_failed",
                    request,
                    amount,
                    network=matching_requirements.network,
                    payer=verification.payer,
                    error=verification.invalid_reason or "Payment verification failed",
                )
                return await self._payment_required_response(
                    requirements,
                    amount,
                    description,
                    extra_body,
                    request_url=self._canonical_url(request),
                    error=verification.invalid_reason or "Payment verification failed",
                    extensions=extensions,
                )

            return VerifiedPayment(
                payer=verification.payer or "",
                amount=amount,
                payment_payload=payment_payload,
                matching_requirements=matching_requirements,
            )
        except Exception:
            log.error("payment_processing_error", exc_info=True)
            return self._json_response(502, {"error": "Payment processing error"})

    async def settle_verified(self, request: Request, verified: VerifiedPayment) -> bool:
        """Settle a payment already verified by ``verify_only``.

        Call ONLY after the paid resource has been delivered. Attaches the
        settlement headers to ``request.state`` (surfaced by the ASGI
        middleware) and records the ledger event. Returns whether settlement
        succeeded; on failure the resource was already delivered, so the caller
        keeps the response — a rare uncharged delivery, never a double-charge.
        """
        if verified.dev_bypass:
            request.state.payment_tx = "dev_bypass_0x0"
            await self._record(
                "dev_bypass",
                request,
                verified.amount,
                payer="0xDEV_TEST_WALLET",
                tx_hash="dev_bypass_0x0",
            )
            return True

        try:
            settlement = await self.server.settle_payment(
                verified.payment_payload,
                verified.matching_requirements,
            )
        except Exception:
            # A facilitator error must not become an unhandled 500 in the route;
            # report failed settlement so the caller withholds the paid result.
            log.error("payment_settlement_error", exc_info=True)
            await self._record(
                "settle_failed",
                request,
                verified.amount,
                network=verified.matching_requirements.network,
                asset=verified.matching_requirements.asset,
                payer=verified.payer,
                error="Payment settlement error",
            )
            return False
        settlement_header = encode_payment_response_header(settlement)
        request.state.payment_response_headers = {
            PAYMENT_RESPONSE_HEADER: settlement_header,
            X_PAYMENT_RESPONSE_HEADER: settlement_header,
        }

        if not settlement.success:
            log.warning(
                "payment_settlement_failed",
                error_reason=settlement.error_reason,
                error_message=settlement.error_message,
            )
            await self._record(
                "settle_failed",
                request,
                verified.amount,
                network=verified.matching_requirements.network,
                asset=verified.matching_requirements.asset,
                payer=settlement.payer or verified.payer,
                error=settlement.error_reason or "Payment settlement failed",
            )
            return False

        wallet = settlement.payer or verified.payer
        tx_hash = settlement.transaction or ""
        log.info("payment_settled", wallet=wallet, amount=str(verified.amount), tx_hash=tx_hash)
        await self._record(
            "settled",
            request,
            verified.amount,
            network=verified.matching_requirements.network,
            asset=verified.matching_requirements.asset,
            payer=wallet,
            tx_hash=tx_hash,
        )
        request.state.payment_tx = tx_hash
        return True

    @staticmethod
    def _extract_wallet(payment_header: str) -> str | None:
        """Extract payer wallet address from the payment header using the SDK."""
        try:
            payload = decode_payment_signature_header(payment_header)
            if isinstance(payload, PaymentPayload):
                auth = payload.payload.get("authorization", {})
                return auth.get("from") or payload.payload.get("from")
            return None
        except Exception:
            return None
