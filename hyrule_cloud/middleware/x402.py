"""
x402 payment integration using the official Coinbase SDK.

The official PaymentMiddlewareASGI works for static per-route pricing,
but our endpoints have dynamic pricing (VM size * duration). So we use
the SDK's lower-level primitives:

- x402ResourceServer + ExactEvmServerScheme for verify/settle
- HTTPFacilitatorClient for facilitator communication
- PaymentOption / RouteConfig types for response formatting

Route handlers call `require_payment()` with a computed amount and get
back either a 402 Response or the verified payment details.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from typing import Any

import structlog
from fastapi import Request, Response
from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.server import x402ResourceServer

from hyrule_cloud.config import PaymentConfig

log = structlog.get_logger()


class PaymentGate:
    """
    Handles x402 payment verification for dynamically-priced endpoints.

    Uses the official x402 SDK for all protocol-level operations.
    Route handlers call `check_payment()` which either returns
    a 402 Response (no/bad payment) or the payer's wallet address.
    """

    def __init__(self, config: PaymentConfig) -> None:
        self.config = config
        self.facilitator = HTTPFacilitatorClient(
            FacilitatorConfig(url=config.facilitator_url)
        )
        self.server = x402ResourceServer(self.facilitator)
        self.server.register(config.network, ExactEvmServerScheme())

    def build_402_response(
        self,
        amount: Decimal,
        description: str = "",
        extra_body: dict[str, Any] | None = None,
    ) -> Response:
        """
        Build a 402 Payment Required response using x402 SDK types.

        The response includes both the standard x402 header and a
        JSON body with application-specific metadata (cost breakdown, etc).
        """
        payment_option = PaymentOption(
            scheme="exact",
            network=self.config.network,
            price=f"${amount}",
            pay_to=self.config.receiver_address,
        )

        # Build the accepts array per x402 v2 spec
        accepts = [payment_option.model_dump()]

        payment_required = {
            "x402Version": 2,
            "accepts": accepts,
            "description": description,
        }

        encoded = base64.b64encode(
            json.dumps(payment_required).encode()
        ).decode()

        body = extra_body or {}
        body["payment_required"] = True
        body["amount"] = str(amount)
        body["currency"] = self.config.asset
        body["network"] = self.config.network

        return Response(
            status_code=402,
            content=json.dumps(body),
            headers={
                "X-PAYMENT-REQUIRED": encoded,
                "Content-Type": "application/json",
            },
        )

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
        payment_header = (
            request.headers.get("X-PAYMENT")
            or request.headers.get("x-payment")
            or request.headers.get("PAYMENT-SIGNATURE")
            or request.headers.get("payment-signature")
        )

        if not payment_header:
            return self.build_402_response(amount, description, extra_body)

        # Use SDK server to verify the payment
        try:
            verification = await self.server.verify(
                payment_header,
                {
                    "scheme": "exact",
                    "network": self.config.network,
                    "maxAmountRequired": str(int(amount * 10**6)),  # USDC 6 decimals
                    "resource": self.config.receiver_address,
                },
            )

            if not verification or not verification.get("isValid"):
                log.warning("payment_verification_failed", verification=verification)
                return Response(
                    status_code=402,
                    content=json.dumps({"error": "Payment verification failed"}),
                    headers={"Content-Type": "application/json"},
                )

            # Settle the payment
            settlement = await self.server.settle(
                payment_header,
                {
                    "scheme": "exact",
                    "network": self.config.network,
                    "maxAmountRequired": str(int(amount * 10**6)),
                    "resource": self.config.receiver_address,
                },
            )

            if not settlement:
                log.error("payment_settlement_failed")
                return Response(
                    status_code=502,
                    content=json.dumps({"error": "Payment settlement failed"}),
                    headers={"Content-Type": "application/json"},
                )

            wallet = self._extract_wallet(payment_header)
            tx_hash = settlement.get("txHash", "")

            log.info(
                "payment_settled",
                wallet=wallet,
                amount=str(amount),
                tx_hash=tx_hash,
            )

            # Store tx_hash on request state for the route handler
            request.state.payment_tx = tx_hash
            return wallet or "unknown"

        except Exception:
            log.error("payment_processing_error", exc_info=True)
            return Response(
                status_code=502,
                content=json.dumps({"error": "Payment processing error"}),
                headers={"Content-Type": "application/json"},
            )

    @staticmethod
    def _extract_wallet(payment_header: str) -> str | None:
        """Extract payer wallet address from the payment header."""
        try:
            decoded = base64.b64decode(payment_header)
            payload = json.loads(decoded)
            # x402 exact scheme: the 'from' field in the authorization
            return (
                payload.get("payload", {}).get("authorization", {}).get("from")
                or payload.get("from")
            )
        except Exception:
            return None
