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
from x402.http import FacilitatorConfig, HTTPFacilitatorClient
from x402.http.utils import decode_payment_signature_header
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.mechanisms.svm.exact.register import register_exact_svm_server
from x402.schemas import PaymentRequirements
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
        # `self.server._initialized` is the SDK's own one-shot guard for the
        # facilitator.get_supported() HTTP fetch. We read it directly rather
        # than mirror it onto the wrapper.
        # Block C: register EVM exact scheme per eip155 network.
        # Block H: register the SVM exact scheme once (V2-only; the SDK helper
        # iterates the SVM networks it supports). We only register SVM if any
        # solana:* network is enabled to avoid a wildcard registration when the
        # operator hasn't opted in.
        svm_caip2s = [n.caip2 for n in self.config.networks if n.family == "svm"]
        for net in self.config.networks:
            if net.family == "evm":
                self.server.register(net.caip2, ExactEvmServerScheme())
        if svm_caip2s:
            register_exact_svm_server(self.server, networks=svm_caip2s)

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
        accepts = []
        for net in self.config.networks:
            entry: dict[str, Any] = {
                "scheme": "exact",
                "network": net.caip2,
                "price": f"${amount}",
                "pay_to": self.config.receiver_address,
                "token_address": net.token_address,
                "token_decimals": net.token_decimals,
                "family": net.family,
            }
            if net.family == "evm":
                # EVM signs EIP-3009 via EIP-712; the browser needs the domain.
                entry["chain_id"] = net.chain_id
                entry["eip712_domain"] = {
                    "name": net.eip712_domain_name,
                    "version": net.eip712_domain_version,
                }
            # Solana doesn't need extra metadata: the facilitator builds the
            # unsigned SPL transfer for the wallet to sign on the client retry.
            accepts.append(entry)

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
        body["networks"] = [
            {
                "key": n.key,
                "display_name": n.display_name,
                "caip2": n.caip2,
                "chain_id": n.chain_id,
                "asset": n.asset,
            }
            for n in self.config.networks
        ]

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
        # Dev bypass for testing (never enable in production)
        if self.config.dev_bypass_secret:
            bypass = request.headers.get("X-DEV-BYPASS")
            if bypass == self.config.dev_bypass_secret:
                log.warning("dev_bypass_payment", amount=str(amount))
                request.state.payment_tx = "dev_bypass_0x0"
                return "0xDEV_TEST_WALLET"

        payment_header = (
            request.headers.get("X-PAYMENT")
            or request.headers.get("x-payment")
            or request.headers.get("PAYMENT-SIGNATURE")
            or request.headers.get("payment-signature")
        )

        if not payment_header:
            return self.build_402_response(amount, description, extra_body)

        # Parse the X-PAYMENT header into a typed PaymentPayload using the
        # SDK's canonical helper. Prior to this fix the gate decoded the header
        # by hand and called `self.server.verify(header, dict)` — but the SDK
        # exposes `verify_payment(payload, requirements)` with typed args, so
        # the prior call always raised AttributeError and the gate only ever
        # succeeded via the dev_bypass branch. Test:
        # test_check_payment_uses_typed_verify_settle covers this regression.
        try:
            payment_payload = decode_payment_signature_header(payment_header)
        except Exception:
            log.warning("payment_header_decode_failed", exc_info=True)
            return Response(
                status_code=402,
                content=json.dumps({"error": "Malformed X-PAYMENT header"}),
                headers={"Content-Type": "application/json"},
            )

        req_network = payment_payload.get_network()

        # Find the matching network for the asset / decimals lookup so the
        # `amount` field is encoded in the on-chain integer unit.
        net_match = next(
            (n for n in self.config.networks if n.caip2 == req_network), None
        )
        if net_match is None:
            log.warning(
                "payment_unknown_network",
                req_network=req_network,
                enabled=[n.caip2 for n in self.config.networks],
            )
            return Response(
                status_code=402,
                content=json.dumps({"error": f"Unsupported network: {req_network}"}),
                headers={"Content-Type": "application/json"},
            )

        requirements = PaymentRequirements(
            scheme="exact",
            network=req_network,
            asset=net_match.token_address,
            amount=str(int(amount * 10**net_match.token_decimals)),
            pay_to=self.config.receiver_address,
            max_timeout_seconds=60,
            extra={},
        )

        # Use SDK server to verify + settle the payment.
        try:
            if not self.server._initialized:
                # SDK only ships a sync `initialize` (one-shot HTTP GET to the
                # facilitator's /supported endpoint). Off-load to a worker
                # thread so the first paid request doesn't block the loop.
                import asyncio as _asyncio
                await _asyncio.to_thread(self.server.initialize)

            verification = await self.server.verify_payment(payment_payload, requirements)

            if not verification.is_valid:
                log.warning(
                    "payment_verification_failed",
                    reason=verification.invalid_reason,
                    message=verification.invalid_message,
                )
                return Response(
                    status_code=402,
                    content=json.dumps({"error": "Payment verification failed"}),
                    headers={"Content-Type": "application/json"},
                )

            settlement = await self.server.settle_payment(payment_payload, requirements)

            if not settlement.success:
                log.error(
                    "payment_settlement_failed",
                    reason=settlement.error_reason,
                    message=settlement.error_message,
                )
                return Response(
                    status_code=502,
                    content=json.dumps({"error": "Payment settlement failed"}),
                    headers={"Content-Type": "application/json"},
                )

            wallet = settlement.payer or verification.payer
            tx_hash = settlement.transaction or ""

            log.info(
                "payment_settled",
                wallet=wallet,
                network=req_network,
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
