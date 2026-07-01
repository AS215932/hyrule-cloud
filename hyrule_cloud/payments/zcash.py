"""Custom x402 v2 Zcash binding.

The MVP is client-broadcast: the client sends a ZEC transaction through its
wallet, then retries the protected request with a txid bound to the invoice.
Shielded payments are verified from the merchant wallet view via zcashd.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import string
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from x402.schemas import (
    AssetAmount,
    Network,
    PaymentPayload,
    PaymentRequirements,
    Price,
    ResourceConfig,
    SettleResponse,
    SupportedKind,
    SupportedResponse,
    VerifyResponse,
)

from hyrule_cloud.config import PaymentConfig
from hyrule_cloud.db import ZcashInvoiceRow, ZcashPaymentRow

log = structlog.get_logger()

ZCASH_MAINNET = "bip122:00040fe8ec8471911baa1db1266ea15d"
ZCASH_TESTNET = "bip122:05a60a92d99d85997cce3b87616c089f"
ZCASH_ASSET = "slip44:133"
ZATOSHIS_PER_ZEC = Decimal("100000000")
_BASE62 = string.ascii_letters + string.digits


def _now() -> datetime:
    return datetime.now(UTC)


def generate_invoice_id() -> str:
    return "inv_" + "".join(secrets.choice(_BASE62) for _ in range(22))


def generate_payment_id() -> str:
    return "zpay_" + "".join(secrets.choice(_BASE62) for _ in range(22))


def resource_hash(resource_url: str) -> str:
    digest = hashlib.sha256(resource_url.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def build_invoice_memo_hex(
    *,
    invoice_id: str,
    resource_hash_value: str,
    amount_zat: str,
    merchant: str,
) -> str:
    payload = {
        "proto": "x402-zcash",
        "v": 1,
        "invoice": invoice_id,
        "resourceHash": resource_hash_value,
        "amountZat": amount_zat,
        "merchant": merchant,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return raw.hex()


def zatoshis_to_zec_decimal_string(amount_zat: int) -> str:
    amount = (Decimal(amount_zat) / ZATOSHIS_PER_ZEC).quantize(Decimal("0.00000001"))
    return format(amount, "f")


def usd_to_zatoshis(amount_usd: Decimal, usd_per_zec: Decimal) -> int:
    if amount_usd <= 0:
        raise ValueError("amount_usd must be positive")
    if usd_per_zec <= 0:
        raise ValueError("usd_per_zec must be positive")
    raw = (amount_usd / usd_per_zec) * ZATOSHIS_PER_ZEC
    amount_zat = int(raw.to_integral_value(rounding=ROUND_CEILING))
    return max(1, amount_zat)


def normalize_zcash_network(network: str) -> str:
    value = network.strip().lower()
    if value.startswith("bip122:"):
        return value
    if value in {"mainnet", "main"}:
        return ZCASH_MAINNET
    if value in {"testnet", "test"}:
        return ZCASH_TESTNET
    raise ValueError(f"unsupported Zcash network: {network}")


def normalize_txid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    txid = value.strip().lower()
    if len(txid) != 64:
        return None
    if any(ch not in "0123456789abcdef" for ch in txid):
        return None
    return txid


class ZcashRpcClient:
    """Tiny async zcashd JSON-RPC adapter."""

    def __init__(
        self,
        *,
        url: str,
        user: str = "",
        password: str = "",
        timeout_seconds: float = 30.0,
    ) -> None:
        self.url = url
        self.user = user
        self.password = password
        self.timeout_seconds = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._client is None:
            auth = (self.user, self.password) if self.user or self.password else None
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds, auth=auth)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def rpc(self, method: str, params: list[Any] | None = None) -> Any:
        if self._client is None:
            await self.start()
        assert self._client is not None
        payload = {
            "jsonrpc": "1.0",
            "id": "hyrule-zcash-x402",
            "method": method,
            "params": params or [],
        }
        response = await self._client.post(self.url, json=payload)
        response.raise_for_status()
        body = response.json()
        if body.get("error") is not None:
            raise RuntimeError(f"zcashd {method} failed: {body['error']}")
        return body.get("result")

    async def get_address_for_account(
        self,
        account: int,
        receiver_types: list[str],
    ) -> dict[str, Any]:
        return await self.rpc("z_getaddressforaccount", [account, receiver_types])

    async def view_transaction(self, txid: str) -> dict[str, Any]:
        return await self.rpc("z_viewtransaction", [txid])


class ZcashExactServerScheme:
    """x402 server-side requirement builder for exact native ZEC payments."""

    @property
    def scheme(self) -> str:
        return "exact"

    def parse_price(self, price: Price, network: Network) -> AssetAmount:
        if isinstance(price, AssetAmount):
            return price
        if isinstance(price, dict):
            return AssetAmount.model_validate(price)
        raise ValueError(
            f"Zcash x402 requirements for {network} must be built with an explicit AssetAmount"
        )

    def enhance_payment_requirements(
        self,
        requirements: PaymentRequirements,
        supported_kind: SupportedKind,
        extensions: list[str],
    ) -> PaymentRequirements:
        extra = dict(supported_kind.extra or {})
        extra.update(requirements.extra or {})
        return requirements.model_copy(update={"extra": extra})


class ZcashPaymentService:
    """Creates and verifies one-time Zcash x402 invoices."""

    def __init__(
        self,
        *,
        config: PaymentConfig,
        session_factory: Any,
        rates: Any,
        rpc: ZcashRpcClient | None = None,
    ) -> None:
        self.config = config
        self.session_factory = session_factory
        self.rates = rates
        self.rpc = rpc or ZcashRpcClient(
            url=config.zcash_rpc_url,
            user=config.zcash_rpc_user,
            password=config.zcash_rpc_password,
        )
        self.network = normalize_zcash_network(config.zcash_network)

    @property
    def enabled(self) -> bool:
        return bool(self.config.zcash_enabled)

    @property
    def receiver_types(self) -> list[str]:
        values = [v.strip().lower() for v in self.config.zcash_receiver_types if v.strip()]
        return values or ["orchard"]

    @property
    def pool(self) -> str:
        if "orchard" in self.receiver_types:
            return "orchard"
        if "sapling" in self.receiver_types:
            return "sapling"
        return self.receiver_types[0]

    async def start(self) -> None:
        if self.enabled:
            await self.rpc.start()

    async def close(self) -> None:
        await self.rpc.close()

    def supported_extra(self) -> dict[str, Any]:
        return {
            "asset": ZCASH_ASSET,
            "assetId": ZCASH_ASSET,
            "assetName": "ZEC",
            "unit": "zatoshi",
            "decimals": 8,
            "modes": ["client-broadcast"],
            "pools": [self.pool],
            "supportsShielded": True,
            "requiresMemo": True,
        }

    def supported_response(self) -> SupportedResponse:
        if not self.enabled:
            return SupportedResponse(kinds=[], extensions=[], signers={})
        return SupportedResponse(
            kinds=[
                SupportedKind(
                    x402_version=2,
                    scheme="exact",
                    network=self.network,
                    extra=self.supported_extra(),
                )
            ],
            extensions=[],
            signers={},
        )

    def payment_required_extensions(self) -> dict[str, Any]:
        return {
            "zcash": {
                "version": 1,
                "supportsShielded": True,
                "supportsTransparent": False,
                "requiresMemo": True,
            }
        }

    async def create_invoice_requirement(
        self,
        *,
        resource_url: str,
        amount_usd: Decimal,
    ) -> PaymentRequirements:
        invoice = await self.create_invoice(resource_url=resource_url, amount_usd=amount_usd)
        return self.requirement_for_invoice(invoice)

    async def create_invoice(self, *, resource_url: str, amount_usd: Decimal) -> ZcashInvoiceRow:
        if not self.enabled:
            raise RuntimeError("Zcash payments are disabled")
        usd_per_zec = await self.rates.get_usd_per("ZEC")
        amount_zat = str(usd_to_zatoshis(amount_usd, usd_per_zec))
        address_info = await self.rpc.get_address_for_account(
            self.config.zcash_account,
            self.receiver_types,
        )
        pay_to = str(address_info["address"])
        invoice_id = generate_invoice_id()
        res_hash = resource_hash(resource_url)
        merchant = self.config.zcash_merchant or "hyrule.host"
        memo_hex = build_invoice_memo_hex(
            invoice_id=invoice_id,
            resource_hash_value=res_hash,
            amount_zat=amount_zat,
            merchant=merchant,
        )
        now = _now()
        invoice = ZcashInvoiceRow(
            invoice_id=invoice_id,
            resource_url=resource_url,
            resource_hash=res_hash,
            network=self.network,
            amount_zat=amount_zat,
            amount_usd=amount_usd,
            rate_snapshot=usd_per_zec,
            pay_to=pay_to,
            memo_hex=memo_hex,
            merchant=merchant,
            pool=self.pool,
            account=self.config.zcash_account,
            diversifier_index=str(address_info.get("diversifier_index", "")) or None,
            min_confirmations=self.config.zcash_min_confirmations,
            max_timeout_seconds=self.config.zcash_invoice_ttl_seconds,
            status="created",
            expires_at=now + timedelta(seconds=self.config.zcash_invoice_ttl_seconds),
        )
        async with self.session_factory() as db:
            db.add(invoice)
            await db.commit()
            await db.refresh(invoice)
        return invoice

    def requirement_for_invoice(self, invoice: ZcashInvoiceRow) -> PaymentRequirements:
        extra = {
            "assetName": "ZEC",
            "unit": "zatoshi",
            "decimals": 8,
            "pool": invoice.pool,
            "invoiceId": invoice.invoice_id,
            "memoHex": invoice.memo_hex,
            "minConfirmations": invoice.min_confirmations,
            "broadcastMode": "client",
            "resourceHash": invoice.resource_hash,
        }
        return PaymentRequirements(
            scheme="exact",
            network=invoice.network,
            amount=invoice.amount_zat,
            asset=ZCASH_ASSET,
            pay_to=invoice.pay_to,
            max_timeout_seconds=invoice.max_timeout_seconds,
            extra=extra,
        )

    def resource_config_for_invoice(self, invoice: ZcashInvoiceRow) -> ResourceConfig:
        return ResourceConfig(
            scheme="exact",
            network=invoice.network,
            pay_to=invoice.pay_to,
            price=AssetAmount(
                amount=invoice.amount_zat,
                asset=ZCASH_ASSET,
                extra=self.requirement_for_invoice(invoice).extra,
            ),
            max_timeout_seconds=invoice.max_timeout_seconds,
        )

    async def get_invoice(self, invoice_id: str) -> ZcashInvoiceRow | None:
        async with self.session_factory() as db:
            return await db.get(ZcashInvoiceRow, invoice_id)

    async def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        reason = await self._verify_and_record(payload, requirements)
        if reason is not None:
            return VerifyResponse(is_valid=False, invalid_reason=reason, payer=None)
        return VerifyResponse(is_valid=True, invalid_reason=None, payer=None)

    async def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse:
        verification = await self.verify(payload, requirements)
        txid = normalize_txid(payload.payload.get("txid"))
        invoice_id = self._payload_invoice_id(payload)
        if not verification.is_valid or not txid or not invoice_id:
            return SettleResponse(
                success=False,
                error_reason=verification.invalid_reason or "invalid_zcash_payment",
                transaction="",
                network=requirements.network,
                amount=requirements.amount,
            )

        async with self.session_factory() as db:
            invoice = await db.get(ZcashInvoiceRow, invoice_id)
            if invoice is None:
                return SettleResponse(
                    success=False,
                    error_reason="invoice_not_found",
                    transaction="",
                    network=requirements.network,
                    amount=requirements.amount,
                )
            invoice.status = "settled"
            invoice.settled_at = invoice.settled_at or _now()
            invoice.txid = invoice.txid or txid
            await db.commit()

        return SettleResponse(
            success=True,
            transaction=txid,
            network=requirements.network,
            payer=None,
            amount=requirements.amount,
        )

    async def _verify_and_record(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> str | None:
        if not self.enabled:
            return "zcash_disabled"
        if payload.x402_version != 2:
            return "unsupported_x402_version"

        txid = normalize_txid(payload.payload.get("txid"))
        if txid is None:
            return "invalid_txid"

        invoice_id = self._payload_invoice_id(payload)
        if not invoice_id:
            return "missing_invoice_id"

        async with self.session_factory() as db:
            invoice = await db.get(ZcashInvoiceRow, invoice_id)
            if invoice is None:
                return "invoice_not_found"

            expected = self.requirement_for_invoice(invoice)
            mismatch = self._requirements_mismatch(payload.accepted, expected)
            if mismatch is not None:
                return mismatch
            mismatch = self._requirements_mismatch(requirements, expected)
            if mismatch is not None:
                return mismatch

            existing_for_invoice = (
                await db.execute(
                    select(ZcashPaymentRow).where(ZcashPaymentRow.invoice_id == invoice_id)
                )
            ).scalar_one_or_none()
            if existing_for_invoice is not None:
                if existing_for_invoice.txid == txid:
                    return None
                return "invoice_already_paid"

            existing_for_txid = (
                await db.execute(select(ZcashPaymentRow).where(ZcashPaymentRow.txid == txid))
            ).scalar_one_or_none()
            if existing_for_txid is not None:
                return "txid_already_used"

            if invoice.expires_at.replace(tzinfo=invoice.expires_at.tzinfo or UTC) < _now():
                return "invoice_expired"

        tx = await self._view_transaction_or_none(txid)
        if tx is None:
            return "payment_not_detected"

        output = self._matching_output(tx, invoice)
        if output is None:
            return "no_matching_output"

        confirmations = int(tx.get("confirmations") or 0)
        if confirmations < invoice.min_confirmations:
            return "insufficient_confirmations"

        async with self.session_factory() as db:
            invoice = await db.get(ZcashInvoiceRow, invoice_id)
            if invoice is None:
                return "invoice_not_found"
            payment = ZcashPaymentRow(
                payment_id=generate_payment_id(),
                invoice_id=invoice_id,
                txid=txid,
                network=invoice.network,
                amount_zat=invoice.amount_zat,
                confirmations=confirmations,
                pool=str(output.get("pool") or output.get("type") or ""),
                memo_hex=str(output.get("memo") or ""),
            )
            db.add(payment)
            invoice.status = "verified"
            invoice.verified_at = invoice.verified_at or _now()
            invoice.txid = txid
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                existing_for_invoice = (
                    await db.execute(
                        select(ZcashPaymentRow).where(ZcashPaymentRow.invoice_id == invoice_id)
                    )
                ).scalar_one_or_none()
                if existing_for_invoice is not None and existing_for_invoice.txid == txid:
                    return None
                return "payment_race_conflict"
        return None

    async def _view_transaction_or_none(self, txid: str) -> dict[str, Any] | None:
        try:
            tx = await self.rpc.view_transaction(txid)
            return tx if isinstance(tx, dict) else None
        except Exception as exc:
            log.warning("zcash_viewtransaction_failed", txid=txid, error=str(exc))
            return None

    def _matching_output(
        self,
        tx: dict[str, Any],
        invoice: ZcashInvoiceRow,
    ) -> dict[str, Any] | None:
        for output in tx.get("outputs") or []:
            if not isinstance(output, dict):
                continue
            if output.get("address") != invoice.pay_to:
                continue
            if str(output.get("memo") or "").lower() != invoice.memo_hex.lower():
                continue
            try:
                if int(output.get("valueZat")) != int(invoice.amount_zat):
                    continue
            except (TypeError, ValueError):
                continue
            pool = str(output.get("pool") or output.get("type") or "")
            if invoice.pool and pool and pool != invoice.pool:
                continue
            return output
        return None

    @staticmethod
    def _payload_invoice_id(payload: PaymentPayload) -> str | None:
        raw = payload.payload.get("invoiceId")
        accepted_raw = payload.accepted.extra.get("invoiceId") if payload.accepted.extra else None
        if isinstance(raw, str) and raw:
            if isinstance(accepted_raw, str) and accepted_raw and accepted_raw != raw:
                return None
            return raw
        return accepted_raw if isinstance(accepted_raw, str) and accepted_raw else None

    @staticmethod
    def _requirements_mismatch(
        actual: PaymentRequirements,
        expected: PaymentRequirements,
    ) -> str | None:
        if actual.scheme != expected.scheme:
            return "scheme_mismatch"
        if actual.network != expected.network:
            return "network_mismatch"
        if actual.asset != expected.asset:
            return "asset_mismatch"
        if actual.amount != expected.amount:
            return "amount_mismatch"
        if actual.pay_to != expected.pay_to:
            return "pay_to_mismatch"
        invoice_id = (actual.extra or {}).get("invoiceId")
        if invoice_id != expected.extra.get("invoiceId"):
            return "invoice_id_mismatch"
        memo_hex = (actual.extra or {}).get("memoHex")
        if memo_hex != expected.extra.get("memoHex"):
            return "memo_mismatch"
        return None


class ZcashFacilitatorClient:
    """In-process facilitator client used by the resource server."""

    def __init__(self, service: ZcashPaymentService) -> None:
        self.service = service

    def get_supported(self) -> SupportedResponse:
        return self.service.supported_response()

    async def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        return await self.service.verify(payload, requirements)

    async def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse:
        return await self.service.settle(payload, requirements)
