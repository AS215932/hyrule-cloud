"""Block E: native BTC/XMR provider.

BTC scanning is pure HTTP (mempool.space primary + blockstream.info
fallback — both expose the Esplora API). XMR scanning uses a tiny local
monero-wallet-rpc daemon on 127.0.0.1 that talks to a public Monero
remote node (rino.io / cakewallet). No local blockchain storage either way.

The provider is purely about address derivation and balance scanning. The
LENIENT off-amount policy and state-machine transitions live in
`api/intent_poller.py` (called from app.py lifespan).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

import httpx
import structlog

from hyrule_cloud.config import PaymentConfig

log = structlog.get_logger()

Asset = Literal["BTC", "XMR"]

_ESPLORA_PRIMARY = "https://mempool.space/api"
_ESPLORA_FALLBACK = "https://blockstream.info/api"
_XMR_RPC_DEFAULT = "http://127.0.0.1:18088/json_rpc"

# BTC unit conversions
SAT_PER_BTC = Decimal("100000000")
# XMR unit conversions (atomic units)
PICONERO_PER_XMR = Decimal("1000000000000")


@dataclass
class AddressScanResult:
    """Result of polling a single address for incoming payments."""
    address: str
    received_total: Decimal           # in asset units (BTC or XMR)
    confirmations: int                # of the most recent matching tx
    tx_hash: str | None = None


class NativeCryptoProvider:
    """Async BTC + XMR payment-address provider.

    BTC: HD derivation from xpub via bip-utils; balance scanning via
    Esplora public endpoints. No keys held; we can only RECEIVE.

    XMR: subaddress generation + transfer polling via monero-wallet-rpc
    (small local daemon, view-only wallet, talks to a public remote node).
    The spend key is NOT on this server; we can scan but not spend.
    """

    def __init__(self, config: PaymentConfig, *, xmr_rpc_url: str = _XMR_RPC_DEFAULT) -> None:
        self.config = config
        self.xmr_rpc_url = xmr_rpc_url
        # Lazy-init the BIP84 derivation context only if BTC is configured.
        self._btc_ctx = None
        self._http: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=15.0)

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ---------------- BTC ----------------

    def _btc_account_ctx(self):
        """Cached BIP84 m/84'/0'/0' account context derived from the xpub."""
        if self._btc_ctx is None:
            from bip_utils import (
                Bip44Changes,
                Bip84,
                Bip84Coins,
            )

            xpub = self.config.btc_xpub.strip()
            if not xpub:
                raise RuntimeError("PAYMENT_BTC_XPUB is empty — BTC payments disabled")
            # The xpub is the account-level extended pubkey (m/84'/0'/0').
            # bip-utils' FromExtendedKey takes us there; AddressIndex slots in.
            ctx = Bip84.FromExtendedKey(xpub, Bip84Coins.BITCOIN).Change(Bip44Changes.CHAIN_EXT)
            self._btc_ctx = ctx
        return self._btc_ctx

    def derive_btc_address(self, bip32_index: int) -> str:
        """m/84'/0'/0'/0/<bip32_index> → bc1q... (P2WPKH bech32)."""
        return self._btc_account_ctx().AddressIndex(bip32_index).PublicKey().ToAddress()

    async def scan_btc_address(self, address: str) -> AddressScanResult:
        """Returns the total received + confirmation count for `address`.

        Falls back from mempool.space → blockstream.info on any failure.
        Both expose the Esplora `/address/<addr>` shape; the response carries:
          chain_stats.funded_txo_sum   — sats received (confirmed)
          mempool_stats.funded_txo_sum — sats received (unconfirmed)
        We separately fetch `/address/<addr>/txs` for the most recent tx hash
        and block height (for confirmations).
        """
        if self._http is None:
            raise RuntimeError("NativeCryptoProvider.start() must be called before scanning")
        for base in (_ESPLORA_PRIMARY, _ESPLORA_FALLBACK):
            try:
                addr_resp = await self._http.get(f"{base}/address/{address}")
                if addr_resp.status_code != 200:
                    log.warning("esplora_non_200", endpoint=base, status=addr_resp.status_code)
                    continue
                stats = addr_resp.json()
                funded_sats = (
                    stats.get("chain_stats", {}).get("funded_txo_sum", 0)
                    + stats.get("mempool_stats", {}).get("funded_txo_sum", 0)
                )
                received = Decimal(funded_sats) / SAT_PER_BTC

                if funded_sats == 0:
                    return AddressScanResult(address=address, received_total=Decimal("0"), confirmations=0)

                # Fetch the most recent tx for hash + confirmations
                txs_resp = await self._http.get(f"{base}/address/{address}/txs")
                if txs_resp.status_code != 200:
                    return AddressScanResult(address=address, received_total=received, confirmations=0)
                txs = txs_resp.json()
                if not txs:
                    return AddressScanResult(address=address, received_total=received, confirmations=0)
                latest = txs[0]
                tx_hash = latest.get("txid")
                status = latest.get("status", {})
                if status.get("confirmed"):
                    # Compute confirmations = current_tip_height - tx_block_height + 1
                    tip_resp = await self._http.get(f"{base}/blocks/tip/height")
                    if tip_resp.status_code == 200:
                        tip = int(tip_resp.text.strip())
                        confs = max(0, tip - int(status["block_height"]) + 1)
                    else:
                        confs = 1
                else:
                    confs = 0
                return AddressScanResult(
                    address=address, received_total=received, confirmations=confs, tx_hash=tx_hash
                )
            except Exception as exc:
                log.warning("esplora_failed", endpoint=base, error=str(exc))
                continue
        raise RuntimeError(f"all Esplora endpoints failed scanning {address}")

    # ---------------- XMR ----------------

    async def _xmr_rpc(self, method: str, params: dict | None = None) -> dict:
        """Single JSON-RPC call to monero-wallet-rpc on 127.0.0.1."""
        if self._http is None:
            raise RuntimeError("NativeCryptoProvider.start() must be called before scanning")
        payload = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params or {},
        }
        resp = await self._http.post(self.xmr_rpc_url, json=payload)
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"monero-wallet-rpc {method} failed: {body['error']}")
        return body.get("result", {})

    async def create_xmr_subaddress(self, label: str | None = None) -> tuple[str, int]:
        """Create a fresh subaddress on account 0. Returns (address, address_index)."""
        params: dict = {"account_index": 0}
        if label:
            params["label"] = label
        result = await self._xmr_rpc("create_address", params)
        return result["address"], int(result["address_index"])

    async def scan_xmr_subaddress(self, subaddr_index: int) -> AddressScanResult:
        """Polls get_transfers for incoming TX matching the subaddress.

        Returns aggregated received total + the highest confirmation count
        (max of all matching incoming transfers).
        """
        result = await self._xmr_rpc(
            "get_transfers",
            {
                "in": True,
                "subaddr_indices": [subaddr_index],
                "account_index": 0,
            },
        )
        incoming = result.get("in", [])
        if not incoming:
            return AddressScanResult(address="", received_total=Decimal("0"), confirmations=0)
        total_pico = sum(int(tx.get("amount", 0)) for tx in incoming)
        # XMR confirmations field is provided per-tx by monero-wallet-rpc.
        max_confs = max(int(tx.get("confirmations", 0)) for tx in incoming)
        # All txs to this subaddress share the same address; pick the first.
        addr = incoming[0].get("address", "")
        tx_hash = incoming[0].get("txid")
        return AddressScanResult(
            address=addr,
            received_total=Decimal(total_pico) / PICONERO_PER_XMR,
            confirmations=max_confs,
            tx_hash=tx_hash,
        )

    # ---------------- QR code URI ----------------

    @staticmethod
    def build_uri(asset: Asset, address: str, amount: Decimal) -> str:
        """Returns a BIP-21 / monero-uri payment string for QR encoding.

        BTC:   bitcoin:<addr>?amount=<x.xxxxxxxx>      (amount in BTC)
        XMR:   monero:<addr>?tx_amount=<x.xxxxxxxxxxxx> (amount in XMR)
        """
        # Trim trailing zeros but keep at least 8 (BTC) / 12 (XMR) precision
        if asset == "BTC":
            amt = format(amount.quantize(Decimal("0.00000001")), "f")
            return f"bitcoin:{address}?amount={amt}"
        if asset == "XMR":
            amt = format(amount.quantize(Decimal("0.000000000001")), "f")
            return f"monero:{address}?tx_amount={amt}"
        raise ValueError(f"unsupported asset: {asset}")
