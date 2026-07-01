"""Block E: USD-per-asset rate fetcher.

Used by NativeCryptoProvider at intent creation time to convert the USD
quote into a target BTC/XMR amount, and again at scan time for the LENIENT
late-paid re-quote.

Primary: CoinGecko (free tier, no API key, generous rate limits)
Fallback: Kraken public ticker

60-second in-process TTL cache. Concurrent callers share the lookup.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Literal

import httpx
import structlog
from cachetools import TTLCache

log = structlog.get_logger()

Asset = Literal["BTC", "XMR", "ZEC"]

_COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"
_COINGECKO_IDS = {"BTC": "bitcoin", "XMR": "monero", "ZEC": "zcash"}
_KRAKEN_URL = "https://api.kraken.com/0/public/Ticker"
_KRAKEN_PAIRS = {"BTC": "XBTUSD", "XMR": "XMRUSD", "ZEC": "ZECUSD"}


class RateProvider:
    """Async USD/asset rate fetcher with primary+fallback and TTL caching.

    Instantiate once at app startup (lifespan), inject into
    NativeCryptoProvider. Holds a single httpx.AsyncClient for the
    process lifetime.
    """

    def __init__(self, *, ttl_seconds: int = 60, timeout_seconds: float = 5.0) -> None:
        self._cache: TTLCache[str, Decimal] = TTLCache(maxsize=16, ttl=ttl_seconds)
        self._locks: dict[str, asyncio.Lock] = {}
        self._timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_usd_per(self, asset: Asset) -> Decimal:
        """Returns the USD price of 1 unit of `asset` (e.g. 65000 for BTC).

        Raises RuntimeError if BOTH primary and fallback fail. Callers should
        treat a raise as a hard failure (don't create an intent without a rate).
        """
        key = asset.upper()
        if key in self._cache:
            return self._cache[key]

        # Serialize concurrent lookups for the same asset.
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:
                return self._cache[key]
            rate = await self._fetch_with_fallback(key)
            self._cache[key] = rate
            return rate

    async def _fetch_with_fallback(self, asset: str) -> Decimal:
        for provider_name, fn in (("coingecko", self._fetch_coingecko), ("kraken", self._fetch_kraken)):
            try:
                rate = await fn(asset)
                if rate > 0:
                    log.info("rate_fetched", asset=asset, provider=provider_name, usd=str(rate))
                    return rate
            except Exception as exc:
                log.warning("rate_provider_failed", asset=asset, provider=provider_name, error=str(exc))
                continue
        raise RuntimeError(f"all rate providers failed for {asset}")

    async def _fetch_coingecko(self, asset: str) -> Decimal:
        assert self._client is not None
        coin_id = _COINGECKO_IDS.get(asset)
        if not coin_id:
            raise ValueError(f"unsupported asset: {asset}")
        resp = await self._client.get(
            _COINGECKO_URL,
            params={"ids": coin_id, "vs_currencies": "usd"},
        )
        resp.raise_for_status()
        body = resp.json()
        usd = body.get(coin_id, {}).get("usd")
        if usd is None:
            raise ValueError(f"coingecko returned no usd for {asset}: {body}")
        return Decimal(str(usd))

    async def _fetch_kraken(self, asset: str) -> Decimal:
        assert self._client is not None
        pair = _KRAKEN_PAIRS.get(asset)
        if not pair:
            raise ValueError(f"unsupported asset: {asset}")
        resp = await self._client.get(_KRAKEN_URL, params={"pair": pair})
        resp.raise_for_status()
        body = resp.json()
        if body.get("error"):
            raise ValueError(f"kraken error: {body['error']}")
        result = body.get("result", {})
        if not result:
            raise ValueError("kraken returned empty result")
        # Kraken returns the pair under a normalized key (e.g. "XXBTZUSD")
        first_pair = next(iter(result.values()))
        # 'c' is "last trade closed": [price, lot_volume]
        last = first_pair.get("c") or first_pair.get("p") or first_pair.get("a")
        if not last:
            raise ValueError(f"kraken returned no price for {asset}")
        return Decimal(str(last[0]))
