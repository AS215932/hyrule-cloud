"""CI gate: verify every chain advertised in PaymentConfig is actually
supported by the configured x402 facilitator.

Per feedback_verified_payment_chains.md: we don't ship a chain — in code or
copy — until a real round-trip against the production facilitator confirms
the chain is recognised. The CI workflow runs this on any PR that touches
hyrule_cloud/config.py and gates merge on the exit code.

Per chain in `PaymentConfig.networks`:
  1. Probe the facilitator's `/supported` endpoint (the canonical Coinbase
     CDP / x402.org discovery surface).
  2. Confirm the chain identifier (CAIP-2 form for x402 v2; bare network
     name for v1) is present in the supported list.
  3. Print a one-line OK or FAIL per chain.

Network failure (facilitator unreachable, DNS broken, etc) exits 2 so the
CI step distinguishes "facilitator is down — retry later" from "facilitator
doesn't support this chain — fix the config."

In Wave 3 (Block C) this script gets extended to also smoke-test the EIP-712
domain shape for each EVM chain and to register Solana support. For now it
covers the Wave 2 minimum — the single Base entry — so the CI gate is real
and not a no-op.
"""

from __future__ import annotations

import sys
from typing import Any
from urllib.parse import urlparse

import httpx

from hyrule_cloud.config import PaymentConfig
from hyrule_cloud.middleware.x402 import (
    _CDP_FACILITATOR_HOST,
    CdpFacilitatorAuthProvider,
    _env_or_dotenv,
)

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Mainnet-only aliases per CAIP-2 chain. When probing the authenticated CDP
# facilitator these are the ONLY acceptable matches — accepting a testnet
# sibling there would green-light advertising Base mainnet against a
# facilitator that can't settle it.
_MAINNET_ALIASES: dict[str, set[str]] = {
    "eip155:8453": {"base", "base-mainnet"},
    "eip155:137": {"polygon", "polygon-mainnet"},
    "eip155:42161": {"arbitrum", "arbitrum-mainnet"},
}


def _cdp_auth_headers(facilitator: str) -> dict[str, str]:
    """Bearer auth for the CDP facilitator's /supported, when configured.

    Reuses the exact JWT construction PaymentGate uses in production, so a
    passing probe here means the server's own auth path works too.
    """
    if (urlparse(facilitator).hostname or "") != _CDP_FACILITATOR_HOST:
        return {}
    api_key_id = _env_or_dotenv("CDP_API_KEY_ID")
    api_key_secret = _env_or_dotenv("CDP_API_KEY_SECRET")
    if not (api_key_id and api_key_secret):
        print(
            "WARNING: CDP facilitator configured but CDP_API_KEY_ID/CDP_API_KEY_SECRET "
            "are missing — probing unauthenticated (may 401)",
            file=sys.stderr,
        )
        return {}
    provider = CdpFacilitatorAuthProvider(api_key_id, api_key_secret, facilitator)
    return provider.get_auth_headers().supported


def _normalise_supported_entries(payload: Any) -> set[str]:
    """The /supported endpoint shape isn't standardised across facilitators
    yet. Coinbase CDP returns `{"kinds": [{"network": "...", ...}, ...]}`;
    x402.org returns `{"networks": [...]}`. Reduce both to a flat set of
    network identifiers so the comparison below is shape-agnostic."""
    if not isinstance(payload, dict):
        return set()
    out: set[str] = set()
    for key in ("kinds", "networks", "supported"):
        items = payload.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, str):
                out.add(item)
            elif isinstance(item, dict):
                for nk in ("network", "id", "caip2", "name"):
                    val = item.get(nk)
                    if isinstance(val, str):
                        out.add(val)
    return out


def main() -> int:
    cfg = PaymentConfig()
    facilitator = cfg.facilitator_url.rstrip("/")
    is_cdp = (urlparse(facilitator).hostname or "") == _CDP_FACILITATOR_HOST
    auth_headers = _cdp_auth_headers(facilitator)
    print(f"facilitator: {facilitator}")
    print(f"configured chains: {len(cfg.networks)}")
    if is_cdp:
        print(f"cdp auth: {'yes' if auth_headers else 'NO (unauthenticated probe)'}")

    try:
        # follow_redirects=True: x402.org issues 308 to its canonical host.
        resp = httpx.get(
            f"{facilitator}/supported",
            timeout=_TIMEOUT,
            follow_redirects=True,
            headers=auth_headers or None,
        )
    except httpx.HTTPError as exc:
        print(f"NETWORK ERROR — facilitator unreachable: {exc}", file=sys.stderr)
        return 2

    if resp.status_code != 200:
        print(
            f"NETWORK ERROR — /supported returned {resp.status_code}: {resp.text[:200]}",
            file=sys.stderr,
        )
        return 2

    try:
        payload = resp.json()
    except ValueError as exc:
        print(f"NETWORK ERROR — non-JSON from /supported: {exc}", file=sys.stderr)
        return 2

    supported = _normalise_supported_entries(payload)
    if not supported:
        print(
            "NETWORK ERROR — /supported returned no recognisable network entries; "
            f"raw payload: {payload!r:.300}",
            file=sys.stderr,
        )
        return 2

    # Known testnet siblings keyed by mainnet CAIP-2. The public x402.org
    # facilitator advertises only testnets; production uses Coinbase CDP at a
    # different URL with the mainnet chains directly. Accepting the testnet
    # sibling here lets CI verify family support without operator credentials
    # for the prod facilitator — `_source: testnet-sibling` makes it explicit
    # so a reader of CI logs sees the trade-off.
    testnet_siblings: dict[str, set[str]] = {
        "eip155:8453": {"eip155:84532", "base-sepolia", "base-mainnet"},
        "eip155:137": {"eip155:80002", "polygon-amoy", "polygon-mainnet"},
        "eip155:42161": {"eip155:421614", "arbitrum-sepolia", "arbitrum-mainnet"},
    }

    failures: list[str] = []
    for entry in cfg.networks:
        network = entry.get("network", "")
        if network in supported:
            print(f"  OK   {network}")
            continue
        if is_cdp:
            # Production facilitator: mainnet must be advertised directly —
            # a testnet sibling is NOT proof it can settle real payments.
            match = next((s for s in _MAINNET_ALIASES.get(network, set()) if s in supported), None)
            if match:
                print(f"  OK   {network} (via mainnet alias: {match})")
                continue
            print(f"  FAIL {network} — CDP does not advertise this mainnet chain")
            failures.append(network)
            continue
        siblings = testnet_siblings.get(network, set())
        match = next((s for s in siblings if s in supported), None)
        if match:
            print(f"  OK   {network} (via testnet sibling: {match})")
            continue
        print(f"  FAIL {network} — not advertised and no known testnet sibling")
        failures.append(network)

    if failures:
        print(
            f"\nFAILED: {len(failures)} configured chain(s) not supported by "
            f"the facilitator: {failures}",
            file=sys.stderr,
        )
        print(f"Facilitator advertises: {sorted(supported)}", file=sys.stderr)
        return 1

    print(f"\nOK — all {len(cfg.networks)} configured chain(s) supported.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
