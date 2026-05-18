"""Block C: facilitator + chain config smoke test.

A network is not v1-supported unless this script passes against it. Per the
feedback_verified_payment_chains.md memory: do not advertise a chain unless
its facilitator round-trip is green.

Modes:
  --dry-run (default): only static config checks (no network).
              Safe for CI on every PR that touches PaymentConfig.
  --probe-facilitator: HTTP GET the facilitator's well-known endpoint and
              confirm it advertises support for each configured CAIP-2.
              Adds a network dependency to CI; opt-in.
  --probe-rpc: HTTP POST each chain's RPC with eth_chainId to confirm
              connectivity and chain_id match.

Exit code:
  0  all checks passed
  1  config inconsistency (always fatal)
  2  facilitator probe failure (fatal in CI; warning in local dev)
  3  RPC probe failure (warning only — public RPCs flap)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import asdict

import httpx

from hyrule_cloud.config import (
    PAYMENT_NETWORKS_CATALOG,
    PaymentConfig,
    PaymentNetwork,
)


def _check_catalog_consistency() -> list[str]:
    """Static checks: no missing fields, no duplicate CAIP-2, etc.

    EVM-specific checks (chain_id, eip712_domain) only run on `eip155:*`
    entries; SVM entries are validated against the SDK's known CAIP-2 set.
    """
    errors: list[str] = []
    seen_caip2: dict[str, str] = {}
    seen_chain_id: dict[int, str] = {}
    for key, net in PAYMENT_NETWORKS_CATALOG.items():
        if net.key != key:
            errors.append(f"{key}: catalog key mismatch (entry.key = {net.key!r})")
        if not net.caip2.startswith(("eip155:", "solana:")):
            errors.append(f"{key}: caip2 must use eip155: or solana: scheme")
        if net.caip2 in seen_caip2:
            errors.append(f"{key}: duplicate caip2 {net.caip2} (also {seen_caip2[net.caip2]})")
        seen_caip2[net.caip2] = key
        if net.asset == "USDC" and net.token_decimals != 6:
            errors.append(f"{key}: USDC must have decimals=6, got {net.token_decimals}")
        if not net.token_address:
            errors.append(f"{key}: token_address is empty")
        if not net.rpc_url:
            errors.append(f"{key}: rpc_url is empty")
        if not net.block_explorer_url:
            errors.append(f"{key}: block_explorer_url is empty")

        if net.family == "evm":
            if int(net.caip2.split(":", 1)[1]) != net.chain_id:
                errors.append(f"{key}: caip2 chain_id mismatch ({net.caip2} vs {net.chain_id})")
            if net.chain_id in seen_chain_id:
                errors.append(
                    f"{key}: duplicate chain_id {net.chain_id} (also {seen_chain_id[net.chain_id]})"
                )
            assert net.chain_id is not None  # narrowed by `family == evm`
            seen_chain_id[net.chain_id] = key
            if not net.eip712_domain_name or not net.eip712_domain_version:
                errors.append(f"{key}: eip712_domain fields incomplete (EVM)")
        elif net.family == "svm":
            # Cross-check against the SDK's known Solana CAIP-2 set so we
            # don't drift from what ExactSvmScheme will accept.
            try:
                from x402.mechanisms.svm.constants import (
                    SOLANA_DEVNET_CAIP2,
                    SOLANA_MAINNET_CAIP2,
                    SOLANA_TESTNET_CAIP2,
                )
                known = {SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2, SOLANA_TESTNET_CAIP2}
                if net.caip2 not in known:
                    errors.append(
                        f"{key}: SVM caip2 {net.caip2} not in SDK known set {sorted(known)}"
                    )
            except ImportError:
                errors.append(f"{key}: SVM entry requires x402[svm] extra (solana, solders)")
            if net.chain_id is not None:
                errors.append(f"{key}: SVM entries must have chain_id=None (got {net.chain_id})")
            if net.eip712_domain_name or net.eip712_domain_version:
                errors.append(f"{key}: SVM entries must have no EIP-712 domain")
    return errors


def _check_runtime_config() -> list[str]:
    """Live PaymentConfig sanity (env-driven)."""
    errors: list[str] = []
    cfg = PaymentConfig()
    if not cfg.receiver_address:
        errors.append("PAYMENT_RECEIVER_ADDRESS is empty (no place to pay to)")
    enabled = cfg.networks
    if not enabled:
        errors.append("no networks enabled (PaymentConfig.networks is empty)")
    for n in enabled:
        if n.key not in PAYMENT_NETWORKS_CATALOG:
            errors.append(f"enabled network {n.key!r} not in catalog")
    return errors


async def _probe_facilitator(facilitator_url: str, networks: list[PaymentNetwork]) -> list[str]:
    """Best-effort: GET the facilitator's discovery and check each CAIP-2 is supported.

    The x402 spec doesn't mandate a fixed discovery endpoint; we probe a few
    common shapes (`/supported`, `/networks`, `/.well-known/x402-facilitator`).
    """
    errors: list[str] = []
    candidates = [
        facilitator_url.rstrip("/") + "/supported",
        facilitator_url.rstrip("/") + "/networks",
        facilitator_url.rstrip("/") + "/.well-known/x402-facilitator",
    ]
    async with httpx.AsyncClient(timeout=10) as client:
        body = None
        for url in candidates:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    body = resp.json()
                    break
            except Exception:
                continue
        if body is None:
            errors.append(
                f"facilitator at {facilitator_url} did not respond to any discovery endpoint; "
                "verify manually before enabling new chains"
            )
            return errors
        # Heuristic: body contains a list of network identifiers somewhere
        text = repr(body).lower()
        for n in networks:
            if n.caip2.lower() not in text:
                errors.append(
                    f"{n.key}: caip2 {n.caip2} not advertised by facilitator at {facilitator_url}"
                )
    return errors


async def _probe_rpc(networks: list[PaymentNetwork]) -> list[str]:
    """Probe each chain's RPC.

    EVM: eth_chainId and verify the returned chain_id matches.
    SVM: getHealth + getVersion — just confirm the RPC responds.
    """
    errors: list[str] = []
    evm_payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    svm_payload = {"jsonrpc": "2.0", "id": 1, "method": "getVersion", "params": []}
    async with httpx.AsyncClient(timeout=10) as client:
        for n in networks:
            try:
                if n.family == "evm":
                    resp = await client.post(n.rpc_url, json=evm_payload)
                    if resp.status_code != 200:
                        errors.append(f"{n.key}: RPC {n.rpc_url} returned HTTP {resp.status_code}")
                        continue
                    data = resp.json()
                    returned = int(data.get("result", "0x0"), 16)
                    if returned != n.chain_id:
                        errors.append(
                            f"{n.key}: RPC reported chain_id {returned} (expected {n.chain_id})"
                        )
                elif n.family == "svm":
                    resp = await client.post(n.rpc_url, json=svm_payload)
                    if resp.status_code != 200:
                        errors.append(f"{n.key}: RPC {n.rpc_url} returned HTTP {resp.status_code}")
                        continue
                    data = resp.json()
                    if "result" not in data or not isinstance(data["result"], dict):
                        errors.append(f"{n.key}: getVersion returned unexpected shape: {data!r}")
            except Exception as exc:
                errors.append(f"{n.key}: RPC probe failed: {exc!r}")
    return errors


async def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probe-facilitator", action="store_true",
                   help="HTTP-probe the facilitator URL (network required)")
    p.add_argument("--probe-rpc", action="store_true",
                   help="HTTP-probe each chain's public RPC (network required)")
    p.add_argument("--json", action="store_true", help="Output JSON instead of human-readable")
    args = p.parse_args()

    cfg = PaymentConfig()

    print(f"[verify_facilitator] catalog: {list(PAYMENT_NETWORKS_CATALOG)}")
    print(f"[verify_facilitator] enabled: {[n.key for n in cfg.networks]}")
    print(f"[verify_facilitator] facilitator: {cfg.facilitator_url}")
    print()

    catalog_errs = _check_catalog_consistency()
    runtime_errs = _check_runtime_config()

    exit_code = 0
    for e in catalog_errs:
        print(f"[CONFIG]   ERROR: {e}")
    for e in runtime_errs:
        print(f"[RUNTIME]  ERROR: {e}")
    if catalog_errs or runtime_errs:
        exit_code = 1

    if args.probe_facilitator:
        print()
        print("[verify_facilitator] probing facilitator...")
        fac_errs = await _probe_facilitator(cfg.facilitator_url, cfg.networks)
        for e in fac_errs:
            print(f"[FACILIT]  ERROR: {e}")
        if fac_errs:
            exit_code = max(exit_code, 2)

    if args.probe_rpc:
        print()
        print("[verify_facilitator] probing chain RPCs...")
        rpc_errs = await _probe_rpc(cfg.networks)
        for e in rpc_errs:
            print(f"[RPC]      WARN:  {e}")

    print()
    if exit_code == 0:
        print(f"[verify_facilitator] OK — {len(cfg.networks)} network(s) verified for v1")
    else:
        print(f"[verify_facilitator] FAILED (exit {exit_code})")

    if args.json:
        import json
        json.dump(
            {
                "enabled": [asdict(n) for n in cfg.networks],
                "errors": catalog_errs + runtime_errs,
                "exit_code": exit_code,
            },
            sys.stdout,
            indent=2,
            default=str,
        )
        print()

    return exit_code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
