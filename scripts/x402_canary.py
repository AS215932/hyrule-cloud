#!/usr/bin/env python3
"""x402 live-payment canary for Hyrule Cloud.

Pays REAL USDC on Base mainnet to exercise a paid endpoint end to end
(402 -> EIP-3009 sign -> retry -> 200 + settlement). Use it to run the
per-service launch canaries: 3a network-intel, 3b proxy, 3c domain, 3d VM.

The x402 client auto-handles the 402 challenge, signs the payment, and retries.
A max-amount policy caps each call at its expected price (+10% margin) so a
malformed 402 can never overspend the wallet.

Usage
-----
  export CANARY_KEY=0x<private key of a funded Base wallet (USDC + gas)>
  # optional: export HYRULE_API_URL=https://cloud.hyrule.host
  # optional (vm): export SSH_PUBKEY="ssh-ed25519 AAAA... you@host"

  python x402_canary.py list                 # show tests + prices, no spend
  python x402_canary.py dns                  # cheapest first live spend ($0.001)
  python x402_canary.py intel                # every network-intel probe (~$0.06)
  python x402_canary.py proxy                # direct + tor network requests
  python x402_canary.py domain --name mytest12345   # REAL registration ($6)
  python x402_canary.py vm                   # provision a real VM + print SSH target
  python x402_canary.py vm --destroy         # ...and tear it down afterwards
  python x402_canary.py all                  # every non-spendy test (intel + proxy)

Nothing is spent until you name a test. `domain` and `vm` cost real money and
have side effects, so they require an explicit name / confirmation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import sys
from decimal import Decimal

import httpx
from eth_account import Account
from x402 import x402Client
from x402.client import max_amount
from x402.http import decode_payment_response_header
from x402.http.clients import x402HttpxClient
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner

API = os.environ.get("HYRULE_API_URL", "https://cloud.hyrule.host").rstrip("/")
SSH_PUBKEY = os.environ.get("SSH_PUBKEY", "")

# (method, path, body, price_usd, group). Bodies mirror the manifest's Bazaar
# discovery examples so they hit a real backend.
TESTS: dict[str, dict] = {
    # --- 3a network-intel ---
    "dns":       {"path": "/v1/dns/lookup",  "body": {"name": "example.com", "type": "AAAA"}, "usd": "0.001", "group": "intel"},
    "ip":        {"path": "/v1/ip/lookup",   "body": {"address": "2a0c:b641:b50::1"}, "usd": "0.003", "group": "intel"},
    "bgp":       {"path": "/v1/bgp/lookup",  "body": {"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}}, "usd": "0.005", "group": "intel"},
    "rdap":      {"path": "/v1/rdap/lookup", "body": {"subject": {"type": "domain", "value": "example.com"}}, "usd": "0.003", "group": "intel"},
    "whois":     {"path": "/v1/whois/lookup","body": {"subject": {"type": "domain", "value": "example.com"}}, "usd": "0.005", "group": "intel"},
    "web":       {"path": "/v1/web/check",   "body": {"target": "https://example.com"}, "usd": "0.005", "group": "intel"},
    "mx":        {"path": "/v1/mx/check",    "body": {"tool": "mx", "target": "example.com"}, "usd": "0.005", "group": "intel"},
    "path":      {"path": "/v1/path/ping",   "body": {"target": "example.com"}, "usd": "0.005", "group": "intel"},
    "ports":     {"path": "/v1/ports/check", "body": {"target": "example.com", "port": 443}, "usd": "0.003", "group": "intel"},
    "nat":       {"path": "/v1/nat/lookup",  "body": {"customer_reported_wan_ip": "100.64.1.1"}, "usd": "0.003", "group": "intel"},
    "threat":    {"path": "/v1/threat/lookup","body": {"subject": {"type": "domain", "value": "example.com"}}, "usd": "0.01", "group": "intel"},
    "voip":      {"path": "/v1/voip/check",  "body": {"target": "sip.example.com"}, "usd": "0.01", "group": "intel"},
    "voipnum":   {"path": "/v1/voip/number/lookup", "body": {"number": "+31201234567"}, "usd": "0.05", "group": "intel"},
    # --- 3b network proxy ---
    "proxy-direct": {"path": "/v1/network/request", "body": {"url": "https://example.com", "method": "GET", "proxy_mode": "direct"}, "usd": "0.01", "group": "proxy"},
    "proxy-tor":    {"path": "/v1/network/request", "body": {"url": "https://example.com", "method": "GET", "proxy_mode": "tor"}, "usd": "0.05", "group": "proxy"},
    # --- 3c domain (REAL registration, side effects) ---
    "domain":    {"path": "/v1/domain/register", "body": {"name": None, "extension": "dev", "duration_years": 1}, "usd": "6.00", "group": "domain", "spendy": True},
    # --- 3d VM (provisions a real VM) ---
    "vm":        {"path": "/v1/vm/create", "body": {"duration_days": 1, "size": "xs", "os": "debian-13", "ssh_pubkey": None, "domain_mode": "auto", "open_ports": [80, 443]}, "usd": "0.05", "group": "vm", "spendy": True},
}


def _cap_units(usd: str) -> int:
    """USDC (6 dp) atomic cap = price + 10% margin, so a bad 402 can't overspend."""
    return math.ceil(Decimal(usd) * Decimal("1.10") * Decimal(10**6))


def _client(usd: str) -> x402Client:
    key = os.environ.get("CANARY_KEY")
    if not key:
        sys.exit("ERROR: set CANARY_KEY to a funded Base wallet private key (0x...).")
    signer = EthAccountSigner(Account.from_key(key))
    client = x402Client()
    # eip155:* wildcard scheme + a per-call max-amount guardrail.
    register_exact_evm_client(client, signer, policies=[max_amount(_cap_units(usd))])
    return client


def _settlement(resp: httpx.Response) -> str:
    raw = resp.headers.get("x-payment-response") or resp.headers.get("payment-response")
    if not raw:
        return "(no settlement header)"
    try:
        s = decode_payment_response_header(raw)
        tx = getattr(s, "transaction", None) or getattr(s, "tx_hash", None)
        net = getattr(s, "network", None)
        payer = getattr(s, "payer", None)
        ok = getattr(s, "success", None)
        return f"settled success={ok} tx={tx} network={net} payer={payer}"
    except Exception as e:
        return f"(settlement header present but undecodable: {e}) raw={raw[:80]}"


async def _run_one(name: str, *, destroy: bool, domain_name: str | None) -> bool:
    t = TESTS[name]
    body = json.loads(json.dumps(t["body"]))  # deep copy
    if name == "vm":
        if not SSH_PUBKEY:
            sys.exit("ERROR: set SSH_PUBKEY for the vm test (the key injected into the VM).")
        body["ssh_pubkey"] = SSH_PUBKEY
    if name == "domain":
        if not domain_name:
            sys.exit("ERROR: domain test needs --name <label> (registers <label>.dev for REAL money).")
        body["name"] = domain_name

    print(f"\n=== {name}  POST {t['path']}  (~${t['usd']})  cap={_cap_units(t['usd'])} units ===")
    print(f"    body: {json.dumps(body)}")
    client = _client(t["usd"])
    async with x402HttpxClient(client, base_url=API, timeout=60.0) as http:
        try:
            r = await http.post(t["path"], json=body)
        except Exception as e:
            print(f"    !! request failed: {e!r}")
            return False
    print(f"    HTTP {r.status_code}   {_settlement(r)}")
    text = r.text
    print(f"    body: {text[:600]}{'...' if len(text) > 600 else ''}")
    if r.status_code >= 400:
        return False

    if name == "vm":
        await _poll_and_report_vm(r, destroy=destroy)
    return True


async def _poll_and_report_vm(create_resp: httpx.Response, *, destroy: bool) -> None:
    data = create_resp.json()
    vm_id = data.get("vm_id")
    status_url = data.get("status_url") or f"{API}/v1/vm/{vm_id}/status"
    mgmt_token = data.get("management_token")
    print(f"\n    --- provisioning VM {vm_id}; polling {status_url} ---")
    async with httpx.AsyncClient(timeout=30.0) as poll:
        for i in range(60):  # up to ~5 min
            await asyncio.sleep(5)
            try:
                s = await poll.get(status_url)
                sj = s.json()
            except Exception as e:
                print(f"    [{i}] poll error: {e!r}")
                continue
            st = sj.get("status") or sj.get("launch_proof_status")
            host = sj.get("hostname")
            ipv6 = sj.get("ipv6")
            print(f"    [{i}] status={st} hostname={host} ipv6={ipv6}")
            if st in ("ready", "running", "provisioned"):
                print("\n    ✅ VM READY — manually verify over IPv6:")
                print(f"        ssh root@{host or ipv6}")
                lp = sj.get("launch_proof") or {}
                if lp:
                    print(f"        launch_proof: {json.dumps(lp)}")
                if mgmt_token:
                    print(f"        management: {API}/v1/vm/{vm_id}?token={mgmt_token}")
                    print(f"        destroy:    curl -X DELETE {API}/v1/vm/{vm_id} "
                          f"-H 'Authorization: Bearer {mgmt_token}'")
                if destroy and mgmt_token:
                    d = await poll.request("DELETE", f"{API}/v1/vm/{vm_id}",
                                           headers={"Authorization": f"Bearer {mgmt_token}"})
                    print(f"\n    destroy -> HTTP {d.status_code} {d.text[:200]}")
                return
            if st in ("failed",):
                print(f"    ❌ provisioning FAILED: {json.dumps(sj)[:400]}")
                return
    print("    ⏱ timed out waiting for the VM to become ready — check status_url manually.")


def _select(target: str) -> list[str]:
    if target == "all":  # non-spendy only
        return [n for n, t in TESTS.items() if not t.get("spendy")]
    if target in {"intel", "proxy", "domain", "vm"}:
        return [n for n, t in TESTS.items() if t["group"] == target]
    if target in TESTS:
        return [target]
    sys.exit(f"unknown test '{target}'. Try: list, all, intel, proxy, domain, vm, or one of "
             f"{', '.join(TESTS)}")


async def _main() -> None:
    ap = argparse.ArgumentParser(description="x402 live-payment canary for Hyrule Cloud")
    ap.add_argument("target", help="a test name, a group (intel|proxy|domain|vm), 'all', or 'list'")
    ap.add_argument("--name", help="domain label to register (domain test)")
    ap.add_argument("--destroy", action="store_true", help="destroy the VM after it comes up (vm test)")
    ap.add_argument("--yes", action="store_true", help="skip the spend confirmation prompt")
    args = ap.parse_args()

    if args.target == "list":
        print(f"API: {API}\n")
        print(f"{'name':14} {'price':>8}  path")
        for n, t in TESTS.items():
            flag = "  [REAL $]" if t.get("spendy") else ""
            print(f"{n:14} {'$'+t['usd']:>8}  {t['path']}{flag}")
        return

    names = _select(args.target)
    total = sum(Decimal(TESTS[n]["usd"]) for n in names)
    spendy = [n for n in names if TESTS[n].get("spendy")]
    print(f"About to run {len(names)} canary payment(s) on {API}: {', '.join(names)}")
    print(f"Estimated total spend: ${total} (real USDC on Base mainnet)")
    if spendy:
        print(f"⚠  side-effecting / higher-cost: {', '.join(spendy)}")
    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted.")
            return

    ok = 0
    for n in names:
        if await _run_one(n, destroy=args.destroy, domain_name=args.name):
            ok += 1
    print(f"\n=== done: {ok}/{len(names)} succeeded ===")


if __name__ == "__main__":
    asyncio.run(_main())
