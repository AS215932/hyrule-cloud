#!/usr/bin/env python3
"""x402 live-payment canary for Hyrule Cloud.

Pays REAL USDC on Base mainnet to exercise a paid endpoint end to end
(402 -> EIP-3009 sign -> retry -> successful 2xx + settlement). Use it to run the
per-service launch canaries: 3a network-intel, 3b proxy, 3c domain, 3d VM.

The x402 client auto-handles the 402 challenge, signs the payment, and retries.
A max-amount policy caps each call at its expected price (+10% margin) so a
malformed 402 can never overspend the wallet.

Usage
-----
  export CANARY_KEY=0x<private key of a funded Base wallet (USDC + gas)>
  # optional: export HYRULE_API_URL=https://cloud.hyrule.host
  # optional (vm): export SSH_PUBKEY="ssh-ed25519 AAAA... you@host"
  # domain: export HYRULE_API_KEY=<account key with domain purchase/read/dns scopes>

  python x402_canary.py list                 # show tests + prices, no spend
  python x402_canary.py dns                  # cheapest first live spend ($0.001)
  python x402_canary.py intel                # every network-intel probe (~$0.06)
  python x402_canary.py proxy                # direct + tor network requests
  python x402_canary.py domain --name mytest12345   # REAL account-owned registration
  python x402_canary.py tunnel               # provision a real 1h reverse tunnel, then revoke it
  python x402_canary.py vm                   # provision a real VM + print SSH target
  python x402_canary.py vm --quote --destroy # via the locked-quote flow, then tear down
  python x402_canary.py path-report          # gated probe: run by name once a prober is live
  python x402_canary.py all                  # every non-spendy test (intel + proxy)

Nothing is spent until you name a test. `domain` and `vm` cost real money and
have side effects, so they require an explicit name / confirmation. The VM gate
only passes when the VM reaches ready AND its launch-proof (SSH smoke + DNS
AAAA) verifies; a paid 2xx without a settlement header also fails. `gated` tests
(de-advertised endpoints that 501 until configured) run only when named.
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
    "dns": {
        "path": "/v1/dns/lookup",
        "body": {"name": "example.com", "type": "AAAA"},
        "usd": "0.001",
        "group": "intel",
    },
    "ip": {
        "path": "/v1/ip/lookup",
        "body": {"address": "2a0c:b641:b50::1"},
        "usd": "0.003",
        "group": "intel",
    },
    "bgp": {
        "path": "/v1/bgp/lookup",
        "body": {"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}},
        "usd": "0.005",
        "group": "intel",
    },
    "rdap": {
        "path": "/v1/rdap/lookup",
        "body": {"subject": {"type": "domain", "value": "example.com"}},
        "usd": "0.003",
        "group": "intel",
    },
    "whois": {
        "path": "/v1/whois/lookup",
        "body": {"subject": {"type": "domain", "value": "example.com"}},
        "usd": "0.005",
        "group": "intel",
    },
    "web": {
        "path": "/v1/web/check",
        "body": {"target": "https://example.com"},
        "usd": "0.005",
        "group": "intel",
    },
    "web-tls": {
        "path": "/v1/web/tls/deep",
        "body": {"host": "example.com"},
        "usd": "0.10",
        "group": "intel",
    },
    "mx": {
        "path": "/v1/mx/check",
        "body": {"tool": "mx", "target": "example.com"},
        "usd": "0.005",
        "group": "intel",
    },
    "path": {
        "path": "/v1/path/ping",
        "body": {"target": "example.com", "vantages": ["extmon", "as215932", "globalping"]},
        "usd": "0.005",
        "group": "intel",
    },
    # /v1/path/report (Phase-3a path evidence) uses the endpoint's default
    # vantage set so it actually probes once a vantage (Globalping/RIPE Atlas) is
    # configured. Until then it returns 501 before charging (PR #42), which the
    # sweep treats as "not launched yet, skipped" rather than a failure — so the
    # runbook's required paid /v1/path/report call is validated the moment a
    # prober goes live, without failing the pre-launch sweep.
    "path-report": {
        "path": "/v1/path/report",
        "body": {
            "target": "example.com",
            "vantages": ["extmon", "as215932", "globalping"],
            "checks": ["ping", "traceroute"],
        },
        "usd": "0.05",
        "group": "intel",
    },
    "ports": {
        "path": "/v1/ports/check",
        "body": {"target": "example.com", "port": 443},
        "usd": "0.003",
        "group": "intel",
    },
    "nat": {
        "path": "/v1/nat/port-forward/check",
        "body": {"target": "example.com", "port": 443},
        "usd": "0.005",
        "group": "intel",
    },
    "threat": {
        "path": "/v1/threat/lookup",
        "body": {"subject": {"type": "domain", "value": "example.com"}},
        "usd": "0.01",
        "group": "intel",
    },
    "voip": {
        "path": "/v1/voip/check",
        "body": {"target": "sip.example.com"},
        "usd": "0.01",
        "group": "intel",
    },
    "voipnum": {
        "path": "/v1/voip/number/lookup",
        "body": {"number": "+31201234567"},
        "usd": "0.05",
        "group": "intel",
    },
    # --- 3b network proxy ---
    "proxy-direct": {
        "path": "/v1/network/request",
        "body": {"url": "https://example.com", "method": "GET", "proxy_mode": "direct"},
        "usd": "0.01",
        "group": "proxy",
    },
    "proxy-tor": {
        "path": "/v1/network/request",
        "body": {"url": "https://example.com", "method": "GET", "proxy_mode": "tor"},
        "usd": "0.05",
        "group": "proxy",
    },
    # --- 3e reverse-SSH tunnel (provisions a real 1h lease, then revokes) ---
    "tunnel": {
        "path": "/v1/tunnel/create",
        "body": {"hours": 1},
        "usd": "0.05",
        "group": "provision",
        "spendy": True,
    },
    # --- 3c domain (REAL registration, side effects) ---
    # The dedicated runner performs check -> quote -> authenticated x402 order
    # -> durable poll -> revisioned managed-DNS write -> public resolution.
    "domain": {
        "path": "/v1/domains/orders",
        "body": {},
        "usd": "15.00",
        "group": "domain",
        "spendy": True,
    },
    # --- 3d VM (provisions a real VM) ---
    "vm": {
        "path": "/v1/vm/create",
        "body": {
            "duration_days": 1,
            "size": "xs",
            "os": "debian-13",
            "ssh_pubkey": None,
            "domain_mode": "auto",
            "open_ports": [80, 443],
        },
        "usd": "0.20",
        "group": "vm",
        "spendy": True,
    },
}


def _cap_units(usd: str) -> int:
    """USDC (6 dp) atomic cap = price + 10% margin, so a bad 402 can't overspend."""
    return math.ceil(Decimal(usd) * Decimal("1.10") * Decimal(10**6))


def _client(usd: str, network: str) -> x402Client:
    key = os.environ.get("CANARY_KEY")
    if not key:
        sys.exit(f"ERROR: set CANARY_KEY to a wallet private key (0x...) funded on {network}.")
    signer = EthAccountSigner(Account.from_key(key))
    client = x402Client()
    # Pin to ONE chain (--network, default Base mainnet) + a per-call
    # max-amount guardrail. Without the pin the SDK would sign for whatever
    # EVM chain the API advertises first, causing a false failure or a
    # wrong-chain spend from an unfunded/differently-funded wallet.
    register_exact_evm_client(
        client, signer, networks=network, policies=[max_amount(_cap_units(usd))]
    )
    return client


def _settlement(resp: httpx.Response) -> tuple[bool, str]:
    """(settled_ok, human detail). ``settled_ok`` is True only when the paid
    response actually carried a successful x402 settlement. A 2xx WITHOUT one
    means the route wasn't charged — ungated, or the settlement-header
    middleware is broken — and the canary must not count it as a pass."""
    raw = resp.headers.get("x-payment-response") or resp.headers.get("payment-response")
    if not raw:
        return False, "(no settlement header)"
    try:
        s = decode_payment_response_header(raw)
        tx = getattr(s, "transaction", None) or getattr(s, "tx_hash", None)
        net = getattr(s, "network", None)
        payer = getattr(s, "payer", None)
        ok = getattr(s, "success", None)
        settled_ok = bool(ok) if ok is not None else bool(tx)
        return settled_ok, f"settled success={ok} tx={tx} network={net} payer={payer}"
    except Exception as e:
        return False, f"(settlement header present but undecodable: {e}) raw={raw[:80]}"


async def _create_domain_quote(fqdn: str) -> dict | None:
    """Check availability and create the exact 15-minute registration quote."""
    async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
        try:
            check = await http.get("/v1/domains/check", params={"domain": fqdn})
        except Exception as e:
            print(f"    !! /v1/domains/check failed: {e!r}")
            return None
        if check.status_code >= 400:
            print(f"    !! /v1/domains/check HTTP {check.status_code} {check.text[:200]}")
            return None
        check_data = check.json()
        if not check_data.get("eligible") or not check_data.get("available"):
            print(f"    !! {fqdn} is not eligible and available for registration.")
            return None
        try:
            quote = await http.post(
                "/v1/domains/quotes",
                json={"domain": fqdn, "action": "register"},
            )
        except Exception as e:
            print(f"    !! /v1/domains/quotes failed: {e!r}")
            return None
    if quote.status_code >= 400:
        print(f"    !! /v1/domains/quotes HTTP {quote.status_code} {quote.text[:200]}")
        return None
    data = quote.json()
    if not data.get("quote_id") or not data.get("terms_version"):
        print(f"    !! domain quote omitted required fields: {quote.text[:200]}")
        return None
    return data


async def _run_one(
    name: str,
    *,
    destroy: bool,
    domain_name: str | None,
    use_quote: bool,
    yes: bool,
    network: str = "eip155:8453",
) -> bool:
    t = TESTS[name]
    if name == "domain":
        return await _run_domain(domain_name, network)
    body = json.loads(json.dumps(t["body"]))  # deep copy
    quote_id: str | None = None
    if name == "vm":
        if not SSH_PUBKEY:
            sys.exit("ERROR: set SSH_PUBKEY for the vm test (the key injected into the VM).")
        body["ssh_pubkey"] = SSH_PUBKEY
        if use_quote:
            # Exercise the documented public quote flow (Phase 3d gate): lock a
            # price via POST /v1/vm/quote, then pay the create against quote_id.
            quote_id = await _create_quote(body)
            if not quote_id:
                return False
            body["quote_id"] = quote_id
    cap_usd = t["usd"]
    print(f"\n=== {name}  POST {t['path']}  (~${cap_usd})  cap={_cap_units(cap_usd)} units ===")
    if quote_id:
        print(f"    quote_id: {quote_id}")
    print(f"    body: {json.dumps(body)}")
    client = _client(cap_usd, network)
    async with x402HttpxClient(client, base_url=API, timeout=60.0) as http:
        try:
            r = await http.post(t["path"], json=body)
        except Exception as e:
            print(f"    !! request failed: {e!r}")
            return False
    settled_ok, settle_detail = _settlement(r)
    print(f"    HTTP {r.status_code}   {settle_detail}")
    text = r.text
    if name == "tunnel":
        # The tunnel response carries the one-time token (SSH username + mgmt
        # credential) in both `token` and `ssh_command`; redact before any log so
        # a failed cleanup can't leave a live credential in CI logs.
        try:
            tok = r.json().get("token")
            if tok:
                text = text.replace(tok, "<redacted-token>")
        except Exception:
            pass
    print(f"    body: {text[:600]}{'...' if len(text) > 600 else ''}")
    if r.status_code == 501:
        # 501 is the intentional "not launched yet" signal (PR #42: a diagnostic
        # whose source isn't configured 501s BEFORE charging). No money was
        # spent, so a launch-readiness sweep treats it as skipped, not failed —
        # configure the source and re-run to validate it.
        print(f"    -- {name}: gated / not launched (HTTP 501); SKIPPED, not counted as a failure.")
        return True
    if r.status_code >= 400:
        return False
    if not settled_ok:
        # A paid endpoint that returns 2xx without a successful settlement was
        # not actually charged — a broken gate, not a passing canary.
        print("    !! paid 2xx with no successful settlement — route not charged; FAILING.")
        return False

    if name == "vm":
        if r.status_code != 202:
            print(f"    !! VM create returned HTTP {r.status_code}; expected 202 Accepted. FAILING.")
            return False
        # The 202 only means the create was accepted + charged; the Phase-3d
        # gate isn't passed until the VM reaches ready AND its launch-proof
        # (SSH smoke + DNS AAAA) verifies. Propagate that.
        return await _poll_and_report_vm(r, destroy=destroy, yes=yes)
    if name == "tunnel":
        return await _verify_and_cleanup_tunnel(r)
    return True


async def _verify_and_cleanup_tunnel(create_resp: httpx.Response) -> bool:
    """Assert the tunnel create returned a usable lease, then revoke it so the
    canary never leaks a live tunnel (min lease is 1h; revoke frees it now)."""
    data = create_resp.json()
    token = data.get("token")
    tunnel_id = data.get("tunnel_id")
    port = data.get("public_port")
    if not (token and tunnel_id and port):
        print(f"    !! tunnel create omitted token/id/port: {create_resp.text[:200]}")
        return False
    print(f"    tunnel {tunnel_id} -> {data.get('endpoint_host')}:{port}")
    # The ssh_command embeds the one-time token (the SSH username). Redact it in
    # logs — if the cleanup revoke below fails, an un-redacted log would leave a
    # live credential exposed to every log reader for the rest of the lease.
    ssh_command = str(data.get("ssh_command", "")).replace(token, "<redacted-token>")
    print(f"    ssh: {ssh_command}")
    async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
        status_ok = False
        try:
            # Status is best-effort verification; a failure here must NOT skip the
            # cleanup revoke below, or a paid tunnel leaks for the rest of its lease.
            status = await http.get(f"/v1/tunnel/{tunnel_id}/status", headers={"X-Tunnel-Token": token})
            status_ok = status.status_code == 200
            print(f"    status: HTTP {status.status_code} (owner-token gated)")
        except Exception as e:
            print(f"    status check failed (continuing to cleanup): {e!r}")
        finally:
            rev = await http.delete(f"/v1/tunnel/{tunnel_id}", headers={"X-Tunnel-Token": token})
            revoke_ok = rev.status_code in (200, 404)
            print(f"    cleanup revoke: HTTP {rev.status_code}")
    if not revoke_ok:
        # A failed cleanup leaves a paid tunnel live with its printed token; fail
        # the canary so automation notices and remediates the leaked lease.
        print("    !! tunnel cleanup revoke failed — leaked lease; FAILING.")
    return status_ok and revoke_ok


async def _create_quote(order_payload: dict) -> str | None:
    """POST /v1/vm/quote (free) and return the locked quote_id."""
    async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
        try:
            q = await http.post("/v1/vm/quote", json={"order_payload": order_payload})
        except Exception as e:
            print(f"    !! quote request failed: {e!r}")
            return None
    if q.status_code >= 400:
        print(f"    !! quote HTTP {q.status_code}: {q.text[:300]}")
        return None
    quote_id = q.json().get("quote_id")
    if not quote_id:
        print(f"    !! quote returned no quote_id: {q.text[:300]}")
        return None
    return quote_id


async def _run_domain(domain_name: str | None, network: str) -> bool:
    """Run the account-owned managed-domain contract end to end."""
    if not domain_name:
        sys.exit("ERROR: domain test needs --name <label> (registers <label>.dev for REAL money).")
    api_key = os.environ.get("HYRULE_API_KEY")
    if not api_key:
        sys.exit(
            "ERROR: set HYRULE_API_KEY to an account key with "
            "domain:purchase, domain:read, and domain:dns scopes."
        )
    fqdn = f"{domain_name}.dev"
    quote = await _create_domain_quote(fqdn)
    if quote is None:
        print("    !! no payable domain quote; refusing to sign blind. FAILING.")
        return False
    try:
        price = Decimal(str(quote["price"]["total_usd"]))
    except (KeyError, TypeError, ArithmeticError, ValueError):
        print("    !! domain quote has no valid total_usd; refusing to sign. FAILING.")
        return False
    ceiling = Decimal(TESTS["domain"]["usd"])
    if price > ceiling:
        print(
            f"    !! domain price ${price} exceeds the ${ceiling} canary ceiling; "
            "refusing to overspend. FAILING."
        )
        return False
    body = {
        "quote_id": quote["quote_id"],
        "payment_method": "usdc",
        "terms_version": quote["terms_version"],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Idempotency-Key": f"canary-domain-{quote['quote_id']}",
    }
    print(
        f"\n=== domain  POST /v1/domains/orders  (${price})  cap={_cap_units(str(price))} units ==="
    )
    print(f"    domain: {fqdn}  quote_id: {quote['quote_id']}")
    client = _client(str(price), network)
    async with x402HttpxClient(client, base_url=API, timeout=60.0) as http:
        try:
            response = await http.post("/v1/domains/orders", json=body, headers=headers)
        except Exception as e:
            print(f"    !! domain order failed: {e!r}")
            return False
    settled_ok, settlement = _settlement(response)
    print(f"    HTTP {response.status_code}   {settlement}")
    print(f"    body: {response.text[:600]}")
    if response.status_code >= 400 or not settled_ok:
        print("    !! domain order was not accepted with a successful settlement. FAILING.")
        return False
    order_id = response.json().get("order_id")
    if not order_id:
        print("    !! domain order response omitted order_id. FAILING.")
        return False
    return await _poll_domain_order(str(order_id), fqdn, api_key)


async def _poll_domain_order(order_id: str, fqdn: str, api_key: str) -> bool:
    """Wait for durable registrar/DNS fulfillment before mutating the zone."""
    headers = {"Authorization": f"Bearer {api_key}"}
    previous: str | None = None
    async with httpx.AsyncClient(base_url=API, timeout=30.0, headers=headers) as http:
        for attempt in range(120):  # up to ten minutes
            if attempt:
                await asyncio.sleep(5)
            try:
                response = await http.get(f"/v1/domains/orders/{order_id}")
            except Exception as e:
                print(f"    [{attempt}] order poll error: {e!r}")
                continue
            if response.status_code >= 400:
                print(
                    f"    [{attempt}] order poll HTTP {response.status_code}: {response.text[:200]}"
                )
                continue
            data = response.json()
            status = str(data.get("status") or "unknown")
            if status != previous:
                print(f"    [{attempt}] domain order status={status}")
                previous = status
            if status == "active":
                return await _write_domain_dns(fqdn, api_key)
            if status in {"refund_due", "refunded", "failed", "cancelled", "expired"}:
                print(
                    f"    !! domain order reached terminal status={status}: "
                    f"{data.get('error_code')}; FAILING."
                )
                return False
    print(
        "    !! domain order did not become active within ten minutes; "
        "leave it for reconciliation and do not repurchase. FAILING."
    )
    return False


async def _write_domain_dns(zone: str, api_key: str) -> bool:
    """Write one revision-checked AAAA RRset, then verify public DNS."""
    record = {
        "action": "upsert",
        "rrset": {
            "type": "AAAA",
            "name": "canary",
            "values": ["2a0c:b641:b50::1"],
            "ttl": 300,
        },
    }
    auth = {"Authorization": f"Bearer {api_key}"}
    print(f"    --- writing AAAA canary.{zone} -> {record['rrset']['values'][0]} ---")
    async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
        try:
            current = await http.get(f"/v1/domains/{zone}/dns", headers=auth)
            if current.status_code >= 400:
                print(f"    !! DNS read HTTP {current.status_code}: {current.text[:200]}")
                return False
            revision = current.json().get("revision")
            if not isinstance(revision, int):
                print("    !! DNS response omitted numeric revision. FAILING.")
                return False
            resp = await http.post(
                f"/v1/domains/{zone}/dns/changesets",
                json={"changes": [record]},
                headers={
                    **auth,
                    "If-Match": str(revision),
                    "Idempotency-Key": f"canary-dns-{zone}-{revision}",
                },
            )
        except Exception as e:
            print(f"    !! managed-DNS request failed: {e!r}")
            return False
    print(f"    DNS changeset -> HTTP {resp.status_code} {resp.text[:200]}")
    if resp.status_code >= 400:
        return False
    fqdn = f"canary.{zone}"
    expected = record["rrset"]["values"][0]
    print(f"    --- polling public DNS for {fqdn} AAAA {expected} ---")
    if await _resolve_aaaa(fqdn, expected, zone):
        print(f"    ✅ {fqdn} resolves to {expected}")
        return True
    # The Phase-3c gate requires public resolution, not just a 2xx write — a
    # broken delegation or propagation failure must fail the canary.
    print(
        f"    !! {fqdn} did not resolve to {expected} in time (delegation/propagation?); FAILING."
    )
    return False


async def _authoritative_aaaa(fqdn: str, zone: str):
    """AAAA values for ``fqdn`` seen by querying the zone's OWN nameservers
    directly. This bypasses recursive negative caches — a recursive resolver
    that cached NXDOMAIN before the domain was registered can outlast a short
    poll window, but the authoritative servers reflect the RFC2136 write at
    once (subject only to registry NS delegation being visible)."""
    import ipaddress

    import dns.asyncresolver

    found: set = set()
    try:
        ns_answer = await dns.asyncresolver.resolve(zone, "NS")
    except Exception:
        return found  # delegation not visible yet
    for ns in ns_answer:
        ns_host = str(ns.target).rstrip(".")
        ns_addrs: list[str] = []
        for rtype in ("AAAA", "A"):
            try:
                ns_addrs += [a.address for a in await dns.asyncresolver.resolve(ns_host, rtype)]
            except Exception:
                pass
        if not ns_addrs:
            continue
        direct = dns.asyncresolver.Resolver(configure=False)
        direct.nameservers = ns_addrs
        try:
            ans = await direct.resolve(fqdn, "AAAA")
            found |= {ipaddress.IPv6Address(a.address) for a in ans}
        except Exception:
            continue
    return found


async def _resolve_aaaa(
    fqdn: str, expected: str, zone: str, *, attempts: int = 20, delay: float = 15.0
) -> bool:
    """Poll public DNS until ``fqdn`` resolves to the expected AAAA, via the
    zone's authoritative nameservers AND the default recursive resolver. Returns
    True once seen, False after ~attempts*delay seconds.

    A freshly registered domain needs registry delegation plus recursive cache
    expiry, which routinely outlasts 60s; the default deadline here is ~5 min and
    the authoritative path avoids waiting on recursive negative-cache TTLs."""
    import ipaddress

    import dns.asyncresolver

    want = ipaddress.IPv6Address(expected)
    resolver = dns.asyncresolver.Resolver()
    for i in range(attempts):
        got: set = set()
        try:
            got |= {ipaddress.IPv6Address(a.address) for a in await resolver.resolve(fqdn, "AAAA")}
        except Exception as e:
            print(f"    [dns {i}] recursive {fqdn} AAAA not resolvable yet: {e}")
        got |= await _authoritative_aaaa(fqdn, zone)
        if got:
            print(f"    [dns {i}] {fqdn} AAAA -> {sorted(str(g) for g in got)}")
        if want in got:
            return True
        await asyncio.sleep(delay)
    return False


async def _poll_and_report_vm(create_resp: httpx.Response, *, destroy: bool, yes: bool) -> bool:
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
                # The status endpoint returns launch-proof fields FLAT (issue
                # #28). The VM reaching READY is not enough: real provisioning
                # can mark READY while the SSH smoke test or DNS AAAA check
                # failed. The Phase-3d gate only passes if both verify.
                dns_ok = bool(sj.get("dns_aaaa_verified"))
                ssh_smoke = sj.get("ssh_smoke_status")
                proof_ok = dns_ok and ssh_smoke == "passed"
                icon = "✅" if proof_ok else "⚠️"
                print(
                    f"\n    {icon} VM {st.upper()} — launch-proof: "
                    f"ssh_smoke_status={ssh_smoke} dns_aaaa_verified={dns_ok}"
                )
                print("       manually verify over IPv6:")
                print(f"        ssh root@{host or ipv6}")
                if mgmt_token:
                    print(f"        management: {API}/v1/vm/{vm_id}?token={mgmt_token}")
                    print(
                        f"        destroy:    curl -X DELETE {API}/v1/vm/{vm_id} "
                        f"-H 'Authorization: Bearer {mgmt_token}'"
                    )
                if not proof_ok:
                    print(
                        "    !! launch-proof did NOT verify (ssh smoke / DNS AAAA); FAILING gate."
                    )
                destroy_ok = await _maybe_destroy(poll, vm_id, mgmt_token, destroy=destroy, yes=yes)
                return proof_ok and destroy_ok
            if st in ("failed",):
                print(f"    ❌ provisioning FAILED: {json.dumps(sj)[:400]}")
                return False
    print("    ⏱ timed out waiting for the VM to become ready — check status_url manually.")
    return False


async def _maybe_destroy(
    poll: httpx.AsyncClient, vm_id: str, mgmt_token: str | None, *, destroy: bool, yes: bool
) -> bool:
    """Tear down the gate VM if requested. Pauses first (unless --yes) so the
    operator can run the manual SSH check, and treats a non-2xx DELETE as a
    failure — otherwise a billable VM is left running behind a 'passed' canary."""
    if not destroy:
        return True
    if not mgmt_token:
        print("    !! --destroy requested but no management_token — cannot tear down; FAILING.")
        return False
    if not yes:
        if not sys.stdin.isatty():
            # A non-interactive runner (CI/Ansible) can't answer the prompt;
            # skipping teardown would silently leak a billable VM behind a
            # "passed" gate. Require --yes for unattended teardown.
            print(
                "    !! --destroy from a non-interactive runner needs --yes to confirm "
                "teardown; refusing to leave a billable VM ambiguous. FAILING."
            )
            return False
        try:
            input(
                "\n    Press Enter to DESTROY the VM after you've verified SSH (Ctrl-C to keep it)... "
            )
        except (EOFError, KeyboardInterrupt):
            # Requested teardown was skipped — the paid VM is still running, so
            # the gate must not report success.
            print(
                "\n    destroy skipped by operator — the paid VM is still running; FAILING the gate."
            )
            return False
    d = await poll.request(
        "DELETE", f"{API}/v1/vm/{vm_id}", headers={"Authorization": f"Bearer {mgmt_token}"}
    )
    print(f"    destroy -> HTTP {d.status_code} {d.text[:200]}")
    if d.status_code >= 400:
        print("    !! destroy did NOT succeed — the paid VM may still be active/billable.")
        return False
    return True


def _select(target: str) -> list[str]:
    # `gated` tests (a de-advertised endpoint that 501s until configured) never
    # join a group/all sweep — they only run when named explicitly.
    if target == "all":  # non-spendy only
        return [n for n, t in TESTS.items() if not t.get("spendy") and not t.get("gated")]
    if target in {"intel", "proxy", "domain", "vm"}:
        return [n for n, t in TESTS.items() if t["group"] == target and not t.get("gated")]
    if target in TESTS:
        return [target]
    sys.exit(
        f"unknown test '{target}'. Try: list, all, intel, proxy, domain, vm, or one of "
        f"{', '.join(TESTS)}"
    )


async def _main() -> None:
    ap = argparse.ArgumentParser(description="x402 live-payment canary for Hyrule Cloud")
    ap.add_argument("target", help="a test name, a group (intel|proxy|domain|vm), 'all', or 'list'")
    ap.add_argument("--name", help="domain label to register (domain test)")
    ap.add_argument(
        "--destroy", action="store_true", help="destroy the VM after it comes up (vm test)"
    )
    ap.add_argument(
        "--quote",
        action="store_true",
        help="pay the vm create against a locked quote_id (POST /v1/vm/quote first)",
    )
    ap.add_argument(
        "--yes", action="store_true", help="skip the spend + destroy confirmation prompts"
    )
    ap.add_argument(
        "--network",
        default="eip155:8453",
        help="CAIP-2 chain to pay on (default Base mainnet); CANARY_KEY must be funded there",
    )
    args = ap.parse_args()

    if args.target == "list":
        print(f"API: {API}\n")
        print(f"{'name':14} {'price':>8}  path")
        for n, t in TESTS.items():
            flags = "".join(
                [
                    "  [REAL $]" if t.get("spendy") else "",
                    "  [gated: run by name only]" if t.get("gated") else "",
                ]
            )
            print(f"{n:14} {'$' + t['usd']:>8}  {t['path']}{flags}")
        return

    names = _select(args.target)
    # Fail fast BEFORE any paid provisioning: an unattended --destroy without
    # --yes can't answer the teardown prompt, so _maybe_destroy would refuse and
    # leave a billable VM running behind a failed gate. Reject up front instead.
    if args.destroy and not args.yes and not sys.stdin.isatty() and "vm" in names:
        sys.exit(
            "ERROR: --destroy from a non-interactive runner requires --yes; otherwise the "
            "canary would provision a billable VM and then refuse to tear it down. "
            "Aborting before any spend."
        )
    total = sum(Decimal(TESTS[n]["usd"]) for n in names)
    spendy = [n for n in names if TESTS[n].get("spendy")]
    print(f"About to run {len(names)} canary payment(s) on {API}: {', '.join(names)}")
    print(f"Estimated total spend: ${total} (real USDC on {args.network})")
    if spendy:
        print(f"⚠  side-effecting / higher-cost: {', '.join(spendy)}")
    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted.")
            return

    ok = 0
    for n in names:
        if await _run_one(
            n,
            destroy=args.destroy,
            domain_name=args.name,
            use_quote=args.quote,
            yes=args.yes,
            network=args.network,
        ):
            ok += 1
    print(f"\n=== done: {ok}/{len(names)} succeeded ===")
    if ok != len(names):
        # Exit non-zero so a CI/Ansible/shell phase gate actually stops on
        # failure instead of treating a 0/N canary run as a pass.
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(_main())
