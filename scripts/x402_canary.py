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
    "dns":       {"path": "/v1/dns/lookup",  "body": {"name": "example.com", "type": "AAAA"}, "usd": "0.001", "group": "intel"},
    "ip":        {"path": "/v1/ip/lookup",   "body": {"address": "2a0c:b641:b50::1"}, "usd": "0.003", "group": "intel"},
    "bgp":       {"path": "/v1/bgp/lookup",  "body": {"subject": {"type": "prefix", "value": "2a0c:b641:b50::/44"}}, "usd": "0.005", "group": "intel"},
    "rdap":      {"path": "/v1/rdap/lookup", "body": {"subject": {"type": "domain", "value": "example.com"}}, "usd": "0.003", "group": "intel"},
    "whois":     {"path": "/v1/whois/lookup","body": {"subject": {"type": "domain", "value": "example.com"}}, "usd": "0.005", "group": "intel"},
    "web":       {"path": "/v1/web/check",   "body": {"target": "https://example.com"}, "usd": "0.005", "group": "intel"},
    "web-tls":   {"path": "/v1/web/tls/deep","body": {"host": "example.com"}, "usd": "0.10", "group": "intel"},
    "mx":        {"path": "/v1/mx/check",    "body": {"tool": "mx", "target": "example.com"}, "usd": "0.005", "group": "intel"},
    "path":      {"path": "/v1/path/ping",   "body": {"target": "example.com", "vantages": ["extmon", "as215932", "globalping"]}, "usd": "0.005", "group": "intel"},
    # /v1/path/report (Phase-3a path evidence) uses the endpoint's default
    # vantage set so it actually probes once a vantage (Globalping/RIPE Atlas) is
    # configured. Until then it returns 501 before charging (PR #42), which the
    # sweep treats as "not launched yet, skipped" rather than a failure — so the
    # runbook's required paid /v1/path/report call is validated the moment a
    # prober goes live, without failing the pre-launch sweep.
    "path-report": {"path": "/v1/path/report", "body": {"target": "example.com", "vantages": ["extmon", "as215932", "globalping"], "checks": ["ping", "traceroute"]}, "usd": "0.05", "group": "intel"},
    "ports":     {"path": "/v1/ports/check", "body": {"target": "example.com", "port": 443}, "usd": "0.003", "group": "intel"},
    "nat":       {"path": "/v1/nat/lookup",  "body": {"customer_reported_wan_ip": "100.64.1.1"}, "usd": "0.003", "group": "intel"},
    "threat":    {"path": "/v1/threat/lookup","body": {"subject": {"type": "domain", "value": "example.com"}}, "usd": "0.01", "group": "intel"},
    "voip":      {"path": "/v1/voip/check",  "body": {"target": "sip.example.com"}, "usd": "0.01", "group": "intel"},
    "voipnum":   {"path": "/v1/voip/number/lookup", "body": {"number": "+31201234567"}, "usd": "0.05", "group": "intel"},
    # --- 3b network proxy ---
    "proxy-direct": {"path": "/v1/network/request", "body": {"url": "https://example.com", "method": "GET", "proxy_mode": "direct"}, "usd": "0.01", "group": "proxy"},
    "proxy-tor":    {"path": "/v1/network/request", "body": {"url": "https://example.com", "method": "GET", "proxy_mode": "tor"}, "usd": "0.05", "group": "proxy"},
    # --- 3c domain (REAL registration, side effects) ---
    # /v1/domain/register prices dynamically from Openprovider at request time
    # (registrar fee + markup, ~$10 fallback), so the cap is set generously; the
    # operator still confirms the actual spend interactively before it runs.
    "domain":    {"path": "/v1/domain/register", "body": {"name": None, "extension": "dev", "duration_years": 1}, "usd": "15.00", "group": "domain", "spendy": True},
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
    # Pin to Base mainnet (eip155:8453) + a per-call max-amount guardrail. The
    # canary key is Base-funded; without the network pin the SDK would sign for
    # whatever EVM chain the API advertises first (e.g. Polygon/Arbitrum if CDP
    # enables them before Base), causing a false failure or wrong-chain spend.
    register_exact_evm_client(
        client, signer, networks="eip155:8453", policies=[max_amount(_cap_units(usd))]
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


async def _receipt_check(resp: httpx.Response) -> bool:
    """Verify the trust receipt advertised by a paid response, if any.

    Advisory when the server has receipts disabled (no HYRULE-RECEIPT header
    → note and pass). When a header IS present, the receipt must fetch and
    BOTH signatures must verify offline — a served-but-unverifiable receipt
    is a trust-layer regression and fails the canary.
    """
    receipt_id = resp.headers.get("hyrule-receipt") or resp.headers.get("x-hyrule-receipt")
    if not receipt_id:
        print("    receipt: none (trust receipts disabled on server)")
        return True
    try:
        from hyrule_cloud.trust.receipts import recover_receipt_signer, verify_receipt_jws

        async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
            body = (await http.get(f"/v1/receipts/{receipt_id}")).raise_for_status().json()
            jwks = (await http.get("/.well-known/jwks.json")).raise_for_status().json()
        # Verify against every served key until one matches the JWS kid.
        payload = None
        last_error: Exception | None = None
        for key in jwks.get("keys", []):
            try:
                payload = verify_receipt_jws(body["jws"], key)
                break
            except Exception as e:  # try the next (retired) key
                last_error = e
        if payload is None:
            print(f"    !! receipt {receipt_id}: JWS verified against NO served key: {last_error}")
            return False
        if payload != body["payload"]:
            print(f"    !! receipt {receipt_id}: JWS payload != served payload")
            return False
        signer = recover_receipt_signer(body["payload"], body["evm_signature"])
        if signer != body["evm_signer"]:
            print(f"    !! receipt {receipt_id}: EIP-712 signer mismatch ({signer})")
            return False
        print(f"    receipt: {receipt_id} verified (JWS + EIP-712 by {signer})")
        return True
    except Exception as e:
        print(f"    !! receipt {receipt_id}: verification errored: {e!r}")
        return False


async def _domain_check_price(name: str, extension: str) -> Decimal | None:
    """GET /v1/domain/check (free) for the REAL registration price, so the
    payment cap tracks the actual quote instead of a generous static guess.
    Returns the total (registrar + markup) USD when available, else None."""
    async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
        try:
            r = await http.get("/v1/domain/check", params={"name": name, "extension": extension})
        except Exception as e:
            print(f"    !! /v1/domain/check failed: {e!r}")
            return None
    if r.status_code >= 400:
        print(f"    !! /v1/domain/check HTTP {r.status_code} {r.text[:200]}")
        return None
    data = r.json()
    if not data.get("available"):
        print(f"    !! {name}.{extension} is not available for registration.")
        return None
    total = data.get("total") or data.get("price")
    if total is None:
        print("    !! /v1/domain/check returned no price to cap against.")
        return None
    try:
        return Decimal(str(total))
    except (ArithmeticError, ValueError):
        return None


async def _run_one(name: str, *, destroy: bool, domain_name: str | None, use_quote: bool, yes: bool) -> bool:
    t = TESTS[name]
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
    if name == "domain":
        if not domain_name:
            sys.exit("ERROR: domain test needs --name <label> (registers <label>.dev for REAL money).")
        body["name"] = domain_name
        # /v1/domain/register is dynamically priced, so cap on the ACTUAL quote
        # from /v1/domain/check rather than a static guess — otherwise a
        # malformed/higher registrar price could still be auto-signed up to the
        # generous static cap.
        extension = body.get("extension", "dev")
        price = await _domain_check_price(domain_name, extension)
        if price is None:
            print("    !! /v1/domain/check gave no available price; refusing to sign blind. FAILING.")
            return False
        ceiling = Decimal(t["usd"])
        if price > ceiling:
            print(f"    !! domain price ${price} exceeds the ${ceiling} canary ceiling; "
                  "refusing to overspend. FAILING.")
            return False
        cap_usd = str(price)
        print(f"    /v1/domain/check price: ${price} (cap set to this, not the ${ceiling} default)")

    print(f"\n=== {name}  POST {t['path']}  (~${cap_usd})  cap={_cap_units(cap_usd)} units ===")
    if quote_id:
        print(f"    quote_id: {quote_id}")
    print(f"    body: {json.dumps(body)}")
    client = _client(cap_usd)
    async with x402HttpxClient(client, base_url=API, timeout=60.0) as http:
        try:
            r = await http.post(t["path"], json=body)
        except Exception as e:
            print(f"    !! request failed: {e!r}")
            return False
    settled_ok, settle_detail = _settlement(r)
    print(f"    HTTP {r.status_code}   {settle_detail}")
    text = r.text
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
    if not await _receipt_check(r):
        return False

    if name == "vm":
        # The 202 only means the create was accepted + charged; the Phase-3d
        # gate isn't passed until the VM reaches ready AND its launch-proof
        # (SSH smoke + DNS AAAA) verifies. Propagate that.
        return await _poll_and_report_vm(r, destroy=destroy, yes=yes)
    if name == "domain":
        # Phase-3c gate is register -> zone-record write -> public resolve.
        return await _zone_write_after_register(r, domain_name)
    return True


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


async def _zone_write_after_register(reg_resp: httpx.Response, domain_name: str | None) -> bool:
    """After a real registration, write one AAAA record and poll public DNS
    until it resolves — the full Phase-3c gate (register -> zone write -> public
    resolution). Returns False if the record never resolves."""
    data = reg_resp.json()
    zone = data.get("domain") or (f"{domain_name}.dev" if domain_name else None)
    token = data.get("management_token")
    if not zone or not token:
        print("    !! registration response lacked domain/management_token — cannot write zone record.")
        return False
    record = {"type": "AAAA", "name": "canary", "value": "2a0c:b641:b50::1", "ttl": 300}
    print(f"    --- writing AAAA canary.{zone} -> {record['value']} ---")
    async with httpx.AsyncClient(base_url=API, timeout=30.0) as http:
        try:
            resp = await http.post(
                "/v1/zone/record",
                params={"zone": zone},
                json=record,
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception as e:
            print(f"    !! zone-record request failed: {e!r}")
            return False
    print(f"    zone-record -> HTTP {resp.status_code} {resp.text[:200]}")
    if resp.status_code >= 400:
        return False
    fqdn = f"canary.{zone}"
    print(f"    --- polling public DNS for {fqdn} AAAA {record['value']} ---")
    if await _resolve_aaaa(fqdn, record["value"], zone):
        print(f"    ✅ {fqdn} resolves to {record['value']}")
        return True
    # The Phase-3c gate requires public resolution, not just a 2xx write — a
    # broken delegation or propagation failure must fail the canary.
    print(f"    !! {fqdn} did not resolve to {record['value']} in time "
          "(delegation/propagation?); FAILING.")
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
                print(f"\n    {icon} VM {st.upper()} — launch-proof: "
                      f"ssh_smoke_status={ssh_smoke} dns_aaaa_verified={dns_ok}")
                print("       manually verify over IPv6:")
                print(f"        ssh root@{host or ipv6}")
                if mgmt_token:
                    print(f"        management: {API}/v1/vm/{vm_id}?token={mgmt_token}")
                    print(f"        destroy:    curl -X DELETE {API}/v1/vm/{vm_id} "
                          f"-H 'Authorization: Bearer {mgmt_token}'")
                if not proof_ok:
                    print("    !! launch-proof did NOT verify (ssh smoke / DNS AAAA); FAILING gate.")
                destroy_ok = await _maybe_destroy(poll, vm_id, mgmt_token, destroy=destroy, yes=yes)
                return proof_ok and destroy_ok
            if st in ("failed",):
                print(f"    ❌ provisioning FAILED: {json.dumps(sj)[:400]}")
                return False
    print("    ⏱ timed out waiting for the VM to become ready — check status_url manually.")
    return False


async def _maybe_destroy(poll: httpx.AsyncClient, vm_id: str, mgmt_token: str | None, *, destroy: bool, yes: bool) -> bool:
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
            print("    !! --destroy from a non-interactive runner needs --yes to confirm "
                  "teardown; refusing to leave a billable VM ambiguous. FAILING.")
            return False
        try:
            input("\n    Press Enter to DESTROY the VM after you've verified SSH (Ctrl-C to keep it)... ")
        except (EOFError, KeyboardInterrupt):
            # Requested teardown was skipped — the paid VM is still running, so
            # the gate must not report success.
            print("\n    destroy skipped by operator — the paid VM is still running; FAILING the gate.")
            return False
    d = await poll.request("DELETE", f"{API}/v1/vm/{vm_id}",
                           headers={"Authorization": f"Bearer {mgmt_token}"})
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
    sys.exit(f"unknown test '{target}'. Try: list, all, intel, proxy, domain, vm, or one of "
             f"{', '.join(TESTS)}")


async def _main() -> None:
    ap = argparse.ArgumentParser(description="x402 live-payment canary for Hyrule Cloud")
    ap.add_argument("target", help="a test name, a group (intel|proxy|domain|vm), 'all', or 'list'")
    ap.add_argument("--name", help="domain label to register (domain test)")
    ap.add_argument("--destroy", action="store_true", help="destroy the VM after it comes up (vm test)")
    ap.add_argument("--quote", action="store_true", help="pay the vm create against a locked quote_id (POST /v1/vm/quote first)")
    ap.add_argument("--yes", action="store_true", help="skip the spend + destroy confirmation prompts")
    args = ap.parse_args()

    if args.target == "list":
        print(f"API: {API}\n")
        print(f"{'name':14} {'price':>8}  path")
        for n, t in TESTS.items():
            flags = "".join([
                "  [REAL $]" if t.get("spendy") else "",
                "  [gated: run by name only]" if t.get("gated") else "",
            ])
            print(f"{n:14} {'$'+t['usd']:>8}  {t['path']}{flags}")
        return

    names = _select(args.target)
    # Fail fast BEFORE any paid provisioning: an unattended --destroy without
    # --yes can't answer the teardown prompt, so _maybe_destroy would refuse and
    # leave a billable VM running behind a failed gate. Reject up front instead.
    if args.destroy and not args.yes and not sys.stdin.isatty() and "vm" in names:
        sys.exit("ERROR: --destroy from a non-interactive runner requires --yes; otherwise the "
                 "canary would provision a billable VM and then refuse to tear it down. "
                 "Aborting before any spend.")
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
        if await _run_one(n, destroy=args.destroy, domain_name=args.name, use_quote=args.quote, yes=args.yes):
            ok += 1
    print(f"\n=== done: {ok}/{len(names)} succeeded ===")
    if ok != len(names):
        # Exit non-zero so a CI/Ansible/shell phase gate actually stops on
        # failure instead of treating a 0/N canary run as a pass.
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(_main())
