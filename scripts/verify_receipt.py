#!/usr/bin/env python3
"""Offline verifier for x402 Compute Fulfillment Receipts.

The customer-facing walkthrough (docs/x402-compute-fulfillment-receipt.md):
fetch a receipt + the service's JWKS, then verify BOTH signatures locally —
the ES256 JWS against a served key, and the EIP-712 signature by recovering
the signer from sha256 of the canonical payload bytes.

Usage:
  python scripts/verify_receipt.py https://cloud.hyrule.host/v1/receipts/hyr_rcpt_...
  python scripts/verify_receipt.py hyr_rcpt_... --base-url https://cloud.hyrule.host

Exit codes: 0 verified, 1 verification failed, 2 usage/fetch error.
"""

from __future__ import annotations

import argparse
import json
import sys

import httpx

from hyrule_cloud.trust.receipts import recover_receipt_signer, verify_receipt_jws


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", help="Receipt URL or bare hyr_rcpt_... id")
    parser.add_argument("--base-url", default="https://cloud.hyrule.host")
    args = parser.parse_args()

    url = args.receipt
    if not url.startswith("http"):
        url = f"{args.base_url.rstrip('/')}/v1/receipts/{args.receipt}"

    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as http:
            body = http.get(url).raise_for_status().json()
            # Fetch the JWKS from the SAME origin the receipt came from —
            # the advertised jwks_url names the canonical public origin,
            # which differs when verifying against staging/local.
            receipt_origin = httpx.URL(url)
            jwks_path = httpx.URL(body["jwks_url"]).path
            same_origin = str(receipt_origin.copy_with(path=jwks_path, query=None))
            try:
                jwks = http.get(same_origin).raise_for_status().json()
            except Exception:
                jwks = http.get(body["jwks_url"]).raise_for_status().json()
    except Exception as exc:
        print(f"fetch failed: {exc}")
        return 2

    payload = body["payload"]
    print(f"receipt:  {body['receipt_id']}")
    print(f"kind:     {payload['kind']}  outcome: {payload['outcome']['status']}")
    print(f"resource: {payload['resource']['method']} {payload['resource']['path']}")
    print(f"payment:  {payload['payment']['rail']}  ${payload['payment'].get('amount_usd')}")

    verified_jws = None
    for key in jwks.get("keys", []):
        try:
            verified_jws = verify_receipt_jws(body["jws"], key)
            print(f"JWS:      OK (kid {key.get('kid')})")
            break
        except Exception:
            continue
    if verified_jws is None:
        print("JWS:      FAILED — no served key verifies this receipt")
        return 1
    if verified_jws != payload:
        print("JWS:      FAILED — signed payload differs from the served payload")
        return 1

    if body.get("evm_signature") and body.get("evm_signer"):
        signer = recover_receipt_signer(payload, body["evm_signature"])
        if signer != body["evm_signer"]:
            print(f"EIP-712:  FAILED — recovered {signer}, expected {body['evm_signer']}")
            return 1
        print(f"EIP-712:  OK (signer {signer})")
    else:
        print("EIP-712:  absent")

    print("\nVERIFIED. Signed payload:")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
