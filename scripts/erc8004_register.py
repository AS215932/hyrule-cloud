#!/usr/bin/env python3
"""One-shot ERC-8004 Identity Registry registration for Hyrule Cloud.

Registers (or updates) the Hyrule Cloud Provisioning Agent on an ERC-8004
IdentityRegistry via raw JSON-RPC + eth-account — deliberately NOT a
runtime dependency of the API: registration is a human ceremony (see
docs/runbooks/trust-keys.md), and the app itself never talks to a chain.

Spec pin (verified 2026-07-10 against the Draft EIP, created 2025-08-13):
  - register(string agentURI) -> uint256 agentId      selector 0xf2c298be
  - setAgentURI(uint256 agentId, string newURI)
  - event Registered(uint256 indexed agentId, string agentURI, address indexed owner)
  - registration document served at /.well-known/agent-registration.json
Official deployments (github.com/erc-8004/erc-8004-contracts, no tagged
release — re-verify before mainnet):
  - Base Sepolia  IdentityRegistry 0x8004A818BFB912233c491871b3d84c89A494BD9e
  - Base mainnet  IdentityRegistry 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432

Usage:
  # Fresh registration (Base Sepolia first!):
  ERC8004_OWNER_KEY=0x... python scripts/erc8004_register.py \
      --rpc-url https://sepolia.base.org \
      --registry 0x8004A818BFB912233c491871b3d84c89A494BD9e

  # Update the agentURI of an existing registration:
  ERC8004_OWNER_KEY=0x... python scripts/erc8004_register.py \
      --rpc-url ... --registry 0x... --set-uri --agent-id 42

Afterwards set (Vault kv/hyrule-cloud in production):
  TRUST_AGENT_CARD_ENABLED=true
  TRUST_ERC8004_REGISTRY_CAIP10=eip155:<chainId>:<registry>
  TRUST_ERC8004_AGENT_ID=<agentId>
  TRUST_ERC8004_OWNER_ADDRESS=<owner>
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any

import httpx
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import keccak

DEFAULT_AGENT_URI = "https://cloud.hyrule.host/.well-known/agent-registration.json"

REGISTER_SELECTOR = keccak(b"register(string)")[:4]
SET_URI_SELECTOR = keccak(b"setAgentURI(uint256,string)")[:4]
REGISTERED_TOPIC = "0x" + keccak(b"Registered(uint256,string,address)").hex()
URI_UPDATED_TOPIC = "0x" + keccak(b"URIUpdated(uint256,string,address)").hex()
METADATA_SET_TOPIC = "0x" + keccak(b"MetadataSet(uint256,string,string,bytes)").hex()
TRANSFER_TOPIC = "0x" + keccak(b"Transfer(address,address,uint256)").hex()


class RPC:
    def __init__(self, url: str) -> None:
        self.url = url
        self._id = 0
        self._http = httpx.Client(timeout=30.0)

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        resp = self._http.post(
            self.url,
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params},
        )
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"{method} failed: {body['error']}")
        return body["result"]


def _send_tx(rpc: RPC, account: Any, to: str, data: bytes, *, dry_run: bool) -> str | None:
    chain_id = int(rpc.call("eth_chainId", []), 16)
    nonce = int(rpc.call("eth_getTransactionCount", [account.address, "pending"]), 16)
    gas_price = int(rpc.call("eth_gasPrice", []), 16)
    tx: dict[str, Any] = {
        "from": account.address,
        "to": to,
        "data": "0x" + data.hex(),
        "value": "0x0",
    }
    gas = int(rpc.call("eth_estimateGas", [tx]), 16)
    signed = account.sign_transaction(
        {
            "chainId": chain_id,
            "nonce": nonce,
            "to": to,
            "value": 0,
            "data": data,
            "gas": int(gas * 1.2),
            "gasPrice": gas_price,
        }
    )
    print(f"  chainId={chain_id} nonce={nonce} gas={gas} gasPrice={gas_price}")
    if dry_run:
        print("  --dry-run: not broadcasting.")
        return None
    tx_hash = rpc.call("eth_sendRawTransaction", ["0x" + bytes(signed.raw_transaction).hex()])
    print(f"  broadcast: {tx_hash}")
    return str(tx_hash)


def _wait_receipt(rpc: RPC, tx_hash: str, timeout: float = 120.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = rpc.call("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return dict(receipt)
        time.sleep(3)
    raise TimeoutError(f"no receipt for {tx_hash} within {timeout}s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rpc-url", required=True, help="EVM JSON-RPC endpoint")
    parser.add_argument("--registry", required=True, help="IdentityRegistry address (0x...)")
    parser.add_argument("--agent-uri", default=DEFAULT_AGENT_URI)
    parser.add_argument(
        "--private-key-env",
        default="ERC8004_OWNER_KEY",
        help="Env var holding the OWNER key (org-controlled; NOT the receipt signer)",
    )
    parser.add_argument("--set-uri", action="store_true", help="Update instead of register")
    parser.add_argument("--agent-id", type=int, help="Existing agentId (required with --set-uri)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    key = os.environ.get(args.private_key_env, "")
    if not key:
        print(f"ERROR: set {args.private_key_env} to the registry owner private key.")
        return 2
    account = Account.from_key(key)
    rpc = RPC(args.rpc_url)
    chain_id = int(rpc.call("eth_chainId", []), 16)
    caip10 = f"eip155:{chain_id}:{args.registry}"
    print(f"owner:    {account.address}")
    print(f"registry: {caip10}")
    print(f"agentURI: {args.agent_uri}")

    if args.set_uri:
        if args.agent_id is None:
            print("ERROR: --set-uri requires --agent-id.")
            return 2
        data = SET_URI_SELECTOR + abi_encode(["uint256", "string"], [args.agent_id, args.agent_uri])
        tx_hash = _send_tx(rpc, account, args.registry, data, dry_run=args.dry_run)
        if tx_hash:
            receipt = _wait_receipt(rpc, tx_hash)
            print(f"  status: {receipt.get('status')}")
        agent_id: int | None = args.agent_id
    else:
        data = REGISTER_SELECTOR + abi_encode(["string"], [args.agent_uri])
        tx_hash = _send_tx(rpc, account, args.registry, data, dry_run=args.dry_run)
        agent_id = None
        if tx_hash:
            receipt = _wait_receipt(rpc, tx_hash)
            print(f"  status: {receipt.get('status')}")
            for entry in receipt.get("logs", []):
                topics = entry.get("topics", [])
                if topics and topics[0].lower() == REGISTERED_TOPIC:
                    agent_id = int(topics[1], 16)
            if agent_id is None:
                print("WARNING: no Registered event found in the receipt logs.")

    print("\nNext steps:")
    if agent_id is not None:
        print("  TRUST_AGENT_CARD_ENABLED=true")
        print(f"  TRUST_ERC8004_REGISTRY_CAIP10={caip10}")
        print(f"  TRUST_ERC8004_AGENT_ID={agent_id}")
        print(f"  TRUST_ERC8004_OWNER_ADDRESS={account.address}")
    print(
        "\nOps monitoring (network-operations repo): watch for unexpected "
        "ownership/URI changes with eth_getLogs, e.g.\n"
        f'  {{"address": "{args.registry}", "fromBlock": "<deploy>",\n'
        f'   "topics": [[{REGISTERED_TOPIC!r}, {URI_UPDATED_TOPIC!r},\n'
        f"              {METADATA_SET_TOPIC!r}, {TRANSFER_TOPIC!r}]]}}\n"
        "Disable trust-dependent behavior if an unexpected Transfer or "
        "URIUpdated appears (see docs/runbooks/trust-keys.md)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
