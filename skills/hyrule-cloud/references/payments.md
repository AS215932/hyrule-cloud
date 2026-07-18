# x402 v2 payment and spend controls

Use the official x402 Python client. It reads `Payment-Required`, creates the
payment payload, sends `Payment-Signature`, and retries the same request.

```python
import os
from decimal import Decimal

from eth_account import Account
from x402 import max_amount, x402Client
from x402.http.clients import wrapHttpxWithPayment
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner

account = Account.from_key(os.environ["EVM_PRIVATE_KEY"])
payments = x402Client()
register_exact_evm_client(payments, EthAccountSigner(account))

# USDC uses six atomic decimal places. Keep the limit operator-owned.
max_usd = Decimal(os.environ.get("HYRULE_MAX_PAYMENT_USD", "0.10"))
payments.register_policy(max_amount(int(max_usd * 1_000_000)))

async with wrapHttpxWithPayment(
    payments,
    base_url="https://cloud.hyrule.host",
    timeout=60,
) as client:
    response = await client.post("/path/from-live-manifest", json={})
    response.raise_for_status()
```

Before automatic payment, enforce all of these outside the model:

- exact allowed origin (`https://cloud.hyrule.host` by default);
- path allowlist resolved from the live manifest;
- per-payment maximum in atomic asset units;
- daily aggregate budget with a durable local ledger;
- wallet secret supplied only through the runtime secret store;
- no automatic VM/domain/destructive operation unless separately enabled.

Never paste a private key or signed payment payload into a prompt, skill,
trace, log, action proposal, or approval record.
