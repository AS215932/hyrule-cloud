# Zcash x402 v2 Binding Implementation Plan

This plan captures the original implementation direction for a custom x402 v2
Zcash network binding plus a Zcash-aware merchant-hosted facilitator/verifier.

The core caveat is architectural: shielded Zcash cannot be verified from a txid
alone by an arbitrary third party. A shielded transaction hides recipient and
amount from the public chain. A production implementation therefore needs either
merchant-side wallet scanning/viewing capability or a sender-provided payment
disclosure. That is the major difference from EVM and Solana x402 rails.

## Target MVP

The clean MVP flow is:

1. The resource server returns HTTP `402 Payment Required` with a ZEC invoice in
   `PAYMENT-REQUIRED`.
2. The client pays with a Zcash wallet.
3. The client retries the original request with `PAYMENT-SIGNATURE` containing
   the txid and invoice binding.
4. The facilitator verifies the payment by scanning the merchant wallet view or
   validating a transaction-specific disclosure.
5. The resource server returns the resource with `PAYMENT-RESPONSE`.

## Package Shape

```text
x402-zcash-core
  schemas
  constants
  CAIP network IDs
  zatoshi/ZEC conversion
  invoice binding helpers

x402-zcash-client
  fetch/axios wrapper
  zcashd RPC wallet adapter
  light-wallet adapter later

x402-zcash-facilitator
  /supported
  /verify
  /settle
  scanner/verifier
  invoice database

x402-zcash-middleware
  Express/Fastify/Go/Rust middleware for resource servers
```

For Hyrule Cloud, the MVP is implemented inside the existing FastAPI/x402 server
boundary rather than as separately published packages.

## Binding

Use the x402 `exact` scheme:

```json
{
  "scheme": "exact"
}
```

The x402 v2 `network` field uses CAIP-2. Zcash uses the BIP122 namespace with
the first 32 characters of the genesis block hash:

```ts
export const ZCASH_MAINNET = "bip122:00040fe8ec8471911baa1db1266ea15d";
export const ZCASH_TESTNET = "bip122:05a60a92d99d85997cce3b87616c089f";
```

Native ZEC is identified as:

```json
{
  "asset": "slip44:133"
}
```

For compatibility with x402 shapes that expect token-like strings, the catalog
can also expose display metadata such as `asset: "ZEC"` and `asset_id:
"slip44:133"`, but `slip44:133` is the canonical x402 asset identifier.

Amounts are represented in zatoshis:

```text
1 ZEC = 100,000,000 zatoshis
```

Never use floating point for ZEC amount conversion. Use `Decimal`, decimal
strings, fixed-precision libraries, or integer zatoshis.

## PaymentRequired Shape

The resource server creates a one-time invoice and returns a base64 JSON
`PAYMENT-REQUIRED` header with an accepted requirement similar to:

```json
{
  "x402Version": 2,
  "error": "PAYMENT-SIGNATURE header is required",
  "resource": {
    "url": "https://api.example.net/v1/report",
    "description": "One paid report",
    "mimeType": "application/json",
    "serviceName": "Example API"
  },
  "accepts": [
    {
      "scheme": "exact",
      "network": "bip122:00040fe8ec8471911baa1db1266ea15d",
      "amount": "50000",
      "asset": "slip44:133",
      "payTo": "u1...",
      "maxTimeoutSeconds": 180,
      "extra": {
        "assetName": "ZEC",
        "unit": "zatoshi",
        "decimals": 8,
        "pool": "orchard",
        "invoiceId": "inv_01J...",
        "memoHex": "783430323a696e765f30314a2e2e2e",
        "minConfirmations": 0,
        "broadcastMode": "client"
      }
    }
  ],
  "extensions": {
    "zcash": {
      "version": 1,
      "supportsShielded": true,
      "supportsTransparent": false,
      "requiresMemo": true
    }
  }
}
```

The `payTo` value should be a fresh Unified Address or an invoice-specific
receiver. The memo binds the on-chain output to the HTTP invoice. The first
version uses `broadcastMode: "client"` so clients broadcast through their own
wallets and send only the txid and invoice binding in HTTP headers.

## PaymentPayload Shape

The client retries the original request with a base64 JSON
`PAYMENT-SIGNATURE` header containing:

```json
{
  "x402Version": 2,
  "resource": {
    "url": "https://api.example.net/v1/report"
  },
  "accepted": {
    "scheme": "exact",
    "network": "bip122:00040fe8ec8471911baa1db1266ea15d",
    "amount": "50000",
    "asset": "slip44:133",
    "payTo": "u1...",
    "maxTimeoutSeconds": 180,
    "extra": {
      "invoiceId": "inv_01J...",
      "memoHex": "783430323a696e765f30314a2e2e2e",
      "broadcastMode": "client"
    }
  },
  "payload": {
    "txid": "f00d...",
    "invoiceId": "inv_01J...",
    "paymentDisclosure": null
  }
}
```

For shielded payments, the txid is not sufficient for public verification. The
verifier must either have wallet visibility into the recipient side or the
client must provide a valid payment disclosure.

## Facilitator Behavior

### `/supported`

The facilitator advertises native ZEC support on Zcash mainnet/testnet:

```json
{
  "kinds": [
    {
      "scheme": "exact",
      "network": "bip122:00040fe8ec8471911baa1db1266ea15d",
      "asset": "slip44:133",
      "extra": {
        "assetName": "ZEC",
        "unit": "zatoshi",
        "decimals": 8,
        "modes": ["client-broadcast"],
        "pools": ["orchard"]
      }
    }
  ]
}
```

If the concrete x402 SDK schema does not support top-level `asset` on
`SupportedKind`, carry the canonical asset identifier in `extra`.

### `/verify`

Verification checks:

```text
accepted.scheme == "exact"
accepted.network == invoice.network
accepted.asset == "slip44:133"
accepted.amount == invoice.amountZat
accepted.payTo == invoice.payTo
payload.invoiceId == invoice.id
invoice has not expired
invoice has not already been paid by a different txid
txid is wallet-visible
transaction has a matching output
output address == invoice payTo
output valueZat == invoice amount
output memo == invoice memo
confirmations >= invoice minConfirmations
```

For a `zcashd` merchant wallet, use `z_viewtransaction(txid)` and inspect
wallet-visible shielded outputs. This intentionally relies on merchant-side
receive visibility instead of pretending that a public txid reveals shielded
recipient and amount.

### `/settle`

In client-broadcast mode, `/settle` does not broadcast a transaction. It
finalizes the invoice after verification and returns:

```json
{
  "success": true,
  "transaction": "f00d...",
  "network": "bip122:00040fe8ec8471911baa1db1266ea15d",
  "payer": null,
  "amount": "50000"
}
```

A later facilitator-broadcast mode can accept a signed raw transaction or a
payload reference and call `sendrawtransaction`, but raw shielded transactions
should not be placed directly in `PAYMENT-SIGNATURE` headers in production.

## Client Spending Flow

For a `zcashd`-backed client:

1. Make the original HTTP request.
2. Receive `402` and decode `PAYMENT-REQUIRED`.
3. Select the Zcash payment requirement.
4. Use `z_sendmany` to send exact ZEC to the Unified Address.
5. Include the invoice memo.
6. Poll `z_getoperationstatus` until the wallet returns a txid.
7. Retry the HTTP request with `PAYMENT-SIGNATURE`.

Example shape:

```ts
async function payWithZcashd(req: PaymentRequirements) {
  const amountZec = zatoshisToZecDecimalString(BigInt(req.amount));

  const opid = await zcashRpc.z_sendmany(
    "fromAccountOrAddress",
    [
      {
        address: req.payTo,
        amount: amountZec,
        memo: req.extra.memoHex
      }
    ],
    1,
    null,
    "AllowRevealedRecipients",
    null
  );

  const txid = await pollOperationForTxid(opid);

  return {
    x402Version: 2,
    accepted: req,
    payload: {
      txid,
      invoiceId: req.extra.invoiceId
    }
  };
}
```

Prefer fully shielded policy when wallet support, source funds, and recipient
type allow it.

## Verification Models

The first version should be merchant-hosted:

```text
resource server
facilitator/verifier
zcashd or wallet scanner
invoice DB
```

A third-party facilitator needs one of:

```text
1. incoming viewing key / unified incoming viewing key
2. payment disclosure from sender
3. transparent address only
4. merchant-side callback proving receipt
```

Viewing keys leak ongoing receive-side visibility to the facilitator. Payment
disclosure is narrower but requires robust wallet/protocol support. Transparent
mode is easier to verify from public chain data, but it weakens the main privacy
benefit of Zcash and should be treated as a compatibility/test harness.

## Settlement Latency

Zcash is not instant-finality. Recommended policy:

```text
small API call, low abuse risk:
  minConfirmations = 0
  rate-limit payer/IP/API key
  mark as provisional
  revoke future access if payment disappears

larger purchase:
  minConfirmations = 1+

high-value purchase:
  minConfirmations = N
  return 202/pending or ask client to retry later
```

## Fee Handling

Do not hardcode arbitrary Zcash fees. Let `zcashd` choose fees for the MVP,
which tracks the conventional ZIP-317-style fee behavior in modern wallets.

## Replay Protection And Invoice Binding

Use all of:

```text
invoiceId
fresh payTo receiver/address
exact amount
memo commitment
resource URL
expiration
single-use DB constraint
txid uniqueness
```

Memo payload:

```json
{
  "proto": "x402-zcash",
  "v": 1,
  "invoice": "inv_01J...",
  "resourceHash": "sha256:...",
  "amountZat": "50000",
  "merchant": "example.net"
}
```

Database constraints:

```sql
create unique index invoices_invoice_id_uq on invoices(invoice_id);
create unique index payments_txid_uq on payments(txid);
create unique index payments_invoice_id_uq on payments(invoice_id);
```

## Resource Server Middleware

Conceptually:

```ts
app.get("/v1/report", async (req, res) => {
  const paymentHeader = req.header("PAYMENT-SIGNATURE");

  if (!paymentHeader) {
    const invoice = await invoices.create({
      resourceUrl: "https://api.example.net/v1/report",
      amountZat: 50_000n,
      asset: "slip44:133",
      network: ZCASH_MAINNET
    });

    const required = buildPaymentRequired(invoice);

    res
      .status(402)
      .set("PAYMENT-REQUIRED", base64Json(required))
      .json({ error: "payment_required" });

    return;
  }

  const payment = parseBase64Json(paymentHeader);
  const verify = await facilitator.verify(payment);

  if (!verify.isValid) {
    res
      .status(402)
      .set("PAYMENT-REQUIRED", base64Json(await rebuildRequirement(payment)))
      .json({ error: verify.invalidReason });

    return;
  }

  const settlement = await facilitator.settle(payment);

  res
    .status(200)
    .set("PAYMENT-RESPONSE", base64Json(settlement))
    .json(await buildReport());
});
```

## MVP Build Order

Start with Zcash testnet, client-broadcast, shielded receive, and a
merchant-hosted verifier.

```text
Phase 1
  x402 HTTP middleware
  invoice DB
  static ZEC amount
  testnet Unified Address
  zcashd client wallet using z_sendmany
  verifier using z_viewtransaction
  1 confirmation required

Phase 2
  0-conf provisional mode
  memo binding
  per-invoice addresses/receivers
  replay protection
  PAYMENT-RESPONSE settlement receipts

Phase 3
  Orchard-only policy
  light wallet support
  payment disclosure support
  third-party facilitator mode

Phase 4
  batching / delayed settlement
  refund handling
  production monitoring
  multi-merchant facilitator
```

First production target:

```text
network: Zcash mainnet
scheme: exact
asset: slip44:133
amount unit: zatoshi
recipient: Unified Address, preferably Orchard-capable
mode: client-broadcast
verifier: merchant-hosted scanner
default confirmations: 1 for paid API access, 0 only for low-risk usage
```
