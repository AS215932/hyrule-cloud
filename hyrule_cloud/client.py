"""
Thin async Python client for the Hyrule Cloud API.

Install (not on PyPI yet — `pip install hyrule-cloud` 404s today)::

    pip install "git+https://github.com/AS215932/hyrule-cloud"

Read-only usage::

    from hyrule_cloud.client import HyruleClient

    async with HyruleClient("https://cloud.hyrule.host") as hc:
        pricing = await hc.pricing()
        avail = await hc.check_domain("example", "com")

Autonomous (agent pays for itself) usage — hand the client a funded EVM
private key and paid calls transparently do 402 -> sign -> retry::

    import os

    async with HyruleClient(
        "https://cloud.hyrule.host",
        private_key=os.environ["HYRULE_AGENT_KEY"],  # funded USDC wallet on Base
        max_usd_per_call="5.00",                     # hard spend cap per call
    ) as hc:
        result = await hc.provision_vm(
            duration_days=7,
            size="sm",
            ssh_pubkey="ssh-ed25519 AAAA...",
        )
        print(result.ssh, result.management_token)
        print(hc.last_settlement.transaction)

Every paid call is capped by `max_usd_per_call` and pinned to a single
chain (`payment_network`, Base mainnet by default), so a malformed or
hostile 402 challenge cannot make the agent overspend or sign for a chain
it never meant to touch.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from decimal import ROUND_DOWN, Decimal, InvalidOperation
from typing import Any

import httpx
from eth_account import Account
from x402 import x402Client
from x402.client import max_amount
from x402.http import decode_payment_response_header
from x402.http.clients import PaymentError as X402PaymentError
from x402.http.clients import x402_httpx_transport
from x402.http.clients.httpx import x402AsyncTransport
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner
from x402.mechanisms.evm.v1.constants import V1_DEFAULT_ASSETS, V1_NETWORK_CHAIN_IDS

#: Base mainnet. Paid calls are pinned to exactly one chain so the SDK never
#: signs for whatever EVM network the challenge happens to advertise first.
DEFAULT_PAYMENT_NETWORK = "eip155:8453"

#: Default per-call spend ceiling in USD. Deliberately low enough that an
#: unattended agent cannot drain a wallet on a single bad 402.
DEFAULT_MAX_USD_PER_CALL = "10.00"

#: USDC (and every x402 `exact` stablecoin we accept) is 6-decimal.
_USDC_DECIMALS = 6

#: httpx response-extension key set by `_SettlementMarkingTransport`.
_PAID_MARKER = "hyrule_x402_paid"

#: Settlement receipt header. `payment-response` is x402 v2, `x-payment-response`
#: the legacy spelling; the API emits both.
_SETTLEMENT_HEADERS = ("payment-response", "x-payment-response")

#: VM statuses that end a provisioning poll loop.
_TERMINAL_OK = frozenset({"ready", "running"})
_TERMINAL_BAD = frozenset({"failed", "destroyed"})


class HyruleError(Exception):
    """Raised when the Hyrule Cloud API returns an error."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class HyrulePaymentError(HyruleError):
    """Raised when an x402 payment could not be completed.

    Covers both "the agent refused to pay" (the 402 asked for more than
    `max_usd_per_call`, or advertised a chain we are not pinned to) and
    "the facilitator reported the settlement as failed".
    """

    def __init__(self, detail: str) -> None:
        super().__init__(402, detail)


class SettlementMissingError(HyruleError):
    """Raised when a paid call's settlement receipt could not be read.

    A 2xx that follows a 402 -> sign -> retry cycle should come back with a
    settlement header, but a proxy or middleware between the API and this
    client can strip it after the underlying charge and provisioning have
    already succeeded. Settlement is therefore UNKNOWN here, not "unpaid":
    asserting the call was never charged would tell a caller it is safe to
    retry an unquoted request, which can purchase a second resource while
    the reveal-once data (e.g. a VM's management token) from the first is
    lost. `response_body` carries the underlying response's parsed JSON
    (when parseable) so a caller can recover it instead.
    """

    def __init__(self, detail: str, *, response_body: dict[str, Any] | None = None) -> None:
        self.response_body = response_body
        super().__init__(502, detail)


class ProvisioningError(HyruleError):
    """Raised when `provision_vm` observes a terminal failure."""

    def __init__(self, detail: str, *, vm_id: str | None = None, status_code: int = 502) -> None:
        self.vm_id = vm_id
        super().__init__(status_code, detail)


class ProvisioningTimeoutError(ProvisioningError):
    """Raised when `provision_vm` gives up waiting for a VM to become ready."""

    def __init__(self, detail: str, *, vm_id: str | None = None) -> None:
        super().__init__(detail, vm_id=vm_id, status_code=504)


@dataclass(frozen=True)
class Settlement:
    """Decoded x402 settlement receipt for a paid call."""

    success: bool
    transaction: str | None
    network: str | None
    payer: str | None
    raw: str

    @classmethod
    def from_header(
        cls, raw: str, *, response_body: dict[str, Any] | None = None
    ) -> Settlement:
        """Decode a `PAYMENT-RESPONSE` header value.

        Raises `SettlementMissingError` when the header is present but
        undecodable — an unreadable receipt leaves settlement unknown, same
        as a missing one. `response_body` is forwarded onto the error so a
        caller can still recover the underlying response's data.
        """
        try:
            decoded = decode_payment_response_header(raw)
        except Exception as exc:  # any decode failure is fatal — an unreadable receipt is none
            raise SettlementMissingError(
                f"settlement header present but undecodable: {exc}",
                response_body=response_body,
            ) from exc
        transaction = getattr(decoded, "transaction", None) or getattr(decoded, "tx_hash", None)
        success = getattr(decoded, "success", None)
        return cls(
            success=bool(success) if success is not None else bool(transaction),
            transaction=transaction,
            network=getattr(decoded, "network", None),
            payer=getattr(decoded, "payer", None),
            raw=raw,
        )


@dataclass
class ProvisionResult:
    """Everything an agent needs after a one-call VM provision."""

    vm_id: str
    status: str
    hostname: str | None
    ipv6: str | None
    ssh: str | None
    management_token: str | None
    settlement: Settlement | None
    create_response: dict[str, Any]
    status_response: dict[str, Any] | None


class _SettlementMarkingTransport(httpx.AsyncBaseTransport):
    """Flags responses that came out of an x402 pay-and-retry cycle.

    The SDK transport silently retries the original request with a signed
    payment header and hands back only the final response, so the caller
    cannot tell a paid 200 from a free one. We sit *underneath* it, see the
    retry flag the SDK stamps on the retried request, and mark the response.

    That marker is what lets `_request` demand a settlement receipt for calls
    we actually paid for — without falsely rejecting the 2xx of a dev-bypass
    or pre-built-`payment_header` caller, whose request never saw a 402.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        if request.extensions.get(x402AsyncTransport.RETRY_KEY):
            response.extensions[_PAID_MARKER] = True
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


def _as_usd(value: Decimal | str | int) -> Decimal:
    """Parse and validate a USD amount used as a spend ceiling."""
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"max_usd_per_call is not a valid decimal amount: {value!r}") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError(f"max_usd_per_call must be a positive amount, got {value!r}")
    return amount


def _atomic_units(usd: Decimal) -> int:
    """USD -> 6-decimal atomic token units, rounded down so the cap never creeps up."""
    return int((usd * Decimal(10**_USDC_DECIMALS)).to_integral_value(rounding=ROUND_DOWN))


def _chain_id(caip2_network: str) -> int:
    """Parse the numeric chain id out of a CAIP-2 EVM network string."""
    return int(caip2_network.split(":", 1)[1])


def _pinned_usdc_address(payment_network: str) -> str:
    """Canonical USDC address for `payment_network`, off the SDK's own
    legacy-network asset table (keyed by chain id so it stays in sync with
    whichever chains the SDK's v1 registration actually supports)."""
    chain_id = _chain_id(payment_network)
    for name, known_chain_id in V1_NETWORK_CHAIN_IDS.items():
        if known_chain_id == chain_id:
            asset = V1_DEFAULT_ASSETS.get(name)
            if asset is not None:
                return asset["address"]
    raise ValueError(
        f"no known USDC address for payment_network={payment_network!r}; "
        "add it to the pin table before pointing a client at this chain"
    )


def _asset_allowlist(expected_asset: str) -> Any:
    """x402 PaymentPolicy: accept only the one asset address we expect.

    `max_amount()` alone checks the raw atomic amount, not the asset — a 402
    advertising a different token (wrong decimals, or simply not USDC) could
    pass the nominal cap while authorizing a much larger real spend.
    """

    def policy(_version: int, reqs: list[Any]) -> list[Any]:
        return [r for r in reqs if r.asset.lower() == expected_asset.lower()]

    return policy


class HyruleClient:
    """Async client for the Hyrule Cloud API."""

    def __init__(
        self,
        base_url: str = "https://cloud.hyrule.host",
        *,
        payment_header: str | None = None,
        dev_bypass: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
        private_key: str | None = None,
        x402_client: x402Client | None = None,
        max_usd_per_call: Decimal | str = DEFAULT_MAX_USD_PER_CALL,
        payment_network: str = DEFAULT_PAYMENT_NETWORK,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Build a client.

        Auth
        ----
        `api_key` (Wave 3 / Block D) is the *account* bearer, sent on every
        request in place of session-cookie auth. Keys are minted via
        `register(with_api_key=True)` or `/v1/me/api-keys`. It is NOT the
        per-VM `management_token` — that one is a one-time credential handed
        out by the create 202 and is passed per call.

        Payment
        -------
        `private_key`: EVM private key (`0x…`) of a wallet funded with USDC on
        `payment_network`. When set, paid endpoints transparently perform
        402 -> sign -> retry and return the 2xx body. Use `x402_client` instead
        to supply a fully pre-configured `x402Client` (custom signer, extra
        policies, non-EVM mechanisms); the client is then used as given and
        the arguments below are not applied to it.

        `max_usd_per_call`: hard per-call spend ceiling, default
        `DEFAULT_MAX_USD_PER_CALL` ("10.00"). Enforced as an x402 `max_amount`
        policy, so a 402 asking for more is dropped *before* anything is
        signed and the call raises `HyrulePaymentError` instead of paying.

        `payment_network`: CAIP-2 chain the payment is pinned to, default
        `DEFAULT_PAYMENT_NETWORK` (`eip155:8453`, Base mainnet). Pinning stops
        the SDK from signing against whichever chain a challenge advertises
        first, which would otherwise mean a wrong-chain spend.

        `payment_header`: pre-built `X-PAYMENT` header for callers that sign
        elsewhere. Still supported and unchanged; it is sent on the first
        attempt, so no 402 round-trip happens at all.

        `transport`: underlying httpx transport, mainly for tests
        (`ASGITransport`/`MockTransport`). Payment handling is layered on top
        of it, so a mocked transport exercises the real signing path offline.
        """
        headers: dict[str, str] = {}
        if payment_header:
            headers["X-PAYMENT"] = payment_header
        if dev_bypass:
            headers["X-DEV-BYPASS"] = dev_bypass
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        self.max_usd_per_call = _as_usd(max_usd_per_call)
        self.payment_network = payment_network
        self._last_settlement: Settlement | None = None

        if x402_client is not None:
            self._x402_client: x402Client | None = x402_client
        elif private_key:
            self._x402_client = self._build_x402_client(private_key)
        else:
            self._x402_client = None

        client_kwargs: dict[str, Any] = {}
        if self._x402_client is not None:
            inner = transport if transport is not None else httpx.AsyncHTTPTransport()
            client_kwargs["transport"] = x402_httpx_transport(
                self._x402_client, transport=_SettlementMarkingTransport(inner)
            )
        elif transport is not None:
            client_kwargs["transport"] = transport

        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            **client_kwargs,
        )

    def _build_x402_client(self, private_key: str) -> x402Client:
        """Wire an `x402Client` that can only spend up to the cap, in the
        expected stablecoin, on one chain — never whatever a 402 advertises."""
        signer = EthAccountSigner(Account.from_key(private_key))
        client = x402Client()
        register_exact_evm_client(
            client,
            signer,
            networks=self.payment_network,
            policies=[
                _asset_allowlist(_pinned_usdc_address(self.payment_network)),
                max_amount(_atomic_units(self.max_usd_per_call)),
            ],
        )
        # `networks=` above only restricts the V2 registration.
        # register_exact_evm_client unconditionally registers the V1 legacy
        # scheme for every network it supports, so a v1-format 402 naming a
        # different chain (Polygon, Avalanche, ...) would still be signed by
        # this same key despite the single-chain pin. Drop every V1
        # registration except the one matching our pinned chain.
        pinned_chain_id = _chain_id(self.payment_network)
        client._schemes_v1 = {
            name: schemes
            for name, schemes in client._schemes_v1.items()
            if V1_NETWORK_CHAIN_IDS.get(name) == pinned_chain_id
        }
        return client

    @property
    def can_pay(self) -> bool:
        """True when this client can settle a 402 on its own."""
        return self._x402_client is not None

    @property
    def last_settlement(self) -> Settlement | None:
        """Settlement receipt of the most recent autonomously paid call.

        `None` until a call actually goes through 402 -> sign -> retry.
        Carries the on-chain transaction hash, payer address and network.
        """
        return self._last_settlement

    async def __aenter__(self) -> HyruleClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    # -- internal --

    @staticmethod
    def _settlement_header(resp: httpx.Response) -> str | None:
        for name in _SETTLEMENT_HEADERS:
            raw = resp.headers.get(name)
            if raw:
                return raw
        return None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        management_token: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if management_token:
            # Per-call bearer. Overrides the account `api_key` header for this
            # request only — `_vm_for_management` accepts either credential,
            # and the VM token is the one the order flow actually handed out.
            headers = dict(kwargs.pop("headers", None) or {})
            headers["Authorization"] = f"Bearer {management_token}"
            kwargs["headers"] = headers

        try:
            resp = await self._http.request(method, path, **kwargs)
        except X402PaymentError as exc:
            raise HyrulePaymentError(
                f"x402 payment not completed for {method} {path}: {exc} "
                f"(cap ${self.max_usd_per_call}/call, network {self.payment_network})"
            ) from exc

        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise HyruleError(resp.status_code, detail)

        if resp.extensions.get(_PAID_MARKER):
            try:
                body: dict[str, Any] | None = resp.json()
            except Exception:
                body = None
            raw = self._settlement_header(resp)
            if not raw:
                raise SettlementMissingError(
                    f"{method} {path} returned {resp.status_code} but the settlement "
                    "header is missing (likely stripped by a proxy) — settlement is "
                    "UNKNOWN, not unpaid; the call may already be charged and the "
                    "resource provisioned. Do not blindly retry an unquoted request; "
                    "see response_body for any recoverable resource/token data.",
                    response_body=body,
                )
            settlement = Settlement.from_header(raw, response_body=body)
            if not settlement.success:
                raise HyrulePaymentError(
                    f"{method} {path} settlement failed (tx={settlement.transaction}, "
                    f"payer={settlement.payer})"
                )
            self._last_settlement = settlement

        return resp.json()

    # -- Free endpoints --

    async def pricing(self) -> dict[str, Any]:
        """Get current pricing for all resources."""
        return await self._request("GET", "/v1/pricing")

    async def os_list(self) -> dict[str, Any]:
        """List available OS templates."""
        return await self._request("GET", "/v1/os/list")

    async def vm_products(self) -> dict[str, Any]:
        """Get technical VM profiles and the customization contract."""
        return await self._request("GET", "/v1/products/vms")

    async def quote_vm(
        self,
        order_payload: dict[str, Any],
        *,
        client_order_id: str | None = None,
    ) -> dict[str, Any]:
        """Lock a canonical VM configuration and USD price for checkout."""
        body: dict[str, Any] = {"order_payload": order_payload}
        if client_order_id is not None:
            body["client_order_id"] = client_order_id
        return await self._request("POST", "/v1/vm/quote", json=body)

    async def vm_quote(self, quote_id: str) -> dict[str, Any]:
        """Restore a durable VM quote and its exact resource snapshot."""
        return await self._request("GET", f"/v1/vm/quote/{quote_id}")

    async def vm_status(self, vm_id: str) -> dict[str, Any]:
        """Poll the public VM status view: status, ipv6, hostname, expiry, launch proof.

        Hits `GET /v1/vm/{id}/status`, which any caller may read. This is the
        endpoint the documented poll loop should use — the bare
        `GET /v1/vm/{id}` is management-gated and 404s without the one-time
        `management_token`. Use `vm_details()` for that fuller view.
        """
        return await self._request("GET", f"/v1/vm/{vm_id}/status")

    async def vm_details(
        self, vm_id: str, *, management_token: str | None = None
    ) -> dict[str, Any]:
        """Full management view: adds ssh string, firewall state and error detail.

        `GET /v1/vm/{id}` requires management authority — either the one-time
        `management_token` from the create 202, or an account session/API key
        that owns the VM. Returns 404 (not 403) when neither is present.
        """
        return await self._request(
            "GET", f"/v1/vm/{vm_id}", management_token=management_token
        )

    async def vm_logs(self, vm_id: str, *, management_token: str | None = None) -> dict[str, Any]:
        """Get VM provisioning logs. Management-gated (see `vm_details`)."""
        return await self._request(
            "GET", f"/v1/vm/{vm_id}/logs", management_token=management_token
        )

    async def check_domain(self, name: str, extension: str) -> dict[str, Any]:
        """Check domain availability and price."""
        return await self._request(
            "GET", "/v1/domains/check", params={"domain": f"{name}.{extension}"}
        )

    async def check_zone(self, name: str, extension: str) -> dict[str, Any]:
        """Check DNS zone availability and price (same as domain availability)."""
        return await self._request(
            "GET", "/v1/domains/check", params={"domain": f"{name}.{extension}"}
        )

    async def domain_tlds(self) -> dict[str, Any]:
        """List the current eligible generic TLD catalog."""
        return await self._request("GET", "/v1/domains/tlds")

    async def quote_domain(self, domain: str, action: str = "register") -> dict[str, Any]:
        """Create a 15-minute registration or renewal quote."""
        return await self._request(
            "POST", "/v1/domains/quotes", json={"domain": domain, "action": action}
        )

    async def domain_order(self, order_id: str) -> dict[str, Any]:
        """Fetch a durable domain order and its fulfillment state."""
        return await self._request("GET", f"/v1/domains/orders/{order_id}")

    async def domains(self) -> dict[str, Any]:
        """List domains owned by the authenticated account."""
        return await self._request("GET", "/v1/domains")

    # -- Paid endpoints --

    async def create_vm(
        self,
        *,
        duration_days: int,
        ssh_pubkey: str,
        size: str = "xs",
        os: str = "debian-13",
        domain_mode: str = "auto",
        domain: str | None = None,
        open_ports: list[int] | None = None,
        setup_script: str | None = None,
        resources: dict[str, int] | None = None,
        quote_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Provision a bare VM. Paid via x402.

        With `private_key`/`x402_client` set on the constructor the 402 is
        settled transparently and this returns the 202 body — including the
        one-time `management_token` you must keep to manage the VM later.
        Without a payment credential the 402 surfaces as `HyruleError`, whose
        `detail` carries the pricing and x402 payment instructions.

        See `provision_vm()` for the one-call quote -> pay -> poll workflow.
        """
        body: dict[str, Any] = {
            "duration_days": duration_days,
            "size": size,
            "os": os,
            "ssh_pubkey": ssh_pubkey,
            "domain_mode": domain_mode,
        }
        if domain:
            body["domain"] = domain
        if open_ports is not None:
            body["open_ports"] = open_ports
        if setup_script is not None:
            body["setup_script"] = setup_script
        if resources is not None:
            body["resources"] = resources
        if quote_id is not None:
            body["quote_id"] = quote_id

        return await self._request("POST", "/v1/vm/create", json=body)

    async def extend_vm(
        self, vm_id: str, days: int, *, management_token: str | None = None
    ) -> dict[str, Any]:
        """Add days to a running VM. Management-gated AND paid via x402."""
        return await self._request(
            "POST",
            f"/v1/vm/{vm_id}/extend",
            json={"days": days},
            management_token=management_token,
        )

    async def reboot_vm(self, vm_id: str, *, management_token: str | None = None) -> dict[str, Any]:
        """Hard reboot a VM. Management-gated (see `vm_details`)."""
        return await self._request(
            "POST", f"/v1/vm/{vm_id}/reboot", management_token=management_token
        )

    async def destroy_vm(
        self, vm_id: str, *, management_token: str | None = None
    ) -> dict[str, Any]:
        """Destroy a VM permanently. Management-gated (see `vm_details`)."""
        return await self._request(
            "DELETE", f"/v1/vm/{vm_id}", management_token=management_token
        )

    # -- One-call provisioning workflow --

    async def provision_vm(
        self,
        *,
        duration_days: int,
        ssh_pubkey: str,
        size: str = "xs",
        os: str = "debian-13",
        domain_mode: str = "auto",
        domain: str | None = None,
        open_ports: list[int] | None = None,
        setup_script: str | None = None,
        resources: dict[str, int] | None = None,
        quote_id: str | None = None,
        quote_first: bool = False,
        wait: bool = True,
        poll_timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> ProvisionResult:
        """Quote (optional) -> pay -> create -> poll until ready, in one call.

        This is the whole documented workflow for an autonomous agent. It
        needs a paying client (`private_key=` or `x402_client=`) unless a
        `payment_header`/`dev_bypass` covers the create.

        `quote_first=True` locks a canonical price via `POST /v1/vm/quote`
        first and pays against that `quote_id`. Polling uses the public
        `/v1/vm/{id}/status` endpoint, so no management token is needed.

        Raises `ProvisioningError` on a terminal failure, `ProvisioningTimeoutError`
        when `poll_timeout` elapses first, and `HyrulePaymentError` when the
        402 could not be settled within the spend cap.
        """
        spec: dict[str, Any] = {
            "duration_days": duration_days,
            "size": size,
            "os": os,
            "ssh_pubkey": ssh_pubkey,
            "domain_mode": domain_mode,
        }
        if domain:
            spec["domain"] = domain
        if open_ports is not None:
            spec["open_ports"] = open_ports
        if setup_script is not None:
            spec["setup_script"] = setup_script
        if resources is not None:
            spec["resources"] = resources

        if quote_first and quote_id is None:
            quote_id = (await self.quote_vm(spec))["quote_id"]

        created = await self.create_vm(quote_id=quote_id, **spec)
        settlement = self._last_settlement
        vm_id = created["vm_id"]
        result = ProvisionResult(
            vm_id=vm_id,
            status=str(created.get("status", "provisioning")),
            hostname=None,
            ipv6=None,
            ssh=None,
            management_token=created.get("management_token"),
            settlement=settlement,
            create_response=created,
            status_response=None,
        )
        if not wait:
            return result

        deadline = asyncio.get_running_loop().time() + poll_timeout
        while True:
            status = await self.vm_status(vm_id)
            result.status_response = status
            result.status = str(status.get("status", result.status))
            result.hostname = status.get("hostname")
            result.ipv6 = status.get("ipv6")

            if result.status in _TERMINAL_BAD:
                raise ProvisioningError(
                    f"VM {vm_id} provisioning ended in state {result.status!r}: "
                    f"{status.get('customer_message') or status.get('operator_message') or ''}",
                    vm_id=vm_id,
                )
            if result.status in _TERMINAL_OK:
                host = result.hostname or result.ipv6
                result.ssh = f"ssh root@{host}" if host else None
                return result
            if asyncio.get_running_loop().time() >= deadline:
                raise ProvisioningTimeoutError(
                    f"VM {vm_id} still {result.status!r} after {poll_timeout:g}s; "
                    f"keep the management token and poll /v1/vm/{vm_id}/status",
                    vm_id=vm_id,
                )
            await asyncio.sleep(poll_interval)

    async def register_domain(
        self,
        name: str,
        extension: str,
        *,
        payment_method: str = "usdc",
        refund_address: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Quote and create an account-owned registrar order."""
        quote = await self.quote_domain(f"{name}.{extension}")
        body: dict[str, Any] = {
            "quote_id": quote["quote_id"],
            "payment_method": payment_method,
            "terms_version": quote["terms_version"],
        }
        if refund_address:
            body["refund_address"] = refund_address
        return await self._request(
            "POST",
            "/v1/domains/orders",
            json=body,
            headers={"Idempotency-Key": idempotency_key or secrets.token_urlsafe(24)},
        )

    async def buy_zone(
        self,
        name: str,
        extension: str,
    ) -> dict[str, Any]:
        """
        Buy a DNS zone (register the domain + configure our nameservers).

        The zone will be managed by Hyrule Cloud's authoritative DNS.
        Agents can then create records in the zone via the records API.
        """
        return await self.register_domain(name, extension)

    async def create_record(
        self,
        zone: str,
        name: str,
        rtype: str,
        value: str,
        ttl: int = 300,
    ) -> dict[str, Any]:
        """Create a DNS record in a zone owned by the caller."""
        current = await self._request("GET", f"/v1/domains/{zone}/dns")
        return await self._request(
            "POST",
            f"/v1/domains/{zone}/dns/changesets",
            json={
                "changes": [
                    {
                        "action": "upsert",
                        "rrset": {
                            "name": name,
                            "type": rtype,
                            "ttl": ttl,
                            "values": [value],
                        },
                    }
                ]
            },
            headers={
                "If-Match": str(current["revision"]),
                "Idempotency-Key": secrets.token_urlsafe(24),
            },
        )

    async def delete_record(
        self,
        zone: str,
        name: str,
        rtype: str,
    ) -> dict[str, Any]:
        """Delete a DNS record from a zone owned by the caller."""
        current = await self._request("GET", f"/v1/domains/{zone}/dns")
        existing = next(
            (
                record
                for record in current.get("records", [])
                if record.get("name") == name and record.get("type") == rtype.upper()
            ),
            None,
        )
        if existing is None:
            return current
        return await self._request(
            "POST",
            f"/v1/domains/{zone}/dns/changesets",
            json={"changes": [{"action": "delete", "rrset": existing}]},
            headers={
                "If-Match": str(current["revision"]),
                "Idempotency-Key": secrets.token_urlsafe(24),
            },
        )

    # -- Network intelligence / agentic support --

    async def bgp_status(self) -> dict[str, Any]:
        """Free AS215932 BGP/routing status."""
        return await self._request("GET", "/v1/bgp/status")

    async def bgp_lookup(self, subject: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Paid BGP lookup by prefix, IP, or ASN. Prefix/IP do not require ASN."""
        payload: dict[str, Any] = {"subject": subject, **kwargs}
        return await self._request("POST", "/v1/bgp/lookup", json=payload)

    async def ip_lookup(self, address: str, views: list[str] | None = None) -> dict[str, Any]:
        """Paid IP geolocation/ASN/rDNS/RDAP/WHOIS/reputation lookup."""
        payload: dict[str, Any] = {"address": address}
        if views:
            payload["views"] = views
        return await self._request("POST", "/v1/ip/lookup", json=payload)

    async def dns_lookup(
        self,
        name: str,
        record_type: str = "A",
        *,
        dnssec: bool = False,
        trace: bool = False,
    ) -> dict[str, Any]:
        """Paid read-only DNS lookup."""
        return await self._request(
            "POST",
            "/v1/dns/lookup",
            json={"name": name, "type": record_type, "dnssec": dnssec, "trace": trace},
        )

    async def dns_propagation(
        self,
        name: str,
        record_type: str = "A",
        *,
        expected: list[str] | None = None,
        resolvers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Paid DNS propagation comparison across recursive resolvers."""
        payload: dict[str, Any] = {"name": name, "type": record_type}
        if expected is not None:
            payload["expected"] = expected
        if resolvers is not None:
            payload["resolvers"] = resolvers
        return await self._request("POST", "/v1/dns/propagation", json=payload)

    async def rdap_lookup(self, subject_type: str, value: str | int, *, include_raw: bool = False) -> dict[str, Any]:
        """Paid RDAP lookup for domain/IP/prefix/ASN/entity."""
        return await self._request(
            "POST",
            "/v1/rdap/lookup",
            json={"subject": {"type": subject_type, "value": value}, "include_raw": include_raw},
        )

    async def whois_lookup(self, subject_type: str, value: str | int, *, include_raw: bool = False) -> dict[str, Any]:
        """Paid WHOIS lookup for domain/IP/prefix/ASN."""
        return await self._request(
            "POST",
            "/v1/whois/lookup",
            json={"subject": {"type": subject_type, "value": value}, "include_raw": include_raw},
        )

    async def web_check(self, target: str, checks: list[str] | None = None) -> dict[str, Any]:
        """Paid web reachability/TLS/header/CDN check."""
        payload: dict[str, Any] = {"target": target}
        if checks:
            payload["checks"] = checks
        return await self._request("POST", "/v1/web/check", json=payload)

    async def web_tls_deep(self, host: str, port: int = 443) -> dict[str, Any]:
        """Paid deep TLS protocol/certificate/cipher scan with grade."""
        return await self._request("POST", "/v1/web/tls/deep", json={"host": host, "port": port})

    async def mx_tools(self) -> dict[str, Any]:
        """Free list of MXToolbox-compatible diagnostic tools."""
        return await self._request("GET", "/v1/mx/tools")

    async def mx_check(
        self,
        tool: str,
        target: str,
        *,
        dkim_selectors: list[str] | None = None,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        """Paid MXToolbox-compatible single diagnostic check."""
        options: dict[str, Any] = {"include_raw": include_raw}
        if dkim_selectors:
            options["dkim_selectors"] = dkim_selectors
        return await self._request(
            "POST",
            "/v1/mx/check",
            json={"tool": tool, "target": target, "options": options},
        )

    async def mx_report(self, target: str, checks: list[str] | None = None) -> dict[str, Any]:
        """Paid full mail-delivery diagnostic report."""
        payload: dict[str, Any] = {"profile": "mail_delivery", "target": target}
        if checks:
            payload["checks"] = checks
        return await self._request("POST", "/v1/mx/jobs", json=payload)

    async def mx_parse_bounce(self, message: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Paid bounce/rejection parser."""
        return await self._request("POST", "/v1/mx/bounce/parse", json={"message": message, "context": context or {}})

    async def path_report(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Paid routing/path evidence pack."""
        return await self._request("POST", "/v1/path/report", json={"target": target, **kwargs})

    async def port_check(self, target: str, port: int, protocol: str = "tcp", profile: str = "custom") -> dict[str, Any]:
        """Paid outside-in single-service reachability check."""
        return await self._request("POST", "/v1/ports/check", json={"target": target, "port": port, "protocol": protocol, "profile": profile})

    async def nat_ip(self) -> dict[str, Any]:
        """Free caller-observed IP."""
        return await self._request("GET", "/v1/nat/ip")

    async def nat_port_forward_check(self, target: str, port: int, protocol: str = "tcp", profile: str = "custom") -> dict[str, Any]:
        """Paid NAT port-forward outside-in check."""
        return await self._request("POST", "/v1/nat/port-forward/check", json={"target": target, "port": port, "protocol": protocol, "profile": profile})

    async def threat_lookup(self, subject_type: str, value: str, views: list[str] | None = None) -> dict[str, Any]:
        """Paid threat/reputation lookup."""
        payload: dict[str, Any] = {"subject": {"type": subject_type, "value": value}}
        if views:
            payload["views"] = views
        return await self._request("POST", "/v1/threat/lookup", json=payload)

    async def voip_check(self, target: str, checks: list[str] | None = None) -> dict[str, Any]:
        """Paid SIP/VoIP diagnostic check."""
        payload: dict[str, Any] = {"target": target}
        if checks:
            payload["checks"] = checks
        return await self._request("POST", "/v1/voip/check", json=payload)

    async def voip_number_lookup(self, number: str, country: str | None = None) -> dict[str, Any]:
        """Paid VoIP number-provider lookup contract."""
        payload: dict[str, Any] = {"number": number}
        if country:
            payload["country"] = country
        return await self._request("POST", "/v1/voip/number/lookup", json=payload)

    # -- Discovery --

    async def x402_manifest(self) -> dict[str, Any]:
        """Fetch the x402 service manifest for agent discovery."""
        return await self._request("GET", "/.well-known/x402.json")

    async def health(self) -> dict[str, Any]:
        """Health check."""
        return await self._request("GET", "/health")

    # -- Block A1 (Wave 2) + D (Wave 3): account-level operations --

    async def payment_networks(self) -> dict[str, Any]:
        """Block C: list the chains the backend currently accepts.

        Frontends and agent SDKs SHOULD call this rather than hardcoding a
        chain list — operators flip individual chains on/off in Vault and
        the wire format is the single source of truth."""
        return await self._request("GET", "/v1/payments/networks")

    async def create_crypto_intent(
        self,
        *,
        asset: str,
        amount_usd: str,
        order_payload: dict[str, Any],
        client_order_id: str | None = None,
    ) -> dict[str, Any]:
        """Block E/H: open a BTC or XMR payment intent. Returns deposit address
        + QR + rate snapshot. Use client_order_id for idempotent retries."""
        body: dict[str, Any] = {
            "asset": asset,
            "amount_usd": amount_usd,
            "order_payload": order_payload,
        }
        if client_order_id:
            body["client_order_id"] = client_order_id
        return await self._request("POST", "/v1/intent/create", json=body)

    async def get_crypto_intent(self, intent_id: str) -> dict[str, Any]:
        """Block E/H: poll a crypto intent. Returns status, confirmations, and
        once PROVISIONED the resulting vm_id + one-shot management token."""
        return await self._request("GET", f"/v1/intent/{intent_id}")

    async def register(
        self,
        password: str,
        *,
        with_api_key: bool = False,
        api_key_name: str | None = None,
    ) -> dict[str, Any]:
        """Register a fresh account. Returns `{account_id, recovery_code, ...}`.

        If `with_api_key=True` the response also carries a cleartext
        `api_key` (Block D agent bootstrap) with the narrow
        DEFAULT_BOOTSTRAP_SCOPES — save it; we never re-show it."""
        payload: dict[str, Any] = {"password": password}
        if with_api_key:
            payload["with_api_key"] = True
            if api_key_name:
                payload["api_key_name"] = api_key_name
        return await self._request("POST", "/v1/auth/register", json=payload)

    async def list_api_keys(self) -> dict[str, Any]:
        """Block D: list active (non-revoked) API keys for the current
        account. Authenticate via `api_key=` on the client constructor."""
        return await self._request("GET", "/v1/me/api-keys")

    async def create_api_key(
        self, name: str, scopes: list[str], *, expires_in_days: int | None = None,
    ) -> dict[str, Any]:
        """Block D: mint a new API key. Response carries the cleartext
        bearer exactly once."""
        payload: dict[str, Any] = {"name": name, "scopes": scopes}
        if expires_in_days is not None:
            payload["expires_in_days"] = expires_in_days
        return await self._request("POST", "/v1/me/api-keys", json=payload)

    async def revoke_api_key(self, key_id: str) -> dict[str, Any]:
        """Block D: idempotent revocation."""
        return await self._request("DELETE", f"/v1/me/api-keys/{key_id}")
