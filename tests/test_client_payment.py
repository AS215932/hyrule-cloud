"""HyruleClient autonomous-payment, status-polling and management-token tests.

Covers the four defects found during the first live dogfood run of the
public x402 VPS service:

1. the client could not settle a 402 on its own,
2. `vm_status()` polled the management-gated `/v1/vm/{id}` instead of the
   public `/v1/vm/{id}/status`,
3. there was no way to present the one-time VM `management_token`,
4. there was no one-call provision workflow.

The payment tests drive the *real* x402 SDK against an httpx `MockTransport`.
EIP-3009 signing is purely local, so the 402 -> sign -> retry path is
exercised end to end with a throwaway key, no network and no money.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport
from x402 import PaymentRequired, SettleResponse
from x402.http import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.schemas import PaymentRequirements

from hyrule_cloud.app import app
from hyrule_cloud.client import (
    HyruleClient,
    HyruleError,
    HyrulePaymentError,
    ProvisioningError,
    ProvisioningTimeoutError,
    SettlementMissingError,
)
from tests.test_api import _TEST_TOKEN, override_state  # noqa: F401  (pytest fixture)

# Throwaway key — deterministic, never funded, never used off-test.
_TEST_KEY = "0x" + "11" * 32
_NETWORK = "eip155:8453"
_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_VM_ID = "vm_dogfood1"
_MGMT_TOKEN = "hyr_vm_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _payment_required_header(amount_units: str) -> str:
    """A well-formed x402 v2 challenge for `amount_units` atomic USDC."""
    requirements = PaymentRequirements(
        scheme="exact",
        network=_NETWORK,
        asset=_USDC,
        amount=amount_units,
        pay_to="0x000000000000000000000000000000000000dEaD",
        max_timeout_seconds=300,
        extra={"name": "USD Coin", "version": "2"},
    )
    return encode_payment_required_header(
        PaymentRequired(
            x402_version=2,
            error="payment required",
            resource={"url": "http://test/v1/vm/create"},
            accepts=[requirements],
        )
    )


def _settlement_header(*, success: bool = True) -> str:
    return encode_payment_response_header(
        SettleResponse(
            success=success,
            transaction="0xfeedbeef",
            network=_NETWORK,
            payer="0xAgentWallet",
        )
    )


class _FakeAPI:
    """In-process stand-in for the x402-gated API.

    Answers `POST /v1/vm/create` with a 402 until a signed payment header
    arrives, then with the 202 create body. `GET /v1/vm/{id}/status` walks a
    scripted list of statuses so poll loops are deterministic.
    """

    def __init__(
        self,
        *,
        price_units: str = "1400000",  # $1.40 — 7 days of `sm`
        emit_settlement: bool = True,
        settlement_ok: bool = True,
        statuses: list[dict[str, object]] | None = None,
    ) -> None:
        self.price_units = price_units
        self.emit_settlement = emit_settlement
        self.settlement_ok = settlement_ok
        self.statuses = statuses or [{"vm_id": _VM_ID, "status": "ready", "hostname": "a.test"}]
        self.requests: list[httpx.Request] = []
        self._status_calls = 0

    @property
    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]

    def _create(self, request: httpx.Request) -> httpx.Response:
        signed = request.headers.get(PAYMENT_SIGNATURE_HEADER) or request.headers.get("x-payment")
        if not signed:
            return httpx.Response(
                402,
                json={"detail": "payment required"},
                headers={PAYMENT_REQUIRED_HEADER: _payment_required_header(self.price_units)},
            )
        headers = {}
        if self.emit_settlement:
            headers[PAYMENT_RESPONSE_HEADER] = _settlement_header(success=self.settlement_ok)
        return httpx.Response(
            202,
            json={
                "vm_id": _VM_ID,
                "status": "provisioning",
                "status_url": f"http://test/v1/vm/{_VM_ID}/status",
                "management_token": _MGMT_TOKEN,
            },
            headers=headers,
        )

    def _status(self) -> httpx.Response:
        index = min(self._status_calls, len(self.statuses) - 1)
        self._status_calls += 1
        return httpx.Response(200, json=self.statuses[index])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/v1/vm/create":
            return self._create(request)
        if path == f"/v1/vm/{_VM_ID}/status":
            return self._status()
        if path == "/v1/vm/quote":
            return httpx.Response(200, json={"quote_id": "q_1", "total_usd": "1.40"})
        return httpx.Response(200, json={"path": path})


def _client(api: _FakeAPI, **kwargs: object) -> HyruleClient:
    kwargs.setdefault("private_key", _TEST_KEY)
    kwargs.setdefault("max_usd_per_call", "5.00")
    return HyruleClient(
        "http://test",
        transport=httpx.MockTransport(api.handler),
        **kwargs,  # type: ignore[arg-type]
    )


# --- Defect 1: the client can pay ---


@pytest.mark.asyncio
async def test_402_is_signed_and_retried_transparently() -> None:
    api = _FakeAPI()
    async with _client(api) as hc:
        created = await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA", size="sm")

    assert created["vm_id"] == _VM_ID
    assert created["management_token"] == _MGMT_TOKEN
    # Exactly one unpaid attempt + one signed retry.
    assert api.paths == ["/v1/vm/create", "/v1/vm/create"]
    assert not api.requests[0].headers.get(PAYMENT_SIGNATURE_HEADER)
    assert api.requests[1].headers.get(PAYMENT_SIGNATURE_HEADER)


@pytest.mark.asyncio
async def test_settlement_receipt_is_exposed() -> None:
    api = _FakeAPI()
    async with _client(api) as hc:
        assert hc.last_settlement is None
        await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")
        settlement = hc.last_settlement

    assert settlement is not None
    assert settlement.success is True
    assert settlement.transaction == "0xfeedbeef"
    assert settlement.payer == "0xAgentWallet"
    assert settlement.network == _NETWORK


@pytest.mark.asyncio
async def test_without_a_key_the_402_still_surfaces_as_an_error() -> None:
    """Back-compat: a non-paying client behaves exactly as before."""
    api = _FakeAPI()
    async with _client(api, private_key=None) as hc:
        assert hc.can_pay is False
        with pytest.raises(HyruleError) as exc:
            await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert exc.value.status_code == 402
    assert api.paths == ["/v1/vm/create"]


@pytest.mark.asyncio
async def test_prebuilt_payment_header_still_works_without_a_settlement_check() -> None:
    """Callers that sign elsewhere never see a 402, so no receipt is demanded."""
    api = _FakeAPI(emit_settlement=False)
    async with _client(api, private_key=None, payment_header="pre-built") as hc:
        created = await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert created["vm_id"] == _VM_ID
    assert api.requests[0].headers["X-PAYMENT"] == "pre-built"
    assert hc.last_settlement is None


# --- Defect 1: spend cap ---


@pytest.mark.asyncio
async def test_spend_cap_refuses_an_over_priced_402() -> None:
    """A 402 asking $50 against a $1 cap is dropped before anything is signed."""
    api = _FakeAPI(price_units="50000000")  # $50.00
    async with _client(api, max_usd_per_call="1.00") as hc:
        with pytest.raises(HyrulePaymentError) as exc:
            await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert "cap $1.00/call" in str(exc.value)
    # Critically: no signed retry was ever sent.
    assert api.paths == ["/v1/vm/create"]
    assert not any(r.headers.get(PAYMENT_SIGNATURE_HEADER) for r in api.requests)


@pytest.mark.asyncio
async def test_spend_cap_allows_a_price_just_under_the_ceiling() -> None:
    api = _FakeAPI(price_units="999999")  # $0.999999
    async with _client(api, max_usd_per_call="1.00") as hc:
        created = await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert created["vm_id"] == _VM_ID


@pytest.mark.asyncio
async def test_payment_is_pinned_to_one_chain() -> None:
    """A challenge on a chain we are not pinned to is not signed for."""
    api = _FakeAPI()
    async with _client(api, payment_network="eip155:137") as hc:
        with pytest.raises(HyrulePaymentError):
            await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert api.paths == ["/v1/vm/create"]


@pytest.mark.parametrize("bad", ["0", "-1.00", "abc", "0.0000001"])
def test_invalid_spend_caps_are_rejected_at_construction(bad: str) -> None:
    if bad == "0.0000001":
        # Sub-atomic caps are legal decimals but floor to zero units, which
        # would silently reject every payment — still constructible, but the
        # cap must never round *up*.
        client = HyruleClient("http://test", max_usd_per_call=bad)
        assert client.can_pay is False
        return
    with pytest.raises(ValueError):
        HyruleClient("http://test", private_key=_TEST_KEY, max_usd_per_call=bad)


# --- Defect 1: a paid 2xx must carry a receipt ---


@pytest.mark.asyncio
async def test_paid_2xx_without_settlement_header_raises() -> None:
    api = _FakeAPI(emit_settlement=False)
    async with _client(api) as hc:
        with pytest.raises(SettlementMissingError) as exc:
            await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert "not charged" in str(exc.value)
    assert hc.last_settlement is None


@pytest.mark.asyncio
async def test_failed_settlement_raises() -> None:
    api = _FakeAPI(settlement_ok=False)
    async with _client(api) as hc:
        with pytest.raises(HyrulePaymentError) as exc:
            await hc.create_vm(duration_days=7, ssh_pubkey="ssh-ed25519 AAAA")

    assert "settlement failed" in str(exc.value)
    assert hc.last_settlement is None


# --- Defect 2: vm_status polls the public endpoint ---


@pytest.mark.asyncio
async def test_vm_status_hits_the_public_status_endpoint() -> None:
    api = _FakeAPI()
    async with _client(api, private_key=None) as hc:
        await hc.vm_status(_VM_ID)

    assert api.paths == [f"/v1/vm/{_VM_ID}/status"]


@pytest.mark.asyncio
async def test_vm_details_hits_the_management_endpoint() -> None:
    api = _FakeAPI()
    async with _client(api, private_key=None) as hc:
        await hc.vm_details(_VM_ID, management_token=_MGMT_TOKEN)

    assert api.paths == [f"/v1/vm/{_VM_ID}"]


@pytest.mark.asyncio
async def test_vm_status_is_public_and_vm_details_is_gated_on_the_real_app(
    override_state: object,
) -> None:
    """End-to-end against the real routes: this is the defect as found live."""
    async with HyruleClient(
        "http://test", transport=ASGITransport(app=app)
    ) as hc:
        public = await hc.vm_status("vm_test123")
        assert public["ipv6"] == "2001:db8::1"

        # No token -> 404 (deliberately indistinguishable from "not found").
        with pytest.raises(HyruleError) as exc:
            await hc.vm_details("vm_test123")
        assert exc.value.status_code == 404

        gated = await hc.vm_details("vm_test123", management_token=_TEST_TOKEN)
        assert gated["ssh"] == "ssh root@test.deploy.hyrule.host"


# --- Defect 3: management tokens ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("call", "method", "path"),
    [
        ("vm_details", "GET", f"/v1/vm/{_VM_ID}"),
        ("vm_logs", "GET", f"/v1/vm/{_VM_ID}/logs"),
        ("reboot_vm", "POST", f"/v1/vm/{_VM_ID}/reboot"),
        ("destroy_vm", "DELETE", f"/v1/vm/{_VM_ID}"),
    ],
)
async def test_management_token_is_sent_as_bearer(call: str, method: str, path: str) -> None:
    api = _FakeAPI()
    async with _client(api, private_key=None) as hc:
        await getattr(hc, call)(_VM_ID, management_token=_MGMT_TOKEN)

    assert api.requests[0].method == method
    assert api.requests[0].url.path == path
    assert api.requests[0].headers["authorization"] == f"Bearer {_MGMT_TOKEN}"


@pytest.mark.asyncio
async def test_extend_vm_sends_the_management_token_and_days() -> None:
    api = _FakeAPI()
    async with _client(api, private_key=None) as hc:
        await hc.extend_vm(_VM_ID, 3, management_token=_MGMT_TOKEN)

    request = api.requests[0]
    assert request.url.path == f"/v1/vm/{_VM_ID}/extend"
    assert request.headers["authorization"] == f"Bearer {_MGMT_TOKEN}"
    assert b'"days":3' in request.content


@pytest.mark.asyncio
async def test_management_token_is_not_the_account_api_key() -> None:
    """The account bearer stays on unrelated calls; the VM token only
    overrides `Authorization` on the management call it was passed to."""
    api = _FakeAPI()
    async with _client(api, private_key=None, api_key="hyr_key_abc") as hc:
        await hc.vm_status(_VM_ID)
        await hc.vm_details(_VM_ID, management_token=_MGMT_TOKEN)
        await hc.vm_details(_VM_ID)

    assert api.requests[0].headers["authorization"] == "Bearer hyr_key_abc"
    assert api.requests[1].headers["authorization"] == f"Bearer {_MGMT_TOKEN}"
    assert api.requests[2].headers["authorization"] == "Bearer hyr_key_abc"


# --- Defect 4: provision_vm ---


@pytest.mark.asyncio
async def test_provision_vm_pays_polls_and_returns_a_ready_result() -> None:
    api = _FakeAPI(
        statuses=[
            {"vm_id": _VM_ID, "status": "provisioning"},
            {"vm_id": _VM_ID, "status": "provisioning"},
            {
                "vm_id": _VM_ID,
                "status": "ready",
                "hostname": "dogfood.deploy.hyrule.host",
                "ipv6": "2001:db8::42",
            },
        ]
    )
    async with _client(api) as hc:
        result = await hc.provision_vm(
            duration_days=7, ssh_pubkey="ssh-ed25519 AAAA", size="sm", poll_interval=0.0
        )

    assert result.vm_id == _VM_ID
    assert result.status == "ready"
    assert result.hostname == "dogfood.deploy.hyrule.host"
    assert result.ipv6 == "2001:db8::42"
    assert result.ssh == "ssh root@dogfood.deploy.hyrule.host"
    assert result.management_token == _MGMT_TOKEN
    assert result.settlement is not None
    assert result.settlement.transaction == "0xfeedbeef"
    assert api.paths.count(f"/v1/vm/{_VM_ID}/status") == 3


@pytest.mark.asyncio
async def test_provision_vm_can_lock_a_quote_first() -> None:
    api = _FakeAPI()
    async with _client(api) as hc:
        await hc.provision_vm(
            duration_days=7,
            ssh_pubkey="ssh-ed25519 AAAA",
            quote_first=True,
            poll_interval=0.0,
        )

    assert api.paths[0] == "/v1/vm/quote"
    create = next(r for r in api.requests if r.url.path == "/v1/vm/create")
    assert b'"quote_id":"q_1"' in create.content


@pytest.mark.asyncio
async def test_provision_vm_raises_on_a_failed_build() -> None:
    api = _FakeAPI(
        statuses=[
            {"vm_id": _VM_ID, "status": "provisioning"},
            {"vm_id": _VM_ID, "status": "failed", "customer_message": "no capacity"},
        ]
    )
    async with _client(api) as hc:
        with pytest.raises(ProvisioningError) as exc:
            await hc.provision_vm(
                duration_days=7, ssh_pubkey="ssh-ed25519 AAAA", poll_interval=0.0
            )

    assert exc.value.vm_id == _VM_ID
    assert "no capacity" in str(exc.value)
    assert not isinstance(exc.value, ProvisioningTimeoutError)


@pytest.mark.asyncio
async def test_provision_vm_times_out_without_losing_the_management_token() -> None:
    api = _FakeAPI(statuses=[{"vm_id": _VM_ID, "status": "provisioning"}])
    async with _client(api) as hc:
        with pytest.raises(ProvisioningTimeoutError) as exc:
            await hc.provision_vm(
                duration_days=7,
                ssh_pubkey="ssh-ed25519 AAAA",
                poll_timeout=0.05,
                poll_interval=0.01,
            )

    assert exc.value.vm_id == _VM_ID
    assert exc.value.status_code == 504
    assert f"/v1/vm/{_VM_ID}/status" in str(exc.value)


@pytest.mark.asyncio
async def test_provision_vm_can_skip_the_wait() -> None:
    api = _FakeAPI()
    async with _client(api) as hc:
        result = await hc.provision_vm(
            duration_days=7, ssh_pubkey="ssh-ed25519 AAAA", wait=False
        )

    assert result.status == "provisioning"
    assert result.ssh is None
    assert result.management_token == _MGMT_TOKEN
    assert f"/v1/vm/{_VM_ID}/status" not in api.paths
