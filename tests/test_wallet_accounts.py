"""Wallet-native accounts: a settled x402 payer owns what they bought.

Before this, a browser purchase produced an ownerless VM plus a save-once
management token. The buyer had no account, so nothing appeared on the
dashboard and losing the token meant losing control of a paid VM.

Now the verified payer wallet is resolved to an account (created on the spot
if the wallet has none), the VM is attached to it, and browser callers get a
session cookie. Such an account has NO password — `password_hash` is NULL —
and authenticates by signing a wallet challenge.

The binding runs AFTER settlement, so every failure path here must degrade to
the old behaviour rather than raise: the customer has already been charged.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import select

from hyrule_cloud.api.routes import (
    _bind_payer_account,
    _settled_chain_id,
)
from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import (
    AccountRow,
    AccountWalletRow,
    Base,
    create_db_engine,
    create_session_factory,
)
from hyrule_cloud.domains.errors import DomainProblem
from hyrule_cloud.domains.wallet_auth import WalletAuthService
from hyrule_cloud.services.passwords import hash_password, verify_password

PAYER = "0x" + "a" * 40
OTHER_PAYER = "0x" + "b" * 40
BASE_CAIP2 = "eip155:8453"


@pytest_asyncio.fixture
async def sessions(tmp_path):
    engine = create_db_engine(f"sqlite+aiosqlite:///{tmp_path / 'wallet.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return create_session_factory(engine)


@pytest.fixture
def wallet_auth(sessions):
    return WalletAuthService(HyruleConfig(database_url="sqlite+aiosqlite://"), sessions)


def _gate(*, networks=((BASE_CAIP2, 8453),)):
    return SimpleNamespace(
        config=SimpleNamespace(
            enabled_networks=lambda: [
                SimpleNamespace(caip2=caip2, chain_id=chain_id) for caip2, chain_id in networks
            ]
        )
    )


def _request(app_state, *, network=BASE_CAIP2, is_api_key=False):
    """A stand-in for the settled-payment request.

    `_bind_payer_account` reaches app state through get_app_state(request),
    which reads request.app.state, and reads the settled network + api-key flag
    off request.state.
    """
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(_typed_state=app_state)),
        state=SimpleNamespace(payment_network=network, is_api_key=is_api_key),
    )


# --- chain resolution -------------------------------------------------------


def test_settled_chain_id_only_trusts_configured_networks():
    """The facilitator's network string is untrusted: an `eip155:<n>` we did
    not enable must never be parsed into a chain id."""
    request = _request(SimpleNamespace())
    assert _settled_chain_id(request, _gate()) == 8453

    request.state.payment_network = "eip155:999999"
    assert _settled_chain_id(request, _gate()) is None

    request.state.payment_network = ""
    assert _settled_chain_id(request, _gate()) is None


def test_settled_chain_id_survives_a_broken_gate_config():
    request = _request(SimpleNamespace())
    broken = SimpleNamespace(
        config=SimpleNamespace(
            enabled_networks=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )
    )
    assert _settled_chain_id(request, broken) is None


# --- account binding --------------------------------------------------------


@pytest.mark.asyncio
async def test_anonymous_payer_gets_a_passwordless_account(sessions, wallet_auth):
    app_state = SimpleNamespace(wallet_auth=wallet_auth)

    account_id, may_issue_session = await _bind_payer_account(
        _request(app_state), _gate(), PAYER, None
    )

    assert account_id is not None
    assert may_issue_session is True

    async with sessions() as session:
        account = await session.get(AccountRow, account_id)
        assert account is not None
        # The point of the feature: no password, not a random one nobody holds.
        assert account.password_hash is None
        bound = (
            await session.execute(
                select(AccountWalletRow).where(AccountWalletRow.account_id == account_id)
            )
        ).scalar_one()
        assert bound.address == PAYER.lower()
        assert bound.chain_id == 8453


@pytest.mark.asyncio
async def test_second_purchase_from_the_same_wallet_reuses_the_account(sessions, wallet_auth):
    app_state = SimpleNamespace(wallet_auth=wallet_auth)
    first, _ = await _bind_payer_account(_request(app_state), _gate(), PAYER, None)
    second, _ = await _bind_payer_account(_request(app_state), _gate(), PAYER, None)
    assert first == second

    async with sessions() as session:
        wallets = (
            await session.execute(
                select(AccountWalletRow).where(AccountWalletRow.address == PAYER.lower())
            )
        ).scalars().all()
        assert len(wallets) == 1


@pytest.mark.asyncio
async def test_api_key_caller_is_never_handed_a_browser_session(sessions, wallet_auth):
    """An API key already carries its own credential. It may own the VM, but
    it must not be given a browser session cookie."""
    app_state = SimpleNamespace(wallet_auth=wallet_auth)
    async with sessions() as session:
        account = AccountRow(account_id="H1234567890", password_hash=hash_password("x" * 20))
        session.add(account)
        session.add(
            AccountWalletRow(
                wallet_id="w-1",
                account_id="H1234567890",
                address=PAYER.lower(),
                chain_id=8453,
            )
        )
        await session.commit()

    account_id, may_issue_session = await _bind_payer_account(
        _request(app_state, is_api_key=True), _gate(), PAYER, None
    )
    assert account_id == "H1234567890"
    assert may_issue_session is False


# --- fail-safe behaviour (payment has already settled) ----------------------


@pytest.mark.asyncio
async def test_dev_bypass_sentinel_is_not_treated_as_a_wallet(wallet_auth):
    """Dev-bypass and admin waivers return sentinels like `0xDEV_TEST_WALLET`,
    not addresses. They must not mint accounts."""
    app_state = SimpleNamespace(wallet_auth=wallet_auth)
    for sentinel in ("0xDEV_TEST_WALLET", "unknown", "", "0xnothex"):
        assert await _bind_payer_account(_request(app_state), _gate(), sentinel, None) == (
            None,
            False,
        )


@pytest.mark.asyncio
async def test_missing_wallet_service_falls_back_instead_of_failing():
    account = SimpleNamespace(account_id="H1234567890")
    app_state = SimpleNamespace(wallet_auth=None)
    assert await _bind_payer_account(_request(app_state), _gate(), PAYER, account) == (
        "H1234567890",
        False,
    )


@pytest.mark.asyncio
async def test_unknown_chain_falls_back_to_the_session_account(wallet_auth):
    account = SimpleNamespace(account_id="H1234567890")
    app_state = SimpleNamespace(wallet_auth=wallet_auth)
    request = _request(app_state, network="eip155:999999")
    assert await _bind_payer_account(request, _gate(), PAYER, account) == (
        "H1234567890",
        False,
    )


@pytest.mark.asyncio
async def test_wallet_bound_to_another_account_does_not_fail_the_paid_create():
    """resolve_x402_owner raises 409 when the payer wallet belongs to someone
    else. The domains checkout can surface that because it resolves BEFORE
    settling. Here the money is already taken, so we fall back to the session
    account and log — never a 409 for a VM the customer paid for."""

    class Conflicting:
        async def resolve_x402_owner(self, **_kwargs):
            raise DomainProblem(409, "wallet_account_mismatch", "belongs to another account")

    account = SimpleNamespace(account_id="H1234567890")
    app_state = SimpleNamespace(wallet_auth=Conflicting())
    assert await _bind_payer_account(_request(app_state), _gate(), PAYER, account) == (
        "H1234567890",
        False,
    )


@pytest.mark.asyncio
async def test_unexpected_wallet_service_error_still_yields_a_vm():
    class Exploding:
        async def resolve_x402_owner(self, **_kwargs):
            raise RuntimeError("database on fire")

    app_state = SimpleNamespace(wallet_auth=Exploding())
    assert await _bind_payer_account(_request(app_state), _gate(), PAYER, None) == (None, False)


# --- passwordless accounts --------------------------------------------------


def test_verify_password_rejects_a_null_hash():
    """Wallet-only accounts have password_hash IS NULL. Verification must
    return False rather than raising on None."""
    assert verify_password(None, "anything at all") is False


@pytest.mark.asyncio
async def test_wallet_login_creates_a_passwordless_account(sessions, wallet_auth):
    owner, wallet, created = await wallet_auth.resolve_x402_owner(
        address=OTHER_PAYER,
        chain_id=8453,
        account=None,
        allow_link=True,
    )
    assert created is True
    assert owner.password_hash is None
    assert wallet.address == OTHER_PAYER.lower()

    async with sessions() as session:
        stored = await session.get(AccountRow, owner.account_id)
        assert stored is not None
        assert stored.password_hash is None
        # No password was ever set, so there is nothing to have changed.
        assert stored.password_changed_at is None


# --- end-to-end wiring through POST /v1/vm/create ---------------------------
#
# The unit tests above prove _bind_payer_account decides correctly. These prove
# the decision is actually USED: passed into create_vm as owner_account_id, and
# turned into a session cookie for the buyer.


class _Cfg:
    class Payment:
        price_vm_xs = 1
        price_vm_sm = 1
        price_vm_md = 1
        price_vm_lg = 1
        price_domain_markup = 1
        asset = "USDC"
        network = BASE_CAIP2
        dev_bypass_secret = ""

    class XCPNG:
        templates: dict[str, str] = {}

    payment = Payment()
    xcpng = XCPNG()
    deploy_domain = "deploy.hyrule.host"
    blocked_ports = [25]


class _OrchRecording:
    """Records the owner_account_id the route passes down."""

    def __init__(self):
        self.owner_account_ids: list[str | None] = []
        self.db = None

    def compute_price(self, request):
        from decimal import Decimal

        from hyrule_cloud.models import CostBreakdown

        return Decimal("1.00"), CostBreakdown(
            vm_cost="$1.00", domain_cost="$0.00", total="$1.00"
        )

    async def start_provisioning(self, vm_id):
        return None

    async def create_vm(
        self,
        request,
        owner_wallet,
        owner_account_id=None,
        start_provisioning=True,
        **kwargs,
    ):
        from hyrule_cloud.models import (
            VMStatus,
            generate_anon_management_token,
            generate_vm_id,
        )

        self.owner_account_ids.append(owner_account_id)

        class _Row:
            vm_id = generate_vm_id()
            status = VMStatus.PROVISIONING
            payment_tx = None

        return _Row(), generate_anon_management_token()


class _GateSettlingOnBase:
    """Mimics a settled payment on an enabled chain."""

    config = SimpleNamespace(
        enabled_networks=lambda: [SimpleNamespace(caip2=BASE_CAIP2, chain_id=8453)]
    )

    async def check_payment(self, request, amount, description, extra_body):
        from fastapi import Response as FastAPIResponse

        wallet = request.headers.get("X-Mock-Wallet")
        if not wallet:
            return FastAPIResponse(status_code=402)
        request.state.payment_tx = "0xMock"
        request.state.payment_network = BASE_CAIP2
        return wallet


@pytest_asyncio.fixture
async def paid_create_app(sessions, wallet_auth):
    from hyrule_cloud.app import app
    from hyrule_cloud.state import AppState

    orch = _OrchRecording()
    original = getattr(app.state, "_typed_state", None)
    app.state._typed_state = AppState(
        config=_Cfg(),
        orchestrator=orch,
        payment_gate=_GateSettlingOnBase(),
        network_provider=SimpleNamespace(),
        wallet_auth=wallet_auth,
    )
    yield app, orch
    app.state._typed_state = original


@pytest.mark.asyncio
async def test_paid_create_attaches_the_vm_to_the_payer_and_logs_them_in(
    paid_create_app, sessions
):
    from httpx import ASGITransport, AsyncClient

    app, orch = paid_create_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        res = await client.post(
            "/v1/vm/create",
            headers={"X-Mock-Wallet": PAYER},
            json={"duration_days": 7, "size": "xs", "ssh_pubkey": "ssh-ed25519 AAAA"},
        )

    assert res.status_code == 202, res.text

    # The VM is owned by an account, not left anonymous.
    assert len(orch.owner_account_ids) == 1
    owner_account_id = orch.owner_account_ids[0]
    assert owner_account_id is not None

    # That account is the one bound to the paying wallet.
    async with sessions() as session:
        bound = (
            await session.execute(
                select(AccountWalletRow).where(AccountWalletRow.address == PAYER.lower())
            )
        ).scalar_one()
        assert bound.account_id == owner_account_id

    # And the buyer is logged into it.
    assert "set-cookie" in res.headers, res.headers
    assert "hyr_sess" in res.headers["set-cookie"]


@pytest.mark.asyncio
async def test_paid_create_still_succeeds_when_the_wallet_service_is_down(
    paid_create_app,
):
    """A settled payment must never be lost to an account-binding failure."""
    from httpx import ASGITransport, AsyncClient

    app, orch = paid_create_app
    app.state._typed_state.wallet_auth = None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        res = await client.post(
            "/v1/vm/create",
            headers={"X-Mock-Wallet": PAYER},
            json={"duration_days": 7, "size": "xs", "ssh_pubkey": "ssh-ed25519 AAAA"},
        )

    assert res.status_code == 202, res.text
    # Falls back to the old anonymous + management-token behaviour.
    assert orch.owner_account_ids == [None]
    assert res.json()["management_token"].startswith("hyr_vm_")
