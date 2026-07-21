"""x402 client construction and durable, conservative spend reservations."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from eth_account import Account
from x402 import AbortResult, PaymentCreationContext, max_amount, prefer_network, x402Client
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner

from hyrule_cloud_mcp.config import USDC_ASSETS, Settings


class SpendLimitError(RuntimeError):
    """A payment would exceed an operator-owned spend boundary."""


@dataclass(frozen=True, slots=True)
class SpendReservation:
    reservation_id: str
    day: str
    amount_atomic: int
    total_atomic: int


class SpendLedger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS spend_reservations (
                reservation_id TEXT PRIMARY KEY,
                utc_day TEXT NOT NULL,
                amount_atomic INTEGER NOT NULL CHECK (amount_atomic > 0),
                resource_url TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS spend_reservations_day_idx ON spend_reservations (utc_day)"
        )
        return connection

    def reserve(
        self,
        *,
        amount_atomic: int,
        daily_budget_atomic: int,
        resource_url: str,
        now: datetime | None = None,
    ) -> SpendReservation:
        if amount_atomic <= 0:
            raise SpendLimitError("payment amount must be positive")
        observed = now or datetime.now(UTC)
        if observed.tzinfo is None:
            raise ValueError("reservation timestamps must be timezone-aware")
        day = observed.astimezone(UTC).date().isoformat()
        reservation_id = uuid.uuid4().hex
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT COALESCE(SUM(amount_atomic), 0) FROM spend_reservations WHERE utc_day = ?",
                (day,),
            ).fetchone()
            current = int(row[0]) if row else 0
            total = current + amount_atomic
            if total > daily_budget_atomic:
                raise SpendLimitError(
                    f"daily x402 budget exceeded: {total} > {daily_budget_atomic} atomic units"
                )
            connection.execute(
                "INSERT INTO spend_reservations "
                "(reservation_id, utc_day, amount_atomic, resource_url, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    reservation_id,
                    day,
                    amount_atomic,
                    resource_url,
                    observed.astimezone(UTC).isoformat(),
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return SpendReservation(reservation_id, day, amount_atomic, total)


class PaymentGuard:
    def __init__(
        self,
        settings: Settings,
        allowed_path: str,
        ledger: SpendLedger,
        *,
        minimum_amount_atomic: int,
        maximum_amount_atomic: int | None,
    ) -> None:
        self.settings = settings
        self.allowed_path = allowed_path
        self.ledger = ledger
        self.minimum_amount_atomic = minimum_amount_atomic
        self.maximum_amount_atomic = maximum_amount_atomic
        self.expected_origin = urlsplit(settings.base_url)

    def __call__(self, context: PaymentCreationContext) -> AbortResult | None:
        if context.payment_required.x402_version != 2:
            return AbortResult("buyer MCP accepts only x402 v2 payment challenges")
        resource = getattr(context.payment_required, "resource", None)
        resource_url = resource.url if resource is not None else ""
        parsed = urlsplit(resource_url)
        expected_port = self.expected_origin.port or 443
        observed_port = parsed.port or (443 if parsed.scheme == "https" else None)
        if (
            parsed.scheme != self.expected_origin.scheme
            or parsed.hostname != self.expected_origin.hostname
            or observed_port != expected_port
            or parsed.username
            or parsed.password
            or parsed.path != self.allowed_path
        ):
            return AbortResult("payment resource is outside the exact allowed origin and path")

        requirements = context.selected_requirements
        network = str(getattr(requirements, "network", ""))
        asset = str(getattr(requirements, "asset", ""))
        expected_asset = USDC_ASSETS.get(network)
        if network != self.settings.preferred_network or expected_asset is None:
            return AbortResult("payment network is outside HYRULE_MCP_PREFERRED_NETWORK")
        if asset.lower() != expected_asset.lower():
            return AbortResult("payment asset is not the canonical USDC contract")

        amount = int(requirements.get_amount())
        if amount < self.minimum_amount_atomic:
            return AbortResult("payment is below the live manifest minimum")
        if self.maximum_amount_atomic is not None and amount > self.maximum_amount_atomic:
            return AbortResult("payment exceeds the live manifest maximum")
        if amount > self.settings.max_payment_atomic:
            return AbortResult("payment exceeds HYRULE_MCP_MAX_PAYMENT_USD")
        try:
            self.ledger.reserve(
                amount_atomic=amount,
                daily_budget_atomic=self.settings.daily_budget_atomic,
                resource_url=resource_url,
            )
        except SpendLimitError as exc:
            return AbortResult(str(exc))
        return None


def build_x402_client(
    settings: Settings,
    *,
    allowed_path: str,
    ledger: SpendLedger,
    minimum_amount_atomic: int,
    maximum_amount_atomic: int | None,
) -> x402Client:
    if not settings.private_key:
        raise ValueError("EVM_PRIVATE_KEY is required for paid Hyrule calls")
    account = Account.from_key(settings.private_key)
    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(account))
    client.register_policy(prefer_network(settings.preferred_network))
    client.register_policy(max_amount(settings.max_payment_atomic))
    client.on_before_payment_creation(
        PaymentGuard(
            settings,
            allowed_path,
            ledger,
            minimum_amount_atomic=minimum_amount_atomic,
            maximum_amount_atomic=maximum_amount_atomic,
        )
    )
    return client
