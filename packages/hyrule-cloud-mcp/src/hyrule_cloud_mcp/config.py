"""Operator-owned configuration for the Hyrule buyer MCP."""

from __future__ import annotations

import os
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlsplit

USDC_ATOMIC_UNITS = 1_000_000
DEFAULT_SAFE_PREFIXES = (
    "hyrule.bgp.",
    "hyrule.dns.",
    "hyrule.ip.",
    "hyrule.mx.",
    "hyrule.nat.",
    "hyrule.path.",
    "hyrule.ports.",
    "hyrule.rdap.",
    "hyrule.threat.",
    "hyrule.voip.",
    "hyrule.web.",
    "hyrule.whois.",
)
INFRASTRUCTURE_PREFIXES = ("hyrule.vm.", "hyrule.network.")


def _usd_atomic(name: str, raw: str) -> int:
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError(f"{name} must be a decimal USD amount") from exc
    scaled = value * USDC_ATOMIC_UNITS
    if value <= 0 or scaled != scaled.to_integral_value():
        raise ValueError(f"{name} must be positive with at most six decimal places")
    return int(scaled)


def _default_ledger_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    root = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return root / "hyrule-cloud-mcp" / "spend.sqlite3"


@dataclass(frozen=True, slots=True)
class Settings:
    base_url: str
    private_key: str | None
    max_payment_atomic: int
    daily_budget_atomic: int
    ledger_path: Path
    capabilities: frozenset[str]
    capabilities_explicit: bool
    allow_infrastructure: bool
    preferred_network: str
    timeout_seconds: float = 60.0
    max_response_bytes: int = 524_288

    @classmethod
    def from_env(cls) -> Settings:
        base_url = os.environ.get("HYRULE_MCP_BASE_URL", "https://cloud.hyrule.host").rstrip("/")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("HYRULE_MCP_BASE_URL must be an HTTPS origin without a path")

        maximum = _usd_atomic(
            "HYRULE_MCP_MAX_PAYMENT_USD",
            os.environ.get("HYRULE_MCP_MAX_PAYMENT_USD", "0.10"),
        )
        daily = _usd_atomic(
            "HYRULE_MCP_DAILY_BUDGET_USD",
            os.environ.get("HYRULE_MCP_DAILY_BUDGET_USD", "1.00"),
        )
        if daily < maximum:
            raise ValueError("HYRULE_MCP_DAILY_BUDGET_USD must cover at least one max payment")

        raw_capabilities = os.environ.get("HYRULE_MCP_CAPABILITIES", "")
        capabilities = frozenset(
            value.strip() for value in raw_capabilities.split(",") if value.strip()
        )
        ledger = Path(
            os.environ.get("HYRULE_MCP_LEDGER_PATH", str(_default_ledger_path()))
        ).expanduser()
        return cls(
            base_url=base_url,
            private_key=os.environ.get("EVM_PRIVATE_KEY") or None,
            max_payment_atomic=maximum,
            daily_budget_atomic=daily,
            ledger_path=ledger,
            capabilities=capabilities,
            capabilities_explicit=bool(raw_capabilities.strip()),
            allow_infrastructure=os.environ.get("HYRULE_MCP_ALLOW_INFRASTRUCTURE") == "1",
            preferred_network=os.environ.get("HYRULE_MCP_PREFERRED_NETWORK", "eip155:8453"),
        )

    def allows(self, capability_id: str) -> bool:
        if capability_id.startswith(INFRASTRUCTURE_PREFIXES):
            return (
                self.allow_infrastructure
                and self.capabilities_explicit
                and capability_id in self.capabilities
            )
        if self.capabilities_explicit:
            return capability_id in self.capabilities
        return capability_id.startswith(DEFAULT_SAFE_PREFIXES)
