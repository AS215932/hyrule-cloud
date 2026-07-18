"""stdio MCP surface for the spend-controlled Hyrule buyer."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from hyrule_cloud_mcp.buyer import Buyer, render
from hyrule_cloud_mcp.config import Settings

mcp = FastMCP(
    "Hyrule Cloud buyer",
    instructions=(
        "Discover Hyrule's live paid catalog by buyer intent, then call safe "
        "x402 diagnostic capabilities through operator-owned wallet and spend controls. "
        "Do not ask for, display, or pass a private key as a tool argument."
    ),
)


def _buyer() -> Buyer:
    return Buyer(Settings.from_env())


@mcp.tool()
async def discover_hyrule(query: str = "") -> str:
    """Find live Hyrule x402 resources by intent, capability, or stable ID.

    This reads the public manifest and never creates a payment.
    """

    return render(await _buyer().discover(query))


@mcp.tool()
async def call_hyrule(capability_id: str, arguments: dict[str, Any]) -> str:
    """Call one live Hyrule capability and automatically handle x402 v2 payment.

    Payment is possible only when the capability, exact origin/path, per-call
    amount, and durable daily budget all pass policy outside the model.
    """

    return render(await _buyer().call(capability_id, arguments))


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
