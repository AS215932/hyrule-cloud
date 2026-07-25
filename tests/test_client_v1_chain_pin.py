"""Regression tests for the x402 v1 legacy-scheme chain pin bypass.

`register_exact_evm_client`'s `networks=` parameter only restricts the V2
scheme registration; it unconditionally registers the V1 legacy scheme for
every network it supports (`x402.mechanisms.evm.exact.register.py`:
"Registers: V2: ... (or specific networks if provided); V1: All supported
EVM networks"). Without pruning, a client constructed with
`payment_network="eip155:8453"` (Base) would still sign a v1-format 402
challenge naming Polygon, Avalanche, or any other legacy network — directly
contradicting the documented "pinned to a single chain" guarantee in
`HyruleClient`'s docstring.

`_build_x402_client` prunes `client._schemes_v1` down to the one legacy
network name matching the pinned chain id right after registration. These
tests assert that pruning directly against the client's registration state,
the same style already used for the XO websocket reconnect regression
(`test_xcpng_ws_reconnect.py`) — asserting on internal wiring is how this
codebase pins down "the mechanism that caused the bug can't recur", not
just "today's fake challenge gets rejected".
"""

from __future__ import annotations

from hyrule_cloud.client import HyruleClient

# Throwaway key — deterministic, never funded, never used off-test. Same
# value as tests/test_client_payment.py's _TEST_KEY; not imported from
# there to avoid pulling in the full FastAPI app graph for what is a
# narrow, dependency-light check of _build_x402_client's registration state.
_TEST_KEY = "0x" + "11" * 32


def test_v1_schemes_pruned_to_the_pinned_chain_base() -> None:
    hc = HyruleClient("http://test", private_key=_TEST_KEY, payment_network="eip155:8453")
    assert hc._x402_client is not None
    assert set(hc._x402_client._schemes_v1) == {"base"}


def test_v1_schemes_pruned_to_a_different_pinned_chain_polygon() -> None:
    hc = HyruleClient("http://test", private_key=_TEST_KEY, payment_network="eip155:137")
    assert hc._x402_client is not None
    assert set(hc._x402_client._schemes_v1) == {"polygon"}


def test_v1_schemes_are_not_left_registered_for_every_legacy_network() -> None:
    """Direct assertion of the bug this fixes: pre-fix, `_schemes_v1` held
    every network in the SDK's V1_NETWORKS list (19 entries) regardless of
    the pin, so a v1 challenge on any of them was signed."""
    hc = HyruleClient("http://test", private_key=_TEST_KEY, payment_network="eip155:8453")
    assert hc._x402_client is not None
    v1_networks = set(hc._x402_client._schemes_v1)
    assert "polygon" not in v1_networks
    assert "avalanche" not in v1_networks
    assert len(v1_networks) == 1
