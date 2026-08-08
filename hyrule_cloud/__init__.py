"""Hyrule Cloud: x402-payable network infrastructure for AI agents on AS215932."""

# Single source of truth for the runtime version (pyproject.toml mirrors it).
# The project is not installed as a distribution in production or CI, so
# importlib.metadata cannot resolve it; a constant keeps the FastAPI app,
# the A2A agent card, and server.json in agreement.
__version__ = "0.2.0"
