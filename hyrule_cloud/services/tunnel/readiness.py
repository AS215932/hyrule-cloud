"""Readiness gate for the reverse-SSH tunnel catalog entry.

Mirrors the other discovery gates (sync, config-backed): the tunnel operations
stay hidden from the catalog / curated OpenAPI until the operator has seeded the
daemon control token. Live daemon health is enforced at request time (create
returns 503 when the daemon is unreachable), not here.
"""
from __future__ import annotations


def tunnel_service_ready() -> bool:
    from hyrule_cloud.config import HyruleConfig

    return bool(HyruleConfig().tunnel_proxy_token)
