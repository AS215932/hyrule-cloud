"""Router-snapshot download backend availability."""

from __future__ import annotations

import os


def router_snapshot_download_enabled() -> bool:
    """Whether router snapshot artifacts are available on the API host.

    The collector currently writes artifacts on ``noc`` while the download
    handler reads local paths on ``api``.  Metadata ingestion alone therefore
    cannot make a snapshot downloadable.  Keep the paid route fail-closed
    until artifact transfer/shared storage is deployed and explicitly enabled.
    """
    return os.environ.get("HYRULE_BGP_ROUTER_SNAPSHOT_DOWNLOAD_ENABLED") == "1"
