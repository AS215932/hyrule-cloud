"""BGPStream historical-job backend availability."""

from __future__ import annotations

import os


def bgpstream_worker_enabled() -> bool:
    """Whether a BGPStream processing worker is deployed.

    Queued /v1/bgp/jobs rows are only ever fulfilled by an external worker
    that claims them through /internal/bgp/jobs. Until one is live, paid job
    creation is refused before charging (and the operation is hidden from the
    catalog) rather than billing for a job that never completes. Deploys flip
    HYRULE_BGPSTREAM_WORKER_ENABLED=1 alongside the worker to re-list it.
    """
    return os.environ.get("HYRULE_BGPSTREAM_WORKER_ENABLED") == "1"
