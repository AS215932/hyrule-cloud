"""Regression coverage for production-safe structured tracebacks."""

from __future__ import annotations

import json

from hyrule_cloud.logging_config import SAFE_DICT_TRACEBACKS


def test_structured_tracebacks_never_serialize_frame_locals() -> None:
    secret_marker = "must-never-reach-logs"

    try:
        raise RuntimeError("provider authentication failed")
    except RuntimeError:
        event = SAFE_DICT_TRACEBACKS(
            None,
            "error",
            {"event": "provider_failed", "exc_info": True},
        )

    payload = json.dumps(event)
    assert secret_marker not in payload
    assert '"locals"' not in payload
    assert "RuntimeError" in payload
