"""Per-process request-latency middleware (Block B).

Records every successful HTTP request's wall-clock duration into a bounded
rolling deque so `/v1/stats/runtime` can publish a live p50.

This is intentionally per-process and per-worker — the runtime endpoint
labels the source as `api-process-local-rolling-window` so the frontend
(and any honest reader) knows it's not fleet-wide. A real Prometheus-backed
fleet metric lives in plan Block H.

Cost: one perf_counter() call per request plus an O(1) append. The deque is
bounded so memory is constant.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

_WINDOW = 1000


class MetricsRecorder:
    """In-memory deque of recent request durations in milliseconds.

    Held on `app.state.metrics`. Public `record()` for the middleware,
    `percentile()` for the runtime endpoint. Not thread-safe in the strict
    sense, but FastAPI/uvicorn workers run one event loop per process and
    deque appends are GIL-protected — good enough for a p50 readout.
    """

    def __init__(self, window: int = _WINDOW) -> None:
        self._samples: deque[float] = deque(maxlen=window)

    def record(self, duration_ms: float) -> None:
        self._samples.append(duration_ms)

    def percentile(self, p: float = 0.5) -> int | None:
        """Return the p-th percentile rounded to whole milliseconds.

        Returns None when no samples have been recorded yet — the runtime
        endpoint substitutes a fallback so the frontend never shows null.
        """
        if not self._samples:
            return None
        sorted_samples = sorted(self._samples)
        idx = min(len(sorted_samples) - 1, int(len(sorted_samples) * p))
        return round(sorted_samples[idx])

    def sample_count(self) -> int:
        return len(self._samples)


async def metrics_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    recorder: MetricsRecorder | None = getattr(request.app.state, "metrics", None)
    # /health and the metrics endpoint itself would skew the sample with
    # synthetic load if we recorded them — they're cheap and constant-time.
    skip = request.url.path in ("/health", "/v1/stats/runtime")
    if recorder is None or skip:
        return await call_next(request)
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    recorder.record(elapsed_ms)
    return response


def install_metrics(app: FastAPI) -> MetricsRecorder:
    """Mount the middleware and wire a fresh recorder onto app.state."""
    recorder = MetricsRecorder()
    app.state.metrics = recorder
    app.middleware("http")(metrics_middleware)
    return recorder
