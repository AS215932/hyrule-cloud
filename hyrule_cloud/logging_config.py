"""Shared, secret-safe structured logging processors."""

from __future__ import annotations

import structlog

# structlog's ``dict_tracebacks`` convenience processor includes frame locals
# by default. Configuration objects contain credentials and tokens, so an
# exception raised while one is in scope would serialize those secrets into
# journald and Loki. Keep structured stack frames, but never capture locals.
SAFE_DICT_TRACEBACKS = structlog.processors.ExceptionRenderer(
    structlog.tracebacks.ExceptionDictTransformer(show_locals=False)
)
