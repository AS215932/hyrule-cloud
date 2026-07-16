"""ASGI middleware that ed25519-signs paid 2xx JSON responses (trust layer).

Signs the exact response body a buyer receives so the measurement is verifiable
against the key published in /.well-known/jwks.json. Only enabled paid-catalog
operations are signed; free endpoints, non-2xx (402/501), and non-JSON/streaming
responses pass through untouched. Soft-fail: a signing error returns the body
unsigned rather than 500ing, and no signer configured is a full passthrough.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from hyrule_cloud.services.discovery import DISCOVERY, discovery_for
from hyrule_cloud.trust.measurements import MeasurementSigner

log = structlog.get_logger()

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_EXPOSE_HEADERS = b"Hyrule-Signature, Hyrule-Signature-Key"
_MATCHERS: list[tuple[str, str, re.Pattern[str]]] | None = None


def _template_regex(template: str) -> re.Pattern[str]:
    parts = [
        r"[^/]+" if seg.startswith("{") and seg.endswith("}") else re.escape(seg)
        for seg in template.split("/")
    ]
    return re.compile("^" + "/".join(parts) + "$")


def _matchers() -> list[tuple[str, str, re.Pattern[str]]]:
    global _MATCHERS
    if _MATCHERS is None:
        _MATCHERS = [
            (method.upper(), template, _template_regex(template))
            for (method, template) in DISCOVERY
        ]
    return _MATCHERS


def _is_paid_operation(scope: Scope) -> bool:
    method = scope.get("method", "").upper()
    path = (scope.get("path", "") or "").rstrip("/") or "/"
    for op_method, template, regex in _matchers():
        if op_method != method or not regex.fullmatch(path):
            continue
        # discovery_for re-applies the per-op gate on the template, so a gated
        # -off op (which 501s) is never treated as signable.
        if discovery_for(op_method, template) is not None:
            return True
    return False


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return None


def _signer_from_scope(scope: Scope) -> MeasurementSigner | None:
    app = scope.get("app")
    state = getattr(getattr(app, "state", None), "_typed_state", None)
    trust = getattr(state, "trust", None)
    return getattr(trust, "measurements", None)


class ResponseSigningMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        signer = _signer_from_scope(scope)
        if signer is None or not _is_paid_operation(scope):
            await self.app(scope, receive, send)
            return

        start_message: Message | None = None
        chunks: list[bytes] = []
        signing = False

        async def send_wrapper(message: Message) -> None:
            nonlocal start_message, signing
            if message["type"] == "http.response.start":
                status = message["status"]
                content_type = _header(message.get("headers", []), b"content-type") or b""
                if 200 <= status < 300 and content_type.startswith(b"application/json"):
                    start_message = message
                    signing = True
                    return
                await send(message)
                return

            if message["type"] == "http.response.body" and signing and start_message is not None:
                chunks.append(message.get("body", b""))
                if message.get("more_body", False):
                    return
                body = b"".join(chunks)
                headers: list[tuple[bytes, bytes]] = list(start_message.get("headers", []))
                try:
                    signature = signer.sign(body)
                    headers.append((b"hyrule-signature", f"ed25519={signature}".encode()))
                    headers.append((b"hyrule-signature-key", signer.key_id.encode()))
                    _merge_expose_headers(headers)
                except Exception as exc:  # never fail the response over signing
                    log.warning("measurement_signing_failed", error=str(exc))
                await send({**start_message, "headers": headers})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return

            await send(message)

        await self.app(scope, receive, send_wrapper)


def _merge_expose_headers(headers: list[tuple[bytes, bytes]]) -> None:
    existing = _header(headers, b"access-control-expose-headers")
    if existing is None:
        headers.append((b"access-control-expose-headers", _EXPOSE_HEADERS))
        return
    for index, (key, _value) in enumerate(headers):
        if key.lower() == b"access-control-expose-headers":
            headers[index] = (key, existing + b", " + _EXPOSE_HEADERS)
            return
