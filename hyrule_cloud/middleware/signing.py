"""ASGI middleware that ed25519-signs paid 2xx JSON responses.

Signs the exact response body a buyer receives so a measurement is verifiable
against the published key. Only enabled paid-catalog operations are signed (the
"signed paid measurement" contract); free endpoints, non-2xx (402/501), and
non-JSON/streaming responses pass through untouched. A signing failure never
breaks the response — the body is returned unsigned rather than 500ing.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from hyrule_cloud.services.discovery import match_enabled_operation
from hyrule_cloud.services.signing import ResponseSigner

log = structlog.get_logger()

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_EXPOSE_HEADERS = b"Hyrule-Signature, Hyrule-Signature-Key"


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return None


def _signer_from_scope(scope: Scope) -> ResponseSigner | None:
    app = scope.get("app")
    state = getattr(getattr(app, "state", None), "_typed_state", None)
    return getattr(state, "response_signer", None)


def _is_paid_operation(scope: Scope) -> bool:
    method = scope.get("method", "")
    path = scope.get("path", "")
    return match_enabled_operation(method, path) is not None


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
                    # Hold the start until we've buffered the body and can add
                    # the signature headers.
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
                    log.warning("response_signing_failed", error=str(exc))
                await send({**start_message, "headers": headers})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return

            await send(message)

        await self.app(scope, receive, send_wrapper)


def _merge_expose_headers(headers: list[tuple[bytes, bytes]]) -> None:
    """Add our signature headers to Access-Control-Expose-Headers so browser
    clients can read them under CORS, preserving any existing value."""
    existing = _header(headers, b"access-control-expose-headers")
    if existing is None:
        headers.append((b"access-control-expose-headers", _EXPOSE_HEADERS))
        return
    for index, (key, _value) in enumerate(headers):
        if key.lower() == b"access-control-expose-headers":
            headers[index] = (key, existing + b", " + _EXPOSE_HEADERS)
            return
