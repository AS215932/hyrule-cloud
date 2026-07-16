"""RFC 9457 errors for the managed-domain API."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse


class DomainProblem(Exception):  # noqa: N818 - RFC 9457 calls this a problem detail
    """A safe, public error with stable machine-readable semantics."""

    def __init__(
        self,
        status: int,
        code: str,
        detail: str,
        *,
        title: str | None = None,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.detail = detail
        self.title = title or _title(status)
        self.headers = headers
        self.extra = extra or {}
        super().__init__(detail)


def problem_response(request: Request, exc: DomainProblem) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"https://cloud.hyrule.host/problems/{exc.code}",
        "title": exc.title,
        "status": exc.status,
        "detail": exc.detail,
        "instance": request.url.path,
        "code": exc.code,
    }
    body.update(exc.extra)
    return JSONResponse(
        status_code=exc.status,
        content=jsonable_encoder(body),
        headers=exc.headers,
        media_type="application/problem+json",
    )


def _title(status: int) -> str:
    return {
        400: "Invalid request",
        401: "Authentication required",
        403: "Not permitted",
        404: "Not found",
        409: "Conflict",
        412: "Precondition failed",
        413: "Payload too large",
        422: "Unprocessable request",
        428: "Precondition required",
        429: "Too many requests",
        502: "Registrar error",
        503: "Domain service unavailable",
    }.get(status, "Domain operation failed")
