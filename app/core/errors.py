"""Errores HTTP en formato RFC 7807 Problem Details (ADR-0004)."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import correlation_id_var

PROBLEM_JSON = "application/problem+json"
ERROR_BASE = "https://auth.boletera.local/errors/"


class ProblemError(Exception):
    def __init__(
        self,
        status: int,
        title: str,
        detail: str,
        slug: str = "about:blank",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.title = title
        self.detail = detail
        self.slug = slug
        self.headers = headers or {}


def unauthorized(detail: str = "No autenticado.", slug: str = "unauthorized") -> ProblemError:
    return ProblemError(401, "Unauthorized", detail, slug, headers={"WWW-Authenticate": "Bearer"})


def forbidden(detail: str = "Permisos insuficientes.") -> ProblemError:
    return ProblemError(403, "Forbidden", detail, "forbidden")


def not_found(detail: str) -> ProblemError:
    return ProblemError(404, "Not Found", detail, "not-found")


def bad_request(detail: str, slug: str = "invalid-request") -> ProblemError:
    return ProblemError(400, "Bad Request", detail, slug)


def conflict(detail: str, slug: str = "conflict") -> ProblemError:
    return ProblemError(409, "Conflict", detail, slug)


def too_many(detail: str, retry_after: int) -> ProblemError:
    return ProblemError(
        429, "Too Many Requests", detail, "rate-limited", headers={"Retry-After": str(retry_after)}
    )


def _problem(
    request: Request,
    status: int,
    title: str,
    detail: str,
    slug: str,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": slug if slug == "about:blank" else ERROR_BASE + slug,
        "title": title,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
        "correlation_id": correlation_id_var.get(),
    }
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem_error(request: Request, exc: ProblemError) -> JSONResponse:
        return _problem(request, exc.status, exc.title, exc.detail, exc.slug, exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "Error HTTP."
        return _problem(
            request,
            exc.status_code,
            _title(exc.status_code),
            detail,
            "about:blank",
            dict(exc.headers or {}),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "")} for e in exc.errors()]
        return _problem(
            request,
            422,
            "Unprocessable Entity",
            "Datos de entrada inválidos.",
            "validation-error",
            extra={"errors": errors},
        )


def _title(status: int) -> str:
    return {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        429: "Too Many Requests",
    }.get(status, "Error")
