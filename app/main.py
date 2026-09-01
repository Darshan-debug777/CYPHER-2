"""FastAPI application entry point."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from app.api.routes import health, incidents, investigation
from app.config import settings
from app.core.errors import AppError, ModuleError, NotFoundError, ValidationError
from app.core.logging import setup_logging
from app.schemas.api import ErrorResponse

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Backend API for SIH26 Agentic AI Cybersecurity Assistant",
)

app.include_router(health.router)
app.include_router(investigation.router, prefix=settings.api_prefix)
app.include_router(incidents.router, prefix=settings.api_prefix)


@app.exception_handler(AppError)
async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
    status_code = 400
    if isinstance(exc, NotFoundError):
        status_code = 404
    elif isinstance(exc, ModuleError):
        status_code = 502
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(error=exc.message, code=exc.code, details=exc.details).model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    serializable_errors = []
    for err in exc.errors():
        clean = dict(err)
        if "ctx" in clean and clean["ctx"]:
            clean["ctx"] = {k: str(v) for k, v in clean["ctx"].items()}
        if "input" in clean and not isinstance(clean["input"], (str, int, float, bool, type(None), list, dict)):
            clean["input"] = str(clean["input"])
        serializable_errors.append(clean)

    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="Request validation failed",
            code="validation_error",
            details={"errors": serializable_errors},
        ).model_dump(),
    )


@app.exception_handler(PydanticValidationError)
async def pydantic_error_handler(_request: Request, exc: PydanticValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="Schema validation failed",
            code="validation_error",
            details={"errors": exc.errors()},
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            code="internal_error",
            details={"detail": str(exc)} if settings.debug else {},
        ).model_dump(),
    )
