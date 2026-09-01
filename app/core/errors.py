"""Application error types and HTTP exception mapping."""

from typing import Any


class AppError(Exception):
    """Base application error."""

    def __init__(self, message: str, code: str = "app_error", details: dict[str, Any] | None = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(message)


class ValidationError(AppError):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, code="validation_error", details=details)


class NotFoundError(AppError):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, code="not_found", details=details)


class ModuleError(AppError):
    def __init__(self, module: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, code="module_error", details={"module": module, **(details or {})})


class ModuleTimeoutError(ModuleError):
    def __init__(self, module: str, timeout_seconds: float):
        super().__init__(
            module,
            f"Module '{module}' timed out after {timeout_seconds}s",
            details={"timeout_seconds": timeout_seconds},
        )


class EmptyResultError(ModuleError):
    def __init__(self, module: str, message: str = "Module returned empty result"):
        super().__init__(module, message, details={"empty": True})


class InvalidModuleOutputError(ModuleError):
    def __init__(self, module: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(module, message, details=details)
