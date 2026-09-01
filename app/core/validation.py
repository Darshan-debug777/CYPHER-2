"""Validate module outputs against Pydantic contracts."""

from typing import TypeVar

from pydantic import BaseModel, ValidationError as PydanticValidationError

from app.core.errors import EmptyResultError, InvalidModuleOutputError

T = TypeVar("T", bound=BaseModel)


def validate_module_output(module: str, model: type[T], data: object) -> T:
    """Ensure a module returned a valid Pydantic model instance."""
    if data is None:
        raise InvalidModuleOutputError(module, "Module returned None")

    if isinstance(data, model):
        return data

    try:
        return model.model_validate(data)
    except PydanticValidationError as exc:
        raise InvalidModuleOutputError(
            module,
            "Module output failed schema validation",
            details={"errors": exc.errors()},
        ) from exc


def validate_non_empty_list(module: str, items: list, label: str = "results") -> list:
    """Ensure a module returned a non-empty list."""
    if not items:
        raise EmptyResultError(module, f"Module returned empty {label}")
    return items


def validate_model_list(module: str, model: type[T], items: list) -> list[T]:
    """Validate every item in a module output list."""
    validated = validate_non_empty_list(module, items, model.__name__)
    return [validate_module_output(module, model, item) for item in validated]
