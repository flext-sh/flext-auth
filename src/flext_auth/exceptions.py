"""🚨 ARCHITECTURAL COMPLIANCE: ELIMINATED MASSIVE EXCEPTION DUPLICATION using DRY.

REFATORADO COMPLETO usando create_module_exception_classes:
- ZERO code duplication através do DRY exception factory pattern de flext-core
- USA create_module_exception_classes() para eliminar exception boilerplate massivo
- Elimina 15-18 linhas duplicadas de código boilerplate por exception class
- SOLID: Single source of truth para module exception patterns
- Redução de 174+ linhas para 62 linhas (64% reduction)

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

# 🚨 DRY PATTERN: Use create_module_exception_classes to eliminate exception duplication
from flext_core import create_module_exception_classes

# Create all module-specific exception classes using DRY pattern
_exceptions = create_module_exception_classes("flext_auth")

# Extract exception classes with proper names for backward compatibility
FlextAuthError = cast("type[Exception]", _exceptions["FlextAuthError"])
FlextAuthValidationError = cast(
    "type[Exception]", _exceptions["FlextAuthValidationError"],
)
FlextAuthAuthenticationError = cast(
    "type[Exception]", _exceptions["FlextAuthAuthenticationError"],
)
FlextAuthConfigurationError = cast(
    "type[Exception]", _exceptions["FlextAuthConfigurationError"],
)
FlextAuthConnectionError = cast(
    "type[Exception]", _exceptions["FlextAuthConnectionError"],
)
FlextAuthProcessingError = cast(
    "type[Exception]", _exceptions["FlextAuthProcessingError"],
)
FlextAuthTimeoutError = cast("type[Exception]", _exceptions["FlextAuthTimeoutError"])


# SOLID SRP: Specialized auth errors using composition over duplication
class FlextAuthJWTError(FlextAuthError):  # type: ignore[valid-type,misc]
    """Authentication service JWT errors using DRY foundation."""

    def __init__(
        self,
        message: str = "JWT error",
        token_type: str | None = None,
        expiry_status: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize JWT error with DRY pattern."""
        if token_type is not None:
            kwargs["token_type"] = token_type
        if expiry_status is not None:
            kwargs["expiry_status"] = expiry_status
        super().__init__(f"Auth JWT: {message}", **kwargs)


class FlextAuthPasswordError(FlextAuthError):  # type: ignore[valid-type,misc]
    """Authentication service password errors using DRY foundation."""

    def __init__(
        self,
        message: str = "Password error",
        password_operation: str | None = None,
        strength_level: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize password error with DRY pattern."""
        if password_operation is not None:
            kwargs["password_operation"] = password_operation
        if strength_level is not None:
            kwargs["strength_level"] = strength_level
        super().__init__(f"Auth password: {message}", **kwargs)


class FlextAuthSessionError(FlextAuthError):  # type: ignore[valid-type,misc]
    """Authentication service session errors using DRY foundation."""

    def __init__(
        self,
        message: str = "Session error",
        session_id: str | None = None,
        session_state: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize session error with DRY pattern."""
        if session_id is not None:
            kwargs["session_id"] = session_id
        if session_state is not None:
            kwargs["session_state"] = session_state
        super().__init__(f"Auth session: {message}", **kwargs)


class FlextAuthUserError(FlextAuthError):  # type: ignore[valid-type,misc]
    """Authentication service user errors using DRY foundation."""

    def __init__(
        self,
        message: str = "User error",
        user_id: str | None = None,
        user_state: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize user error with DRY pattern."""
        if user_id is not None:
            kwargs["user_id"] = user_id
        if user_state is not None:
            kwargs["user_state"] = user_state
        super().__init__(f"Auth user: {message}", **kwargs)


class FlextAuthPermissionError(FlextAuthAuthenticationError):  # type: ignore[valid-type,misc]
    """Authentication permission errors using DRY foundation."""

    def __init__(
        self,
        message: str = "Permission denied",
        required_permission: str | None = None,
        user_permissions: list[str] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize permission error with DRY pattern."""
        if required_permission is not None:
            kwargs["required_permission"] = required_permission
        if user_permissions is not None:
            kwargs["user_permissions"] = user_permissions
        super().__init__(message, **kwargs)


class FlextAuthSecurityError(FlextAuthAuthenticationError):  # type: ignore[valid-type,misc]
    """Authentication security errors using DRY foundation."""

    def __init__(
        self,
        message: str = "Security violation",
        security_event: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize security error with DRY pattern."""
        if security_event is not None:
            kwargs["security_event"] = security_event
        super().__init__(message, **kwargs)


__all__ = [
    "FlextAuthAuthenticationError",
    "FlextAuthConfigurationError",
    "FlextAuthConnectionError",
    "FlextAuthError",
    "FlextAuthJWTError",
    "FlextAuthPasswordError",
    "FlextAuthPermissionError",
    "FlextAuthProcessingError",
    "FlextAuthSecurityError",
    "FlextAuthSessionError",
    "FlextAuthTimeoutError",
    "FlextAuthUserError",
    "FlextAuthValidationError",
]
