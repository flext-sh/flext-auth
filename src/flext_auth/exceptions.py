"""FLEXT Auth Exceptions - Type-safe error handling for authentication operations.

This module provides comprehensive exception handling for FLEXT Auth using the
flext-core exception factory pattern to eliminate code duplication. All exceptions
follow the railway-oriented programming pattern and integrate with FlextResult.

Architecture:
    - Exception Layer: Type-safe error handling
    - DRY Pattern: Uses flext-core exception factory to eliminate duplication
    - Railway-Oriented: Integrates with FlextResult[T] error handling
    - Hierarchical: Proper exception inheritance and categorization

Exception Hierarchy:
    FlextAuthError (base)
    ├── FlextAuthValidationError: Input validation failures
    ├── FlextAuthAuthenticationError: Authentication failures
    ├── FlextAuthConfigurationError: Configuration issues
    ├── FlextAuthConnectionError: External service connection failures
    ├── FlextAuthProcessingError: Business logic processing errors
    ├── FlextAuthTimeoutError: Operation timeout failures
    ├── FlextAuthSecurityError: Security policy violations
    └── FlextAuthPermissionError: Access control violations

TODO (Based on docs/TODO.md):
    - [ ] MEDIUM: Add error context and correlation IDs (Issue #9)
    - [ ] MEDIUM: Add error categorization system (Issue #9)
    - [ ] LOW: Add error analytics and monitoring (Issue #10)
    - [ ] LOW: Add error internationalization (Issue #12)

Current Project Status:
    ✅ Comprehensive exception hierarchy documented with proper inheritance
    ✅ Railway-oriented programming integration with FlextResult documented
    ✅ Security and authentication error patterns documented
    🔄 Implementation focus: Error context and correlation IDs for debugging

Design Patterns:
    - Factory Pattern: Exception creation through flext-core factory
    - Hierarchy Pattern: Proper exception inheritance
    - Context Pattern: Rich error context and details
    - Railway Pattern: Integration with FlextResult error handling

Error Categories:
    - Validation Errors: Input validation and format issues
    - Authentication Errors: Login and credential failures
    - Configuration Errors: Setup and configuration problems
    - Security Errors: Security policy violations
    - Permission Errors: Access control and authorization failures

Example Usage:
    >>> from flext_auth.exceptions import FlextAuthValidationError
    >>>
    >>> def validate_user_input(data):
    ...     if not data.get("username"):
    ...         raise FlextAuthValidationError(
    ...             "Username is required",
    ...             validation_details={"field": "username", "code": "REQUIRED"},
    ...         )

Error Context:
    All exceptions support rich context for debugging:
    - Error codes for programmatic handling
    - Validation details for input errors
    - Security context for audit logging
    - Performance metrics for monitoring

Integration Points:
    - FlextResult: Type-safe error handling
    - Logging: Structured error logging
    - Monitoring: Error metrics and analytics
    - Audit: Security event tracking

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

from flext_core import create_module_exception_classes

# Create all module-specific exception classes using DRY pattern
_exceptions = create_module_exception_classes("flext_auth")

# Extract exception classes with proper names for backward compatibility
FlextAuthError = cast("type[Exception]", _exceptions["FlextAuthError"])
FlextAuthValidationError = cast(
    "type[Exception]",
    _exceptions["FlextAuthValidationError"],
)
FlextAuthAuthenticationError = cast(
    "type[Exception]",
    _exceptions["FlextAuthAuthenticationError"],
)
FlextAuthConfigurationError = cast(
    "type[Exception]",
    _exceptions["FlextAuthConfigurationError"],
)
FlextAuthConnectionError = cast(
    "type[Exception]",
    _exceptions["FlextAuthConnectionError"],
)
FlextAuthProcessingError = cast(
    "type[Exception]",
    _exceptions["FlextAuthProcessingError"],
)
FlextAuthTimeoutError = cast("type[Exception]", _exceptions["FlextAuthTimeoutError"])


# Specialized auth errors using composition over duplication
# =============================================================================
# REFACTORING: Template Method Pattern - eliminates 16-line duplication
# =============================================================================


class FlextAuthSpecificError(FlextAuthError):  # type: ignore[valid-type,misc]
    """Template Method Pattern base for specific auth errors - DRY principle.

    SOLID REFACTORING: Eliminates 16 lines of similar code in 4 locations (mass = 94)
    using Template Method Pattern for exception initialization.
    """

    def __init__(
        self,
        message: str,
        error_prefix: str,
        context_fields: dict[str, str | None] | None = None,
        **kwargs: object,
    ) -> None:
        """Template method for specific auth error initialization."""
        # Template Method Pattern: Add context fields to kwargs if not None
        if context_fields:
            kwargs.update(
                {
                    field_name: field_value
                    for field_name, field_value in context_fields.items()
                    if field_value is not None
                },
            )

        # Template Method Pattern: Format message with error prefix
        super().__init__(f"Auth {error_prefix}: {message}", **kwargs)


class FlextAuthJWTError(FlextAuthSpecificError):
    """Authentication service JWT errors using Template Method Pattern."""

    def __init__(
        self,
        message: str = "JWT error",
        token_type: str | None = None,
        expiry_status: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize JWT error using Template Method Pattern."""
        context_fields = {
            "token_type": token_type,
            "expiry_status": expiry_status,
        }
        super().__init__(message, "JWT", context_fields, **kwargs)


class FlextAuthPasswordError(FlextAuthSpecificError):
    """Authentication service password errors using Template Method Pattern."""

    def __init__(
        self,
        message: str = "Password error",
        password_operation: str | None = None,
        strength_level: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize password error using Template Method Pattern."""
        context_fields = {
            "password_operation": password_operation,
            "strength_level": strength_level,
        }
        super().__init__(message, "password", context_fields, **kwargs)


class FlextAuthSessionError(FlextAuthSpecificError):
    """Authentication service session errors using Template Method Pattern."""

    def __init__(
        self,
        message: str = "Session error",
        session_id: str | None = None,
        session_state: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize session error using Template Method Pattern."""
        context_fields = {
            "session_id": session_id,
            "session_state": session_state,
        }
        super().__init__(message, "session", context_fields, **kwargs)


class FlextAuthUserError(FlextAuthSpecificError):
    """Authentication service user errors using Template Method Pattern."""

    def __init__(
        self,
        message: str = "User error",
        user_id: str | None = None,
        user_state: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize user error using Template Method Pattern."""
        context_fields = {
            "user_id": user_id,
            "user_state": user_state,
        }
        super().__init__(message, "user", context_fields, **kwargs)


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


__all__: list[str] = [
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
