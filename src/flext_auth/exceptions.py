"""Authentication service exception hierarchy using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Authentication service exceptions.
"""

from __future__ import annotations

from flext_core.exceptions import (
    FlextAuthenticationError,
    FlextConfigurationError,
    FlextConnectionError,
    FlextError,
    FlextProcessingError,
    FlextTimeoutError,
    FlextValidationError,
)


class FlextAuthError(FlextError):
    """Base exception for authentication service operations."""

    def __init__(
        self,
        message: str = "Authentication service error",
        user_id: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication service error with context."""
        context = kwargs.copy()
        if user_id is not None:
            context["user_id"] = user_id

        super().__init__(message, error_code="AUTH_SERVICE_ERROR", context=context)


class FlextAuthValidationError(FlextValidationError):
    """Authentication service validation errors."""

    def __init__(
        self,
        message: str = "Authentication validation failed",
        field: str | None = None,
        value: object = None,
        validation_type: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication validation error with context."""
        validation_details: dict[str, object] = {}
        if field is not None:
            validation_details["field"] = field
        if value is not None:
            validation_details["value"] = str(value)[:100]  # Truncate long values

        context = kwargs.copy()
        if validation_type is not None:
            context["validation_type"] = validation_type

        super().__init__(
            f"Auth validation: {message}",
            validation_details=validation_details,
            context=context,
        )


class FlextAuthAuthenticationError(FlextAuthenticationError):
    """Authentication service authentication errors."""

    def __init__(
        self,
        message: str = "Authentication failed",
        username: str | None = None,
        auth_method: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication error with context."""
        context = kwargs.copy()
        if username is not None:
            context["username"] = username
        if auth_method is not None:
            context["auth_method"] = auth_method

        super().__init__(f"Auth: {message}", **context)


class FlextAuthConfigurationError(FlextConfigurationError):
    """Authentication service configuration errors."""

    def __init__(
        self,
        message: str = "Authentication configuration error",
        config_key: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication configuration error with context."""
        context = kwargs.copy()
        if config_key is not None:
            context["config_key"] = config_key

        super().__init__(f"Auth config: {message}", **context)


class FlextAuthConnectionError(FlextConnectionError):
    """Authentication service connection errors."""

    def __init__(
        self,
        message: str = "Authentication connection failed",
        service_name: str | None = None,
        endpoint: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication connection error with context."""
        context = kwargs.copy()
        if service_name is not None:
            context["service_name"] = service_name
        if endpoint is not None:
            context["endpoint"] = endpoint

        super().__init__(f"Auth connection: {message}", **context)


class FlextAuthProcessingError(FlextProcessingError):
    """Authentication service processing errors."""

    def __init__(
        self,
        message: str = "Authentication processing failed",
        operation: str | None = None,
        user_id: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication processing error with context."""
        context = kwargs.copy()
        if operation is not None:
            context["operation"] = operation
        if user_id is not None:
            context["user_id"] = user_id

        super().__init__(f"Auth processing: {message}", **context)


class FlextAuthTimeoutError(FlextTimeoutError):
    """Authentication service timeout errors."""

    def __init__(
        self,
        message: str = "Authentication operation timed out",
        operation: str | None = None,
        timeout_seconds: float | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize authentication timeout error with context."""
        context = kwargs.copy()
        if operation is not None:
            context["operation"] = operation
        if timeout_seconds is not None:
            context["timeout_seconds"] = timeout_seconds

        super().__init__(f"Auth timeout: {message}", **context)


class FlextAuthJWTError(FlextAuthError):
    """Authentication service JWT errors."""

    def __init__(
        self,
        message: str = "JWT error",
        token_type: str | None = None,
        expiry_status: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize JWT error with context."""
        context = kwargs.copy()
        if token_type is not None:
            context["token_type"] = token_type
        if expiry_status is not None:
            context["expiry_status"] = expiry_status

        super().__init__(f"Auth JWT: {message}", context=context)


class FlextAuthPasswordError(FlextAuthError):
    """Authentication service password errors."""

    def __init__(
        self,
        message: str = "Password error",
        password_operation: str | None = None,
        strength_level: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize password error with context."""
        context = kwargs.copy()
        if password_operation is not None:
            context["password_operation"] = password_operation
        if strength_level is not None:
            context["strength_level"] = strength_level

        super().__init__(f"Auth password: {message}", context=context)


class FlextAuthSessionError(FlextAuthError):
    """Authentication service session errors."""

    def __init__(
        self,
        message: str = "Session error",
        session_id: str | None = None,
        session_state: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize session error with context."""
        context = kwargs.copy()
        if session_id is not None:
            context["session_id"] = session_id
        if session_state is not None:
            context["session_state"] = session_state

        super().__init__(f"Auth session: {message}", context=context)


class FlextAuthUserError(FlextAuthError):
    """Authentication service user errors."""

    def __init__(
        self,
        message: str = "User error",
        user_id: str | None = None,
        user_state: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize user error with context."""
        context = kwargs.copy()
        if user_state is not None:
            context["user_state"] = user_state

        super().__init__(f"Auth user: {message}", user_id=user_id, **context)


__all__ = [
    "FlextAuthAuthenticationError",
    "FlextAuthConfigurationError",
    "FlextAuthConnectionError",
    "FlextAuthError",
    "FlextAuthJWTError",
    "FlextAuthPasswordError",
    "FlextAuthProcessingError",
    "FlextAuthSessionError",
    "FlextAuthTimeoutError",
    "FlextAuthUserError",
    "FlextAuthValidationError",
]
