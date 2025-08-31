"""FLEXT Auth Exceptions - Inheriting from flext-core foundation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Following FLEXT_REFACTORING_PROMPT.md: Inherit from FlextExceptions base class.
"""

from __future__ import annotations

from flext_core import FlextExceptions

from flext_auth.typings import FlextAuthTypes


class FlextAuthError(FlextExceptions.BaseError):
    """Base exception for all authentication errors."""

    def __init__(
        self,
        message: FlextAuthTypes.ErrorMessage,
        error_code: FlextAuthTypes.String = "AUTH_ERROR",
    ) -> None:
        super().__init__(message, code=error_code)


class FlextAuthValidationError(FlextAuthError):
    """Authentication validation error."""

    def __init__(self, message: FlextAuthTypes.ErrorMessage) -> None:
        super().__init__(message, "AUTH_VALIDATION_ERROR")


class FlextAuthCredentialsError(FlextAuthError):
    """Invalid credentials error."""

    def __init__(
        self, message: FlextAuthTypes.ErrorMessage = "Invalid credentials"
    ) -> None:
        super().__init__(message, "AUTH_INVALID_CREDENTIALS")


class FlextAuthTokenError(FlextAuthError):
    """JWT token error."""

    def __init__(self, message: FlextAuthTypes.ErrorMessage) -> None:
        super().__init__(message, "AUTH_TOKEN_ERROR")


class FlextAuthPermissionError(FlextAuthError):
    """Permission denied error."""

    def __init__(
        self, message: FlextAuthTypes.ErrorMessage = "Permission denied"
    ) -> None:
        super().__init__(message, "AUTH_PERMISSION_DENIED")


class FlextAuthSessionError(FlextAuthError):
    """Session error."""

    def __init__(self, message: FlextAuthTypes.ErrorMessage) -> None:
        super().__init__(message, "AUTH_SESSION_ERROR")


# Backward compatibility alias
FlextAuthException = FlextAuthError

__all__ = [
    "FlextAuthCredentialsError",
    "FlextAuthError",
    "FlextAuthException",
    "FlextAuthPermissionError",
    "FlextAuthSessionError",
    "FlextAuthTokenError",
    "FlextAuthValidationError",
]
