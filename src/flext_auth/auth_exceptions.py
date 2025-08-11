"""FLEXT Auth Exceptions - Authentication-specific exception classes.

This module provides authentication-specific exception classes following PEP8
strict naming patterns. It defines a hierarchy of exceptions for different
authentication and authorization scenarios in the FLEXT ecosystem.

Architecture:
    - Exception Layer: Structured error handling
    - Hierarchy: Clear exception inheritance for specific error types
    - Context: Rich error context for debugging and logging

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations


# =============================================================================
# BASE AUTHENTICATION EXCEPTIONS
# =============================================================================


class FlextAuthError(Exception):
    """Base exception for all authentication-related errors."""

    def __init__(self, message: str, error_code: str = "AUTH_ERROR") -> None:
        """Initialize authentication error.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class FlextAuthenticationError(FlextAuthError):
    """Exception raised for authentication failures."""

    def __init__(self, message: str = "Authentication failed") -> None:
        """Initialize authentication error."""
        super().__init__(message, "AUTH_FAILED")


class FlextAuthorizationError(FlextAuthError):
    """Exception raised for authorization failures."""

    def __init__(self, message: str = "Access denied") -> None:
        """Initialize authorization error."""
        super().__init__(message, "AUTH_DENIED")


# =============================================================================
# SPECIFIC AUTHENTICATION EXCEPTIONS
# =============================================================================


class FlextInvalidCredentialsError(FlextAuthenticationError):
    """Exception raised for invalid username/password."""

    def __init__(self, message: str = "Invalid credentials") -> None:
        """Initialize invalid credentials error."""
        super().__init__(message)
        self.error_code = "AUTH_INVALID_CREDENTIALS"


class FlextAccountLockedError(FlextAuthenticationError):
    """Exception raised for locked user accounts."""

    def __init__(self, message: str = "Account is locked") -> None:
        """Initialize account locked error."""
        super().__init__(message)
        self.error_code = "AUTH_ACCOUNT_LOCKED"


class FlextAccountInactiveError(FlextAuthenticationError):
    """Exception raised for inactive user accounts."""

    def __init__(self, message: str = "Account is inactive") -> None:
        """Initialize account inactive error."""
        super().__init__(message)
        self.error_code = "AUTH_ACCOUNT_INACTIVE"


# =============================================================================
# TOKEN EXCEPTIONS
# =============================================================================


class FlextTokenError(FlextAuthError):
    """Base exception for token-related errors."""

    def __init__(self, message: str) -> None:
        """Initialize token error."""
        super().__init__(message, "AUTH_TOKEN_ERROR")


class FlextInvalidTokenError(FlextTokenError):
    """Exception raised for invalid tokens."""

    def __init__(self, message: str = "Invalid token") -> None:
        """Initialize invalid token error."""
        super().__init__(message)
        self.error_code = "AUTH_INVALID_TOKEN"


class FlextExpiredTokenError(FlextTokenError):
    """Exception raised for expired tokens."""

    def __init__(self, message: str = "Token has expired") -> None:
        """Initialize expired token error."""
        super().__init__(message)
        self.error_code = "AUTH_TOKEN_EXPIRED"


# =============================================================================
# SESSION EXCEPTIONS
# =============================================================================


class FlextSessionError(FlextAuthError):
    """Base exception for session-related errors."""

    def __init__(self, message: str) -> None:
        """Initialize session error."""
        super().__init__(message, "AUTH_SESSION_ERROR")


class FlextInvalidSessionError(FlextSessionError):
    """Exception raised for invalid sessions."""

    def __init__(self, message: str = "Invalid session") -> None:
        """Initialize invalid session error."""
        super().__init__(message)
        self.error_code = "AUTH_INVALID_SESSION"


class FlextExpiredSessionError(FlextSessionError):
    """Exception raised for expired sessions."""

    def __init__(self, message: str = "Session has expired") -> None:
        """Initialize expired session error."""
        super().__init__(message)
        self.error_code = "AUTH_SESSION_EXPIRED"


# =============================================================================
# PERMISSION EXCEPTIONS
# =============================================================================


class FlextPermissionError(FlextAuthorizationError):
    """Exception raised for permission-related errors."""

    def __init__(self, message: str = "Permission denied") -> None:
        """Initialize permission error."""
        super().__init__(message)
        self.error_code = "AUTH_PERMISSION_DENIED"


class FlextInsufficientPermissionError(FlextPermissionError):
    """Exception raised for insufficient permissions."""

    def __init__(self, required_permission: str) -> None:
        """Initialize insufficient permission error."""
        message = f"Insufficient permission: '{required_permission}' required"
        super().__init__(message)
        self.required_permission = required_permission


class FlextRoleRequiredError(FlextAuthorizationError):
    """Exception raised when specific role is required."""

    def __init__(self, required_role: str) -> None:
        """Initialize role required error."""
        message = f"Role '{required_role}' required"
        super().__init__(message)
        self.error_code = "AUTH_ROLE_REQUIRED"
        self.required_role = required_role


# =============================================================================
# VALIDATION EXCEPTIONS
# =============================================================================


class FlextValidationError(FlextAuthError):
    """Exception raised for validation errors."""

    def __init__(self, message: str, field: str | None = None) -> None:
        """Initialize validation error."""
        super().__init__(message, "AUTH_VALIDATION_ERROR")
        self.field = field


class FlextPasswordValidationError(FlextValidationError):
    """Exception raised for password validation errors."""

    def __init__(self, message: str = "Password does not meet requirements") -> None:
        """Initialize password validation error."""
        super().__init__(message, "password")
        self.error_code = "AUTH_PASSWORD_INVALID"


# =============================================================================
# EXPORTS - Clean exceptions API
# =============================================================================

__all__: list[str] = [
    # Base exceptions
    "FlextAuthError",
    "FlextAuthenticationError", 
    "FlextAuthorizationError",
    # Authentication exceptions
    "FlextInvalidCredentialsError",
    "FlextAccountLockedError",
    "FlextAccountInactiveError",
    # Token exceptions
    "FlextTokenError",
    "FlextInvalidTokenError",
    "FlextExpiredTokenError",
    # Session exceptions
    "FlextSessionError",
    "FlextInvalidSessionError",
    "FlextExpiredSessionError",
    # Permission exceptions
    "FlextPermissionError",
    "FlextInsufficientPermissionError",
    "FlextRoleRequiredError",
    # Validation exceptions
    "FlextValidationError",
    "FlextPasswordValidationError",
]