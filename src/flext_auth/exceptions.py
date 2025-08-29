"""FLEXT Auth Exception System - Single consolidated exception management system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

SINGLE CONSOLIDATED MODULE following FLEXT architectural patterns.
All exception functionality consolidated into FlextAuthExceptionSystem.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

from flext_core import FlextExceptions, FlextResult


class FlextAuthExceptionSystem(FlextExceptions):
    """SINGLE CONSOLIDATED CLASS for all authentication exception functionality.

    Following FLEXT architectural patterns - consolidates ALL exception functionality
    including error codes, exception classes, factory methods, and error handling into one main class
    with nested classes for organization.

    CONSOLIDATED CLASSES: FlextAuthErrorCodes + FlextAuthError + FlextAuthExceptionSystem
    """

    # ==========================================================================
    # CONSTANTS AND CONFIGURATION
    # ==========================================================================

    # Default error messages (not passwords/secrets)
    DEFAULT_AUTH_ERROR_MESSAGE: ClassVar[str] = "Authentication error occurred"  # Error message, not secret
    DEFAULT_TOKEN_ERROR_MESSAGE: ClassVar[str] = "Token validation failed"  # Error message, not secret  # noqa: S105
    DEFAULT_SESSION_ERROR_MESSAGE: ClassVar[str] = "Session validation failed"  # Error message, not secret

    # ==========================================================================
    # NESTED CLASSES FOR ORGANIZATION
    # ==========================================================================

    class ErrorCodes(StrEnum):
        """Nested consolidated error codes for all authentication scenarios."""

        # Base errors
        AUTH_ERROR = "AUTH_ERROR"
        AUTH_FAILED = "AUTH_FAILED"
        AUTH_DENIED = "AUTH_DENIED"

        # Authentication errors
        INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
        ACCOUNT_LOCKED = "AUTH_ACCOUNT_LOCKED"
        ACCOUNT_INACTIVE = "AUTH_ACCOUNT_INACTIVE"

        # Token errors (error codes, not passwords/secrets)
        TOKEN_ERROR = "AUTH_TOKEN_ERROR"  # Error code, not secret  # noqa: S105
        INVALID_TOKEN = "AUTH_INVALID_TOKEN"  # Error code, not secret  # noqa: S105
        EXPIRED_TOKEN = "AUTH_TOKEN_EXPIRED"  # Error code, not secret  # noqa: S105

        # Session errors
        SESSION_ERROR = "AUTH_SESSION_ERROR"
        INVALID_SESSION = "AUTH_INVALID_SESSION"
        EXPIRED_SESSION = "AUTH_SESSION_EXPIRED"

        # Permission errors
        PERMISSION_DENIED = "AUTH_PERMISSION_DENIED"
        INSUFFICIENT_PERMISSION = "AUTH_INSUFFICIENT_PERMISSION"
        ROLE_REQUIRED = "AUTH_ROLE_REQUIRED"

        # Validation errors (error codes, not passwords/secrets)
        VALIDATION_ERROR = "AUTH_VALIDATION_ERROR"  # Error code, not secret
        PASSWORD_INVALID = "AUTH_PASSWORD_INVALID"  # Error code, not secret  # noqa: S105

    class AuthError(Exception):
        """NESTED CONSOLIDATED authentication exception handling all authentication scenarios.

        DRY PRINCIPLE: Single large class instead of multiple inheritance hierarchies.
        Handles all authentication, authorization, token, session, and validation errors.
        """

        def __init__(
            self,
            message: str,
            error_code: FlextAuthExceptionSystem.ErrorCodes | str | None = None,
            *,
            # Authentication context
            username: str | None = None,
            user_id: str | None = None,
            # Token context
            token: str | None = None,
            token_type: str | None = None,
            # Session context
            session_id: str | None = None,
            # Permission context
            required_permission: str | None = None,
            required_role: str | None = None,
            # Validation context
            field: str | None = None,
            # Additional context
            context: dict[str, str | int | float | bool] | None = None,
        ) -> None:
            """Initialize consolidated authentication error."""
            super().__init__(message)

            # Core error information
            self.message = message
            self.error_code = str(
                error_code or FlextAuthExceptionSystem.ErrorCodes.AUTH_ERROR
            )

            # Authentication context
            self.username = username
            self.user_id = user_id

            # Token context
            self.token = token
            self.token_type = token_type

            # Session context
            self.session_id = session_id

            # Permission context
            self.required_permission = required_permission
            self.required_role = required_role

            # Validation context
            self.field = field

            # Additional context
            self.context = context or {}

        def __str__(self) -> str:
            """String representation with context information."""
            parts = [f"[{self.error_code}] {self.message}"]

            # Add relevant context
            if self.username:
                parts.append(f"username={self.username}")
            if self.user_id:
                parts.append(f"user_id={self.user_id}")
            if self.session_id:
                parts.append(f"session_id={self.session_id}")
            if self.required_permission:
                parts.append(f"required_permission={self.required_permission}")
            if self.required_role:
                parts.append(f"required_role={self.required_role}")
            if self.field:
                parts.append(f"field={self.field}")

            return " | ".join(parts)

        def to_result(self) -> FlextResult[None]:
            """Convert exception to FlextResult for railway-oriented programming."""
            return FlextResult[None].fail(str(self), error_code=self.error_code)

        # =============================================================================
        # FACTORY METHODS - DRY creation patterns for common scenarios
        # =============================================================================

        @classmethod
        def authentication_failed(
            cls,
            message: str = "Authentication failed",
            *,
            username: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create authentication failure error."""
            return cls(
                message,
                FlextAuthExceptionSystem.ErrorCodes.AUTH_FAILED,
                username=username,
            )

        @classmethod
        def invalid_credentials(
            cls,
            username: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create invalid credentials error."""
            return cls(
                "Invalid credentials",
                FlextAuthExceptionSystem.ErrorCodes.INVALID_CREDENTIALS,
                username=username,
            )

        @classmethod
        def account_locked(
            cls,
            username: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create account locked error."""
            return cls(
                "Account is locked",
                FlextAuthExceptionSystem.ErrorCodes.ACCOUNT_LOCKED,
                username=username,
            )

        @classmethod
        def account_inactive(
            cls,
            username: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create account inactive error."""
            return cls(
                "Account is inactive",
                FlextAuthExceptionSystem.ErrorCodes.ACCOUNT_INACTIVE,
                username=username,
            )

        @classmethod
        def authorization_denied(
            cls,
            message: str = "Access denied",
            *,
            username: str | None = None,
            required_permission: str | None = None,
            required_role: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create authorization denial error."""
            return cls(
                message,
                FlextAuthExceptionSystem.ErrorCodes.AUTH_DENIED,
                username=username,
                required_permission=required_permission,
                required_role=required_role,
            )

        @classmethod
        def invalid_token(
            cls,
            token_type: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create invalid token error."""
            return cls(
                "Invalid token",
                FlextAuthExceptionSystem.ErrorCodes.INVALID_TOKEN,
                token_type=token_type,
            )

        @classmethod
        def expired_token(
            cls,
            token_type: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create expired token error."""
            return cls(
                "Token has expired",
                FlextAuthExceptionSystem.ErrorCodes.EXPIRED_TOKEN,
                token_type=token_type,
            )

        @classmethod
        def invalid_session(
            cls,
            session_id: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create invalid session error."""
            return cls(
                "Invalid session",
                FlextAuthExceptionSystem.ErrorCodes.INVALID_SESSION,
                session_id=session_id,
            )

        @classmethod
        def expired_session(
            cls,
            session_id: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create expired session error."""
            return cls(
                "Session has expired",
                FlextAuthExceptionSystem.ErrorCodes.EXPIRED_SESSION,
                session_id=session_id,
            )

        @classmethod
        def insufficient_permission(
            cls,
            required_permission: str,
            username: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create insufficient permission error."""
            return cls(
                f"Insufficient permission: '{required_permission}' required",
                FlextAuthExceptionSystem.ErrorCodes.INSUFFICIENT_PERMISSION,
                username=username,
                required_permission=required_permission,
            )

        @classmethod
        def role_required(
            cls,
            required_role: str,
            username: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create role required error."""
            return cls(
                f"Role '{required_role}' required",
                FlextAuthExceptionSystem.ErrorCodes.ROLE_REQUIRED,
                username=username,
                required_role=required_role,
            )

        @classmethod
        def validation_error(
            cls,
            message: str,
            field: str | None = None,
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create validation error."""
            return cls(
                message,
                FlextAuthExceptionSystem.ErrorCodes.VALIDATION_ERROR,
                field=field,
            )

        @classmethod
        def password_validation_error(
            cls,
            message: str = "Password does not meet requirements",
        ) -> FlextAuthExceptionSystem.AuthError:
            """Create password validation error."""
            return cls(
                message,
                FlextAuthExceptionSystem.ErrorCodes.PASSWORD_INVALID,
                field="password",
            )

    # ==========================================================================
    # MAIN CONSOLIDATED CLASS IMPLEMENTATION
    # ==========================================================================

    # ==========================================================================
    # PUBLIC API METHODS - Exception creation and handling
    # ==========================================================================

    def create_auth_error(
        self,
        message: str,
        error_code: ErrorCodes | str | None = None,
        *,
        username: str | None = None,
        user_id: str | None = None,
        token: str | None = None,
        token_type: str | None = None,
        session_id: str | None = None,
        required_permission: str | None = None,
        required_role: str | None = None,
        field: str | None = None,
        context: dict[str, str | int | float | bool] | None = None,
    ) -> AuthError:
        """Create authentication error with context."""
        return self.AuthError(
            message,
            error_code or self.ErrorCodes.AUTH_ERROR,
            username=username,
            user_id=user_id,
            token=token,
            token_type=token_type,
            session_id=session_id,
            required_permission=required_permission,
            required_role=required_role,
            field=field,
            context=context,
        )

    def handle_exception(
        self,
        e: Exception,
        context: dict[str, str | int | float | bool] | None = None,
    ) -> FlextResult[None]:
        """Handle any exception and convert to FlextResult."""
        if isinstance(e, self.AuthError):
            return e.to_result()

        # Convert generic exception to auth error
        auth_error = self.AuthError(
            str(e), self.ErrorCodes.AUTH_ERROR, context=context or {}
        )
        return auth_error.to_result()

    def validate_and_raise(
        self,
        *,
        condition: bool,  # FBT001: Boolean condition parameter is appropriate for validation
        error_message: str,
        error_code: ErrorCodes | str | None = None,
        username: str | None = None,
        user_id: str | None = None,
        token: str | None = None,
        token_type: str | None = None,
        session_id: str | None = None,
        required_permission: str | None = None,
        required_role: str | None = None,
        field: str | None = None,
        context: dict[str, str | int | float | bool] | None = None,
    ) -> None:
        """Validate condition and raise error if false."""
        if not condition:
            raise self.AuthError(
                error_message,
                error_code or self.ErrorCodes.AUTH_ERROR,
                username=username,
                user_id=user_id,
                token=token,
                token_type=token_type,
                session_id=session_id,
                required_permission=required_permission,
                required_role=required_role,
                field=field,
                context=context,
            )

    @classmethod
    def get_error_codes(cls) -> type[ErrorCodes]:
        """Get error codes enum class."""
        return cls.ErrorCodes

    @classmethod
    def get_auth_error_class(cls) -> type[AuthError]:
        """Get authentication error class."""
        return cls.AuthError


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT pattern
# =============================================================================

# Export nested classes for external access (backward compatibility)
FlextAuthErrorCodes = FlextAuthExceptionSystem.ErrorCodes
FlextAuthError = FlextAuthExceptionSystem.AuthError

# All exception types are now just the single consolidated class
FlextAuthorizationError = FlextAuthExceptionSystem.AuthError
FlextInvalidCredentialsError = FlextAuthExceptionSystem.AuthError
FlextAccountLockedError = FlextAuthExceptionSystem.AuthError
FlextAccountInactiveError = FlextAuthExceptionSystem.AuthError
FlextTokenError = FlextAuthExceptionSystem.AuthError
FlextInvalidTokenError = FlextAuthExceptionSystem.AuthError
FlextExpiredTokenError = FlextAuthExceptionSystem.AuthError
FlextSessionError = FlextAuthExceptionSystem.AuthError
FlextInvalidSessionError = FlextAuthExceptionSystem.AuthError
FlextExpiredSessionError = FlextAuthExceptionSystem.AuthError
FlextInsufficientPermissionError = FlextAuthExceptionSystem.AuthError
FlextRoleRequiredError = FlextAuthExceptionSystem.AuthError
FlextPasswordValidationError = FlextAuthExceptionSystem.AuthError

# Type alias for backward compatibility - FlextExceptions already imported from flext_core

__all__: list[str] = [
    # Main consolidated exception classes
    "FlextAccountInactiveError",
    "FlextAccountLockedError",
    "FlextAuthError",
    "FlextAuthErrorCodes",
    "FlextAuthExceptionSystem",
    "FlextAuthorizationError",
    "FlextExceptions",
    "FlextExpiredSessionError",
    "FlextExpiredTokenError",
    "FlextInsufficientPermissionError",
    "FlextInvalidCredentialsError",
    "FlextInvalidSessionError",
    "FlextInvalidTokenError",
    "FlextPasswordValidationError",
    "FlextRoleRequiredError",
    "FlextSessionError",
    "FlextTokenError",
]
