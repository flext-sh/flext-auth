"""FLEXT Auth Exceptions - Single consolidated exception system applying DRY principles.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

DRY PRINCIPLE APPLIED: One large consolidated class instead of many small modules.
"""

from __future__ import annotations

from enum import StrEnum

# Use flext-core base exception but with consolidated approach
from flext_core import FlextResult


class FlextAuthErrorCodes(StrEnum):
    """Consolidated error codes for all authentication scenarios."""

    # Base errors
    AUTH_ERROR = "AUTH_ERROR"
    AUTH_FAILED = "AUTH_FAILED"
    AUTH_DENIED = "AUTH_DENIED"

    # Authentication errors
    INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    ACCOUNT_LOCKED = "AUTH_ACCOUNT_LOCKED"
    ACCOUNT_INACTIVE = "AUTH_ACCOUNT_INACTIVE"

    # Token errors
    TOKEN_ERROR = "AUTH_TOKEN_ERROR"  # noqa: S105
    INVALID_TOKEN = "AUTH_INVALID_TOKEN"  # noqa: S105
    EXPIRED_TOKEN = "AUTH_TOKEN_EXPIRED"  # noqa: S105

    # Session errors
    SESSION_ERROR = "AUTH_SESSION_ERROR"
    INVALID_SESSION = "AUTH_INVALID_SESSION"
    EXPIRED_SESSION = "AUTH_SESSION_EXPIRED"

    # Permission errors
    PERMISSION_DENIED = "AUTH_PERMISSION_DENIED"
    INSUFFICIENT_PERMISSION = "AUTH_INSUFFICIENT_PERMISSION"
    ROLE_REQUIRED = "AUTH_ROLE_REQUIRED"

    # Validation errors
    VALIDATION_ERROR = "AUTH_VALIDATION_ERROR"
    PASSWORD_INVALID = "AUTH_PASSWORD_INVALID"  # noqa: S105


class FlextAuthError(Exception):
    """CONSOLIDATED authentication exception handling all authentication scenarios.

    DRY PRINCIPLE: Single large class instead of multiple inheritance hierarchies.
    Handles all authentication, authorization, token, session, and validation errors.
    """

    def __init__(
        self,
        message: str,
        error_code: FlextAuthErrorCodes | str = FlextAuthErrorCodes.AUTH_ERROR,
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
        """Initialize consolidated authentication error.

        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
            username: Username associated with error (if applicable)
            user_id: User ID associated with error (if applicable)
            token: Token associated with error (if applicable)
            token_type: Type of token (access, refresh, etc.)
            session_id: Session ID associated with error (if applicable)
            required_permission: Required permission for authorization errors
            required_role: Required role for authorization errors
            field: Field name for validation errors
            context: Additional context information

        """
        super().__init__(message)

        # Core error information
        self.message = message
        self.error_code = str(error_code)

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
    ) -> FlextAuthError:
        """Create authentication failure error."""
        return cls(
            message,
            FlextAuthErrorCodes.AUTH_FAILED,
            username=username,
        )

    @classmethod
    def invalid_credentials(
        cls,
        username: str | None = None,
    ) -> FlextAuthError:
        """Create invalid credentials error."""
        return cls(
            "Invalid credentials",
            FlextAuthErrorCodes.INVALID_CREDENTIALS,
            username=username,
        )

    @classmethod
    def account_locked(
        cls,
        username: str | None = None,
    ) -> FlextAuthError:
        """Create account locked error."""
        return cls(
            "Account is locked",
            FlextAuthErrorCodes.ACCOUNT_LOCKED,
            username=username,
        )

    @classmethod
    def account_inactive(
        cls,
        username: str | None = None,
    ) -> FlextAuthError:
        """Create account inactive error."""
        return cls(
            "Account is inactive",
            FlextAuthErrorCodes.ACCOUNT_INACTIVE,
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
    ) -> FlextAuthError:
        """Create authorization denial error."""
        return cls(
            message,
            FlextAuthErrorCodes.AUTH_DENIED,
            username=username,
            required_permission=required_permission,
            required_role=required_role,
        )

    @classmethod
    def invalid_token(
        cls,
        token_type: str | None = None,
    ) -> FlextAuthError:
        """Create invalid token error."""
        return cls(
            "Invalid token",
            FlextAuthErrorCodes.INVALID_TOKEN,
            token_type=token_type,
        )

    @classmethod
    def expired_token(
        cls,
        token_type: str | None = None,
    ) -> FlextAuthError:
        """Create expired token error."""
        return cls(
            "Token has expired",
            FlextAuthErrorCodes.EXPIRED_TOKEN,
            token_type=token_type,
        )

    @classmethod
    def invalid_session(
        cls,
        session_id: str | None = None,
    ) -> FlextAuthError:
        """Create invalid session error."""
        return cls(
            "Invalid session",
            FlextAuthErrorCodes.INVALID_SESSION,
            session_id=session_id,
        )

    @classmethod
    def expired_session(
        cls,
        session_id: str | None = None,
    ) -> FlextAuthError:
        """Create expired session error."""
        return cls(
            "Session has expired",
            FlextAuthErrorCodes.EXPIRED_SESSION,
            session_id=session_id,
        )

    @classmethod
    def insufficient_permission(
        cls,
        required_permission: str,
        username: str | None = None,
    ) -> FlextAuthError:
        """Create insufficient permission error."""
        return cls(
            f"Insufficient permission: '{required_permission}' required",
            FlextAuthErrorCodes.INSUFFICIENT_PERMISSION,
            username=username,
            required_permission=required_permission,
        )

    @classmethod
    def role_required(
        cls,
        required_role: str,
        username: str | None = None,
    ) -> FlextAuthError:
        """Create role required error."""
        return cls(
            f"Role '{required_role}' required",
            FlextAuthErrorCodes.ROLE_REQUIRED,
            username=username,
            required_role=required_role,
        )

    @classmethod
    def validation_error(
        cls,
        message: str,
        field: str | None = None,
    ) -> FlextAuthError:
        """Create validation error."""
        return cls(
            message,
            FlextAuthErrorCodes.VALIDATION_ERROR,
            field=field,
        )

    @classmethod
    def password_validation_error(
        cls,
        message: str = "Password does not meet requirements",
    ) -> FlextAuthError:
        """Create password validation error."""
        return cls(
            message,
            FlextAuthErrorCodes.PASSWORD_INVALID,
            field="password",
        )


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Single source approach
# =============================================================================

# All exception types are now just the single consolidated class
FlextAuthenticationError = FlextAuthError
FlextAuthorizationError = FlextAuthError
FlextInvalidCredentialsError = FlextAuthError
FlextAccountLockedError = FlextAuthError
FlextAccountInactiveError = FlextAuthError
FlextTokenError = FlextAuthError
FlextInvalidTokenError = FlextAuthError
FlextExpiredTokenError = FlextAuthError
FlextSessionError = FlextAuthError
FlextInvalidSessionError = FlextAuthError
FlextExpiredSessionError = FlextAuthError
FlextPermissionError = FlextAuthError
FlextInsufficientPermissionError = FlextAuthError
FlextRoleRequiredError = FlextAuthError
FlextValidationError = FlextAuthError
FlextPasswordValidationError = FlextAuthError


# =============================================================================
# EXPORTS - Single consolidated API
# =============================================================================

__all__: list[str] = [  # noqa: RUF022
    # Main consolidated exception class
    "FlextAuthError",
    "FlextAuthErrorCodes",

    # Backward compatibility aliases (all point to FlextAuthError)
    "FlextAccountInactiveError",
    "FlextAccountLockedError",
    "FlextAuthenticationError",
    "FlextAuthorizationError",
    "FlextExpiredSessionError",
    "FlextExpiredTokenError",
    "FlextInsufficientPermissionError",
    "FlextInvalidCredentialsError",
    "FlextInvalidSessionError",
    "FlextInvalidTokenError",
    "FlextPasswordValidationError",
    "FlextPermissionError",
    "FlextRoleRequiredError",
    "FlextSessionError",
    "FlextTokenError",
    "FlextValidationError",
]
