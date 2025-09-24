"""FLEXT Auth Exceptions - Authentication domain exceptions.

This module contains all exception classes for the authentication domain,
following flext-core standardization and extending FlextException.
"""

from flext_core import FlextExceptions


class FlextAuthExceptions(FlextExceptions):
    """Single unified auth exceptions class following FLEXT standards.

    Contains all exception definitions for authentication domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    """

    class FlextAuthError(FlextExceptions.BaseError):
        """Base authentication error extending FlextExceptions.BaseError."""

        def __init__(self, message: str, error_code: str | None = None) -> None:
            """Initialize authentication error with proper code handling."""
            super().__init__(message, code=error_code)

    class FlextAuthValidationError(FlextAuthError):
        """Authentication validation error for invalid input data."""

        def __init__(self, message: str, field: str | None = None) -> None:
            """Initialize validation error with field context."""
            super().__init__(message, "VALIDATION_ERROR")
            self.field = field

    class FlextAuthenticationError(FlextAuthError):
        """Authentication failure error for login/credential issues."""

        def __init__(self, message: str, username: str | None = None) -> None:
            """Initialize authentication error with username context."""
            super().__init__(message, "AUTHENTICATION_FAILED")
            self.username = username

    class FlextAuthorizationError(FlextAuthError):
        """Authorization error for insufficient permissions."""

        def __init__(self, message: str, required_role: str | None = None) -> None:
            """Initialize authorization error with role context."""
            super().__init__(message, "AUTHORIZATION_DENIED")
            self.required_role = required_role

    class FlextTokenError(FlextAuthError):
        """Token-related errors for JWT and session tokens."""

        def __init__(self, message: str, token_type: str | None = None) -> None:
            """Initialize token error with token type context."""
            super().__init__(message, "TOKEN_ERROR")
            self.token_type = token_type

    class FlextTokenExpiredError(FlextTokenError):
        """Specific error for expired tokens."""

        def __init__(
            self, message: str = "Token has expired", token_type: str | None = None
        ) -> None:
            """Initialize expired token error."""
            super().__init__(message, token_type)
            # Override parent code for specific token expiry
            self.code = "TOKEN_EXPIRED"

    class FlextTokenInvalidError(FlextTokenError):
        """Specific error for invalid tokens."""

        def __init__(
            self, message: str = "Token is invalid", token_type: str | None = None
        ) -> None:
            """Initialize invalid token error."""
            super().__init__(message, token_type)
            # Override parent code for specific token invalidity
            self.code = "TOKEN_INVALID"

    class FlextSessionError(FlextAuthError):
        """Session-related errors for session management."""

        def __init__(self, message: str, session_id: str | None = None) -> None:
            """Initialize session error with session ID context."""
            super().__init__(message, "SESSION_ERROR")
            self.session_id = session_id

    class FlextSessionNotFoundError(FlextSessionError):
        """Specific error for session not found."""

        def __init__(
            self, message: str = "Session not found", session_id: str | None = None
        ) -> None:
            """Initialize session not found error."""
            super().__init__(message, session_id)
            # Override parent code for specific session not found
            self.code = "SESSION_NOT_FOUND"

    class FlextUserError(FlextAuthError):
        """User-related errors for user management."""

        def __init__(self, message: str, user_id: str | None = None) -> None:
            """Initialize user error with user ID context."""
            super().__init__(message, "USER_ERROR")
            self.user_id = user_id

    class FlextUserNotFoundError(FlextUserError):
        """Specific error for user not found."""

        def __init__(
            self, message: str = "User not found", user_id: str | None = None
        ) -> None:
            """Initialize user not found error."""
            super().__init__(message, user_id)
            # Override parent code for specific user not found
            self.code = "USER_NOT_FOUND"

    class FlextUserExistsError(FlextUserError):
        """Specific error for user already exists."""

        def __init__(
            self, message: str = "User already exists", identifier: str | None = None
        ) -> None:
            """Initialize user exists error."""
            super().__init__(message)
            # Override parent code for specific user exists
            self.code = "USER_EXISTS"
            self.identifier = identifier

    class FlextAccountLockedError(FlextAuthenticationError):
        """Specific error for locked user accounts."""

        def __init__(
            self, message: str = "Account is locked", username: str | None = None
        ) -> None:
            """Initialize account locked error."""
            super().__init__(message, username)
            # Override parent code for specific account locked
            self.code = "ACCOUNT_LOCKED"

    class FlextAccountDisabledError(FlextAuthenticationError):
        """Specific error for disabled user accounts."""

        def __init__(
            self, message: str = "Account is disabled", username: str | None = None
        ) -> None:
            """Initialize account disabled error."""
            super().__init__(message, username)
            # Override parent code for specific account disabled
            self.code = "ACCOUNT_DISABLED"


__all__ = [
    "FlextAuthExceptions",
]
