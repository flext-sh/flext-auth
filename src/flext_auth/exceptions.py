"""FLEXT Auth Exceptions - Authentication domain exceptions.

This module contains all exception classes for the authentication domain,
following flext-core standardization and extending FlextException.
"""

from __future__ import annotations

from typing import override

from flext_core import FlextExceptions


class FlextAuthExceptions(FlextExceptions):
    """Single unified auth exceptions class following FLEXT standards.

    Contains all exception definitions for authentication domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    """

    class FlextAuthError(FlextExceptions.BaseError):
        """Base authentication error extending FlextExceptions.BaseError."""

        @override
        def __init__(
            self,
            message: str,
            **kwargs: object,
        ) -> None:
            """Initialize authentication error with context using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context
            context = self._build_context(base_context)

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "AUTH_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextAuthValidationError(FlextAuthError):
        """Authentication validation error for invalid input data."""

        @override
        def __init__(
            self,
            message: str,
            *,
            field: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize validation error with field context using helpers.

            Args:
                message: Error message
                field: Field name that failed validation
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store field before extracting common kwargs
            self.field = field

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with validation-specific fields
            context = self._build_context(
                base_context,
                field=field,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextAuthenticationError(FlextAuthError):
        """Authentication failure error for login/credential issues."""

        @override
        def __init__(
            self,
            message: str,
            *,
            username: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize authentication error with username context using helpers.

            Args:
                message: Error message
                username: Username that failed authentication
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store username before extracting common kwargs
            self.username = username

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with authentication-specific fields
            context = self._build_context(
                base_context,
                username=username,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "AUTHENTICATION_FAILED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextAuthorizationError(FlextAuthError):
        """Authorization error for insufficient permissions."""

        @override
        def __init__(
            self,
            message: str,
            *,
            required_role: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize authorization error with role context using helpers.

            Args:
                message: Error message
                required_role: Role required for operation
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store required_role before extracting common kwargs
            self.required_role = required_role

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with authorization-specific fields
            context = self._build_context(
                base_context,
                required_role=required_role,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "AUTHORIZATION_DENIED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextTokenError(FlextAuthError):
        """Token-related errors for JWT and session tokens."""

        @override
        def __init__(
            self,
            message: str,
            *,
            token_type: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize token error with token type context using helpers.

            Args:
                message: Error message
                token_type: Type of token (JWT, session, etc.)
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store token_type before extracting common kwargs
            self.token_type = token_type

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with token-specific fields
            context = self._build_context(
                base_context,
                token_type=token_type,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "TOKEN_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextTokenExpiredError(FlextTokenError):
        """Specific error for expired tokens."""

        @override
        def __init__(
            self,
            message: str = "Token has expired",
            *,
            token_type: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize expired token error using helpers.

            Args:
                message: Error message
                token_type: Type of token that expired
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with token-specific fields
            context = self._build_context(
                base_context,
                token_type=token_type,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                token_type=token_type,
                code="TOKEN_EXPIRED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextTokenInvalidError(FlextTokenError):
        """Specific error for invalid tokens."""

        @override
        def __init__(
            self,
            message: str = "Token is invalid",
            *,
            token_type: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize invalid token error using helpers.

            Args:
                message: Error message
                token_type: Type of token that is invalid
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with token-specific fields
            context = self._build_context(
                base_context,
                token_type=token_type,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                token_type=token_type,
                code="TOKEN_INVALID",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextSessionError(FlextAuthError):
        """Session-related errors for session management."""

        @override
        def __init__(
            self,
            message: str,
            *,
            session_id: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize session error with session ID context using helpers.

            Args:
                message: Error message
                session_id: Session identifier
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store session_id before extracting common kwargs
            self.session_id = session_id

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with session-specific fields
            context = self._build_context(
                base_context,
                session_id=session_id,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "SESSION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextSessionNotFoundError(FlextSessionError):
        """Specific error for session not found."""

        @override
        def __init__(
            self,
            message: str = "Session not found",
            *,
            session_id: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize session not found error using helpers.

            Args:
                message: Error message
                session_id: Session identifier that was not found
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with session-specific fields
            context = self._build_context(
                base_context,
                session_id=session_id,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                session_id=session_id,
                code="SESSION_NOT_FOUND",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextUserError(FlextAuthError):
        """User-related errors for user management."""

        @override
        def __init__(
            self,
            message: str,
            *,
            user_id: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize user error with user ID context using helpers.

            Args:
                message: Error message
                user_id: User identifier
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store user_id before extracting common kwargs
            self.user_id = user_id

            # Extract common parameters using helper
            base_context, correlation_id, error_code = self._extract_common_kwargs(
                kwargs
            )

            # Build context with user-specific fields
            context = self._build_context(
                base_context,
                user_id=user_id,
            )

            # Call parent with complete error information
            super().__init__(
                message,
                code=error_code or "USER_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextUserNotFoundError(FlextUserError):
        """Specific error for user not found."""

        @override
        def __init__(
            self,
            message: str = "User not found",
            *,
            user_id: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize user not found error using helpers.

            Args:
                message: Error message
                user_id: User identifier that was not found
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with user-specific fields
            context = self._build_context(
                base_context,
                user_id=user_id,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                user_id=user_id,
                code="USER_NOT_FOUND",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextUserExistsError(FlextUserError):
        """Specific error for user already exists."""

        @override
        def __init__(
            self,
            message: str = "User already exists",
            *,
            identifier: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize user exists error using helpers.

            Args:
                message: Error message
                identifier: User identifier (username, email, etc.)
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Store identifier before extracting common kwargs
            self.identifier = identifier

            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with user-specific fields
            context = self._build_context(
                base_context,
                identifier=identifier,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                code="USER_EXISTS",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextAccountLockedError(FlextAuthenticationError):
        """Specific error for locked user accounts."""

        @override
        def __init__(
            self,
            message: str = "Account is locked",
            *,
            username: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize account locked error using helpers.

            Args:
                message: Error message
                username: Username of locked account
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with authentication-specific fields
            context = self._build_context(
                base_context,
                username=username,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                username=username,
                code="ACCOUNT_LOCKED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextAccountDisabledError(FlextAuthenticationError):
        """Specific error for disabled user accounts."""

        @override
        def __init__(
            self,
            message: str = "Account is disabled",
            *,
            username: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize account disabled error using helpers.

            Args:
                message: Error message
                username: Username of disabled account
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context with authentication-specific fields
            context = self._build_context(
                base_context,
                username=username,
            )

            # Call parent with specific error code
            super().__init__(
                message,
                username=username,
                code="ACCOUNT_DISABLED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextPasswordValidationError(FlextAuthValidationError):
        """Error for password validation failures."""

        @override
        def __init__(
            self,
            message: str = "Password validation failed",
            **kwargs: object,
        ) -> None:
            """Initialize password validation error using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context
            context = self._build_context(base_context)

            # Call parent with specific error code
            super().__init__(
                message,
                code="PASSWORD_VALIDATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextRateLimitExceededError(FlextAuthError):
        """Error for rate limit exceeded."""

        @override
        def __init__(
            self,
            message: str = "Rate limit exceeded",
            **kwargs: object,
        ) -> None:
            """Initialize rate limit error using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context
            context = self._build_context(base_context)

            # Call parent with specific error code
            super().__init__(
                message,
                code="RATE_LIMIT_EXCEEDED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextConfigurationError(FlextAuthError):
        """Error for configuration issues."""

        @override
        def __init__(
            self,
            message: str = "Configuration error",
            **kwargs: object,
        ) -> None:
            """Initialize configuration error using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context
            context = self._build_context(base_context)

            # Call parent with specific error code
            super().__init__(
                message,
                code="CONFIGURATION_ERROR",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextSessionExpiredError(FlextSessionError):
        """Error for expired sessions."""

        @override
        def __init__(
            self,
            message: str = "Session has expired",
            **kwargs: object,
        ) -> None:
            """Initialize session expired error using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context
            context = self._build_context(base_context)

            # Call parent with specific error code
            super().__init__(
                message,
                code="SESSION_EXPIRED",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextSessionInvalidError(FlextSessionError):
        """Error for invalid sessions."""

        @override
        def __init__(
            self,
            message: str = "Session is invalid",
            **kwargs: object,
        ) -> None:
            """Initialize session invalid error using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context
            context = self._build_context(base_context)

            # Call parent with specific error code
            super().__init__(
                message,
                code="SESSION_INVALID",
                context=context,
                correlation_id=correlation_id,
            )

    class FlextUserAlreadyExistsError(FlextUserExistsError):
        """Error for when user already exists."""

        @override
        def __init__(
            self,
            message: str = "User already exists",
            **kwargs: object,
        ) -> None:
            """Initialize user already exists error using helpers.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract common parameters using helper
            base_context, correlation_id, _ = self._extract_common_kwargs(kwargs)

            # Build context
            context = self._build_context(base_context)

            # Call parent with specific error code
            super().__init__(
                message,
                code="USER_ALREADY_EXISTS",
                context=context,
                correlation_id=correlation_id,
            )


__all__ = [
    "FlextAuthExceptions",
]
