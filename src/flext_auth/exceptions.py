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
            """Initialize authentication error with context.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
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
            """Initialize validation error with field context.

            Args:
                message: Error message
                field: Field name that failed validation
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.field = field

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["field"] = field

            # Call parent
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
            """Initialize authentication error with username context.

            Args:
                message: Error message
                username: Username that failed authentication
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.username = username

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["username"] = username

            # Call parent
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
            """Initialize authorization error with role context.

            Args:
                message: Error message
                required_role: Role required for operation
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.required_role = required_role

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["required_role"] = required_role

            # Call parent
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
            """Initialize token error with token type context.

            Args:
                message: Error message
                token_type: Type of token (JWT, session, etc.)
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.token_type = token_type

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["token_type"] = token_type

            # Call parent
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
            """Initialize expired token error.

            Args:
                message: Error message
                token_type: Type of token that expired
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["token_type"] = token_type

            # Call parent
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
            """Initialize invalid token error.

            Args:
                message: Error message
                token_type: Type of token that is invalid
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["token_type"] = token_type

            # Call parent
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
            """Initialize session error with session ID context.

            Args:
                message: Error message
                session_id: Session identifier
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.session_id = session_id

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["session_id"] = session_id

            # Call parent
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
            """Initialize session not found error.

            Args:
                message: Error message
                session_id: Session identifier that was not found
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["session_id"] = session_id

            # Call parent
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
            """Initialize user error with user ID context.

            Args:
                message: Error message
                user_id: User identifier
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.user_id = user_id

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")
            error_code = kwargs.get("error_code")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)
            if error_code is not None and not isinstance(error_code, str):
                error_code = str(error_code)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["user_id"] = user_id

            # Call parent
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
            """Initialize user not found error.

            Args:
                message: Error message
                user_id: User identifier that was not found
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["user_id"] = user_id

            # Call parent
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
            """Initialize user exists error.

            Args:
                message: Error message
                identifier: User identifier (username, email, etc.)
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.identifier = identifier

            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["identifier"] = identifier

            # Call parent
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
            """Initialize account locked error.

            Args:
                message: Error message
                username: Username of locked account
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["username"] = username

            # Call parent
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
            """Initialize account disabled error.

            Args:
                message: Error message
                username: Username of disabled account
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"
            context["username"] = username

            # Call parent
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
            """Initialize password validation error.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
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
            """Initialize rate limit error.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
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
            """Initialize configuration error.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
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
            """Initialize session expired error.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
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
            """Initialize session invalid error.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
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
            """Initialize user already exists error.

            Args:
                message: Error message
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            # Extract parameters
            base_context = kwargs.get("context", {})
            correlation_id = kwargs.get("correlation_id")

            # Ensure types
            if not isinstance(base_context, dict):
                base_context = {}
            if correlation_id is not None and not isinstance(correlation_id, str):
                correlation_id = str(correlation_id)

            # Build context
            context = dict(base_context)
            if "domain" not in context:
                context["domain"] = "authentication"
            if "service" not in context:
                context["service"] = "flext_auth"

            # Call parent
            super().__init__(
                message,
                code="USER_ALREADY_EXISTS",
                context=context,
                correlation_id=correlation_id,
            )


__all__ = [
    "FlextAuthExceptions",
]
