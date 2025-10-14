"""FLEXT Auth API - Focused authentication facade with minimal over-engineering.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextCore

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.quickstart import FlextAuthQuickstart


class FlextAuth(FlextCore.Service):
    """Minimal authentication facade exposing only production-used methods.

    This facade provides only the 4 methods actually used in production
    across the FLEXT ecosystem, eliminating massive over-engineering.
    """

    def __init__(self) -> None:
        """Initialize with minimal dependencies using registry pattern."""
        super().__init__()

        # Use FlextCore.Container singleton for all dependencies
        container = FlextCore.Container.get_global()
        self._config = container.get("config").unwrap()
        self._dispatcher = container.get("dispatcher").unwrap_or(FlextCore.Dispatcher())
        self._user_service = container.get("user_service").unwrap()
        self._provider_service = container.get("provider_service").unwrap()

    def execute(self) -> FlextCore.Result[object]:
        """Execute method for FlextCore.Service interface.

        FlextAuth facade doesn't use generic execute pattern.
        Use specific auth methods like register_user() or authenticate_user() instead.
        """
        return FlextCore.Result[object].fail(
            "FlextAuth is focused - use specific auth methods like register_user() or authenticate_user()"
        )

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: FlextCore.Types.StringList | None = None,
        **extra_fields: object,
    ) -> FlextCore.Result[FlextAuthModels.User]:
        """Register a new user account.

        Args:
            username: Unique username for the user
            email: User's email address
            password: Plain text password (will be hashed)
            roles: User roles (defaults to ['user'])
            **extra_fields: Additional user fields

        Returns:
            FlextCore.Result containing the created User or error

        """
        return self._user_service.create_user(
            username=username,
            email=email,
            password=password,
            roles=roles,
            **extra_fields,
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = FlextAuthConstants.AuthDefaults.DEFAULT_PROVIDER,
    ) -> FlextCore.Result[FlextAuthModels.AuthToken]:
        """Authenticate a user with username/password.

        Args:
            username: User's username
            password: User's password
            provider: Authentication provider to use

        Returns:
            FlextCore.Result containing AuthToken or error

        """
        # First authenticate using user service
        auth_result = self._user_service.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextCore.Result[FlextAuthModels.AuthToken].fail(auth_result.error)

        user = auth_result.value

        # Generate tokens using provider
        return self._provider_service.generate_tokens_for_user(user, provider)

    def validate_token(self, token: str) -> FlextCore.Result[FlextAuthModels.User]:
        """Validate an authentication token.

        Args:
            token: JWT token to validate

        Returns:
            FlextCore.Result containing the authenticated User or error

        """
        # Use provider service for token validation
        return self._provider_service.validate_token_and_get_user(token)

    def get_user(self, user_id: str) -> FlextCore.Result[FlextAuthModels.User]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            FlextCore.Result containing the User or error

        """
        # Use user service for user retrieval
        return self._user_service.get_user_by_id(user_id)

    def generate_token_for_user(
        self,
        user_id: str,
        token_type: str = FlextAuthConstants.Jwt.BASIC_TOKEN_TYPE,
        expires_in_minutes: int | None = None,
    ) -> FlextCore.Result[FlextAuthModels.AuthToken]:
        """Generate an authentication token for an existing user.

        Args:
            user_id: User ID to generate token for
            token_type: Type of token (access, refresh, etc.)
            expires_in_minutes: Custom expiration time in minutes

        Returns:
            FlextCore.Result containing the AuthToken or error

        """
        # Get user first
        user_result = self.get_user(user_id)
        if user_result.is_failure:
            return FlextCore.Result[FlextAuthModels.AuthToken].fail(user_result.error)

        user = user_result.value

        # Use provider service to generate token
        return self._provider_service.generate_token_for_user(
            user, token_type, expires_in_minutes
        )

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
    ) -> FlextCore.Result[FlextAuthModels.AuthToken]:
        """Generate a JWT token for a user.

        Args:
            user_id: User ID to generate token for
            expires_in_minutes: Custom expiration time in minutes

        Returns:
            FlextCore.Result containing the AuthToken or error

        """
        return self.generate_token_for_user(
            user_id, FlextAuthConstants.Jwt.BEARER_TOKEN_TYPE, expires_in_minutes
        )

    def logout_user(self, session_id: str) -> FlextCore.Result[None]:
        """Logout user by session ID.

        Args:
            session_id: Session ID to logout

        Returns:
            FlextCore.Result indicating success or failure

        """
        # Use provider service for session management
        return self._provider_service.revoke_session(session_id)

    def get_user_sessions(
        self, user_id: str
    ) -> FlextCore.Result[list[FlextAuthModels.Session]]:
        """Get all active sessions for a user.

        Args:
            user_id: User ID to get sessions for

        Returns:
            FlextCore.Result containing list of sessions or error

        """
        # Use provider service for session retrieval
        return self._provider_service.get_user_sessions(user_id)

    def get_user_by_username(
        self, username: str
    ) -> FlextCore.Result[FlextAuthModels.User]:
        """Get user by username.

        Args:
            username: Username to search for

        Returns:
            FlextCore.Result containing the User or error

        """
        # Use user service for user retrieval
        return self._user_service.get_user_by_username(username)

    @staticmethod
    def quick_start(*, create_REDACTED_LDAP_BIND_PASSWORD: bool = True) -> FlextAuth:
        """Quick start method for backward compatibility.

        This method creates a FlextAuth instance with default configuration
        and optionally creates demo users for testing.

        Args:
            create_REDACTED_LDAP_BIND_PASSWORD: Whether to create an REDACTED_LDAP_BIND_PASSWORD user

        Returns:
            Configured FlextAuth instance

        """
        # Create quickstart wrapper
        quickstart = FlextAuthQuickstart()

        # Initialize with demo users if requested
        if create_REDACTED_LDAP_BIND_PASSWORD:
            result = quickstart.flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=True)
            if result.is_failure:
                # Log warning but don't fail - maintain backward compatibility
                pass

        # Return the underlying FlextAuth instance
        return quickstart.auth


# Module exports
__all__ = ["FlextAuth"]
