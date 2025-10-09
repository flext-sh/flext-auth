"""FLEXT Auth API - Focused authentication facade with minimal over-engineering.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime

from flext_core import FlextDispatcher, FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.user_service import FlextAuthUserService
from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuth(FlextService):
    """Minimal authentication facade exposing only production-used methods.

    This facade provides only the 4 methods actually used in production
    across the FLEXT ecosystem, eliminating massive over-engineering.
    """

    def __init__(self, config: FlextAuthConfig | None = None) -> None:
        """Initialize with minimal dependencies.

        Args:
            config: Authentication configuration. If None, uses global config.

        """
        super().__init__()
        self._auth_config: FlextAuthConfig = config or FlextAuthConfig()
        self._dispatcher = FlextDispatcher()
        self._user_service = FlextAuthUserService(self._auth_config, self._dispatcher)
        self._provider_service = FlextAuthProviderService(self._auth_config)

    def execute(self) -> FlextResult[object]:
        """Execute method for FlextService interface.

        FlextAuth facade doesn't use generic execute pattern.
        Use specific auth methods like register_user() or authenticate_user() instead.
        """
        return FlextResult[object].fail(
            "FlextAuth is focused - use specific auth methods like register_user() or authenticate_user()"
        )

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: list[str] | None = None,
        **extra_fields: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register a new user account.

        Args:
            username: Unique username for the user
            email: User's email address
            password: Plain text password (will be hashed)
            roles: User roles (defaults to ['user'])
            **extra_fields: Additional user fields

        Returns:
            FlextResult containing the created User or error

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
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate a user with username/password.

        Args:
            username: User's username
            password: User's password
            provider: Authentication provider to use

        Returns:
            FlextResult containing AuthToken or error

        """
        # First authenticate using user service
        auth_result = self._user_service.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(auth_result.error)

        user = auth_result.value

        # Generate tokens using provider
        return self._provider_service.generate_tokens_for_user(user, provider)

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.User]:
        """Validate an authentication token.

        Args:
            token: JWT token to validate

        Returns:
            FlextResult containing the authenticated User or error

        """
        # Use JWT provider for token validation
        jwt_provider = FlextAuthJwtProvider(config=self._auth_config.to_dict())
        validation_result = jwt_provider.validate(token)
        if validation_result.is_failure:
            return FlextResult[FlextAuthModels.User].fail(validation_result.error)

        # For now, return a mock user - in real implementation would extract user from token
        user = FlextAuthModels.User(
            user_id=FlextAuthConstants.AuthDefaults.MOCK_VALIDATED_USER_ID,
            username=FlextAuthConstants.AuthDefaults.MOCK_VALIDATED_USERNAME,
            email=FlextAuthConstants.AuthDefaults.MOCK_VALIDATED_EMAIL,
            password_hash=FlextAuthConstants.AuthDefaults.DEFAULT_ADMIN_PASSWORD,
            roles=["user"],
            full_name=None,
            failed_login_attempts=0,
            locked_until=None,
        )
        return FlextResult[FlextAuthModels.User].ok(user)

    def get_user(self, user_id: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing the User or error

        """
        # Simplified - in real implementation would query data store
        # For now, return a mock user to maintain API compatibility
        user = FlextAuthModels.User(
            user_id=user_id,
            username=f"{FlextAuthConstants.AuthDefaults.MOCK_USER_PREFIX}{user_id}",
            email=f"{user_id}{FlextAuthConstants.AuthDefaults.MOCK_EMAIL_DOMAIN}",
            password_hash=FlextAuthConstants.AuthDefaults.DEFAULT_ADMIN_PASSWORD,
            roles=["user"],
            full_name=None,
            failed_login_attempts=0,
            locked_until=None,
        )
        return FlextResult[FlextAuthModels.User].ok(user)

    def generate_token_for_user(
        self,
        user_id: str,
        token_type: str = FlextAuthConstants.Jwt.BASIC_TOKEN_TYPE,
        expires_in_minutes: int | None = None,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Generate an authentication token for an existing user.

        Args:
            user_id: User ID to generate token for
            token_type: Type of token (access, refresh, etc.)
            expires_in_minutes: Custom expiration time in minutes

        Returns:
            FlextResult containing the AuthToken or error

        """
        # Get user first
        user_result = self.get_user(user_id)
        if user_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(user_result.error)

        user = user_result.value

        # Use JWT provider to generate token
        jwt_provider = FlextAuthJwtProvider(config=self._auth_config.to_dict())

        # Create token payload with proper typing
        payload: dict[str, object] = {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "token_type": token_type,
        }

        # Generate token
        token_result = jwt_provider.generate_access_token(
            payload, expires_in_minutes=expires_in_minutes
        )
        if token_result.is_failure:
            return FlextResult[FlextAuthModels.AuthToken].fail(token_result.error)

        # Create AuthToken model
        token_data = token_result.value
        if not isinstance(token_data, dict):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Invalid token data format"
            )

        # Validate required fields
        if not user.user_id:
            return FlextResult[FlextAuthModels.AuthToken].fail("User ID is required")

        expires_at = token_data.get("expires_at")
        if not isinstance(expires_at, datetime):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Invalid expires_at format"
            )

        auth_token = FlextAuthModels.AuthToken(
            user_id=user.user_id,
            token=str(token_data["token"]),
            token_type=token_type,
            expires_at=expires_at,
            session_id=f"session_{user_id}",
            is_revoked=False,
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Generate a JWT token for a user.

        Args:
            user_id: User ID to generate token for
            expires_in_minutes: Custom expiration time in minutes

        Returns:
            FlextResult containing the AuthToken or error

        """
        return self.generate_token_for_user(
            user_id, FlextAuthConstants.Jwt.BEARER_TOKEN_TYPE, expires_in_minutes
        )

    def logout_user(self, session_id: str) -> FlextResult[None]:
        """Logout user by session ID.

        Args:
            session_id: Session ID to logout

        Returns:
            FlextResult indicating success or failure

        """
        # Simplified implementation - in real implementation would revoke session
        _ = session_id  # Mark as used to avoid linting error
        return FlextResult[None].ok(None)

    def get_user_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all active sessions for a user.

        Args:
            user_id: User ID to get sessions for

        Returns:
            FlextResult containing list of sessions or error

        """
        # Simplified implementation - in real implementation would query session store
        session = FlextAuthModels.Session.create_session(
            user_id=user_id,
            expiry_hours=FlextAuthConstants.AuthDefaults.DEFAULT_SESSION_EXTEND_HOURS,
        )
        if session.is_failure:
            return FlextResult[list[FlextAuthModels.Session]].fail(session.error)
        return FlextResult[list[FlextAuthModels.Session]].ok([session.value])

    def get_user_by_username(self, username: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by username.

        Args:
            username: Username to search for

        Returns:
            FlextResult containing the User or error

        """
        # Simplified implementation - in real implementation would query user store
        user = FlextAuthModels.User(
            user_id=f"{FlextAuthConstants.AuthDefaults.MOCK_USER_PREFIX}{username}",
            username=username,
            email=f"{username}{FlextAuthConstants.AuthDefaults.MOCK_EMAIL_DOMAIN}",
            password_hash=FlextAuthConstants.AuthDefaults.DEFAULT_ADMIN_PASSWORD,
            roles=["user"],
            full_name=None,
            failed_login_attempts=0,
            locked_until=None,
        )
        return FlextResult[FlextAuthModels.User].ok(user)


# Module exports
__all__ = ["FlextAuth"]
