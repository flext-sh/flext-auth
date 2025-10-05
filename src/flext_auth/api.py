"""FLEXT Auth API - Enterprise authentication foundation with complete flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
    FlextTypes,
)

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.managers import (
    FlextAuthManagers,
)
from flext_auth.middleware import (
    HttpAuthMiddleware,
    WebAuthMiddleware,
)
from flext_auth.models import FlextAuthModels
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers.base import BaseAuthProvider
from flext_auth.session_service import FlextAuthSessionService
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.user_service import FlextAuthUserService
from flext_auth.utilities import FlextAuthUtilities


class FlextAuth:
    """Thin facade for flext-auth providing enterprise authentication services.

    This service integrates all authentication providers, manages user sessions,
    handles token operations, and provides middleware for web frameworks using
    complete FLEXT ecosystem integration.

    Features:
    - Multi-provider authentication (Basic, JWT, LDAP, OAuth2, SAML, etc.)
    - User management and session handling
    - Token creation, validation, and refresh
    - Password hashing and verification
    - Audit logging and security monitoring
    - Rate limiting and brute force protection
    - Complete flext-core integration (FlextBus, FlextContainer, FlextContext)
    """

    @classmethod
    def create_with_config_overrides(
        cls,
        jwt_secret: str | None = None,
        session_timeout: int | None = None,
        **config_overrides: object,
    ) -> FlextResult[FlextAuth]:
        """Create FlextAuth instance with config overrides.

        Args:
            jwt_secret: Override JWT secret
            session_timeout: Override session timeout in minutes
            **config_overrides: Additional config overrides

        Returns:
            FlextResult containing configured FlextAuth instance

        """
        try:
            config: FlextAuthConfig = FlextAuthConfig()

            # Apply specific overrides
            if jwt_secret is not None:
                config_overrides["jwt_auth_secret"] = jwt_secret
            if session_timeout is not None:
                config_overrides["session_expiry_minutes"] = session_timeout

            # Apply any additional overrides
            for key, value in config_overrides.items():
                if hasattr(config, key):
                    setattr(config, key, value)

            auth_instance = cls(config)
            return FlextResult[FlextAuth].ok(auth_instance)
        except Exception as e:
            return FlextResult[FlextAuth].fail(f"Failed to create FlextAuth: {e}")

    def __init__(self, config: FlextAuthConfig | None = None) -> None:
        """Initialize the authentication service with complete FLEXT integration.

        Args:
            config: Authentication configuration. If None, uses global config.

        """
        super().__init__()

        # Initialize configuration
        self.config = config or FlextAuthConfig.get_global_instance()

        # Complete FLEXT ecosystem integration
        self._container = FlextContainer.get_global()
        self._context = FlextContext()
        self._bus = FlextBus()
        self._dispatcher = FlextDispatcher()
        self._processors = FlextProcessors()
        self._registry = FlextRegistry(dispatcher=self._dispatcher)
        self._logger = FlextLogger(__name__)

        # Initialize focused services
        self._provider_service = FlextAuthProviderService(self.config)
        self._user_service = FlextAuthUserService(self.config, self._dispatcher)
        self._token_service = FlextAuthTokenService(
            self.config, self._provider_service, self._dispatcher
        )
        self._session_service = FlextAuthSessionService(self.config)

        # Initialize additional managers for facade operations
        self._rate_limiter = FlextAuthManagers.FlextAuthRateLimiter(
            self.config, self._dispatcher
        )
        self._audit_logger = FlextAuthManagers.FlextAuthAuditLogger(
            self.config, self._dispatcher
        )

    # User Management Methods
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        **extra_fields: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Create a new user account.

        Args:
            username: Unique username for the user
            email: User's email address
            password: Plain text password (will be hashed)
            **extra_fields: Additional user fields

        Returns:
            FlextResult containing the created User or error

        """
        return self._user_service.create_user(username, email, password, **extra_fields)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: FlextTypes.StringList | None = None,
        **extra_fields: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register a new user account (alias for create_user with role support).

        Args:
            username: Unique username for the user
            email: User's email address
            password: Plain text password (will be hashed)
            roles: User roles (defaults to ['user'])
            **extra_fields: Additional user fields

        Returns:
            FlextResult containing the created User or error

        """
        if roles is None:
            roles = ["user"]
        return self.create_user(
            username=username,
            email=email,
            password=password,
            roles=roles,
            **extra_fields,
        )

    def get_user(self, user_id: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing the User or error

        """
        return self._user_service.get_user(user_id)

    def get_user_by_username(self, username: str) -> FlextResult[FlextAuthModels.User]:
        """Get user by username.

        Args:
            username: Username to search for

        Returns:
            FlextResult containing the User or error

        """
        return self._user_service.get_user_by_username(username)

    def update_user(
        self,
        user_id: str,
        **updates: object,
    ) -> FlextResult[FlextAuthModels.User]:
        """Update user information.

        Args:
            user_id: User identifier
            **updates: Fields to update

        Returns:
            FlextResult containing the updated User or error

        """
        return self._user_service.update_user(user_id, **updates)

    def delete_user(self, user_id: str) -> FlextResult[None]:
        """Delete a user account.

        Args:
            user_id: User identifier to delete

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.delete_user(user_id)

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate a user with username/password.

        Args:
            username: User's username
            password: User's password
            provider: Authentication provider to use

        Returns:
            FlextResult containing AuthToken or error

        """
        # Check rate limiting
        rate_limit_result = self._rate_limiter.check_rate_limit(username)
        if rate_limit_result.is_failure:
            self._audit_logger.log_auth_failure(
                username=username,
                reason="rate_limited",
                provider=provider,
            )
            return FlextResult[FlextAuthModels.AuthToken].fail(rate_limit_result.error)

        # Authenticate using provider service
        auth_result = self._provider_service.authenticate_user(
            username, password, provider
        )

        # Handle authentication result
        if auth_result.is_success:
            self._audit_logger.log_auth_success(username=username, provider=provider)
            # Create session
            auth_token: FlextAuthModels.AuthToken = auth_result.value
            session_result = self._session_service.create_session(
                user_id=auth_token.user_id,
                token=auth_token.token,
            )
            if session_result.is_success:
                # Update token with session info
                auth_token.session_id = session_result.value.id
        else:
            self._audit_logger.log_auth_failure(
                username=username,
                reason=str(auth_result.error),
                provider=provider,
            )
            # Record failed attempt for rate limiting
            self._rate_limiter.record_failed_attempt(username)

        return auth_result

    def validate_token(self, token: str) -> FlextResult[FlextAuthModels.User]:
        """Validate an authentication token.

        Args:
            token: JWT token to validate

        Returns:
            FlextResult containing the authenticated User or error

        """
        return self._token_service.validate_token(token)

    def refresh_token(self, token: str) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh an authentication token.

        Args:
            token: Current valid token to refresh

        Returns:
            FlextResult containing new AuthToken or error

        """
        return self._token_service.refresh_token(token)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
        token_type: str = FlextAuthConstants.Jwt.DEFAULT_ACCESS_TOKEN_TYPE,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Generate a JWT token for a user.

        Args:
            user_id: User ID to generate token for
            expires_in_minutes: Token expiry time in minutes (uses default if None)
            token_type: Type of token ('access', 'refresh', etc.)

        Returns:
            FlextResult containing AuthToken or error

        """
        return self._token_service.generate_jwt_token(
            user_id, expires_in_minutes, token_type
        )

    def logout_user(self, token: str) -> FlextResult[None]:
        """Logout a user by invalidating their session.

        Args:
            token: User's authentication token

        Returns:
            FlextResult indicating success or error

        """
        # Validate token first
        validation_result = self.validate_token(token)
        if validation_result.is_failure:
            return FlextResult[None].fail(f"Invalid token: {validation_result.error}")

        user = validation_result.value

        if not user.user_id:
            return FlextResult[None].fail("User has no user_id")

        # End session
        session_result = self._session_service.end_all_sessions(user.user_id)
        if session_result.is_failure:
            return FlextResult[None].fail(session_result.error)

        # Log logout
        self._audit_logger.log_user_logout(user.username)

        return FlextResult[None].ok(None)

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> FlextResult[None]:
        """Change a user's password.

        Args:
            user_id: User identifier
            current_password: Current password for verification
            new_password: New password to set

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.change_password(
            user_id, current_password, new_password
        )

    def reset_password(self, user_id: str, new_password: str) -> FlextResult[None]:
        """Reset a user's password (REDACTED_LDAP_BIND_PASSWORD operation).

        Args:
            user_id: User identifier
            new_password: New password to set

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.reset_password(user_id, new_password)

    def authorize_user(
        self,
        user_id: str,
        permission: str,
        resource: str | None = None,
    ) -> FlextResult[bool]:
        """Check if a user has a specific permission.

        Args:
            user_id: User identifier
            permission: Permission to check
            resource: Optional resource context

        Returns:
            FlextResult containing boolean authorization result

        """
        return self._user_service.authorize_user(user_id, permission, resource)

    def get_user_permissions(self, user_id: str) -> FlextResult[FlextTypes.StringList]:
        """Get all permissions for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of permission strings

        """
        return self._user_service.get_user_permissions(user_id)

    def get_user_roles(self, user_id: str) -> FlextResult[FlextTypes.StringList]:
        """Get all roles for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of role strings

        """
        return self._user_service.get_user_roles(user_id)

    def add_user_role(self, user_id: str, role: str) -> FlextResult[None]:
        """Add a role to a user.

        Args:
            user_id: User identifier
            role: Role to add

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.add_user_role(user_id, role)

    def remove_user_role(self, user_id: str, role: str) -> FlextResult[None]:
        """Remove a role from a user.

        Args:
            user_id: User identifier
            role: Role to remove

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.remove_user_role(user_id, role)

    def add_user_permission(self, user_id: str, permission: str) -> FlextResult[None]:
        """Add a permission to a user.

        Args:
            user_id: User identifier
            permission: Permission to add

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.add_user_permission(user_id, permission)

    def remove_user_permission(
        self, user_id: str, permission: str
    ) -> FlextResult[None]:
        """Remove a permission from a user.

        Args:
            user_id: User identifier
            permission: Permission to remove

        Returns:
            FlextResult indicating success or error

        """
        return self._user_service.remove_user_permission(user_id, permission)

    # Session Management Methods
    def get_active_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all active sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of active sessions

        """
        return self._session_service.get_active_sessions(user_id)

    def end_session(self, session_id: str) -> FlextResult[None]:
        """End a specific session.

        Args:
            session_id: Session identifier

        Returns:
            FlextResult indicating success or error

        """
        return self._session_service.end_session(session_id)

    def end_all_sessions(self, user_id: str) -> FlextResult[None]:
        """End all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            FlextResult indicating success or error

        """
        return self._session_service.end_all_sessions(user_id)

    def get_user_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all sessions for a user (alias for get_active_sessions).

        Args:
            user_id: User identifier

        Returns:
            FlextResult containing list of user sessions

        """
        return self.get_active_sessions(user_id)

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Clean up expired sessions from the system.

        Returns:
            FlextResult containing number of sessions cleaned up

        """
        return self._session_service.cleanup_expired_sessions()

    # Middleware and Integration Methods
    def get_http_middleware(
        self,
        provider: str | BaseAuthProvider,
        *,
        credentials: FlextTypes.Dict | None = None,
        header_name: str = "Authorization",
        token_prefix: str = FlextAuthConstants.Jwt.BEARER_PREFIX.strip(),
        auto_refresh: bool = True,
        **kwargs: object,
    ) -> HttpAuthMiddleware:
        """Get HTTP middleware for web frameworks.

        Args:
            provider: Provider name or instance
            credentials: Initial credentials for authentication
            **kwargs: Additional middleware arguments

        Returns:
            Configured HTTP middleware

        """
        if isinstance(provider, str):
            provider_result = self._provider_service.get_provider(provider)
            if provider_result.is_failure:
                msg = f"Provider '{provider}' not found"
                raise ValueError(msg)
            provider = provider_result.unwrap()

        return HttpAuthMiddleware(
            provider,
            credentials=credentials,
            header_name=header_name,
            token_prefix=token_prefix,
            auto_refresh=auto_refresh,
            **kwargs,
        )

    def get_web_middleware(
        self,
        provider: str | BaseAuthProvider,
        *,
        header_name: str = "Authorization",
        token_prefix: str = FlextAuthConstants.Jwt.BEARER_PREFIX.strip(),
        cookie_name: str | None = None,
        exclude_paths: list[str] | None = None,
        require_auth: bool = True,
        **kwargs: object,
    ) -> WebAuthMiddleware:
        """Get web middleware for web frameworks.

        Args:
            provider: Provider name or instance
            **kwargs: Additional middleware arguments

        Returns:
            Configured web middleware

        """
        if isinstance(provider, str):
            provider_result = self._provider_service.get_provider(provider)
            if provider_result.is_failure:
                msg = f"Provider '{provider}' not found"
                raise ValueError(msg)
            provider = provider_result.unwrap()

        return WebAuthMiddleware(
            provider,
            header_name=header_name,
            token_prefix=token_prefix,
            cookie_name=cookie_name,
            exclude_paths=exclude_paths,
            require_auth=require_auth,
            **kwargs,
        )

    # Provider Management Methods
    def register_provider(
        self, name: str, provider: BaseAuthProvider
    ) -> FlextResult[None]:
        """Register a custom authentication provider.

        Args:
            name: Provider name
            provider: Provider instance

        Returns:
            FlextResult indicating success or error

        """
        return self._provider_service.register_provider(name, provider)

    def get_provider(self, name: str) -> FlextResult[BaseAuthProvider]:
        """Get a registered authentication provider.

        Args:
            name: Provider name

        Returns:
            FlextResult containing the provider or error

        """
        return self._provider_service.get_provider(name)

    def list_providers(self) -> FlextTypes.StringList:
        """List all registered provider names."""
        return self._provider_service.list_providers()

    # Utility Methods
    def hash_password(self, password: str) -> FlextResult[str]:
        """Hash a password.

        Args:
            password: Plain text password

        Returns:
            FlextResult containing hashed password

        """
        return FlextAuthUtilities.PasswordProcessing.hash_password(password)

    def verify_password_hash(self, password: str, hashed: str) -> FlextResult[bool]:
        """Verify a password against its hash.

        Args:
            password: Plain text password
            hashed: Hashed password

        Returns:
            FlextResult containing boolean verification result

        """
        return FlextAuthUtilities.PasswordProcessing.verify_password(password, hashed)

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate a secure random token.

        Args:
            length: Token length in bytes

        Returns:
            Secure random token string

        """
        return FlextAuthUtilities.TokenProcessing.generate_secure_token(length)

    def validate_password_strength(self, password: str) -> FlextResult[FlextTypes.Dict]:
        """Validate password strength.

        Args:
            password: Password to validate

        Returns:
            FlextResult containing validation results

        """
        return FlextAuthUtilities.PasswordProcessing.validate_password(password)

    # Audit and Monitoring Methods
    def get_audit_logs(
        self,
        user_id: str | None = None,
        event_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
    ) -> FlextResult[list[FlextTypes.NestedDict]]:
        """Get audit logs with optional filtering.

        Args:
            user_id: Filter by user ID
            event_type: Filter by event type
            start_date: Filter from this date
            end_date: Filter to this date
            limit: Maximum number of logs to return

        Returns:
            FlextResult containing list of audit logs

        """
        return self._audit_logger.get_logs(
            user_id=user_id,
            event_type=event_type,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )

    def get_security_stats(self) -> FlextResult[FlextTypes.Dict]:
        """Get security statistics.

        Returns:
            FlextResult containing security statistics

        """
        # Note: This would need to be implemented in the managers
        # For now, return basic stats
        return FlextResult.ok({
            "active_sessions": 0,  # Would come from session manager
            "failed_login_attempts": 0,  # Would come from rate limiter
            "audit_log_entries": 0,  # Would come from audit logger
        })


# Module exports
__all__ = ["FlextAuth"]
